//! HTTP-layer authentication credential extraction for the SSH3 server.
//!
//! Delegates to [`genmeta_ssh3_proto::auth::parse_authorization_header`] for
//! the actual parsing and returns an [`AuthChallenge`] on failure so the caller
//! can build a proper `401 Unauthorized` response.
//!
//! Also provides PAM-based password authentication via the [`pam`] submodule.

pub(crate) mod pam;
use genmeta_ssh3_proto::auth::{parse_authorization_header, AuthCredential};

/// An auth rejection — carries the information needed for a `401` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub status: http::StatusCode,
    pub www_authenticate: String,
}

/// Extract an [`AuthCredential`] from the `Authorization` header.
///
/// # Errors
///
/// Returns [`AuthChallenge`] (401 + `WWW-Authenticate: Basic`) if:
/// - The `Authorization` header is missing
/// - The scheme is not `Basic`
/// - The credentials are malformed
pub fn extract_auth_credential(headers: &http::HeaderMap) -> Result<AuthCredential, AuthChallenge> {
    let challenge = || AuthChallenge {
        status: http::StatusCode::UNAUTHORIZED,
        www_authenticate: "Basic".into(),
    };

    let header_value = headers
        .get(http::header::AUTHORIZATION)
        .ok_or_else(challenge)?
        .to_str()
        .map_err(|_| challenge())?;

    parse_authorization_header(header_value).map_err(|_| challenge())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with(name: &str, value: &str) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        map.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            http::HeaderValue::from_str(value).unwrap(),
        );
        map
    }

    #[test]
    fn test_auth_extract_valid_basic() {
        // "user:pass" → base64 "dXNlcjpwYXNz"
        let hdrs = headers_with("authorization", "Basic dXNlcjpwYXNz");
        let cred = extract_auth_credential(&hdrs).unwrap();
        assert_eq!(
            cred,
            AuthCredential::Basic {
                username: "user".into(),
                password: "pass".into(),
            }
        );
    }

    #[test]
    fn test_auth_extract_missing_header() {
        let hdrs = http::HeaderMap::new();
        let err = extract_auth_credential(&hdrs).unwrap_err();
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.www_authenticate, "Basic");
    }

    #[test]
    fn test_auth_extract_bearer_rejected() {
        let hdrs = headers_with("authorization", "Bearer some-token");
        let err = extract_auth_credential(&hdrs).unwrap_err();
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.www_authenticate, "Basic");
    }

    #[test]
    fn test_auth_extract_malformed_base64() {
        let hdrs = headers_with("authorization", "Basic !!!invalid!!!");
        let err = extract_auth_credential(&hdrs).unwrap_err();
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.www_authenticate, "Basic");
    }

    #[test]
    fn test_auth_extract_missing_colon_in_decoded() {
        // "userpass" (no colon) → base64 "dXNlcnBhc3M="
        let hdrs = headers_with("authorization", "Basic dXNlcnBhc3M=");
        let err = extract_auth_credential(&hdrs).unwrap_err();
        assert_eq!(err.status, http::StatusCode::UNAUTHORIZED);
        assert_eq!(err.www_authenticate, "Basic");
    }

    #[test]
    fn test_auth_extract_password_with_colons() {
        // "user:p:a:ss" → base64 "dXNlcjpwOmE6c3M="
        let hdrs = headers_with("authorization", "Basic dXNlcjpwOmE6c3M=");
        let cred = extract_auth_credential(&hdrs).unwrap();
        assert_eq!(
            cred,
            AuthCredential::Basic {
                username: "user".into(),
                password: "p:a:ss".into(),
            }
        );
    }
}
