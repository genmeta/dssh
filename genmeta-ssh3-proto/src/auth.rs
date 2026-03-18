use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::fmt;

use crate::error::Ssh3Error;

/// Authentication credential — only Basic auth is supported.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AuthCredential {
    Basic { username: String, password: String },
}

impl fmt::Display for AuthCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic { username, .. } => {
                write!(f, "Basic(username={username}, password=<redacted>)")
            }
        }
    }
}

/// Authentication scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    Basic,
}

/// Parse an HTTP Authorization header value into an [`AuthCredential`].
///
/// Only the `"Basic"` scheme is supported. The value after `"Basic "` is
/// base64-decoded and split on the first `':'` to obtain username and password.
///
/// # Examples
/// ```ignore
/// let cred = parse_authorization_header("Basic dXNlcjpwYXNz").unwrap();
/// assert_eq!(cred, AuthCredential::Basic { username: "user".into(), password: "pass".into() });
/// ```
pub fn parse_authorization_header(header_value: &str) -> Result<AuthCredential, Ssh3Error> {
    let (scheme, credentials) = header_value
        .split_once(' ')
        .ok_or(Ssh3Error::MissingSchemeSeparator)?;

    if !scheme.eq_ignore_ascii_case("Basic") {
        return Err(Ssh3Error::UnsupportedAuthScheme {
            scheme: scheme.to_owned(),
        });
    }

    if credentials.is_empty() {
        return Err(Ssh3Error::EmptyCredentials);
    }

    let decoded_bytes = STANDARD
        .decode(credentials)
        .map_err(|_| Ssh3Error::InvalidBase64Credentials)?;

    let decoded = String::from_utf8(decoded_bytes).map_err(|_| Ssh3Error::CredentialsNotUtf8)?;

    let (username, password) = decoded
        .split_once(':')
        .ok_or(Ssh3Error::MissingCredentialSeparator)?;

    Ok(AuthCredential::Basic {
        username: username.to_owned(),
        password: password.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_auth_valid() {
        // "user:pass" → base64 "dXNlcjpwYXNz"
        let cred = parse_authorization_header("Basic dXNlcjpwYXNz").unwrap();
        assert_eq!(
            cred,
            AuthCredential::Basic {
                username: "user".into(),
                password: "pass".into(),
            }
        );
    }

    #[test]
    fn test_parse_basic_auth_case_insensitive() {
        let cred = parse_authorization_header("basic dXNlcjpwYXNz").unwrap();
        assert_eq!(
            cred,
            AuthCredential::Basic {
                username: "user".into(),
                password: "pass".into(),
            }
        );
    }

    #[test]
    fn test_parse_non_basic_scheme_rejected() {
        let result = parse_authorization_header("Bearer xxx");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("unsupported auth scheme"));
    }

    #[test]
    fn test_parse_malformed_base64() {
        let result = parse_authorization_header("Basic !!!not-base64!!!");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("invalid base64"));
    }

    #[test]
    fn test_parse_missing_colon() {
        // "userpass" (no colon) → base64 "dXNlcnBhc3M="
        let result = parse_authorization_header("Basic dXNlcnBhc3M=");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("missing ':'"));
    }

    #[test]
    fn test_parse_empty_header() {
        let result = parse_authorization_header("");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_credentials() {
        let result = parse_authorization_header("Basic ");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("empty credentials"));
    }

    #[test]
    fn test_parse_password_with_colons() {
        // "user:p:a:ss" → base64 "dXNlcjpwOmE6c3M="
        let cred = parse_authorization_header("Basic dXNlcjpwOmE6c3M=").unwrap();
        assert_eq!(
            cred,
            AuthCredential::Basic {
                username: "user".into(),
                password: "p:a:ss".into(),
            }
        );
    }

    #[test]
    fn test_auth_scheme_debug() {
        assert_eq!(format!("{:?}", AuthScheme::Basic), "Basic");
    }

    #[test]
    fn test_auth_credential_display_redacts_password() {
        let credential = AuthCredential::Basic {
            username: "user".into(),
            password: "secret-pass".into(),
        };

        let formatted = credential.to_string();
        assert_eq!(formatted, "Basic(username=user, password=<redacted>)");
        assert!(!formatted.contains("secret-pass"));
    }
}
