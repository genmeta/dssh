//! SSH3 version negotiation per RFC Section 6.
//!
//! The client sends a comma-separated list of supported draft versions in the
//! `ssh-version` request header (without the `"draft-"` prefix). The server
//! picks the first client-offered version it also supports and echoes that
//! single version back in the response `ssh-version` header.

use genmeta_ssh3_proto::error::Ssh3Error;

/// The SSH3 draft versions this server supports.
const SUPPORTED_VERSIONS: &[&str] = &["michel-ssh3-00"];

/// A negotiated SSH3 version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshVersion {
    pub version_string: String,
}

/// Negotiate an SSH3 version from the client's `ssh-version` request header.
///
/// Returns the first client-offered version that the server also supports.
///
/// # Errors
///
/// Returns [`Ssh3Error::Protocol`] if:
/// - The `ssh-version` header is missing
/// - No client version matches any server-supported version
pub fn negotiate_version(headers: &http::HeaderMap) -> Result<SshVersion, Ssh3Error> {
    let header_value = headers
        .get("ssh-version")
        .ok_or(Ssh3Error::MissingSshVersionHeader)?
        .to_str()
        .map_err(|_| Ssh3Error::InvalidSshVersionHeaderValue)?;

    if header_value.is_empty() {
        return Err(Ssh3Error::EmptySshVersionHeader);
    }

    for offered in header_value.split(',') {
        let trimmed = offered.trim();
        if SUPPORTED_VERSIONS.contains(&trimmed) {
            return Ok(SshVersion {
                version_string: trimmed.to_owned(),
            });
        }
    }

    Err(Ssh3Error::UnsupportedSshVersion {
        offered: header_value.to_owned(),
    })
}

/// Build the `ssh-version` response header value (the single negotiated version).
pub fn version_response_header(version: &SshVersion) -> http::HeaderValue {
    http::HeaderValue::from_str(&version.version_string)
        .expect("negotiated version string must be a valid header value")
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
    fn test_version_negotiate_single_valid() {
        let hdrs = headers_with("ssh-version", "michel-ssh3-00");
        let v = negotiate_version(&hdrs).unwrap();
        assert_eq!(v.version_string, "michel-ssh3-00");
    }

    #[test]
    fn test_version_negotiate_multiple_picks_supported() {
        let hdrs = headers_with("ssh-version", "michel-ssh3-01,michel-ssh3-00");
        let v = negotiate_version(&hdrs).unwrap();
        assert_eq!(v.version_string, "michel-ssh3-00");
    }

    #[test]
    fn test_version_negotiate_missing_header() {
        let hdrs = http::HeaderMap::new();
        let err = negotiate_version(&hdrs).unwrap_err();
        assert!(err.to_string().contains("missing ssh-version header"));
    }

    #[test]
    fn test_version_negotiate_no_match() {
        let hdrs = headers_with("ssh-version", "michel-ssh3-99");
        let err = negotiate_version(&hdrs).unwrap_err();
        assert!(err.to_string().contains("no supported ssh-version"));
    }

    #[test]
    fn test_version_negotiate_whitespace_handling() {
        let hdrs = headers_with("ssh-version", "michel-ssh3-00 , michel-ssh3-01");
        let v = negotiate_version(&hdrs).unwrap();
        assert_eq!(v.version_string, "michel-ssh3-00");
    }

    #[test]
    fn test_version_negotiate_whitespace_around_supported() {
        let hdrs = headers_with("ssh-version", " michel-ssh3-01 , michel-ssh3-00 ");
        let v = negotiate_version(&hdrs).unwrap();
        assert_eq!(v.version_string, "michel-ssh3-00");
    }

    #[test]
    fn test_version_negotiate_empty_header() {
        let hdrs = headers_with("ssh-version", "");
        let err = negotiate_version(&hdrs).unwrap_err();
        assert!(err.to_string().contains("empty ssh-version header"));
    }

    #[test]
    fn test_version_response_header() {
        let v = SshVersion {
            version_string: "michel-ssh3-00".into(),
        };
        let hv = version_response_header(&v);
        assert_eq!(hv.to_str().unwrap(), "michel-ssh3-00");
    }
}
