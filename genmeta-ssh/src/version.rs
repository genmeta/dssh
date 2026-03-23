//! SSH3 version negotiation.
//!
//! The client sends a comma-separated list of supported versions in the
//! `ssh-version` request header. The server picks the first match from
//! [`SUPPORTED_SSH_VERSIONS`] and echoes it back.

use crate::{Ssh3Error, ssh3_error};
use crate::constants::SUPPORTED_SSH_VERSIONS;
use snafu::ResultExt;

/// A negotiated SSH3 version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshVersion {
    pub version_string: String,
}

/// Negotiate an SSH3 version from the client's `ssh-version` request header.
///
/// Returns the first client-offered version that the server also supports.
pub fn negotiate_version(headers: &http::HeaderMap) -> Result<SshVersion, Ssh3Error> {
    let header_value = headers
        .get("ssh-version")
        .ok_or(Ssh3Error::MissingSshVersionHeader)?
        .to_str()
        .context(ssh3_error::InvalidSshVersionHeaderValueSnafu)?;

    if header_value.is_empty() {
        return Err(Ssh3Error::EmptySshVersionHeader);
    }

    for offered in header_value.split(',') {
        let trimmed = offered.trim();
        if SUPPORTED_SSH_VERSIONS.contains(&trimmed) {
            return Ok(SshVersion {
                version_string: trimmed.to_owned(),
            });
        }
    }

    Err(Ssh3Error::UnsupportedSshVersion {
        offered: header_value.to_owned(),
    })
}

/// Build the `ssh-version` response header value.
pub fn version_response_header(version: &SshVersion) -> http::HeaderValue {
    http::HeaderValue::from_str(&version.version_string)
        .expect("negotiated version string must be a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::SSH_VERSION;

    fn headers_with(value: &str) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        map.insert("ssh-version", http::HeaderValue::from_str(value).unwrap());
        map
    }

    #[test]
    fn single_valid_version() {
        let v = negotiate_version(&headers_with(SSH_VERSION)).unwrap();
        assert_eq!(v.version_string, SSH_VERSION);
    }

    #[test]
    fn multiple_picks_supported() {
        let v = negotiate_version(&headers_with(&format!("unknown-v1,{SSH_VERSION}"))).unwrap();
        assert_eq!(v.version_string, SSH_VERSION);
    }

    #[test]
    fn missing_header() {
        let err = negotiate_version(&http::HeaderMap::new()).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn no_match() {
        let err = negotiate_version(&headers_with("genmeta-ssh3-99")).unwrap_err();
        assert!(err.to_string().contains("no supported"));
    }

    #[test]
    fn whitespace_handling() {
        let v = negotiate_version(&headers_with(&format!(" {SSH_VERSION} , other-v1 "))).unwrap();
        assert_eq!(v.version_string, SSH_VERSION);
    }

    #[test]
    fn empty_header() {
        let err = negotiate_version(&headers_with("")).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }
}
