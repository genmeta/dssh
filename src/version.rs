//! DShell version negotiation.
//!
//! The client sends a comma-separated list of supported versions in the
//! `ssh-version` request header. The server picks the first match from
//! [`SUPPORTED_DSHELL_VERSIONS`] and echoes it back.

use crate::constants::SUPPORTED_DSHELL_VERSIONS;
use crate::error::{NegotiateVersionError, negotiate_version_error};
use snafu::ResultExt;

/// A negotiated DShell version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DshellVersion {
    pub version_string: String,
}

/// Negotiate a DShell version from the client's `ssh-version` request header.
///
/// Returns the first client-offered version that the server also supports.
pub fn negotiate_version(
    headers: &http::HeaderMap,
) -> Result<DshellVersion, NegotiateVersionError> {
    let header_value = headers
        .get("ssh-version")
        .ok_or(NegotiateVersionError::MissingDshellVersionHeader)?
        .to_str()
        .context(negotiate_version_error::InvalidDshellVersionHeaderValueSnafu)?;

    if header_value.is_empty() {
        return Err(NegotiateVersionError::EmptyDshellVersionHeader);
    }

    for offered in header_value.split(',') {
        let trimmed = offered.trim();
        if SUPPORTED_DSHELL_VERSIONS.contains(&trimmed) {
            return Ok(DshellVersion {
                version_string: trimmed.to_owned(),
            });
        }
    }

    Err(NegotiateVersionError::UnsupportedDshellVersion {
        offered: header_value.to_owned(),
    })
}

/// Build the `ssh-version` response header value.
pub fn version_response_header(version: &DshellVersion) -> http::HeaderValue {
    http::HeaderValue::from_str(&version.version_string)
        .expect("negotiated version string must be a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::DSHELL_VERSION;

    fn headers_with(value: &str) -> http::HeaderMap {
        let mut map = http::HeaderMap::new();
        map.insert("ssh-version", http::HeaderValue::from_str(value).unwrap());
        map
    }

    #[test]
    fn single_valid_version() {
        let v = negotiate_version(&headers_with(DSHELL_VERSION)).unwrap();
        assert_eq!(v.version_string, DSHELL_VERSION);
    }

    #[test]
    fn multiple_picks_supported() {
        let v = negotiate_version(&headers_with(&format!("unknown-v1,{DSHELL_VERSION}"))).unwrap();
        assert_eq!(v.version_string, DSHELL_VERSION);
    }

    #[test]
    fn missing_header() {
        let err = negotiate_version(&http::HeaderMap::new()).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn no_match() {
        let err = negotiate_version(&headers_with("dshell-99")).unwrap_err();
        assert!(err.to_string().contains("no supported"));
    }

    #[test]
    fn whitespace_handling() {
        let v =
            negotiate_version(&headers_with(&format!(" {DSHELL_VERSION} , other-v1 "))).unwrap();
        assert_eq!(v.version_string, DSHELL_VERSION);
    }

    #[test]
    fn empty_header() {
        let err = negotiate_version(&headers_with("")).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }
}
