//! SSH3 version negotiation (RFC Section 6).
//!
//! The client sends an `ssh-version` HTTP header containing a comma-separated
//! list of supported SSH3 version strings. The server selects the first value
//! that matches one of its supported versions.

/// The SSH3 version string supported by this implementation.
pub const SSH3_VERSION: &str = "michel-ssh3-00";

/// Supported SSH3 versions (in preference order).
const SUPPORTED_VERSIONS: &[&str] = &[SSH3_VERSION];

/// Parse the `ssh-version` header value and return the first matching version.
///
/// The client value is a comma-separated list of version strings. Leading and
/// trailing whitespace around each entry is trimmed. Returns `None` if no
/// supported version is found.
///
/// # Examples
///
/// ```
/// use genmeta_ssh3_server::version::negotiate_version;
///
/// assert_eq!(negotiate_version("michel-ssh3-00"), Some("michel-ssh3-00"));
/// assert_eq!(negotiate_version("michel-ssh3-00, future-v2"), Some("michel-ssh3-00"));
/// assert_eq!(negotiate_version("unknown-v1"), None);
/// assert_eq!(negotiate_version(""), None);
/// ```
pub fn negotiate_version(client_versions: &str) -> Option<&'static str> {
    for candidate in client_versions.split(',') {
        let candidate = candidate.trim();
        for &supported in SUPPORTED_VERSIONS {
            if candidate == supported {
                return Some(supported);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_matching_version() {
        assert_eq!(negotiate_version("michel-ssh3-00"), Some("michel-ssh3-00"));
    }

    #[test]
    fn matching_version_in_list() {
        assert_eq!(
            negotiate_version("michel-ssh3-00, future-v2"),
            Some("michel-ssh3-00")
        );
    }

    #[test]
    fn matching_version_second_in_list() {
        assert_eq!(
            negotiate_version("future-v2, michel-ssh3-00"),
            Some("michel-ssh3-00")
        );
    }

    #[test]
    fn no_matching_version() {
        assert_eq!(negotiate_version("unknown-v1"), None);
    }

    #[test]
    fn empty_header() {
        assert_eq!(negotiate_version(""), None);
    }

    #[test]
    fn whitespace_trimming() {
        assert_eq!(
            negotiate_version("  michel-ssh3-00  "),
            Some("michel-ssh3-00")
        );
    }

    #[test]
    fn multiple_unknown_versions() {
        assert_eq!(negotiate_version("v1, v2, v3"), None);
    }
}
