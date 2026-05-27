//! SSH3 client utilities.
//!
//! Provides helpers for SSH3/DSSH client implementations.

use base64::engine::{Engine, general_purpose::STANDARD};
use http::HeaderValue;

/// Encode Basic auth header value: `Basic base64(username:password)`.
pub fn encode_basic_auth(username: &str, password: &str) -> HeaderValue {
    let encoded = STANDARD.encode(format!("{username}:{password}"));
    HeaderValue::from_str(&format!("Basic {encoded}"))
        .expect("base64 credentials are valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_auth_encoding() {
        let header = encode_basic_auth("user", "password");
        assert_eq!(header.to_str().unwrap(), "Basic dXNlcjpwYXNzd29yZA==");
    }

    #[test]
    fn basic_auth_roundtrip() {
        let header = encode_basic_auth("alice", "s3cret");
        let header_str = header.to_str().unwrap();
        let cred = crate::auth::parse_authorization_header(header_str).unwrap();
        assert_eq!(
            cred,
            crate::auth::AuthCredential::Basic {
                username: "alice".into(),
                password: "s3cret".into(),
            }
        );
    }
}
