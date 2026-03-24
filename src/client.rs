//! SSH3 client utilities.
//!
//! Provides constants and helpers for SSH3 client implementations.

use base64::engine::{Engine, general_purpose::STANDARD};
use http::HeaderValue;

/// Well-known path for SSH3 Extended CONNECT requests.
pub const SSH3_CONNECT_PATH: &str = "/.well-known/ssh3/connect";

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
