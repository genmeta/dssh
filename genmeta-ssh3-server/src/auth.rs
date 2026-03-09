//! HTTP Authorization header parsing for SSH3 (RFC Section 6.1).
//!
//! Only HTTP Basic authentication is supported. Other schemes (Bearer, etc.)
//! return [`AuthParseError::UnsupportedScheme`].
//!
//! Security note: credential comparison must be done with constant-time
//! equality to prevent timing attacks. This module only *parses* credentials;
//! the caller is responsible for constant-time comparison during verification.

use http::HeaderValue;
use proto::session::AuthCredential;
use snafu::Snafu;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The result of a successful `Authorization` header parse.
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// The SSH username.
    pub username: String,
    /// The authentication credential extracted from the header.
    pub credential: AuthCredential,
}

/// Errors that can occur while parsing an `Authorization` header.
#[derive(Debug, Snafu, PartialEq, Eq)]
pub enum AuthParseError {
    /// The `Authorization` header value is not valid UTF-8 or ASCII.
    #[snafu(display("Authorization header is not valid ASCII"))]
    InvalidEncoding,

    /// The header value does not contain a scheme prefix.
    #[snafu(display("Authorization header is missing the scheme prefix"))]
    MissingScheme,

    /// The authentication scheme is not supported by this server.
    #[snafu(display("Unsupported authentication scheme: {scheme}"))]
    UnsupportedScheme { scheme: String },

    /// The Basic credentials are not valid base64.
    #[snafu(display("Basic credentials contain invalid base64"))]
    InvalidBase64,

    /// The decoded Basic credentials do not contain a `:` separator.
    #[snafu(display("Basic credentials are missing the ':' separator"))]
    MissingColon,

    /// The decoded Basic credentials are not valid UTF-8.
    #[snafu(display("Basic credentials contain invalid UTF-8"))]
    InvalidUtf8,

    /// The username in the Basic credentials is empty.
    #[snafu(display("Basic credentials have an empty username"))]
    EmptyUsername,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse an HTTP `Authorization` header value.
///
/// Supports only the `Basic` scheme. All other schemes return
/// [`AuthParseError::UnsupportedScheme`].
///
/// # Examples
///
/// ```
/// use http::HeaderValue;
/// use genmeta_ssh3_server::auth::parse_authorization;
///
/// let hv = HeaderValue::from_static("Basic dXNlcjpwYXNz");
/// let result = parse_authorization(&hv).unwrap();
/// assert_eq!(result.username, "user");
/// ```
pub fn parse_authorization(header: &HeaderValue) -> Result<AuthResult, AuthParseError> {
    let raw = header
        .to_str()
        .map_err(|_| AuthParseError::InvalidEncoding)?;

    // Split scheme from credentials.
    let (scheme, rest) = raw.split_once(' ').ok_or(AuthParseError::MissingScheme)?;

    match scheme {
        "Basic" => parse_basic(rest),
        other => UnsupportedSchemeSnafu {
            scheme: other.to_string(),
        }
        .fail(),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Parse the base64-encoded `user:password` token for Basic auth.
fn parse_basic(b64: &str) -> Result<AuthResult, AuthParseError> {
    let decoded_bytes =
        decode_base64_standard(b64.trim()).map_err(|_| AuthParseError::InvalidBase64)?;

    let decoded = std::str::from_utf8(&decoded_bytes).map_err(|_| AuthParseError::InvalidUtf8)?;

    // Split on the *first* colon only — the password may contain colons.
    let (username, password) = decoded
        .split_once(':')
        .ok_or(AuthParseError::MissingColon)?;

    if username.is_empty() {
        return Err(AuthParseError::EmptyUsername);
    }

    Ok(AuthResult {
        username: username.to_string(),
        credential: AuthCredential::Password(password.to_string()),
    })
}

/// Decode standard base64 (RFC 4648 §4, alphabet A-Z a-z 0-9 + / with = padding).
///
/// Returns an error if the input contains characters outside the alphabet or
/// has invalid padding.
fn decode_base64_standard(input: &str) -> Result<Vec<u8>, ()> {
    // Base64 standard alphabet value table.
    const TABLE: [i8; 256] = {
        let mut t = [-1i8; 256];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i as i8;
            t[(b'a' + i) as usize] = (i + 26) as i8;
            i += 1;
        }
        let mut i = 0u8;
        while i < 10 {
            t[(b'0' + i) as usize] = (i + 52) as i8;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };

    let input = input.as_bytes();
    let len = input.len();

    // Must be a multiple of 4.
    if len % 4 != 0 {
        return Err(());
    }

    if len == 0 {
        return Ok(Vec::new());
    }

    // Count padding.
    let pad = input.iter().rev().take(2).filter(|&&b| b == b'=').count();

    let mut out = Vec::with_capacity(len / 4 * 3);

    let mut pos = 0;
    while pos < len {
        let a = TABLE[input[pos] as usize];
        let b = TABLE[input[pos + 1] as usize];
        let c_byte = input[pos + 2];
        let d_byte = input[pos + 3];

        // The last block may use '=' padding.
        let is_last = pos + 4 == len;
        let c_val: i8 = if is_last && c_byte == b'=' {
            0
        } else {
            TABLE[c_byte as usize]
        };
        let d_val: i8 = if is_last && d_byte == b'=' {
            0
        } else {
            TABLE[d_byte as usize]
        };

        if a < 0 || b < 0 || c_val < 0 || d_val < 0 {
            return Err(());
        }

        let triple: u32 =
            ((a as u32) << 18) | ((b as u32) << 12) | ((c_val as u32) << 6) | (d_val as u32);

        out.push((triple >> 16) as u8);
        if !(is_last && pad >= 2) {
            out.push((triple >> 8) as u8);
        }
        if !(is_last && pad >= 1) {
            out.push(triple as u8);
        }

        pos += 4;
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proto::session::AuthCredential;

    fn hv(s: &'static str) -> HeaderValue {
        HeaderValue::from_static(s)
    }

    fn b64_encode(s: &str) -> String {
        // Minimal base64 encoder for tests only.
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes = s.as_bytes();
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(CHARS[((triple >> 18) & 0x3f) as usize] as char);
            out.push(CHARS[((triple >> 12) & 0x3f) as usize] as char);
            if chunk.len() > 1 {
                out.push(CHARS[((triple >> 6) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(CHARS[(triple & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

    #[test]
    fn parse_basic_valid() {
        // "user:pass" base64 → "dXNlcjpwYXNz"
        let result = parse_authorization(&hv("Basic dXNlcjpwYXNz")).unwrap();
        assert_eq!(result.username, "user");
        assert!(matches!(result.credential, AuthCredential::Password(p) if p == "pass"));
    }

    #[test]
    fn parse_basic_password_with_colon() {
        let b64 = b64_encode("user:pa:ss");
        let hv_str = format!("Basic {b64}");
        let hv = HeaderValue::from_str(&hv_str).unwrap();
        let result = parse_authorization(&hv).unwrap();
        assert_eq!(result.username, "user");
        assert!(matches!(result.credential, AuthCredential::Password(p) if p == "pa:ss"));
    }

    #[test]
    fn parse_basic_empty_password() {
        let b64 = b64_encode("user:");
        let hv_str = format!("Basic {b64}");
        let hv = HeaderValue::from_str(&hv_str).unwrap();
        let result = parse_authorization(&hv).unwrap();
        assert_eq!(result.username, "user");
        assert!(matches!(result.credential, AuthCredential::Password(p) if p.is_empty()));
    }

    #[test]
    fn parse_basic_invalid_base64() {
        let err = parse_authorization(&hv("Basic not!@#$")).unwrap_err();
        assert_eq!(err, AuthParseError::InvalidBase64);
    }

    #[test]
    fn parse_basic_missing_colon() {
        let b64 = b64_encode("usernameonly");
        let hv_str = format!("Basic {b64}");
        let hv = HeaderValue::from_str(&hv_str).unwrap();
        let err = parse_authorization(&hv).unwrap_err();
        assert_eq!(err, AuthParseError::MissingColon);
    }

    #[test]
    fn parse_basic_empty_username() {
        let b64 = b64_encode(":password");
        let hv_str = format!("Basic {b64}");
        let hv = HeaderValue::from_str(&hv_str).unwrap();
        let err = parse_authorization(&hv).unwrap_err();
        assert_eq!(err, AuthParseError::EmptyUsername);
    }

    #[test]
    fn unsupported_scheme_bearer() {
        let err = parse_authorization(&hv("Bearer some.jwt.token")).unwrap_err();
        assert!(matches!(err, AuthParseError::UnsupportedScheme { scheme } if scheme == "Bearer"));
    }

    #[test]
    fn unsupported_scheme_unknown() {
        let err = parse_authorization(&hv("Negotiate somecreds")).unwrap_err();
        assert!(
            matches!(err, AuthParseError::UnsupportedScheme { scheme } if scheme == "Negotiate")
        );
    }

    #[test]
    fn missing_scheme() {
        let b64 = b64_encode("user:pass");
        let hv = HeaderValue::from_str(&b64).unwrap();
        let err = parse_authorization(&hv).unwrap_err();
        assert_eq!(err, AuthParseError::MissingScheme);
    }

    #[test]
    fn base64_decode_roundtrip() {
        let cases = ["hello", "user:pass", "a:b:c", "", "x"];
        for s in cases {
            let encoded = b64_encode(s);
            let decoded = decode_base64_standard(&encoded).unwrap();
            assert_eq!(
                std::str::from_utf8(&decoded).unwrap(),
                s,
                "failed for {s:?}"
            );
        }
    }
}
