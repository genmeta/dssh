use snafu::Snafu;

/// Top-level error type for the SSH3 protocol crate.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum Ssh3Error {
    // ── Codec variants ──────────────────────────────────────────────────
    /// Varint exceeds maximum allowed size.
    #[snafu(display("varint too large"))]
    VarintTooLarge,

    // ── Protocol variants ───────────────────────────────────────────────
    /// The `ssh-version` request header is absent.
    #[snafu(display("missing ssh-version header"))]
    MissingSshVersionHeader,

    /// The `ssh-version` header value is not valid ASCII / HTTP header text.
    #[snafu(display("invalid ssh-version header value"))]
    InvalidSshVersionHeaderValue { source: http::header::ToStrError },

    /// The `ssh-version` header is present but empty.
    #[snafu(display("empty ssh-version header"))]
    EmptySshVersionHeader,

    /// None of the client-offered versions are supported by the server.
    #[snafu(display("no supported ssh-version found in client offer: {offered:?}"))]
    UnsupportedSshVersion { offered: String },

    /// Received an unknown channel type.
    #[snafu(display("unknown channel type"))]
    UnknownChannelType,

    // ── Auth variants ───────────────────────────────────────────────────
    /// Authorization header missing the scheme/credentials separator (space).
    #[snafu(display("missing scheme/credentials separator"))]
    MissingSchemeSeparator,

    /// The auth scheme is not supported (only Basic is accepted).
    #[snafu(display("unsupported auth scheme: {scheme}"))]
    UnsupportedAuthScheme { scheme: String },

    /// Credentials portion of the Authorization header is empty.
    #[snafu(display("empty credentials"))]
    EmptyCredentials,

    /// Base64 decoding of the credentials failed.
    #[snafu(display("invalid base64 credentials"))]
    InvalidBase64Credentials { source: base64::DecodeError },

    /// Decoded credentials are not valid UTF-8.
    #[snafu(display("credentials are not valid UTF-8"))]
    CredentialsNotUtf8 { source: std::string::FromUtf8Error },

    /// Decoded credentials lack the `':'` separator between username and password.
    #[snafu(display("missing ':' separator in decoded credentials"))]
    MissingCredentialSeparator,

    /// Generic invalid credentials (e.g. wrong username/password).
    #[snafu(display("invalid credentials"))]
    InvalidCredentials,

    // ── Channel variants ────────────────────────────────────────────────
    /// The channel has been closed.
    #[snafu(display("channel closed"))]
    ChannelClosed,

    // ── Session variants ────────────────────────────────────────────────
    /// Remote command execution failed.
    #[snafu(display("exec failed"))]
    ExecFailed,

    // ── IO variant ──────────────────────────────────────────────────────
    /// IO errors
    #[snafu(display("I/O error"))]
    Io { source: std::io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_error_display() {
        let err = Ssh3Error::VarintTooLarge;
        assert_eq!(err.to_string(), "varint too large");
    }

    #[test]
    fn test_protocol_error_display() {
        let err = Ssh3Error::UnknownChannelType;
        assert_eq!(err.to_string(), "unknown channel type");
    }

    #[test]
    fn test_auth_error_display() {
        let err = Ssh3Error::InvalidCredentials;
        assert_eq!(err.to_string(), "invalid credentials");
    }

    #[test]
    fn test_channel_error_display() {
        let err = Ssh3Error::ChannelClosed;
        assert_eq!(err.to_string(), "channel closed");
    }

    #[test]
    fn test_session_error_display() {
        let err = Ssh3Error::ExecFailed;
        assert_eq!(err.to_string(), "exec failed");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let err = Ssh3Error::Io { source: io_err };
        assert_eq!(err.to_string(), "I/O error");
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset");
        let err: Ssh3Error = Ssh3Error::Io { source: io_err };
        match err {
            Ssh3Error::Io { source } => {
                assert_eq!(source.kind(), std::io::ErrorKind::ConnectionReset);
            }
            _ => panic!("expected Io variant"),
        }
    }
}
