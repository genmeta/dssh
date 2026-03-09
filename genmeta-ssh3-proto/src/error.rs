use snafu::Snafu;

/// Top-level error type for the SSH3 protocol crate.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum Ssh3Error {
    /// Codec-level errors (varint too large, buffer underflow, invalid encoding)
    #[snafu(display("codec error: {message}"))]
    Codec { message: String },

    /// Protocol-level errors (unknown channel type, unexpected message, version mismatch)
    #[snafu(display("protocol error: {message}"))]
    Protocol { message: String },

    /// Authentication errors (invalid credentials, PAM failure, unsupported scheme)
    #[snafu(display("auth error: {message}"))]
    Auth { message: String },

    /// Channel errors (channel closed, EOF, request failed)
    #[snafu(display("channel error: {message}"))]
    Channel { message: String },

    /// Session errors (exec failed, pty allocation failed, forwarding failed)
    #[snafu(display("session error: {message}"))]
    Session { message: String },

    /// IO errors
    #[snafu(display("io error: {source}"))]
    Io { source: std::io::Error },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codec_error_display() {
        let err = Ssh3Error::Codec {
            message: "varint too large".into(),
        };
        assert_eq!(err.to_string(), "codec error: varint too large");
    }

    #[test]
    fn test_protocol_error_display() {
        let err = Ssh3Error::Protocol {
            message: "unknown channel type".into(),
        };
        assert_eq!(err.to_string(), "protocol error: unknown channel type");
    }

    #[test]
    fn test_auth_error_display() {
        let err = Ssh3Error::Auth {
            message: "invalid credentials".into(),
        };
        assert_eq!(err.to_string(), "auth error: invalid credentials");
    }

    #[test]
    fn test_channel_error_display() {
        let err = Ssh3Error::Channel {
            message: "channel closed".into(),
        };
        assert_eq!(err.to_string(), "channel error: channel closed");
    }

    #[test]
    fn test_session_error_display() {
        let err = Ssh3Error::Session {
            message: "exec failed".into(),
        };
        assert_eq!(err.to_string(), "session error: exec failed");
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe broken");
        let err = Ssh3Error::Io { source: io_err };
        assert!(err.to_string().contains("io error:"));
        assert!(err.to_string().contains("pipe broken"));
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
