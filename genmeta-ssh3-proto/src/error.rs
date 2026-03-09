use serde::{Deserialize, Serialize};
use snafu::Snafu;

/// Errors during CBOR encoding/decoding of SSH3 messages
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum CodecError {
    #[snafu(display("CBOR encoding failed: {message}"))]
    CborEncode { message: String },

    #[snafu(display("CBOR decoding failed: {message}"))]
    CborDecode { message: String },

    #[snafu(display("unexpected end of input"))]
    Incomplete,

    #[snafu(display("unknown message type: {value}"))]
    UnknownMessageType { value: u8 },

    #[snafu(display("varint overflow"))]
    VarintOverflow,
}

/// Errors at the SSH3 protocol level
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum ProtocolError {
    #[snafu(display("invalid signal value: expected 0xaf3627e6, got {value:#x}"))]
    InvalidSignalValue { value: u32 },

    #[snafu(display("conversation {id} not found"))]
    ConversationNotFound { id: u64 },

    #[snafu(display("version negotiation failed: {reason}"))]
    VersionNegotiation { reason: String },

    #[snafu(display("codec error"))]
    Codec { source: CodecError },

    #[snafu(display("stream closed unexpectedly"))]
    StreamClosed,
}

/// Errors related to SSH3 channel operations
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), module)]
pub enum ChannelError {
    #[snafu(display("channel open failed: {reason}"))]
    OpenFailed { reason: String },

    #[snafu(display("channel {id} not found"))]
    NotFound { id: u32 },

    #[snafu(display("channel already closed"))]
    AlreadyClosed,

    #[snafu(display("maximum message size exceeded: {size} > {max}"))]
    MessageTooLarge { size: u64, max: u64 },

    #[snafu(display("codec error"))]
    Codec { source: CodecError },
}

/// Authentication errors — Serialize + Deserialize for remoc RTC transport
#[derive(Debug, Snafu, Clone, Serialize, Deserialize)]
#[snafu(visibility(pub(crate)), module)]
pub enum AuthError {
    #[snafu(display("unsupported authentication scheme: {scheme}"))]
    UnsupportedScheme { scheme: String },

    #[snafu(display("invalid credentials"))]
    InvalidCredentials,

    #[snafu(display("authentication required"))]
    AuthRequired,

    #[snafu(display("PAM authentication failed: {message}"))]
    PamFailed { message: String },
}

/// Session-level errors — Serialize + Deserialize for remoc RTC transport
#[derive(Debug, Snafu, Clone, Serialize, Deserialize)]
#[snafu(visibility(pub(crate)), module)]
pub enum SessionError {
    #[snafu(display("session setup failed: {reason}"))]
    SetupFailed { reason: String },

    #[snafu(display("authentication error"))]
    Auth { source: AuthError },

    #[snafu(display("process spawn failed: {reason}"))]
    SpawnFailed { reason: String },

    #[snafu(display("session terminated: {reason}"))]
    Terminated { reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_error_display() {
        let err = CodecError::Incomplete;
        assert_eq!(err.to_string(), "unexpected end of input");
    }

    #[test]
    fn auth_error_display() {
        let err = AuthError::InvalidCredentials;
        assert_eq!(err.to_string(), "invalid credentials");
    }

    #[test]
    fn auth_error_serde_roundtrip() {
        let err = AuthError::UnsupportedScheme {
            scheme: "Bearer".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: AuthError = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.to_string(), err.to_string());
    }

    #[test]
    fn session_error_serde_roundtrip() {
        let err = SessionError::SetupFailed {
            reason: "test".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: SessionError = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.to_string(), err.to_string());
    }
}
