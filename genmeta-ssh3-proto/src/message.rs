//! SSH3 message types — all channel messages and global requests.
//!
//! SSH3 reuses the SSH Connection protocol (RFC4254) message types, with channel
//! numbers removed since each channel runs over its own HTTP/3 stream.
//! Wire format is CBOR (per SSH3 draft-michel-ssh3-00 Section 4.1.4).
//!
//! Wire format on the channel stream:
//! ```text
//! [MessageType (u8)] [CBOR-encoded sub-message body]
//! ```

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::codec::{cbor_decode, cbor_encode, MessageType};
use crate::error::CodecError;

// ─────────────────────────────────────────────────────────────────────────────
// ChannelType
// ─────────────────────────────────────────────────────────────────────────────

/// SSH3 channel type strings (RFC4254 §6, adapted for SSH3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChannelType {
    Session,
    DirectTcp,
    ReverseTcp,
    DirectUdp,
    ReverseUdp,
    /// Catch-all for unknown channel types received from peers.
    Other(String),
}

impl ChannelType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Session => "session",
            Self::DirectTcp => "direct-tcp",
            Self::ReverseTcp => "reverse-tcp",
            Self::DirectUdp => "direct-udp",
            Self::ReverseUdp => "reverse-udp",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl From<&str> for ChannelType {
    fn from(s: &str) -> Self {
        match s {
            "session" => Self::Session,
            "direct-tcp" => Self::DirectTcp,
            "reverse-tcp" => Self::ReverseTcp,
            "direct-udp" => Self::DirectUdp,
            "reverse-udp" => Self::ReverseUdp,
            other => Self::Other(other.to_string()),
        }
    }
}

impl From<String> for ChannelType {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Sub-message structs
// ─────────────────────────────────────────────────────────────────────────────

/// SSH_MSG_CHANNEL_OPEN (type 90) — initiates a new channel (RFC4254 §5.1, SSH3 §4.1).
///
/// Note: channel_id is absent — each channel runs over its own HTTP/3 stream
/// and the channel type is in the stream header, but this struct carries the
/// type for deserialization convenience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelOpenMsg {
    pub channel_type: ChannelType,
    pub maximum_message_size: u64,
}

/// SSH_MSG_CHANNEL_OPEN_CONFIRMATION (type 91) — accepts an open request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelOpenConfirmationMsg {
    pub maximum_message_size: u64,
}

/// SSH_MSG_CHANNEL_OPEN_FAILURE reason codes (RFC4254 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u32)]
pub enum ChannelOpenFailureReason {
    AdministrativelyProhibited = 1,
    ConnectFailed = 2,
    UnknownChannelType = 3,
    ResourceShortage = 4,
}

/// SSH_MSG_CHANNEL_OPEN_FAILURE (type 92).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelOpenFailureMsg {
    pub reason_code: u32,
    pub description: String,
}

/// SSH_MSG_CHANNEL_WINDOW_ADJUST (type 93).
///
/// Not actively used in SSH3 (HTTP/3 has its own flow control), but defined
/// for protocol completeness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelWindowAdjustMsg {
    pub bytes_to_add: u64,
}

/// SSH_MSG_CHANNEL_DATA (type 94) — raw payload data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelDataMsg {
    pub data: Vec<u8>,
}

impl ChannelDataMsg {
    pub fn new(data: impl Into<Vec<u8>>) -> Self {
        Self { data: data.into() }
    }

    pub fn bytes(&self) -> Bytes {
        Bytes::copy_from_slice(&self.data)
    }
}

/// SSH_MSG_CHANNEL_EXTENDED_DATA (type 95) — extended data (e.g. stderr).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelExtendedDataMsg {
    /// 1 = stderr
    pub data_type_code: u32,
    pub data: Vec<u8>,
}

impl ChannelExtendedDataMsg {
    pub const STDERR: u32 = 1;
}

/// SSH_MSG_CHANNEL_EOF (type 96) — no more data will be sent on this channel.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelEOFMsg {}

/// SSH_MSG_CHANNEL_CLOSE (type 97) — channel is being closed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelCloseMsg {}

/// SSH_MSG_CHANNEL_REQUEST (type 98) — requests a service on the channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelRequestMsg {
    pub want_reply: bool,
    pub request: ChannelRequestType,
}

/// SSH_MSG_CHANNEL_SUCCESS (type 99).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelSuccessMsg {}

/// SSH_MSG_CHANNEL_FAILURE (type 100).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChannelFailureMsg {}

// ─────────────────────────────────────────────────────────────────────────────
// ChannelRequestType
// ─────────────────────────────────────────────────────────────────────────────

/// The specific request carried in SSH_MSG_CHANNEL_REQUEST (RFC4254 §6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChannelRequestType {
    /// Pseudo-terminal request (RFC4254 §6.2).
    PtyReq {
        term: String,
        width_chars: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
        /// Terminal mode bytes (opaque).
        modes: Vec<u8>,
    },
    /// Start a shell (RFC4254 §6.5).
    Shell,
    /// Execute a command (RFC4254 §6.5).
    Exec { command: String },
    /// Start a subsystem (RFC4254 §6.5).
    Subsystem { subsystem: String },
    /// Window dimension change (RFC4254 §6.7).
    WindowChange {
        width_chars: u32,
        height_rows: u32,
        width_px: u32,
        height_px: u32,
    },
    /// Send a signal to the process (RFC4254 §6.9).
    Signal { signal: String },
    /// Report exit status (RFC4254 §6.10).
    ExitStatus { exit_status: u32 },
    /// Report exit by signal (RFC4254 §6.10).
    ExitSignal {
        signal: String,
        core_dumped: bool,
        error_message: String,
        language_tag: String,
    },
    /// Set environment variable (RFC4254 §6.4).
    Env { name: String, value: String },
}

impl ChannelRequestType {
    /// The RFC4254 request-type string for this variant.
    pub fn request_type_str(&self) -> &'static str {
        match self {
            Self::PtyReq { .. } => "pty-req",
            Self::Shell => "shell",
            Self::Exec { .. } => "exec",
            Self::Subsystem { .. } => "subsystem",
            Self::WindowChange { .. } => "window-change",
            Self::Signal { .. } => "signal",
            Self::ExitStatus { .. } => "exit-status",
            Self::ExitSignal { .. } => "exit-signal",
            Self::Env { .. } => "env",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GlobalRequest / GlobalReply
// ─────────────────────────────────────────────────────────────────────────────

/// Global request types (RFC4254 §4).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GlobalRequestType {
    /// Request TCP/IP port forwarding (RFC4254 §7.1).
    TcpipForward { bind_host: String, bind_port: u32 },
    /// Cancel TCP/IP port forwarding (RFC4254 §7.1).
    CancelTcpipForward { bind_host: String, bind_port: u32 },
    /// Request UNIX domain socket forwarding.
    StreamlocalForward { socket_path: String },
    /// Cancel UNIX domain socket forwarding.
    CancelStreamlocalForward { socket_path: String },
}

/// SSH_MSG_GLOBAL_REQUEST — sent outside of any channel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalRequestMsg {
    pub want_reply: bool,
    pub request: GlobalRequestType,
}

/// Reply to a SSH_MSG_GLOBAL_REQUEST.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalReplyMsg {
    pub success: bool,
    /// Set when replying to TcpipForward with bind_port=0.
    pub bound_port: Option<u32>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Message type values for global messages (not in RFC4254 channel message range)
// ─────────────────────────────────────────────────────────────────────────────

/// Message type for SSH_MSG_GLOBAL_REQUEST.
pub const MSG_GLOBAL_REQUEST: u8 = 80;
/// Message type for SSH_MSG_REQUEST_SUCCESS / SSH_MSG_REQUEST_FAILURE.
pub const MSG_GLOBAL_REPLY: u8 = 81;

// ─────────────────────────────────────────────────────────────────────────────
// SshMessage — the top-level dispatch enum
// ─────────────────────────────────────────────────────────────────────────────

/// All SSH3 message types, dispatched by the first byte on the channel stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SshMessage {
    /// type 90
    ChannelOpen(ChannelOpenMsg),
    /// type 91
    ChannelOpenConfirmation(ChannelOpenConfirmationMsg),
    /// type 92
    ChannelOpenFailure(ChannelOpenFailureMsg),
    /// type 93
    ChannelWindowAdjust(ChannelWindowAdjustMsg),
    /// type 94
    ChannelData(ChannelDataMsg),
    /// type 95
    ChannelExtendedData(ChannelExtendedDataMsg),
    /// type 96
    ChannelEOF(ChannelEOFMsg),
    /// type 97
    ChannelClose(ChannelCloseMsg),
    /// type 98
    ChannelRequest(ChannelRequestMsg),
    /// type 99
    ChannelSuccess(ChannelSuccessMsg),
    /// type 100
    ChannelFailure(ChannelFailureMsg),
    /// type 80
    GlobalRequest(GlobalRequestMsg),
    /// type 81
    GlobalReply(GlobalReplyMsg),
}

impl SshMessage {
    /// Returns the message type byte for this message.
    pub fn message_type(&self) -> u8 {
        match self {
            Self::ChannelOpen(_) => MessageType::CHANNEL_OPEN.into_inner(),
            Self::ChannelOpenConfirmation(_) => MessageType::CHANNEL_OPEN_CONFIRMATION.into_inner(),
            Self::ChannelOpenFailure(_) => MessageType::CHANNEL_OPEN_FAILURE.into_inner(),
            Self::ChannelWindowAdjust(_) => MessageType::CHANNEL_WINDOW_ADJUST.into_inner(),
            Self::ChannelData(_) => MessageType::CHANNEL_DATA.into_inner(),
            Self::ChannelExtendedData(_) => MessageType::CHANNEL_EXTENDED_DATA.into_inner(),
            Self::ChannelEOF(_) => MessageType::CHANNEL_EOF.into_inner(),
            Self::ChannelClose(_) => MessageType::CHANNEL_CLOSE.into_inner(),
            Self::ChannelRequest(_) => MessageType::CHANNEL_REQUEST.into_inner(),
            Self::ChannelSuccess(_) => MessageType::CHANNEL_SUCCESS.into_inner(),
            Self::ChannelFailure(_) => MessageType::CHANNEL_FAILURE.into_inner(),
            Self::GlobalRequest(_) => MSG_GLOBAL_REQUEST,
            Self::GlobalReply(_) => MSG_GLOBAL_REPLY,
        }
    }

    /// Encode this message to CBOR bytes, prefixed with the message type byte.
    ///
    /// Wire format: `[type: u8] [CBOR body...]`
    pub fn encode(&self) -> Result<Bytes, CodecError> {
        let mut out = Vec::new();
        out.push(self.message_type());

        let body = match self {
            Self::ChannelOpen(m) => cbor_encode(m),
            Self::ChannelOpenConfirmation(m) => cbor_encode(m),
            Self::ChannelOpenFailure(m) => cbor_encode(m),
            Self::ChannelWindowAdjust(m) => cbor_encode(m),
            Self::ChannelData(m) => cbor_encode(m),
            Self::ChannelExtendedData(m) => cbor_encode(m),
            Self::ChannelEOF(m) => cbor_encode(m),
            Self::ChannelClose(m) => cbor_encode(m),
            Self::ChannelRequest(m) => cbor_encode(m),
            Self::ChannelSuccess(m) => cbor_encode(m),
            Self::ChannelFailure(m) => cbor_encode(m),
            Self::GlobalRequest(m) => cbor_encode(m),
            Self::GlobalReply(m) => cbor_encode(m),
        }
        .map_err(|e| CodecError::CborEncode {
            message: e.to_string(),
        })?;

        out.extend_from_slice(&body);
        Ok(Bytes::from(out))
    }

    /// Decode a message from bytes where the first byte is the message type.
    pub fn decode(data: &[u8]) -> Result<Self, CodecError> {
        if data.is_empty() {
            return Err(CodecError::Incomplete);
        }
        let msg_type = data[0];
        let body = &data[1..];

        let msg = if msg_type == MessageType::CHANNEL_OPEN.into_inner() {
            Self::ChannelOpen(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_OPEN_CONFIRMATION.into_inner() {
            Self::ChannelOpenConfirmation(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_OPEN_FAILURE.into_inner() {
            Self::ChannelOpenFailure(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_WINDOW_ADJUST.into_inner() {
            Self::ChannelWindowAdjust(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_DATA.into_inner() {
            Self::ChannelData(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_EXTENDED_DATA.into_inner() {
            Self::ChannelExtendedData(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_EOF.into_inner() {
            Self::ChannelEOF(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_CLOSE.into_inner() {
            Self::ChannelClose(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_REQUEST.into_inner() {
            Self::ChannelRequest(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_SUCCESS.into_inner() {
            Self::ChannelSuccess(decode_body(body)?)
        } else if msg_type == MessageType::CHANNEL_FAILURE.into_inner() {
            Self::ChannelFailure(decode_body(body)?)
        } else if msg_type == MSG_GLOBAL_REQUEST {
            Self::GlobalRequest(decode_body(body)?)
        } else if msg_type == MSG_GLOBAL_REPLY {
            Self::GlobalReply(decode_body(body)?)
        } else {
            return Err(CodecError::UnknownMessageType { value: msg_type });
        };

        Ok(msg)
    }
}

fn decode_body<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T, CodecError> {
    cbor_decode(data).map_err(|e| CodecError::CborDecode {
        message: e.to_string(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::MessageType;

    // ── MessageType value sanity ──────────────────────────────────────────────

    #[test]
    fn message_type_values() {
        assert_eq!(MessageType::CHANNEL_OPEN.into_inner(), 90);
        assert_eq!(MessageType::CHANNEL_OPEN_CONFIRMATION.into_inner(), 91);
        assert_eq!(MessageType::CHANNEL_OPEN_FAILURE.into_inner(), 92);
        assert_eq!(MessageType::CHANNEL_WINDOW_ADJUST.into_inner(), 93);
        assert_eq!(MessageType::CHANNEL_DATA.into_inner(), 94);
        assert_eq!(MessageType::CHANNEL_EXTENDED_DATA.into_inner(), 95);
        assert_eq!(MessageType::CHANNEL_EOF.into_inner(), 96);
        assert_eq!(MessageType::CHANNEL_CLOSE.into_inner(), 97);
        assert_eq!(MessageType::CHANNEL_REQUEST.into_inner(), 98);
        assert_eq!(MessageType::CHANNEL_SUCCESS.into_inner(), 99);
        assert_eq!(MessageType::CHANNEL_FAILURE.into_inner(), 100);
    }

    // ── ChannelType string conversion ─────────────────────────────────────────

    #[test]
    fn channel_type_as_str() {
        assert_eq!(ChannelType::Session.as_str(), "session");
        assert_eq!(ChannelType::DirectTcp.as_str(), "direct-tcp");
        assert_eq!(ChannelType::ReverseTcp.as_str(), "reverse-tcp");
        assert_eq!(ChannelType::DirectUdp.as_str(), "direct-udp");
        assert_eq!(ChannelType::ReverseUdp.as_str(), "reverse-udp");
    }

    #[test]
    fn channel_type_from_str() {
        assert_eq!(ChannelType::from("session"), ChannelType::Session);
        assert_eq!(ChannelType::from("direct-tcp"), ChannelType::DirectTcp);
        assert_eq!(ChannelType::from("reverse-tcp"), ChannelType::ReverseTcp);
        assert_eq!(ChannelType::from("direct-udp"), ChannelType::DirectUdp);
        assert_eq!(ChannelType::from("reverse-udp"), ChannelType::ReverseUdp);
        assert_eq!(
            ChannelType::from("x11"),
            ChannelType::Other("x11".to_string())
        );
    }

    #[test]
    fn channel_type_roundtrip_str() {
        for ct in [
            ChannelType::Session,
            ChannelType::DirectTcp,
            ChannelType::ReverseTcp,
            ChannelType::DirectUdp,
            ChannelType::ReverseUdp,
        ] {
            assert_eq!(ChannelType::from(ct.as_str()), ct);
        }
    }

    // ── SshMessage encode/decode roundtrips ───────────────────────────────────

    fn roundtrip(msg: SshMessage) -> SshMessage {
        let encoded = msg.encode().expect("encode failed");
        SshMessage::decode(&encoded).expect("decode failed")
    }

    #[test]
    fn channel_open_roundtrip() {
        let msg = SshMessage::ChannelOpen(ChannelOpenMsg {
            channel_type: ChannelType::Session,
            maximum_message_size: 65536,
        });
        let decoded = roundtrip(msg);
        if let SshMessage::ChannelOpen(inner) = decoded {
            assert_eq!(inner.channel_type, ChannelType::Session);
            assert_eq!(inner.maximum_message_size, 65536);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_open_encode_first_byte_is_90() {
        let msg = SshMessage::ChannelOpen(ChannelOpenMsg {
            channel_type: ChannelType::Session,
            maximum_message_size: 1024,
        });
        let bytes = msg.encode().unwrap();
        assert_eq!(bytes[0], 90);
    }

    #[test]
    fn channel_open_confirmation_roundtrip() {
        let msg = SshMessage::ChannelOpenConfirmation(ChannelOpenConfirmationMsg {
            maximum_message_size: 131072,
        });
        let decoded = roundtrip(msg);
        if let SshMessage::ChannelOpenConfirmation(inner) = decoded {
            assert_eq!(inner.maximum_message_size, 131072);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_open_failure_roundtrip() {
        let msg = SshMessage::ChannelOpenFailure(ChannelOpenFailureMsg {
            reason_code: ChannelOpenFailureReason::ConnectFailed as u32,
            description: "Connection refused".to_string(),
        });
        let decoded = roundtrip(msg);
        if let SshMessage::ChannelOpenFailure(inner) = decoded {
            assert_eq!(inner.reason_code, 2);
            assert_eq!(inner.description, "Connection refused");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_window_adjust_roundtrip() {
        let msg = SshMessage::ChannelWindowAdjust(ChannelWindowAdjustMsg {
            bytes_to_add: 1_048_576,
        });
        let decoded = roundtrip(msg);
        if let SshMessage::ChannelWindowAdjust(inner) = decoded {
            assert_eq!(inner.bytes_to_add, 1_048_576);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_data_roundtrip() {
        let data = b"hello, SSH3!".to_vec();
        let msg = SshMessage::ChannelData(ChannelDataMsg::new(data.clone()));
        let decoded = roundtrip(msg);
        if let SshMessage::ChannelData(inner) = decoded {
            assert_eq!(inner.data, data);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_extended_data_roundtrip() {
        let msg = SshMessage::ChannelExtendedData(ChannelExtendedDataMsg {
            data_type_code: ChannelExtendedDataMsg::STDERR,
            data: b"error output".to_vec(),
        });
        let decoded = roundtrip(msg);
        if let SshMessage::ChannelExtendedData(inner) = decoded {
            assert_eq!(inner.data_type_code, 1);
            assert_eq!(inner.data, b"error output");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_eof_roundtrip() {
        let msg = SshMessage::ChannelEOF(ChannelEOFMsg::default());
        let decoded = roundtrip(msg);
        assert!(matches!(decoded, SshMessage::ChannelEOF(_)));
    }

    #[test]
    fn channel_close_roundtrip() {
        let msg = SshMessage::ChannelClose(ChannelCloseMsg::default());
        let decoded = roundtrip(msg);
        assert!(matches!(decoded, SshMessage::ChannelClose(_)));
    }

    #[test]
    fn channel_success_roundtrip() {
        let msg = SshMessage::ChannelSuccess(ChannelSuccessMsg::default());
        let decoded = roundtrip(msg);
        assert!(matches!(decoded, SshMessage::ChannelSuccess(_)));
    }

    #[test]
    fn channel_failure_roundtrip() {
        let msg = SshMessage::ChannelFailure(ChannelFailureMsg::default());
        let decoded = roundtrip(msg);
        assert!(matches!(decoded, SshMessage::ChannelFailure(_)));
    }

    // ── ChannelRequestType variants ───────────────────────────────────────────

    fn roundtrip_request(req_type: ChannelRequestType) -> ChannelRequestType {
        let msg = SshMessage::ChannelRequest(ChannelRequestMsg {
            want_reply: true,
            request: req_type,
        });
        let decoded = roundtrip(msg);
        if let SshMessage::ChannelRequest(inner) = decoded {
            assert!(inner.want_reply);
            inner.request
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_request_pty_req_roundtrip() {
        let req = ChannelRequestType::PtyReq {
            term: "xterm-256color".to_string(),
            width_chars: 80,
            height_rows: 24,
            width_px: 0,
            height_px: 0,
            modes: vec![0x80, 0x00, 0x00, 0x25, 0x80, 0x00],
        };
        let decoded = roundtrip_request(req);
        if let ChannelRequestType::PtyReq {
            term,
            width_chars,
            height_rows,
            ..
        } = decoded
        {
            assert_eq!(term, "xterm-256color");
            assert_eq!(width_chars, 80);
            assert_eq!(height_rows, 24);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_request_shell_roundtrip() {
        let req = ChannelRequestType::Shell;
        let decoded = roundtrip_request(req);
        assert!(matches!(decoded, ChannelRequestType::Shell));
    }

    #[test]
    fn channel_request_exec_roundtrip() {
        let req = ChannelRequestType::Exec {
            command: "ls -la /tmp".to_string(),
        };
        let decoded = roundtrip_request(req);
        if let ChannelRequestType::Exec { command } = decoded {
            assert_eq!(command, "ls -la /tmp");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_request_subsystem_roundtrip() {
        let req = ChannelRequestType::Subsystem {
            subsystem: "sftp".to_string(),
        };
        let decoded = roundtrip_request(req);
        if let ChannelRequestType::Subsystem { subsystem } = decoded {
            assert_eq!(subsystem, "sftp");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_request_window_change_roundtrip() {
        let req = ChannelRequestType::WindowChange {
            width_chars: 120,
            height_rows: 40,
            width_px: 960,
            height_px: 640,
        };
        let decoded = roundtrip_request(req);
        if let ChannelRequestType::WindowChange {
            width_chars,
            height_rows,
            width_px,
            height_px,
        } = decoded
        {
            assert_eq!(width_chars, 120);
            assert_eq!(height_rows, 40);
            assert_eq!(width_px, 960);
            assert_eq!(height_px, 640);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_request_signal_roundtrip() {
        let req = ChannelRequestType::Signal {
            signal: "KILL".to_string(),
        };
        let decoded = roundtrip_request(req);
        if let ChannelRequestType::Signal { signal } = decoded {
            assert_eq!(signal, "KILL");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_request_exit_status_roundtrip() {
        let req = ChannelRequestType::ExitStatus { exit_status: 42 };
        let decoded = roundtrip_request(req);
        if let ChannelRequestType::ExitStatus { exit_status } = decoded {
            assert_eq!(exit_status, 42);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_request_exit_signal_roundtrip() {
        let req = ChannelRequestType::ExitSignal {
            signal: "SEGV".to_string(),
            core_dumped: true,
            error_message: "Segmentation fault".to_string(),
            language_tag: "en".to_string(),
        };
        let decoded = roundtrip_request(req);
        if let ChannelRequestType::ExitSignal {
            signal,
            core_dumped,
            error_message,
            language_tag,
        } = decoded
        {
            assert_eq!(signal, "SEGV");
            assert!(core_dumped);
            assert_eq!(error_message, "Segmentation fault");
            assert_eq!(language_tag, "en");
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn channel_request_env_roundtrip() {
        let req = ChannelRequestType::Env {
            name: "LANG".to_string(),
            value: "en_US.UTF-8".to_string(),
        };
        let decoded = roundtrip_request(req);
        if let ChannelRequestType::Env { name, value } = decoded {
            assert_eq!(name, "LANG");
            assert_eq!(value, "en_US.UTF-8");
        } else {
            panic!("wrong variant");
        }
    }

    // ── GlobalRequest / GlobalReply ───────────────────────────────────────────

    #[test]
    fn global_request_tcpip_forward_roundtrip() {
        let msg = SshMessage::GlobalRequest(GlobalRequestMsg {
            want_reply: true,
            request: GlobalRequestType::TcpipForward {
                bind_host: "0.0.0.0".to_string(),
                bind_port: 8080,
            },
        });
        let decoded = roundtrip(msg);
        if let SshMessage::GlobalRequest(inner) = decoded {
            assert!(inner.want_reply);
            if let GlobalRequestType::TcpipForward {
                bind_host,
                bind_port,
            } = inner.request
            {
                assert_eq!(bind_host, "0.0.0.0");
                assert_eq!(bind_port, 8080);
            } else {
                panic!("wrong request type");
            }
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn global_request_cancel_tcpip_forward_roundtrip() {
        let msg = SshMessage::GlobalRequest(GlobalRequestMsg {
            want_reply: false,
            request: GlobalRequestType::CancelTcpipForward {
                bind_host: "127.0.0.1".to_string(),
                bind_port: 2222,
            },
        });
        let decoded = roundtrip(msg);
        if let SshMessage::GlobalRequest(inner) = decoded {
            if let GlobalRequestType::CancelTcpipForward {
                bind_host,
                bind_port,
            } = inner.request
            {
                assert_eq!(bind_host, "127.0.0.1");
                assert_eq!(bind_port, 2222);
            } else {
                panic!("wrong request type");
            }
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn global_request_streamlocal_forward_roundtrip() {
        let msg = SshMessage::GlobalRequest(GlobalRequestMsg {
            want_reply: true,
            request: GlobalRequestType::StreamlocalForward {
                socket_path: "/tmp/test.sock".to_string(),
            },
        });
        let decoded = roundtrip(msg);
        if let SshMessage::GlobalRequest(inner) = decoded {
            if let GlobalRequestType::StreamlocalForward { socket_path } = inner.request {
                assert_eq!(socket_path, "/tmp/test.sock");
            } else {
                panic!("wrong request type");
            }
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn global_request_cancel_streamlocal_roundtrip() {
        let msg = SshMessage::GlobalRequest(GlobalRequestMsg {
            want_reply: false,
            request: GlobalRequestType::CancelStreamlocalForward {
                socket_path: "/run/app.sock".to_string(),
            },
        });
        let decoded = roundtrip(msg);
        if let SshMessage::GlobalRequest(inner) = decoded {
            if let GlobalRequestType::CancelStreamlocalForward { socket_path } = inner.request {
                assert_eq!(socket_path, "/run/app.sock");
            } else {
                panic!("wrong request type");
            }
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn global_reply_success_roundtrip() {
        let msg = SshMessage::GlobalReply(GlobalReplyMsg {
            success: true,
            bound_port: Some(12345),
        });
        let decoded = roundtrip(msg);
        if let SshMessage::GlobalReply(inner) = decoded {
            assert!(inner.success);
            assert_eq!(inner.bound_port, Some(12345));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn global_reply_failure_roundtrip() {
        let msg = SshMessage::GlobalReply(GlobalReplyMsg {
            success: false,
            bound_port: None,
        });
        let decoded = roundtrip(msg);
        if let SshMessage::GlobalReply(inner) = decoded {
            assert!(!inner.success);
            assert_eq!(inner.bound_port, None);
        } else {
            panic!("wrong variant");
        }
    }

    // ── Error cases ───────────────────────────────────────────────────────────

    #[test]
    fn decode_empty_returns_incomplete() {
        let result = SshMessage::decode(&[]);
        assert!(matches!(result, Err(CodecError::Incomplete)));
    }

    #[test]
    fn decode_unknown_message_type() {
        let result = SshMessage::decode(&[0x01]);
        assert!(matches!(
            result,
            Err(CodecError::UnknownMessageType { value: 1 })
        ));
    }

    #[test]
    fn decode_truncated_body_returns_error() {
        // Encode a valid message, then truncate the body
        let msg = SshMessage::ChannelData(ChannelDataMsg::new(b"hello".to_vec()));
        let encoded = msg.encode().unwrap();
        // Only keep the type byte — empty body should fail CBOR decode
        let truncated = &encoded[..1];
        let result = SshMessage::decode(truncated);
        assert!(result.is_err());
    }

    // ── First byte of encoded messages matches expected type ──────────────────

    #[test]
    fn encoded_first_bytes_match_types() {
        let cases: &[(SshMessage, u8)] = &[
            (
                SshMessage::ChannelOpen(ChannelOpenMsg {
                    channel_type: ChannelType::Session,
                    maximum_message_size: 1024,
                }),
                90,
            ),
            (
                SshMessage::ChannelOpenConfirmation(ChannelOpenConfirmationMsg {
                    maximum_message_size: 1024,
                }),
                91,
            ),
            (
                SshMessage::ChannelOpenFailure(ChannelOpenFailureMsg {
                    reason_code: 1,
                    description: String::new(),
                }),
                92,
            ),
            (
                SshMessage::ChannelWindowAdjust(ChannelWindowAdjustMsg { bytes_to_add: 0 }),
                93,
            ),
            (SshMessage::ChannelData(ChannelDataMsg::new(vec![])), 94),
            (
                SshMessage::ChannelExtendedData(ChannelExtendedDataMsg {
                    data_type_code: 1,
                    data: vec![],
                }),
                95,
            ),
            (SshMessage::ChannelEOF(ChannelEOFMsg::default()), 96),
            (SshMessage::ChannelClose(ChannelCloseMsg::default()), 97),
            (
                SshMessage::ChannelRequest(ChannelRequestMsg {
                    want_reply: false,
                    request: ChannelRequestType::Shell,
                }),
                98,
            ),
            (SshMessage::ChannelSuccess(ChannelSuccessMsg::default()), 99),
            (
                SshMessage::ChannelFailure(ChannelFailureMsg::default()),
                100,
            ),
            (
                SshMessage::GlobalRequest(GlobalRequestMsg {
                    want_reply: false,
                    request: GlobalRequestType::TcpipForward {
                        bind_host: "0.0.0.0".to_string(),
                        bind_port: 22,
                    },
                }),
                MSG_GLOBAL_REQUEST,
            ),
            (
                SshMessage::GlobalReply(GlobalReplyMsg {
                    success: true,
                    bound_port: None,
                }),
                MSG_GLOBAL_REPLY,
            ),
        ];

        for (msg, expected_type) in cases {
            let encoded = msg.encode().unwrap();
            assert_eq!(encoded[0], *expected_type, "wrong type byte for {:?}", msg);
        }
    }
}
