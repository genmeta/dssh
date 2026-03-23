use h3x::varint::VarInt;
use snafu::Snafu;

use crate::codec::CodecError;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum MessageError {
    #[snafu(display("message codec failed"))]
    Codec { source: CodecError },

    #[snafu(display("message stream read failed"))]
    ReadIo { source: std::io::Error },

    #[snafu(display("message stream write failed"))]
    WriteIo { source: std::io::Error },

    #[snafu(display("unknown ssh message type {message_type}"))]
    UnknownMessageType { message_type: VarInt },
}

/// SSH channel message type constants (RFC 4254 / SSH3 draft).
///
/// These are VarInt wire values used by the trait-based encoding/decoding
/// in [`conversation`](crate::conversation). No enum wrapper is needed.
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: VarInt = VarInt::from_u32(91);
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: VarInt = VarInt::from_u32(92);
pub const SSH_MSG_CHANNEL_DATA: VarInt = VarInt::from_u32(94);
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: VarInt = VarInt::from_u32(95);
pub const SSH_MSG_CHANNEL_EOF: VarInt = VarInt::from_u32(96);
pub const SSH_MSG_CHANNEL_CLOSE: VarInt = VarInt::from_u32(97);
pub const SSH_MSG_CHANNEL_REQUEST: VarInt = VarInt::from_u32(98);
pub const SSH_MSG_CHANNEL_SUCCESS: VarInt = VarInt::from_u32(99);
pub const SSH_MSG_CHANNEL_FAILURE: VarInt = VarInt::from_u32(100);
