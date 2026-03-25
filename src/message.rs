use h3x::varint::VarInt;

/// SSH global request/response message type constants (RFC 4254 / SSH3 draft).
pub const SSH_MSG_GLOBAL_REQUEST: VarInt = VarInt::from_u32(80);
pub const SSH_MSG_REQUEST_SUCCESS: VarInt = VarInt::from_u32(81);
pub const SSH_MSG_REQUEST_FAILURE: VarInt = VarInt::from_u32(82);

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

/// SSH extended data type for stderr (RFC 4254 Section 5.2).
pub const SSH_EXTENDED_DATA_STDERR: VarInt = VarInt::from_u32(1);
