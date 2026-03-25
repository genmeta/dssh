use h3x::varint::VarInt;

use crate::codec::SshString;

/// Failure response to a channel open request (SSH_MSG_CHANNEL_OPEN_FAILURE).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelOpenFailure {
    pub reason_code: VarInt,
    pub description: SshString,
}

/// Common SSH_OPEN_* reason codes (RFC 4254 §5.1).
pub mod reason_code {
    use h3x::varint::VarInt;

    pub const ADMINISTRATIVELY_PROHIBITED: VarInt = VarInt::from_u32(1);
    pub const CONNECT_FAILED: VarInt = VarInt::from_u32(2);
    pub const UNKNOWN_CHANNEL_TYPE: VarInt = VarInt::from_u32(3);
    pub const RESOURCE_SHORTAGE: VarInt = VarInt::from_u32(4);
}
