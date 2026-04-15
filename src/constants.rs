use h3x::varint::VarInt;

pub const SSH_VERSION: &str = "genmeta-ssh-00";

pub const SUPPORTED_SSH_VERSIONS: &[&str] = &[SSH_VERSION];

pub const CHANNEL_SIGNAL_VALUE: VarInt = VarInt::from_u32(0xaf3627e6);

pub const DEFAULT_MAX_MESSAGE_SIZE: VarInt = VarInt::from_u32(1 << 20);

/// Well-known path for SSH3 Extended CONNECT requests.
pub const SSH3_CONNECT_PATH: &str = "/.well-known/ssh3/connect";
