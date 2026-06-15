use h3x::varint::VarInt;

pub const DSHELL_VERSION: &str = "dshell-00";

pub const SUPPORTED_DSHELL_VERSIONS: &[&str] = &[DSHELL_VERSION];

pub const CHANNEL_SIGNAL_VALUE: VarInt = VarInt::from_u32(0xaf3627e6);

pub const DEFAULT_MAX_MESSAGE_SIZE: VarInt = VarInt::from_u32(1 << 20);

/// Well-known path for DShell WebTransport Extended CONNECT requests.
pub const DSHELL_CONNECT_PATH: &str = "/.well-known/dshell/connect";
