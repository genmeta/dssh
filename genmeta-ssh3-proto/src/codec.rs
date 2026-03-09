//! SSH3 wire format codec — CBOR message encoding/decoding with h3x-style newtypes.
//!
//! Implements the SSH3 channel stream header and CBOR message serialization
//! per RFC Section 4.1.1 and Section 4.1.4.

use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// SSH3 signal value for channel streams (RFC Section 4.1.1).
///
/// Each channel stream begins with this magic value encoded as a QUIC varint.
pub const SIGNAL_VALUE: u32 = 0xaf3627e6;

// ---------------------------------------------------------------------------
// Newtypes
// ---------------------------------------------------------------------------

/// SSH3 conversation identifier — the QUIC stream ID of the CONNECT request.
///
/// Uniquely identifies an SSH3 session within a QUIC connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ConversationId(u64);

impl ConversationId {
    /// Create a new `ConversationId` from a raw `u64`.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Extract the inner `u64` value.
    pub const fn into_inner(self) -> u64 {
        self.0
    }
}

impl fmt::Display for ConversationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "conv:{}", self.0)
    }
}

/// SSH3 channel identifier — unique within a conversation.
///
/// Identifies a single logical channel (e.g., a shell session, port forward)
/// within an SSH3 conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChannelId(u32);

impl ChannelId {
    /// Create a new `ChannelId` from a raw `u32`.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// Extract the inner `u32` value.
    pub const fn into_inner(self) -> u32 {
        self.0
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ch:{}", self.0)
    }
}

/// SSH3 message type discriminator.
///
/// In the SSH3 RFC, message types are encoded as strings (e.g., `"exit-status"`),
/// but we also keep a numeric discriminator for efficient dispatch in the
/// connection protocol layer (following RFC4254 numbering).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MessageType(u8);

impl MessageType {
    // Channel-related message type constants (RFC4254 Section 5)
    /// SSH_MSG_CHANNEL_OPEN (RFC4254 §5.1)
    pub const CHANNEL_OPEN: Self = Self(90);
    /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION (RFC4254 §5.1)
    pub const CHANNEL_OPEN_CONFIRMATION: Self = Self(91);
    /// SSH_MSG_CHANNEL_OPEN_FAILURE (RFC4254 §5.1)
    pub const CHANNEL_OPEN_FAILURE: Self = Self(92);
    /// SSH_MSG_CHANNEL_WINDOW_ADJUST (RFC4254 §5.2)
    pub const CHANNEL_WINDOW_ADJUST: Self = Self(93);
    /// SSH_MSG_CHANNEL_DATA (RFC4254 §5.2)
    pub const CHANNEL_DATA: Self = Self(94);
    /// SSH_MSG_CHANNEL_EXTENDED_DATA (RFC4254 §5.2)
    pub const CHANNEL_EXTENDED_DATA: Self = Self(95);
    /// SSH_MSG_CHANNEL_EOF (RFC4254 §5.3)
    pub const CHANNEL_EOF: Self = Self(96);
    /// SSH_MSG_CHANNEL_CLOSE (RFC4254 §5.3)
    pub const CHANNEL_CLOSE: Self = Self(97);
    /// SSH_MSG_CHANNEL_REQUEST (RFC4254 §5.4)
    pub const CHANNEL_REQUEST: Self = Self(98);
    /// SSH_MSG_CHANNEL_SUCCESS (RFC4254 §5.4)
    pub const CHANNEL_SUCCESS: Self = Self(99);
    /// SSH_MSG_CHANNEL_FAILURE (RFC4254 §5.4)
    pub const CHANNEL_FAILURE: Self = Self(100);

    /// Create a `MessageType` from a raw `u8`.
    pub const fn new(val: u8) -> Self {
        Self(val)
    }

    /// Extract the inner `u8` value.
    pub const fn into_inner(self) -> u8 {
        self.0
    }
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match *self {
            Self::CHANNEL_OPEN => "CHANNEL_OPEN",
            Self::CHANNEL_OPEN_CONFIRMATION => "CHANNEL_OPEN_CONFIRMATION",
            Self::CHANNEL_OPEN_FAILURE => "CHANNEL_OPEN_FAILURE",
            Self::CHANNEL_WINDOW_ADJUST => "CHANNEL_WINDOW_ADJUST",
            Self::CHANNEL_DATA => "CHANNEL_DATA",
            Self::CHANNEL_EXTENDED_DATA => "CHANNEL_EXTENDED_DATA",
            Self::CHANNEL_EOF => "CHANNEL_EOF",
            Self::CHANNEL_CLOSE => "CHANNEL_CLOSE",
            Self::CHANNEL_REQUEST => "CHANNEL_REQUEST",
            Self::CHANNEL_SUCCESS => "CHANNEL_SUCCESS",
            Self::CHANNEL_FAILURE => "CHANNEL_FAILURE",
            Self(v) => return write!(f, "MSG({v})"),
        };
        f.write_str(name)
    }
}

// ---------------------------------------------------------------------------
// Channel stream header
// ---------------------------------------------------------------------------

/// Header sent at the beginning of each channel stream (RFC Section 4.1.1).
///
/// Wire format (all fields as QUIC variable-length integers):
/// ```text
/// Signal Value (varint) = 0xaf3627e6
/// Conversation ID (varint)
/// Channel Type Length (varint)
/// Channel Type (UTF-8 string, variable length)
/// Maximum Message Size (varint)
/// ```
///
/// After this header, the stream carries a sequence of independent CBOR values
/// (SSH messages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelStreamHeader {
    /// The conversation this channel belongs to.
    pub conversation_id: ConversationId,
    /// Channel type string (e.g., `"session"`, `"direct-tcpip"`).
    pub channel_type: String,
    /// Maximum size of a single SSH message in bytes.
    pub max_message_size: u64,
}

impl ChannelStreamHeader {
    /// Create a new channel stream header.
    pub fn new(
        conversation_id: ConversationId,
        channel_type: String,
        max_message_size: u64,
    ) -> Self {
        Self {
            conversation_id,
            channel_type,
            max_message_size,
        }
    }

    /// Encode the channel stream header into a byte buffer using QUIC varints.
    ///
    /// This writes synchronously to a `Vec<u8>` using the h3x `VarInt` encoding
    /// logic. For async stream writing, see the `Encode` impl on async writers.
    pub fn encode_to_vec(&self) -> Result<Vec<u8>, ChannelHeaderEncodeError> {
        use h3x::varint::VarInt;

        let mut buf = Vec::new();

        // Signal value
        let signal = VarInt::from_u64(SIGNAL_VALUE as u64)
            .map_err(|_| ChannelHeaderEncodeError::VarIntOverflow)?;
        encode_varint_sync(signal, &mut buf);

        // Conversation ID
        let conv = VarInt::from_u64(self.conversation_id.into_inner())
            .map_err(|_| ChannelHeaderEncodeError::VarIntOverflow)?;
        encode_varint_sync(conv, &mut buf);

        // Channel type length + channel type bytes
        let ct_bytes = self.channel_type.as_bytes();
        let ct_len = VarInt::from_u64(ct_bytes.len() as u64)
            .map_err(|_| ChannelHeaderEncodeError::VarIntOverflow)?;
        encode_varint_sync(ct_len, &mut buf);
        buf.extend_from_slice(ct_bytes);

        // Maximum message size
        let max_msg = VarInt::from_u64(self.max_message_size)
            .map_err(|_| ChannelHeaderEncodeError::VarIntOverflow)?;
        encode_varint_sync(max_msg, &mut buf);

        Ok(buf)
    }

    /// Decode a channel stream header from a byte slice.
    ///
    /// Returns the header and the number of bytes consumed.
    pub fn decode_from_slice(data: &[u8]) -> Result<(Self, usize), ChannelHeaderDecodeError> {
        let mut offset = 0;

        // Signal value
        let (signal, n) =
            decode_varint_sync(&data[offset..]).ok_or(ChannelHeaderDecodeError::Incomplete)?;
        offset += n;
        if signal.into_inner() != SIGNAL_VALUE as u64 {
            return Err(ChannelHeaderDecodeError::InvalidSignal {
                got: signal.into_inner(),
            });
        }

        // Conversation ID
        let (conv_id, n) =
            decode_varint_sync(&data[offset..]).ok_or(ChannelHeaderDecodeError::Incomplete)?;
        offset += n;

        // Channel type length
        let (ct_len, n) =
            decode_varint_sync(&data[offset..]).ok_or(ChannelHeaderDecodeError::Incomplete)?;
        offset += n;
        let ct_len = ct_len.into_inner() as usize;

        // Channel type bytes
        if data.len() < offset + ct_len {
            return Err(ChannelHeaderDecodeError::Incomplete);
        }
        let channel_type = std::str::from_utf8(&data[offset..offset + ct_len])
            .map_err(|_| ChannelHeaderDecodeError::InvalidUtf8)?
            .to_string();
        offset += ct_len;

        // Maximum message size
        let (max_msg, n) =
            decode_varint_sync(&data[offset..]).ok_or(ChannelHeaderDecodeError::Incomplete)?;
        offset += n;

        let header = Self {
            conversation_id: ConversationId::new(conv_id.into_inner()),
            channel_type,
            max_message_size: max_msg.into_inner(),
        };

        Ok((header, offset))
    }
}

/// Synchronously encode a QUIC VarInt to a buffer.
///
/// Mirrors the h3x async `Encode<VarInt>` logic but writes to a `Vec<u8>`.
fn encode_varint_sync(vi: h3x::varint::VarInt, buf: &mut Vec<u8>) {
    let x = vi.into_inner();
    if x < 1u64 << 6 {
        buf.push(x as u8);
    } else if x < 1u64 << 14 {
        let v = (0b01u16 << 14) | x as u16;
        buf.extend_from_slice(&v.to_be_bytes());
    } else if x < 1u64 << 30 {
        let v = (0b10u32 << 30) | x as u32;
        buf.extend_from_slice(&v.to_be_bytes());
    } else if x < 1u64 << 62 {
        let v = (0b11u64 << 62) | x;
        buf.extend_from_slice(&v.to_be_bytes());
    } else {
        unreachable!("VarInt value too large")
    }
}

/// Synchronously decode a QUIC VarInt from a byte slice.
///
/// Returns the decoded VarInt and the number of bytes consumed, or `None` if
/// the slice is too short.
fn decode_varint_sync(data: &[u8]) -> Option<(h3x::varint::VarInt, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    let len = 2usize.pow((first >> 6) as u32);
    if data.len() < len {
        return None;
    }
    let mut buf = [0u8; 8];
    buf[0] = first & 0b0011_1111;
    buf[1..len].copy_from_slice(&data[1..len]);
    let value = u64::from_be_bytes(buf) >> (8 * (8 - len));
    // Safety: value fits in a VarInt since it was encoded as one
    Some((
        unsafe { h3x::varint::VarInt::from_u64_unchecked(value) },
        len,
    ))
}

// ---------------------------------------------------------------------------
// CBOR encode/decode helpers
// ---------------------------------------------------------------------------

/// Encode a serializable value to CBOR bytes using `ciborium`.
pub fn cbor_encode<T: Serialize>(value: &T) -> Result<Bytes, CborEncodeError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| CborEncodeError::Ciborium {
        message: e.to_string(),
    })?;
    Ok(Bytes::from(buf))
}

/// Decode a CBOR value from a byte slice using `ciborium`.
pub fn cbor_decode<T: for<'de> Deserialize<'de>>(data: &[u8]) -> Result<T, CborDecodeError> {
    ciborium::from_reader(data).map_err(|e| CborDecodeError::Ciborium {
        message: e.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors when encoding a value to CBOR.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum CborEncodeError {
    /// ciborium serialization failed.
    #[snafu(display("CBOR encoding failed: {message}"))]
    Ciborium { message: String },
}

/// Errors when decoding a value from CBOR.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum CborDecodeError {
    /// ciborium deserialization failed.
    #[snafu(display("CBOR decoding failed: {message}"))]
    Ciborium { message: String },
    /// Not enough data to decode a complete CBOR value.
    #[snafu(display("unexpected end of input"))]
    Incomplete,
}

/// Errors when encoding a channel stream header.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ChannelHeaderEncodeError {
    /// A field value exceeds the QUIC VarInt maximum (2^62 - 1).
    #[snafu(display("value overflows QUIC VarInt range"))]
    VarIntOverflow,
}

/// Errors when decoding a channel stream header.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum ChannelHeaderDecodeError {
    /// Not enough bytes to decode the header.
    #[snafu(display("unexpected end of input"))]
    Incomplete,
    /// The signal value does not match the expected SSH3 magic.
    #[snafu(display("invalid signal value: expected {:#x}, got {got:#x}", SIGNAL_VALUE))]
    InvalidSignal { got: u64 },
    /// The channel type is not valid UTF-8.
    #[snafu(display("channel type is not valid UTF-8"))]
    InvalidUtf8,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Newtype construction & Display -----------------------------------------

    #[test]
    fn conversation_id_new_and_inner() {
        let id = ConversationId::new(42);
        assert_eq!(id.into_inner(), 42);
    }

    #[test]
    fn conversation_id_display() {
        let id = ConversationId::new(123);
        assert_eq!(format!("{id}"), "conv:123");
    }

    #[test]
    fn channel_id_new_and_inner() {
        let id = ChannelId::new(7);
        assert_eq!(id.into_inner(), 7);
    }

    #[test]
    fn channel_id_display() {
        let id = ChannelId::new(5);
        assert_eq!(format!("{id}"), "ch:5");
    }

    #[test]
    fn message_type_constants() {
        assert_eq!(MessageType::CHANNEL_OPEN.into_inner(), 90);
        assert_eq!(MessageType::CHANNEL_OPEN_CONFIRMATION.into_inner(), 91);
        assert_eq!(MessageType::CHANNEL_OPEN_FAILURE.into_inner(), 92);
        assert_eq!(MessageType::CHANNEL_DATA.into_inner(), 94);
        assert_eq!(MessageType::CHANNEL_EOF.into_inner(), 96);
        assert_eq!(MessageType::CHANNEL_CLOSE.into_inner(), 97);
        assert_eq!(MessageType::CHANNEL_REQUEST.into_inner(), 98);
        assert_eq!(MessageType::CHANNEL_SUCCESS.into_inner(), 99);
        assert_eq!(MessageType::CHANNEL_FAILURE.into_inner(), 100);
    }

    #[test]
    fn message_type_display_known() {
        assert_eq!(format!("{}", MessageType::CHANNEL_OPEN), "CHANNEL_OPEN");
        assert_eq!(format!("{}", MessageType::CHANNEL_DATA), "CHANNEL_DATA");
        assert_eq!(format!("{}", MessageType::CHANNEL_CLOSE), "CHANNEL_CLOSE");
    }

    #[test]
    fn message_type_display_unknown() {
        let mt = MessageType::new(255);
        assert_eq!(format!("{mt}"), "MSG(255)");
    }

    #[test]
    fn signal_value_constant() {
        assert_eq!(SIGNAL_VALUE, 0xaf3627e6);
    }

    // -- CBOR roundtrip tests ---------------------------------------------------

    #[test]
    fn conversation_id_cbor_roundtrip() {
        let id = ConversationId::new(42);
        let bytes = cbor_encode(&id).unwrap();
        let decoded: ConversationId = cbor_decode(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn conversation_id_cbor_roundtrip_zero() {
        let id = ConversationId::new(0);
        let bytes = cbor_encode(&id).unwrap();
        let decoded: ConversationId = cbor_decode(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn conversation_id_cbor_roundtrip_max() {
        let id = ConversationId::new(u64::MAX);
        let bytes = cbor_encode(&id).unwrap();
        let decoded: ConversationId = cbor_decode(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn channel_id_cbor_roundtrip() {
        let id = ChannelId::new(7);
        let bytes = cbor_encode(&id).unwrap();
        let decoded: ChannelId = cbor_decode(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn channel_id_cbor_roundtrip_zero() {
        let id = ChannelId::new(0);
        let bytes = cbor_encode(&id).unwrap();
        let decoded: ChannelId = cbor_decode(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    #[test]
    fn channel_id_cbor_roundtrip_max() {
        let id = ChannelId::new(u32::MAX);
        let bytes = cbor_encode(&id).unwrap();
        let decoded: ChannelId = cbor_decode(&bytes).unwrap();
        assert_eq!(id, decoded);
    }

    // -- CBOR hex dump tests ---------------------------------------------------

    #[test]
    fn cbor_encode_conversation_id_hex() {
        // ConversationId is a newtype struct wrapping u64.
        // ciborium encodes newtype structs transparently, so
        // ConversationId(0) → CBOR unsigned int 0 → 0x00
        let id = ConversationId::new(0);
        let bytes = cbor_encode(&id).unwrap();
        assert_eq!(
            &bytes[..],
            &[0x00],
            "ConversationId(0) should encode as CBOR uint 0"
        );

        // ConversationId(23) → CBOR unsigned int 23 → 0x17
        let id = ConversationId::new(23);
        let bytes = cbor_encode(&id).unwrap();
        assert_eq!(
            &bytes[..],
            &[0x17],
            "ConversationId(23) should encode as CBOR uint 23"
        );

        // ConversationId(24) → CBOR unsigned int 24 → 0x18 0x18
        let id = ConversationId::new(24);
        let bytes = cbor_encode(&id).unwrap();
        assert_eq!(
            &bytes[..],
            &[0x18, 0x18],
            "ConversationId(24) should encode as CBOR uint 24"
        );

        // ConversationId(1000) → CBOR unsigned int 1000 → 0x19 0x03 0xe8
        let id = ConversationId::new(1000);
        let bytes = cbor_encode(&id).unwrap();
        assert_eq!(
            &bytes[..],
            &[0x19, 0x03, 0xe8],
            "ConversationId(1000) should encode as CBOR uint 1000"
        );
    }

    #[test]
    fn cbor_encode_channel_id_hex() {
        // ChannelId(0) → CBOR uint 0 → 0x00
        let id = ChannelId::new(0);
        let bytes = cbor_encode(&id).unwrap();
        assert_eq!(&bytes[..], &[0x00]);

        // ChannelId(255) → CBOR uint 255 → 0x18 0xff
        let id = ChannelId::new(255);
        let bytes = cbor_encode(&id).unwrap();
        assert_eq!(&bytes[..], &[0x18, 0xff]);
    }

    // -- Channel stream header tests -------------------------------------------

    #[test]
    fn channel_stream_header_roundtrip() {
        let header =
            ChannelStreamHeader::new(ConversationId::new(42), "session".to_string(), 65536);
        let encoded = header.encode_to_vec().unwrap();
        let (decoded, consumed) = ChannelStreamHeader::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn channel_stream_header_signal_value_present() {
        let header = ChannelStreamHeader::new(ConversationId::new(0), "session".to_string(), 1024);
        let encoded = header.encode_to_vec().unwrap();

        // The first bytes should be the varint-encoded SIGNAL_VALUE (0xaf3627e6).
        // 0xaf3627e6 = 2_939_602_918, which is >= 2^30 so it encodes as 8-byte varint.
        let (signal, _) = decode_varint_sync(&encoded).unwrap();
        assert_eq!(signal.into_inner(), SIGNAL_VALUE as u64);
    }

    #[test]
    fn channel_stream_header_invalid_signal() {
        // Construct bytes with wrong signal value (varint 0x00 instead of 0xaf3627e6)
        let data = [0x00]; // varint 0
        let result = ChannelStreamHeader::decode_from_slice(&data);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            format!("{err}").contains("invalid signal value"),
            "error should mention invalid signal, got: {err}"
        );
    }

    #[test]
    fn channel_stream_header_empty_channel_type() {
        let header = ChannelStreamHeader::new(ConversationId::new(99), String::new(), 512);
        let encoded = header.encode_to_vec().unwrap();
        let (decoded, _) = ChannelStreamHeader::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded.channel_type, "");
        assert_eq!(decoded.conversation_id, ConversationId::new(99));
        assert_eq!(decoded.max_message_size, 512);
    }

    #[test]
    fn channel_stream_header_long_channel_type() {
        let long_type = "x".repeat(300);
        let header = ChannelStreamHeader::new(ConversationId::new(1), long_type.clone(), 4096);
        let encoded = header.encode_to_vec().unwrap();
        let (decoded, consumed) = ChannelStreamHeader::decode_from_slice(&encoded).unwrap();
        assert_eq!(decoded.channel_type, long_type);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn channel_stream_header_incomplete_data() {
        let header =
            ChannelStreamHeader::new(ConversationId::new(42), "session".to_string(), 65536);
        let encoded = header.encode_to_vec().unwrap();

        // Truncate at various points — all should return Incomplete
        for truncate_at in 1..encoded.len() {
            let result = ChannelStreamHeader::decode_from_slice(&encoded[..truncate_at]);
            assert!(
                result.is_err(),
                "should fail with truncated data at byte {truncate_at}"
            );
        }
    }

    // -- Varint sync roundtrip tests -------------------------------------------

    #[test]
    fn varint_sync_roundtrip_small() {
        let vi = h3x::varint::VarInt::from_u32(0);
        let mut buf = Vec::new();
        encode_varint_sync(vi, &mut buf);
        let (decoded, n) = decode_varint_sync(&buf).unwrap();
        assert_eq!(decoded.into_inner(), 0);
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_sync_roundtrip_1byte() {
        let vi = h3x::varint::VarInt::from_u32(63); // max 1-byte varint
        let mut buf = Vec::new();
        encode_varint_sync(vi, &mut buf);
        assert_eq!(buf.len(), 1);
        let (decoded, n) = decode_varint_sync(&buf).unwrap();
        assert_eq!(decoded.into_inner(), 63);
        assert_eq!(n, 1);
    }

    #[test]
    fn varint_sync_roundtrip_2byte() {
        let vi = h3x::varint::VarInt::from_u32(64); // min 2-byte varint
        let mut buf = Vec::new();
        encode_varint_sync(vi, &mut buf);
        assert_eq!(buf.len(), 2);
        let (decoded, n) = decode_varint_sync(&buf).unwrap();
        assert_eq!(decoded.into_inner(), 64);
        assert_eq!(n, 2);
    }

    #[test]
    fn varint_sync_roundtrip_4byte() {
        let vi = h3x::varint::VarInt::from_u32(16384); // min 4-byte varint
        let mut buf = Vec::new();
        encode_varint_sync(vi, &mut buf);
        assert_eq!(buf.len(), 4);
        let (decoded, n) = decode_varint_sync(&buf).unwrap();
        assert_eq!(decoded.into_inner(), 16384);
        assert_eq!(n, 4);
    }

    #[test]
    fn varint_sync_roundtrip_8byte() {
        // SIGNAL_VALUE = 0xaf3627e6 is > 2^30, needs 8-byte varint
        let vi = h3x::varint::VarInt::from_u64(SIGNAL_VALUE as u64).unwrap();
        let mut buf = Vec::new();
        encode_varint_sync(vi, &mut buf);
        assert_eq!(buf.len(), 8);
        let (decoded, n) = decode_varint_sync(&buf).unwrap();
        assert_eq!(decoded.into_inner(), SIGNAL_VALUE as u64);
        assert_eq!(n, 8);
    }

    // -- Error case tests ------------------------------------------------------

    #[test]
    fn cbor_decode_invalid_data() {
        let garbage = [0xff, 0xfe, 0xfd];
        let result: Result<ConversationId, _> = cbor_decode(&garbage);
        assert!(result.is_err());
    }

    #[test]
    fn cbor_decode_empty() {
        let result: Result<ConversationId, _> = cbor_decode(&[]);
        assert!(result.is_err());
    }
}
