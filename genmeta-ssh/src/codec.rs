//! SSH3 binary wire format codec.
//!
//! All types use QUIC varint length-prefix + raw bytes encoding,
//! implementing h3x's `EncodeInto`/`DecodeFrom` traits on `AsyncWrite`/`AsyncRead`.

use std::{fmt, ops::Deref, pin::pin};

use bytes::{Bytes, BytesMut};
use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto},
    stream_id::StreamId,
    varint::VarInt,
};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_REMOTE_FIELD_SIZE: usize = 1 << 20;

pub fn checked_remote_field_len(len: u64, field_name: &'static str) -> io::Result<usize> {
    let len = usize::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_name} length does not fit in usize: {len}"),
        )
    })?;

    if len > MAX_REMOTE_FIELD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{field_name} length {len} exceeds maximum {MAX_REMOTE_FIELD_SIZE}"),
        ));
    }

    Ok(len)
}

/// A UTF-8 string encoded as varint length-prefix + UTF-8 bytes.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct SshString(Bytes);

impl SshString {
    pub const fn from_static(s: &'static str) -> Self {
        SshString(Bytes::from_static(s.as_bytes()))
    }
}

impl Deref for SshString {
    type Target = str;

    fn deref(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.0) }
    }
}

impl fmt::Display for SshString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self)
    }
}

impl AsRef<Bytes> for SshString {
    fn as_ref(&self) -> &Bytes {
        &self.0
    }
}

impl From<&'static str> for SshString {
    fn from(s: &'static str) -> Self {
        SshString::from_static(s)
    }
}

impl From<String> for SshString {
    fn from(s: String) -> Self {
        SshString(Bytes::from(s))
    }
}

impl TryFrom<Bytes> for SshString {
    type Error = std::str::Utf8Error;

    fn try_from(bytes: Bytes) -> Result<Self, Self::Error> {
        str::from_utf8(&bytes)?;
        Ok(SshString(bytes))
    }
}

impl From<SshString> for Bytes {
    fn from(ssh_string: SshString) -> Self {
        ssh_string.0
    }
}

/// Raw bytes encoded as varint length-prefix + raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshBytes(Bytes);

impl SshBytes {
    pub const fn from_static(bytes: &'static [u8]) -> Self {
        SshBytes(Bytes::from_static(bytes))
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl AsRef<Bytes> for SshBytes {
    fn as_ref(&self) -> &Bytes {
        &self.0
    }
}

impl From<&'static [u8]> for SshBytes {
    fn from(bytes: &'static [u8]) -> Self {
        SshBytes::from_static(bytes)
    }
}

impl From<Vec<u8>> for SshBytes {
    fn from(vec: Vec<u8>) -> Self {
        SshBytes(Bytes::from(vec))
    }
}

impl From<Bytes> for SshBytes {
    fn from(bytes: Bytes) -> Self {
        SshBytes(bytes)
    }
}

impl From<SshBytes> for Bytes {
    fn from(ssh_bytes: SshBytes) -> Self {
        ssh_bytes.0
    }
}

impl From<SshBytes> for BytesMut {
    fn from(ssh_bytes: SshBytes) -> Self {
        ssh_bytes.0.into()
    }
}

/// A boolean encoded as a single byte: `0x00` for false, `0x01` for true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBool(pub bool);

/// SSH3 channel header, encoded field-by-field using QUIC varints and SSH strings.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChannelHeader {
    pub signal_value: VarInt,
    pub conversation_id: StreamId,
    pub channel_type: SshString,
    pub max_message_size: VarInt,
}

// ---------------------------------------------------------------------------
// SshString
// ---------------------------------------------------------------------------

impl<S: AsyncWrite + Send> EncodeInto<S> for SshString {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), io::Error> {
        let mut stream = pin!(stream);
        let len = VarInt::try_from(self.0.len()).map_err(|_overflow| {
            io::Error::new(io::ErrorKind::InvalidInput, "ssh string too long")
        })?;
        len.encode_into(&mut stream).await?;
        stream.write_all(self.as_bytes()).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SshString {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, io::Error> {
        let mut stream = pin!(stream);
        let len = VarInt::decode_from(&mut stream).await?;
        let len = checked_remote_field_len(len.into_inner(), "ssh string")?;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        let string = String::from_utf8(buf)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Ok(string.into())
    }
}

// ---------------------------------------------------------------------------
// SshBytes
// ---------------------------------------------------------------------------

impl<S: AsyncWrite + Send> EncodeInto<S> for SshBytes {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), io::Error> {
        let mut stream = pin!(stream);
        let len = VarInt::try_from(self.0.len() as u64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        len.encode_into(&mut stream).await?;
        stream.write_all(&self.0).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SshBytes {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, io::Error> {
        let mut stream = pin!(stream);
        let len = VarInt::decode_from(&mut stream).await?;
        let len = checked_remote_field_len(len.into_inner(), "ssh bytes")?;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(buf.into())
    }
}

// ---------------------------------------------------------------------------
// SshBool
// ---------------------------------------------------------------------------

impl<S: AsyncWrite + Send> EncodeInto<S> for SshBool {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), io::Error> {
        let mut stream = pin!(stream);
        stream.write_u8(if self.0 { 0x01 } else { 0x00 }).await?;
        Ok(())
    }
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &SshBool {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), io::Error> {
        let mut stream = pin!(stream);
        stream.write_u8(if self.0 { 0x01 } else { 0x00 }).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SshBool {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, io::Error> {
        let mut stream = pin!(stream);
        let byte = stream.read_u8().await?;
        match byte {
            0x00 => Ok(SshBool(false)),
            0x01 => Ok(SshBool(true)),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid bool byte: 0x{other:02x}"),
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelHeader (encode by reference, decode returns owned)
// ---------------------------------------------------------------------------

impl<S: AsyncWrite + Send> EncodeInto<S> for ChannelHeader {
    type Output = ();
    type Error = io::Error;

    async fn encode_into(self, stream: S) -> Result<(), io::Error> {
        let mut stream = pin!(stream);
        stream.encode_one(self.signal_value).await?;
        stream.encode_one(self.conversation_id).await?;
        stream.encode_one(self.channel_type).await?;
        stream.encode_one(self.max_message_size).await?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for ChannelHeader {
    type Error = io::Error;

    async fn decode_from(stream: S) -> Result<Self, io::Error> {
        let mut stream = pin!(stream);
        Ok(ChannelHeader {
            signal_value: stream.decode_one().await?,
            conversation_id: stream.decode_one().await?,
            channel_type: stream.decode_one().await?,
            max_message_size: stream.decode_one().await?,
        })
    }
}

// TODO: fix tests
// #[cfg(test)]
// mod tests {
//     use super::*;
//     use h3x::codec::EncodeExt;
//     use tokio::io::duplex;

//     // -----------------------------------------------------------------------
//     // SshString
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn ssh_string_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshString("hello".into())
//             .encode_into(&mut writer)
//             .await
//             .unwrap();
//         drop(writer);
//         let decoded = SshString::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, SshString("hello".into()));
//     }

//     #[tokio::test]
//     async fn ssh_string_empty_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshString(String::new())
//             .encode_into(&mut writer)
//             .await
//             .unwrap();
//         drop(writer);
//         let decoded = SshString::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, SshString(String::new()));
//     }

//     #[tokio::test]
//     async fn ssh_string_hex_dump() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshString("hi".into())
//             .encode_into(&mut writer)
//             .await
//             .unwrap();
//         drop(writer);
//         let mut buf = Vec::new();
//         reader.read_to_end(&mut buf).await.unwrap();
//         // varint(2) = 0x02, then b"hi" = [0x68, 0x69]
//         assert_eq!(buf, vec![0x02, 0x68, 0x69]);
//     }

//     // -----------------------------------------------------------------------
//     // SshBytes
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn ssh_bytes_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshBytes(vec![0xde, 0xad, 0xbe, 0xef])
//             .encode_into(&mut writer)
//             .await
//             .unwrap();
//         drop(writer);
//         let decoded = SshBytes::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, SshBytes(vec![0xde, 0xad, 0xbe, 0xef]));
//     }

//     #[tokio::test]
//     async fn ssh_bytes_empty_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshBytes(Vec::new()).encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = SshBytes::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, SshBytes(Vec::new()));
//     }

//     #[tokio::test]
//     async fn ssh_bytes_hex_dump() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshBytes(vec![0xff]).encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let mut buf = Vec::new();
//         reader.read_to_end(&mut buf).await.unwrap();
//         // varint(1) = 0x01, then 0xff
//         assert_eq!(buf, vec![0x01, 0xff]);
//     }

//     // -----------------------------------------------------------------------
//     // SshBool
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn ssh_bool_true_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshBool(true).encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = SshBool::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, SshBool(true));
//     }

//     #[tokio::test]
//     async fn ssh_bool_false_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshBool(false).encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = SshBool::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, SshBool(false));
//     }

//     #[tokio::test]
//     async fn ssh_bool_hex_dump() {
//         let (mut writer, mut reader) = duplex(1024);
//         SshBool(true).encode_into(&mut writer).await.unwrap();
//         SshBool(false).encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let mut buf = Vec::new();
//         reader.read_to_end(&mut buf).await.unwrap();
//         assert_eq!(buf, vec![0x01, 0x00]);
//     }

//     #[tokio::test]
//     async fn ssh_bool_invalid_byte() {
//         let (mut writer, mut reader) = duplex(1024);
//         writer.write_u8(0x02).await.unwrap();
//         drop(writer);
//         let result = SshBool::decode_from(&mut reader).await;
//         assert!(result.is_err());
//         let err = result.unwrap_err();
//         assert_eq!(err.kind(), io::ErrorKind::InvalidData);
//     }

//     // -----------------------------------------------------------------------
//     // ChannelHeader
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn channel_header_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         let header = ChannelHeader {
//             signal_value: 42,
//             conversation_id: 100,
//             channel_type: "session".into(),
//             max_message_size: 65535,
//         };
//         header.encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = ChannelHeader::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, header);
//     }

//     #[tokio::test]
//     async fn channel_header_zero_values_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         let header = ChannelHeader {
//             signal_value: 0,
//             conversation_id: 0,
//             channel_type: String::new(),
//             max_message_size: 0,
//         };
//         header.encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = ChannelHeader::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, header);
//     }

//     #[tokio::test]
//     async fn channel_header_hex_dump() {
//         let (mut writer, mut reader) = duplex(1024);
//         let header = ChannelHeader {
//             signal_value: 1,
//             conversation_id: 2,
//             channel_type: "x".into(),
//             max_message_size: 3,
//         };
//         header.encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let mut buf = Vec::new();
//         reader.read_to_end(&mut buf).await.unwrap();
//         // signal_value=1 → varint 0x01
//         // conversation_id=2 → varint 0x02
//         // channel_type="x" → varint(1) 0x01, then b"x" = 0x78
//         // max_message_size=3 → varint 0x03
//         assert_eq!(buf, vec![0x01, 0x02, 0x01, 0x78, 0x03]);
//     }

//     // -----------------------------------------------------------------------
//     // signal_value 0xaf3627e6 varint encoding
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn signal_value_varint_encoding() {
//         // 0xaf3627e6 = 2,939,725,798
//         // This exceeds 2^30 (1,073,741,824), so it uses 8-byte varint encoding.
//         // 8-byte: (0b11 << 62) | value = 0xC000_0000_AF36_27E6
//         let signal_value: u32 = 0xaf3627e6;
//         let varint = VarInt::try_from(signal_value as u64).expect("signal_value fits in varint");

//         let (mut writer, mut reader) = duplex(1024);
//         writer.encode_one(varint).await.unwrap();
//         drop(writer);

//         let mut buf = Vec::new();
//         reader.read_to_end(&mut buf).await.unwrap();

//         let expected = 0xC000_0000_AF36_27E6u64.to_be_bytes();
//         assert_eq!(
//             buf, expected,
//             "signal_value 0xaf3627e6 should encode as 8-byte varint"
//         );
//         assert_eq!(buf.len(), 8);
//     }

//     #[tokio::test]
//     async fn channel_header_with_signal_value_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024);
//         let header = ChannelHeader {
//             signal_value: 0xaf3627e6,
//             conversation_id: 12345,
//             channel_type: "session".into(),
//             max_message_size: 1 << 20,
//         };
//         header.encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = ChannelHeader::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, header);
//     }

//     // -----------------------------------------------------------------------
//     // Boundary value tests
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn varint_boundary_one_byte_max() {
//         // Max 1-byte varint: 63 (2^6 - 1)
//         let (mut writer, mut reader) = duplex(1024);
//         let header = ChannelHeader {
//             signal_value: 63,
//             conversation_id: 0,
//             channel_type: String::new(),
//             max_message_size: 0,
//         };
//         header.encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = ChannelHeader::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, header);
//     }

//     #[tokio::test]
//     async fn varint_boundary_two_byte_min() {
//         // Min 2-byte varint: 64 (2^6)
//         let (mut writer, mut reader) = duplex(1024);
//         let header = ChannelHeader {
//             signal_value: 64,
//             conversation_id: 0,
//             channel_type: String::new(),
//             max_message_size: 0,
//         };
//         header.encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = ChannelHeader::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, header);
//     }

//     #[tokio::test]
//     async fn ssh_string_large_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024 * 1024);
//         let large = "a".repeat(1000);
//         SshString(large.clone())
//             .encode_into(&mut writer)
//             .await
//             .unwrap();
//         drop(writer);
//         let decoded = SshString::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, SshString(large));
//     }

//     #[tokio::test]
//     async fn ssh_bytes_large_roundtrip() {
//         let (mut writer, mut reader) = duplex(1024 * 1024);
//         let large = vec![0xAB; 1000];
//         SshBytes(large.clone())
//             .encode_into(&mut writer)
//             .await
//             .unwrap();
//         drop(writer);
//         let decoded = SshBytes::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, SshBytes(large));
//     }

//     #[tokio::test]
//     async fn ssh_string_rejects_oversized_payload_before_allocation() {
//         let (mut writer, mut reader) = duplex(64);
//         writer
//             .encode_one(VarInt::try_from((MAX_REMOTE_FIELD_SIZE + 1) as u64).unwrap())
//             .await
//             .unwrap();
//         drop(writer);

//         let err = SshString::decode_from(&mut reader).await.unwrap_err();
//         assert_eq!(err.kind(), io::ErrorKind::InvalidData);
//         assert!(err.to_string().contains("ssh string length"));
//     }

//     #[tokio::test]
//     async fn ssh_bytes_rejects_oversized_payload_before_allocation() {
//         let (mut writer, mut reader) = duplex(64);
//         writer
//             .encode_one(VarInt::try_from((MAX_REMOTE_FIELD_SIZE + 1) as u64).unwrap())
//             .await
//             .unwrap();
//         drop(writer);

//         let err = SshBytes::decode_from(&mut reader).await.unwrap_err();
//         assert_eq!(err.kind(), io::ErrorKind::InvalidData);
//         assert!(err.to_string().contains("ssh bytes length"));
//     }

//     #[tokio::test]
//     async fn channel_header_max_u32_signal_value() {
//         let (mut writer, mut reader) = duplex(1024);
//         let header = ChannelHeader {
//             signal_value: u32::MAX,
//             conversation_id: 0,
//             channel_type: String::new(),
//             max_message_size: 0,
//         };
//         header.encode_into(&mut writer).await.unwrap();
//         drop(writer);
//         let decoded = ChannelHeader::decode_from(&mut reader).await.unwrap();
//         assert_eq!(decoded, header);
//     }
// }
