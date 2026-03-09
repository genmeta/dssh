//! SSH3 binary wire format codec.
//!
//! All types use QUIC varint length-prefix + raw bytes encoding,
//! following the h3x `Encode`/`Decode` trait patterns on `AsyncWrite`/`AsyncRead`.
//!
//! Due to the orphan rule, blanket `impl<S> Encode<LocalType> for S` is not possible
//! when `Encode` is defined in h3x. Instead, each type provides inherent `encode`/`decode`
//! async methods that internally delegate to h3x `VarInt` Encode/Decode impls (which are
//! valid because VarInt is defined in h3x alongside the traits).


use h3x::{
    codec::{DecodeExt, EncodeExt},
    varint::VarInt,
};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A UTF-8 string encoded as varint length-prefix + UTF-8 bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshString(pub String);

/// Raw bytes encoded as varint length-prefix + raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshBytes(pub Vec<u8>);

/// A boolean encoded as a single byte: `0x00` for false, `0x01` for true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SshBool(pub bool);

/// SSH3 channel header, encoded field-by-field using QUIC varints and SSH strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelHeader {
    pub signal_value: u32,
    pub conversation_id: u64,
    pub channel_type: String,
    pub max_message_size: u64,
}

// ---------------------------------------------------------------------------
// SshString
// ---------------------------------------------------------------------------

impl SshString {
    pub async fn encode<S: AsyncWrite + Send + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(), io::Error> {
        let len = VarInt::try_from(self.0.len() as u64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        stream.encode_one(len).await?;
        stream.write_all(self.0.as_bytes()).await?;
        Ok(())
    }

    pub async fn decode<S: AsyncRead + Send + Unpin>(
        stream: &mut S,
    ) -> Result<Self, io::Error> {
        let len: VarInt = stream.decode_one().await?;
        let len = len.into_inner() as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        let s = String::from_utf8(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(SshString(s))
    }
}

// ---------------------------------------------------------------------------
// SshBytes
// ---------------------------------------------------------------------------

impl SshBytes {
    pub async fn encode<S: AsyncWrite + Send + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(), io::Error> {
        let len = VarInt::try_from(self.0.len() as u64)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        stream.encode_one(len).await?;
        stream.write_all(&self.0).await?;
        Ok(())
    }

    pub async fn decode<S: AsyncRead + Send + Unpin>(
        stream: &mut S,
    ) -> Result<Self, io::Error> {
        let len: VarInt = stream.decode_one().await?;
        let len = len.into_inner() as usize;
        let mut buf = vec![0u8; len];
        stream.read_exact(&mut buf).await?;
        Ok(SshBytes(buf))
    }
}

// ---------------------------------------------------------------------------
// SshBool
// ---------------------------------------------------------------------------

impl SshBool {
    pub async fn encode<S: AsyncWrite + Send + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(), io::Error> {
        stream.write_u8(if self.0 { 0x01 } else { 0x00 }).await?;
        Ok(())
    }

    pub async fn decode<S: AsyncRead + Send + Unpin>(
        stream: &mut S,
    ) -> Result<Self, io::Error> {
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

impl ChannelHeader {
    pub async fn encode<S: AsyncWrite + Send + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(), io::Error> {
        stream
            .encode_one(
                VarInt::try_from(self.signal_value as u64)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            )
            .await?;
        stream
            .encode_one(
                VarInt::try_from(self.conversation_id)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            )
            .await?;
        SshString(self.channel_type.clone())
            .encode(stream)
            .await?;
        stream
            .encode_one(
                VarInt::try_from(self.max_message_size)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            )
            .await?;
        Ok(())
    }

    pub async fn decode<S: AsyncRead + Send + Unpin>(
        stream: &mut S,
    ) -> Result<Self, io::Error> {
        let signal_value: VarInt = stream.decode_one().await?;
        let signal_value = signal_value.into_inner() as u32;

        let conversation_id: VarInt = stream.decode_one().await?;
        let conversation_id = conversation_id.into_inner();

        let channel_type = SshString::decode(stream).await?;

        let max_message_size: VarInt = stream.decode_one().await?;
        let max_message_size = max_message_size.into_inner();

        Ok(ChannelHeader {
            signal_value,
            conversation_id,
            channel_type: channel_type.0,
            max_message_size,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    // -----------------------------------------------------------------------
    // SshString
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ssh_string_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshString("hello".into()).encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshString::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, SshString("hello".into()));
    }

    #[tokio::test]
    async fn ssh_string_empty_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshString(String::new()).encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshString::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, SshString(String::new()));
    }

    #[tokio::test]
    async fn ssh_string_hex_dump() {
        let (mut writer, mut reader) = duplex(1024);
        SshString("hi".into()).encode(&mut writer).await.unwrap();
        drop(writer);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        // varint(2) = 0x02, then b"hi" = [0x68, 0x69]
        assert_eq!(buf, vec![0x02, 0x68, 0x69]);
    }

    // -----------------------------------------------------------------------
    // SshBytes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ssh_bytes_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshBytes(vec![0xde, 0xad, 0xbe, 0xef])
            .encode(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let decoded = SshBytes::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBytes(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[tokio::test]
    async fn ssh_bytes_empty_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshBytes(Vec::new()).encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshBytes::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBytes(Vec::new()));
    }

    #[tokio::test]
    async fn ssh_bytes_hex_dump() {
        let (mut writer, mut reader) = duplex(1024);
        SshBytes(vec![0xff]).encode(&mut writer).await.unwrap();
        drop(writer);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        // varint(1) = 0x01, then 0xff
        assert_eq!(buf, vec![0x01, 0xff]);
    }

    // -----------------------------------------------------------------------
    // SshBool
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn ssh_bool_true_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshBool(true).encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshBool::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBool(true));
    }

    #[tokio::test]
    async fn ssh_bool_false_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshBool(false).encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshBool::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBool(false));
    }

    #[tokio::test]
    async fn ssh_bool_hex_dump() {
        let (mut writer, mut reader) = duplex(1024);
        SshBool(true).encode(&mut writer).await.unwrap();
        SshBool(false).encode(&mut writer).await.unwrap();
        drop(writer);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, vec![0x01, 0x00]);
    }

    #[tokio::test]
    async fn ssh_bool_invalid_byte() {
        let (mut writer, mut reader) = duplex(1024);
        writer.write_u8(0x02).await.unwrap();
        drop(writer);
        let result = SshBool::decode(&mut reader).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // -----------------------------------------------------------------------
    // ChannelHeader
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn channel_header_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        let header = ChannelHeader {
            signal_value: 42,
            conversation_id: 100,
            channel_type: "session".into(),
            max_message_size: 65535,
        };
        header.encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = ChannelHeader::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, header);
    }

    #[tokio::test]
    async fn channel_header_zero_values_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 0,
            channel_type: String::new(),
            max_message_size: 0,
        };
        header.encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = ChannelHeader::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, header);
    }

    #[tokio::test]
    async fn channel_header_hex_dump() {
        let (mut writer, mut reader) = duplex(1024);
        let header = ChannelHeader {
            signal_value: 1,
            conversation_id: 2,
            channel_type: "x".into(),
            max_message_size: 3,
        };
        header.encode(&mut writer).await.unwrap();
        drop(writer);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        // signal_value=1 → varint 0x01
        // conversation_id=2 → varint 0x02
        // channel_type="x" → varint(1) 0x01, then b"x" = 0x78
        // max_message_size=3 → varint 0x03
        assert_eq!(buf, vec![0x01, 0x02, 0x01, 0x78, 0x03]);
    }

    // -----------------------------------------------------------------------
    // signal_value 0xaf3627e6 varint encoding
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn signal_value_varint_encoding() {
        // 0xaf3627e6 = 2,939,725,798
        // This exceeds 2^30 (1,073,741,824), so it uses 8-byte varint encoding.
        // 8-byte: (0b11 << 62) | value = 0xC000_0000_AF36_27E6
        let signal_value: u32 = 0xaf3627e6;
        let varint =
            VarInt::try_from(signal_value as u64).expect("signal_value fits in varint");

        let (mut writer, mut reader) = duplex(1024);
        writer.encode_one(varint).await.unwrap();
        drop(writer);

        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();

        let expected = 0xC000_0000_AF36_27E6u64.to_be_bytes();
        assert_eq!(
            buf, expected,
            "signal_value 0xaf3627e6 should encode as 8-byte varint"
        );
        assert_eq!(buf.len(), 8);
    }

    #[tokio::test]
    async fn channel_header_with_signal_value_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 12345,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };
        header.encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = ChannelHeader::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, header);
    }

    // -----------------------------------------------------------------------
    // Boundary value tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn varint_boundary_one_byte_max() {
        // Max 1-byte varint: 63 (2^6 - 1)
        let (mut writer, mut reader) = duplex(1024);
        let header = ChannelHeader {
            signal_value: 63,
            conversation_id: 0,
            channel_type: String::new(),
            max_message_size: 0,
        };
        header.encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = ChannelHeader::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, header);
    }

    #[tokio::test]
    async fn varint_boundary_two_byte_min() {
        // Min 2-byte varint: 64 (2^6)
        let (mut writer, mut reader) = duplex(1024);
        let header = ChannelHeader {
            signal_value: 64,
            conversation_id: 0,
            channel_type: String::new(),
            max_message_size: 0,
        };
        header.encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = ChannelHeader::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, header);
    }

    #[tokio::test]
    async fn ssh_string_large_roundtrip() {
        let (mut writer, mut reader) = duplex(1024 * 1024);
        let large = "a".repeat(1000);
        SshString(large.clone()).encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshString::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, SshString(large));
    }

    #[tokio::test]
    async fn ssh_bytes_large_roundtrip() {
        let (mut writer, mut reader) = duplex(1024 * 1024);
        let large = vec![0xAB; 1000];
        SshBytes(large.clone()).encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshBytes::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBytes(large));
    }

    #[tokio::test]
    async fn channel_header_max_u32_signal_value() {
        let (mut writer, mut reader) = duplex(1024);
        let header = ChannelHeader {
            signal_value: u32::MAX,
            conversation_id: 0,
            channel_type: String::new(),
            max_message_size: 0,
        };
        header.encode(&mut writer).await.unwrap();
        drop(writer);
        let decoded = ChannelHeader::decode(&mut reader).await.unwrap();
        assert_eq!(decoded, header);
    }
}
