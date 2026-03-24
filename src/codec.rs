//! SSH3 binary wire format codec.
//!
//! All types use QUIC varint length-prefix + raw bytes encoding,
//! implementing h3x's `EncodeInto`/`DecodeFrom` traits on `AsyncWrite`/`AsyncRead`.

use std::{fmt, ops::Deref, pin::pin};

use bytes::{Bytes, BytesMut};
use h3x::{
    codec::{DecodeFrom, EncodeInto},
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum CodecError {
    #[snafu(display("field length does not fit in usize"))]
    FieldLengthOverflow {
        field_name: &'static str,
        length: u64,
    },

    #[snafu(display("field length exceeds maximum"))]
    FieldTooLarge {
        field_name: &'static str,
        length: usize,
        maximum: usize,
    },

    #[snafu(display("ssh string too long"))]
    SshStringTooLong,

    #[snafu(display("ssh bytes too long"))]
    SshBytesTooLong,

    #[snafu(display("invalid ssh string utf-8"))]
    InvalidSshStringUtf8 { source: std::string::FromUtf8Error },

    #[snafu(display("invalid ssh bool byte"))]
    InvalidSshBoolByte { byte: u8 },

    #[snafu(display("stream read failed"))]
    ReadIo { source: std::io::Error },

    #[snafu(display("stream write failed"))]
    WriteIo { source: std::io::Error },
}

pub const MAX_REMOTE_FIELD_SIZE: usize = 1 << 20;

pub fn checked_remote_field_len(len: u64, field_name: &'static str) -> Result<usize, CodecError> {
    let len = usize::try_from(len).map_err(|_| CodecError::FieldLengthOverflow {
        field_name,
        length: len,
    })?;

    if len > MAX_REMOTE_FIELD_SIZE {
        return Err(CodecError::FieldTooLarge {
            field_name,
            length: len,
            maximum: MAX_REMOTE_FIELD_SIZE,
        });
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
pub struct SshBytes(Bytes);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRemainder(Bytes);

impl SshBytes {
    pub const fn from_static(bytes: &'static [u8]) -> Self {
        SshBytes(Bytes::from_static(bytes))
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

impl AsRef<Bytes> for RawRemainder {
    fn as_ref(&self) -> &Bytes {
        &self.0
    }
}

impl From<Bytes> for RawRemainder {
    fn from(bytes: Bytes) -> Self {
        RawRemainder(bytes)
    }
}

impl From<Vec<u8>> for RawRemainder {
    fn from(vec: Vec<u8>) -> Self {
        RawRemainder(Bytes::from(vec))
    }
}

impl From<RawRemainder> for Bytes {
    fn from(value: RawRemainder) -> Self {
        value.0
    }
}

/// A boolean encoded as a single byte: `0x00` for false, `0x01` for true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshBool(pub bool);

// ---------------------------------------------------------------------------
// SshString
// ---------------------------------------------------------------------------

impl<S: AsyncWrite + Send> EncodeInto<S> for SshString {
    type Output = ();
    type Error = CodecError;

    async fn encode_into(self, stream: S) -> Result<(), CodecError> {
        let mut stream = pin!(stream);
        let len =
            VarInt::try_from(self.0.len()).map_err(|_overflow| CodecError::SshStringTooLong)?;
        len.encode_into(&mut stream)
            .await
            .context(codec_error::WriteIoSnafu)?;
        stream
            .write_all(self.as_bytes())
            .await
            .context(codec_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SshString {
    type Error = CodecError;

    async fn decode_from(stream: S) -> Result<Self, CodecError> {
        let mut stream = pin!(stream);
        let len = VarInt::decode_from(&mut stream)
            .await
            .context(codec_error::ReadIoSnafu)?;
        let len = checked_remote_field_len(len.into_inner(), "ssh string")?;
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .context(codec_error::ReadIoSnafu)?;
        let string = String::from_utf8(buf).context(codec_error::InvalidSshStringUtf8Snafu)?;
        Ok(string.into())
    }
}

// ---------------------------------------------------------------------------
// SshBytes
// ---------------------------------------------------------------------------

impl<S: AsyncWrite + Send> EncodeInto<S> for SshBytes {
    type Output = ();
    type Error = CodecError;

    async fn encode_into(self, stream: S) -> Result<(), CodecError> {
        let mut stream = pin!(stream);
        let len = VarInt::try_from(self.0.len() as u64).map_err(|_| CodecError::SshBytesTooLong)?;
        len.encode_into(&mut stream)
            .await
            .context(codec_error::WriteIoSnafu)?;
        stream
            .write_all(&self.0)
            .await
            .context(codec_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SshBytes {
    type Error = CodecError;

    async fn decode_from(stream: S) -> Result<Self, CodecError> {
        let mut stream = pin!(stream);
        let len = VarInt::decode_from(&mut stream)
            .await
            .context(codec_error::ReadIoSnafu)?;
        let len = checked_remote_field_len(len.into_inner(), "ssh bytes")?;
        let mut buf = vec![0u8; len];
        stream
            .read_exact(&mut buf)
            .await
            .context(codec_error::ReadIoSnafu)?;
        Ok(buf.into())
    }
}

// ---------------------------------------------------------------------------
// SshBool
// ---------------------------------------------------------------------------

impl<S: AsyncWrite + Send> EncodeInto<S> for SshBool {
    type Output = ();
    type Error = CodecError;

    async fn encode_into(self, stream: S) -> Result<(), CodecError> {
        let mut stream = pin!(stream);
        stream
            .write_u8(if self.0 { 0x01 } else { 0x00 })
            .await
            .context(codec_error::WriteIoSnafu)?;
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for SshBool {
    type Error = CodecError;

    async fn decode_from(stream: S) -> Result<Self, CodecError> {
        let mut stream = pin!(stream);
        let byte = stream.read_u8().await.context(codec_error::ReadIoSnafu)?;
        match byte {
            0x00 => Ok(SshBool(false)),
            0x01 => Ok(SshBool(true)),
            other => Err(CodecError::InvalidSshBoolByte { byte: other }),
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use h3x::codec::EncodeExt;
    use tokio::io::duplex;

    #[tokio::test]
    async fn ssh_string_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshString::from("hello")
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let decoded = SshString::decode_from(&mut reader).await.unwrap();
        assert_eq!(decoded, SshString::from("hello"));
    }

    #[tokio::test]
    async fn ssh_string_empty_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshString::from("")
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let decoded = SshString::decode_from(&mut reader).await.unwrap();
        assert_eq!(decoded, SshString::from(""));
    }

    #[tokio::test]
    async fn ssh_string_hex_dump() {
        let (mut writer, mut reader) = duplex(1024);
        SshString::from("hi")
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        // varint(2) = 0x02, then b"hi" = [0x68, 0x69]
        assert_eq!(buf, vec![0x02, 0x68, 0x69]);
    }

    #[tokio::test]
    async fn ssh_bytes_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshBytes::from(vec![0xde, 0xad, 0xbe, 0xef])
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let decoded = SshBytes::decode_from(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBytes::from(vec![0xde, 0xad, 0xbe, 0xef]));
    }

    #[tokio::test]
    async fn ssh_bytes_empty_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshBytes::from(Vec::new())
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let decoded = SshBytes::decode_from(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBytes::from(Vec::new()));
    }

    #[tokio::test]
    async fn ssh_bytes_hex_dump() {
        let (mut writer, mut reader) = duplex(1024);
        SshBytes::from(vec![0xff])
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        // varint(1) = 0x01, then 0xff
        assert_eq!(buf, vec![0x01, 0xff]);
    }

    #[tokio::test]
    async fn ssh_bool_true_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshBool(true).encode_into(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshBool::decode_from(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBool(true));
    }

    #[tokio::test]
    async fn ssh_bool_false_roundtrip() {
        let (mut writer, mut reader) = duplex(1024);
        SshBool(false).encode_into(&mut writer).await.unwrap();
        drop(writer);
        let decoded = SshBool::decode_from(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBool(false));
    }

    #[tokio::test]
    async fn ssh_bool_hex_dump() {
        let (mut writer, mut reader) = duplex(1024);
        SshBool(true).encode_into(&mut writer).await.unwrap();
        SshBool(false).encode_into(&mut writer).await.unwrap();
        drop(writer);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, vec![0x01, 0x00]);
    }

    #[tokio::test]
    async fn ssh_bool_invalid_byte() {
        let (mut writer, mut reader) = duplex(1024);
        tokio::io::AsyncWriteExt::write_u8(&mut writer, 0x02)
            .await
            .unwrap();
        drop(writer);
        let result = SshBool::decode_from(&mut reader).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn ssh_string_large_roundtrip() {
        let (mut writer, mut reader) = duplex(1024 * 1024);
        let large = "a".repeat(1000);
        SshString::from(large.clone())
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let decoded = SshString::decode_from(&mut reader).await.unwrap();
        assert_eq!(decoded, SshString::from(large.clone()));
    }

    #[tokio::test]
    async fn ssh_bytes_large_roundtrip() {
        let (mut writer, mut reader) = duplex(1024 * 1024);
        let large = vec![0xAB; 1000];
        SshBytes::from(large.clone())
            .encode_into(&mut writer)
            .await
            .unwrap();
        drop(writer);
        let decoded = SshBytes::decode_from(&mut reader).await.unwrap();
        assert_eq!(decoded, SshBytes::from(large));
    }

    #[tokio::test]
    async fn ssh_string_rejects_oversized_payload() {
        let (mut writer, mut reader) = duplex(64);
        writer
            .encode_one(VarInt::try_from((MAX_REMOTE_FIELD_SIZE + 1) as u64).unwrap())
            .await
            .unwrap();
        drop(writer);
        let err = SshString::decode_from(&mut reader).await.unwrap_err();
        assert!(matches!(err, CodecError::FieldTooLarge { .. }));
    }

    #[tokio::test]
    async fn ssh_bytes_rejects_oversized_payload() {
        let (mut writer, mut reader) = duplex(64);
        writer
            .encode_one(VarInt::try_from((MAX_REMOTE_FIELD_SIZE + 1) as u64).unwrap())
            .await
            .unwrap();
        drop(writer);
        let err = SshBytes::decode_from(&mut reader).await.unwrap_err();
        assert!(matches!(err, CodecError::FieldTooLarge { .. }));
    }
}
