//! SSH3 message types for channel and conversation streams.
//!
//! Each message is encoded as `varint(message_type)` followed by type-specific
//! fields using SSH binary format primitives (`SshString`, `SshBytes`, `SshBool`, `VarInt`).

use h3x::{
    codec::{DecodeExt, EncodeExt},
    varint::VarInt,
};
use tokio::io::{self, AsyncRead, AsyncWrite};

use crate::codec::{SshBool, SshBytes, SshString};

/// All SSH3 message types carried on channel streams and the conversation stream.
///
/// SSH3 omits `SSH_MSG_CHANNEL_OPEN` (90) and `SSH_MSG_CHANNEL_WINDOW_ADJUST` (93)
/// from traditional SSH — channels are opened via HTTP semantics and flow control
/// is handled by QUIC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshMessage {
    /// SSH_MSG_GLOBAL_REQUEST = 80
    GlobalRequest {
        request_type: String,
        want_reply: bool,
        data: Vec<u8>,
    },
    /// SSH_MSG_REQUEST_SUCCESS = 81
    RequestSuccess { data: Vec<u8> },
    /// SSH_MSG_REQUEST_FAILURE = 82
    RequestFailure,
    /// SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
    ChannelOpenConfirmation { max_message_size: u64 },
    /// SSH_MSG_CHANNEL_OPEN_FAILURE = 92
    ChannelOpenFailure {
        reason_code: u64,
        description: String,
    },
    /// SSH_MSG_CHANNEL_DATA = 94
    ChannelData { data: Vec<u8> },
    /// SSH_MSG_CHANNEL_EXTENDED_DATA = 95
    ChannelExtendedData { data_type: u64, data: Vec<u8> },
    /// SSH_MSG_CHANNEL_EOF = 96
    ChannelEof,
    /// SSH_MSG_CHANNEL_CLOSE = 97
    ChannelClose,
    /// SSH_MSG_CHANNEL_REQUEST = 98
    ChannelRequest {
        request_type: String,
        want_reply: bool,
        request_data: Vec<u8>,
    },
    /// SSH_MSG_CHANNEL_SUCCESS = 99
    ChannelSuccess,
    /// SSH_MSG_CHANNEL_FAILURE = 100
    ChannelFailure,
}

impl SshMessage {
    pub async fn encode<S: AsyncWrite + Send + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<(), io::Error> {
        match self {
            SshMessage::GlobalRequest {
                request_type,
                want_reply,
                data,
            } => {
                stream
                    .encode_one(VarInt::try_from(80u64).unwrap())
                    .await?;
                SshString(request_type.clone()).encode(stream).await?;
                SshBool(*want_reply).encode(stream).await?;
                SshBytes(data.clone()).encode(stream).await?;
            }
            SshMessage::RequestSuccess { data } => {
                stream
                    .encode_one(VarInt::try_from(81u64).unwrap())
                    .await?;
                SshBytes(data.clone()).encode(stream).await?;
            }
            SshMessage::RequestFailure => {
                stream
                    .encode_one(VarInt::try_from(82u64).unwrap())
                    .await?;
            }
            SshMessage::ChannelOpenConfirmation { max_message_size } => {
                stream
                    .encode_one(VarInt::try_from(91u64).unwrap())
                    .await?;
                stream
                    .encode_one(
                        VarInt::try_from(*max_message_size)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
                    )
                    .await?;
            }
            SshMessage::ChannelOpenFailure {
                reason_code,
                description,
            } => {
                stream
                    .encode_one(VarInt::try_from(92u64).unwrap())
                    .await?;
                stream
                    .encode_one(
                        VarInt::try_from(*reason_code)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
                    )
                    .await?;
                SshString(description.clone()).encode(stream).await?;
            }
            SshMessage::ChannelData { data } => {
                stream
                    .encode_one(VarInt::try_from(94u64).unwrap())
                    .await?;
                SshBytes(data.clone()).encode(stream).await?;
            }
            SshMessage::ChannelExtendedData { data_type, data } => {
                stream
                    .encode_one(VarInt::try_from(95u64).unwrap())
                    .await?;
                stream
                    .encode_one(
                        VarInt::try_from(*data_type)
                            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
                    )
                    .await?;
                SshBytes(data.clone()).encode(stream).await?;
            }
            SshMessage::ChannelEof => {
                stream
                    .encode_one(VarInt::try_from(96u64).unwrap())
                    .await?;
            }
            SshMessage::ChannelClose => {
                stream
                    .encode_one(VarInt::try_from(97u64).unwrap())
                    .await?;
            }
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                stream
                    .encode_one(VarInt::try_from(98u64).unwrap())
                    .await?;
                SshString(request_type.clone()).encode(stream).await?;
                SshBool(*want_reply).encode(stream).await?;
                SshBytes(request_data.clone()).encode(stream).await?;
            }
            SshMessage::ChannelSuccess => {
                stream
                    .encode_one(VarInt::try_from(99u64).unwrap())
                    .await?;
            }
            SshMessage::ChannelFailure => {
                stream
                    .encode_one(VarInt::try_from(100u64).unwrap())
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn decode<S: AsyncRead + Send + Unpin>(
        stream: &mut S,
    ) -> Result<Self, io::Error> {
        let msg_type: VarInt = stream.decode_one().await?;
        match msg_type.into_inner() {
            80 => {
                let request_type = SshString::decode(stream).await?.0;
                let want_reply = SshBool::decode(stream).await?.0;
                let data = SshBytes::decode(stream).await?.0;
                Ok(SshMessage::GlobalRequest {
                    request_type,
                    want_reply,
                    data,
                })
            }
            81 => {
                let data = SshBytes::decode(stream).await?.0;
                Ok(SshMessage::RequestSuccess { data })
            }
            82 => Ok(SshMessage::RequestFailure),
            91 => {
                let max_message_size: VarInt = stream.decode_one().await?;
                Ok(SshMessage::ChannelOpenConfirmation {
                    max_message_size: max_message_size.into_inner(),
                })
            }
            92 => {
                let reason_code: VarInt = stream.decode_one().await?;
                let description = SshString::decode(stream).await?.0;
                Ok(SshMessage::ChannelOpenFailure {
                    reason_code: reason_code.into_inner(),
                    description,
                })
            }
            94 => {
                let data = SshBytes::decode(stream).await?.0;
                Ok(SshMessage::ChannelData { data })
            }
            95 => {
                let data_type: VarInt = stream.decode_one().await?;
                let data = SshBytes::decode(stream).await?.0;
                Ok(SshMessage::ChannelExtendedData {
                    data_type: data_type.into_inner(),
                    data,
                })
            }
            96 => Ok(SshMessage::ChannelEof),
            97 => Ok(SshMessage::ChannelClose),
            98 => {
                let request_type = SshString::decode(stream).await?.0;
                let want_reply = SshBool::decode(stream).await?.0;
                let request_data = SshBytes::decode(stream).await?.0;
                Ok(SshMessage::ChannelRequest {
                    request_type,
                    want_reply,
                    request_data,
                })
            }
            99 => Ok(SshMessage::ChannelSuccess),
            100 => Ok(SshMessage::ChannelFailure),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown message type: {other}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt};

    // Helper: encode a message, return raw bytes
    async fn encode_to_bytes(msg: &SshMessage) -> Vec<u8> {
        let (mut writer, mut reader) = duplex(4096);
        msg.encode(&mut writer).await.unwrap();
        drop(writer);
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).await.unwrap();
        buf
    }

    // Helper: roundtrip a message
    async fn roundtrip(msg: &SshMessage) -> SshMessage {
        let (mut writer, mut reader) = duplex(4096);
        msg.encode(&mut writer).await.unwrap();
        drop(writer);
        SshMessage::decode(&mut reader).await.unwrap()
    }

    // -----------------------------------------------------------------------
    // Test 1: roundtrip_all_variants
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn roundtrip_all_variants() {
        let variants: Vec<SshMessage> = vec![
            SshMessage::GlobalRequest {
                request_type: "tcpip-forward".into(),
                want_reply: true,
                data: vec![0x01, 0x02, 0x03],
            },
            SshMessage::RequestSuccess {
                data: vec![0xaa, 0xbb],
            },
            SshMessage::RequestFailure,
            SshMessage::ChannelOpenConfirmation {
                max_message_size: 65536,
            },
            SshMessage::ChannelOpenFailure {
                reason_code: 1,
                description: "administratively prohibited".into(),
            },
            SshMessage::ChannelData {
                data: vec![0xde, 0xad, 0xbe, 0xef],
            },
            SshMessage::ChannelExtendedData {
                data_type: 1,
                data: vec![0xff],
            },
            SshMessage::ChannelEof,
            SshMessage::ChannelClose,
            SshMessage::ChannelRequest {
                request_type: "exec".into(),
                want_reply: true,
                request_data: vec![0x00, 0x01],
            },
            SshMessage::ChannelSuccess,
            SshMessage::ChannelFailure,
        ];

        for msg in &variants {
            let decoded = roundtrip(msg).await;
            assert_eq!(&decoded, msg, "roundtrip failed for {msg:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Test 2: message_type_hex_dump
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn message_type_hex_dump() {
        // All message types > 63, so they use 2-byte QUIC varint encoding.
        // 2-byte varint: (0b01 << 14) | value → big-endian u16

        // ChannelData(94): (0b01 << 14) | 94 = 0x405e → [0x40, 0x5e]
        let bytes = encode_to_bytes(&SshMessage::ChannelData {
            data: vec![],
        })
        .await;
        assert_eq!(
            &bytes[..2],
            &[0x40, 0x5e],
            "ChannelData type should be 0x405e"
        );

        // ChannelRequest(98): (0b01 << 14) | 98 = 0x4062 → [0x40, 0x62]
        let bytes = encode_to_bytes(&SshMessage::ChannelRequest {
            request_type: String::new(),
            want_reply: false,
            request_data: vec![],
        })
        .await;
        assert_eq!(
            &bytes[..2],
            &[0x40, 0x62],
            "ChannelRequest type should be 0x4062"
        );

        // GlobalRequest(80): (0b01 << 14) | 80 = 0x4050 → [0x40, 0x50]
        let bytes = encode_to_bytes(&SshMessage::GlobalRequest {
            request_type: String::new(),
            want_reply: false,
            data: vec![],
        })
        .await;
        assert_eq!(
            &bytes[..2],
            &[0x40, 0x50],
            "GlobalRequest type should be 0x4050"
        );

        // RequestSuccess(81): 0x4051
        let bytes = encode_to_bytes(&SshMessage::RequestSuccess { data: vec![] }).await;
        assert_eq!(&bytes[..2], &[0x40, 0x51]);

        // RequestFailure(82): 0x4052
        let bytes = encode_to_bytes(&SshMessage::RequestFailure).await;
        assert_eq!(bytes, &[0x40, 0x52]);

        // ChannelOpenConfirmation(91): 0x405b
        let bytes = encode_to_bytes(&SshMessage::ChannelOpenConfirmation {
            max_message_size: 0,
        })
        .await;
        assert_eq!(&bytes[..2], &[0x40, 0x5b]);

        // ChannelOpenFailure(92): 0x405c
        let bytes = encode_to_bytes(&SshMessage::ChannelOpenFailure {
            reason_code: 0,
            description: String::new(),
        })
        .await;
        assert_eq!(&bytes[..2], &[0x40, 0x5c]);

        // ChannelExtendedData(95): 0x405f
        let bytes = encode_to_bytes(&SshMessage::ChannelExtendedData {
            data_type: 0,
            data: vec![],
        })
        .await;
        assert_eq!(&bytes[..2], &[0x40, 0x5f]);

        // ChannelEof(96): 0x4060
        let bytes = encode_to_bytes(&SshMessage::ChannelEof).await;
        assert_eq!(bytes, &[0x40, 0x60]);

        // ChannelClose(97): 0x4061
        let bytes = encode_to_bytes(&SshMessage::ChannelClose).await;
        assert_eq!(bytes, &[0x40, 0x61]);

        // ChannelSuccess(99): 0x4063
        let bytes = encode_to_bytes(&SshMessage::ChannelSuccess).await;
        assert_eq!(bytes, &[0x40, 0x63]);

        // ChannelFailure(100): 0x4064
        let bytes = encode_to_bytes(&SshMessage::ChannelFailure).await;
        assert_eq!(bytes, &[0x40, 0x64]);
    }

    // -----------------------------------------------------------------------
    // Test 3: channel_request_raw_data
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn channel_request_raw_data() {
        // request_data should be preserved as opaque bytes, not interpreted
        let raw_data = vec![0x00, 0x01, 0x02, 0xff, 0xfe, 0xfd];
        let msg = SshMessage::ChannelRequest {
            request_type: "exec".into(),
            want_reply: true,
            request_data: raw_data.clone(),
        };
        let decoded = roundtrip(&msg).await;
        match decoded {
            SshMessage::ChannelRequest { request_data, .. } => {
                assert_eq!(request_data, raw_data, "request_data not preserved as raw bytes");
            }
            other => panic!("expected ChannelRequest, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 4: global_request_roundtrip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn global_request_roundtrip() {
        // All 3 global message types
        let messages = vec![
            SshMessage::GlobalRequest {
                request_type: "tcpip-forward".into(),
                want_reply: true,
                data: vec![0x01, 0x02],
            },
            SshMessage::RequestSuccess {
                data: vec![0xaa],
            },
            SshMessage::RequestFailure,
        ];

        for msg in &messages {
            let decoded = roundtrip(msg).await;
            assert_eq!(&decoded, msg, "global message roundtrip failed for {msg:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: no_channel_open_or_window_adjust
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn no_channel_open_or_window_adjust() {
        // Types 90 (ChannelOpen) and 93 (WindowAdjust) must not exist in SSH3.
        // Attempting to decode them should return an error.
        for msg_type in [90u64, 93u64] {
            let (mut writer, mut reader) = duplex(1024);
            writer
                .encode_one(VarInt::try_from(msg_type).unwrap())
                .await
                .unwrap();
            drop(writer);
            let result = SshMessage::decode(&mut reader).await;
            assert!(result.is_err(), "type {msg_type} should not be decodable");
            let err = result.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
            assert!(
                err.to_string().contains(&format!("{msg_type}")),
                "error should mention type {msg_type}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 6: unknown_message_type_error
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_message_type_error() {
        let (mut writer, mut reader) = duplex(1024);
        writer
            .encode_one(VarInt::try_from(255u64).unwrap())
            .await
            .unwrap();
        drop(writer);
        let result = SshMessage::decode(&mut reader).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("255"));
    }

    // -----------------------------------------------------------------------
    // Test 7: empty_data_fields
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn empty_data_fields() {
        let messages = vec![
            SshMessage::GlobalRequest {
                request_type: String::new(),
                want_reply: false,
                data: vec![],
            },
            SshMessage::RequestSuccess { data: vec![] },
            SshMessage::ChannelData { data: vec![] },
            SshMessage::ChannelExtendedData {
                data_type: 0,
                data: vec![],
            },
            SshMessage::ChannelRequest {
                request_type: String::new(),
                want_reply: false,
                request_data: vec![],
            },
        ];

        for msg in &messages {
            let decoded = roundtrip(msg).await;
            assert_eq!(&decoded, msg, "empty data roundtrip failed for {msg:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: channel_extended_data_stderr
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn channel_extended_data_stderr() {
        // data_type=1 is SSH_EXTENDED_DATA_STDERR
        let msg = SshMessage::ChannelExtendedData {
            data_type: 1,
            data: b"error output".to_vec(),
        };
        let decoded = roundtrip(&msg).await;
        assert_eq!(decoded, msg);
        match decoded {
            SshMessage::ChannelExtendedData { data_type, data } => {
                assert_eq!(data_type, 1, "data_type should be 1 (stderr)");
                assert_eq!(data, b"error output");
            }
            other => panic!("expected ChannelExtendedData, got {other:?}"),
        }
    }
}
