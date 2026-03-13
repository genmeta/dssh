//! SSH3 conversation (session) abstraction.
//!
//! A *conversation* is the SSH3 equivalent of an SSH2 session — it manages
//! channels and global requests over a QUIC CONNECT stream.
//!
//! [`LocalConversation`] is the server-side implementation that wraps the
//! conversation stream plus an mpsc receiver for dispatched channel streams.
#![allow(dead_code)]

use std::{future::Future, ops::DerefMut, pin::Pin, sync::Arc};

use h3x::{
    codec::{DecodeExt, DecodeFrom, EncodeInto},
    varint::VarInt,
};
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

use crate::codec::{ChannelHeader, SshBool, SshBytes, SshString};

// ---------------------------------------------------------------------------
// SSH message type constants (subset used by conversation)
// ---------------------------------------------------------------------------

const SSH_MSG_GLOBAL_REQUEST: VarInt = VarInt::from_u32(80);
const SSH_MSG_REQUEST_SUCCESS: VarInt = VarInt::from_u32(81);
const SSH_MSG_REQUEST_FAILURE: VarInt = VarInt::from_u32(82);

type OpenBiFuture<R, W> = Pin<Box<dyn Future<Output = io::Result<(R, W)>> + Send>>;
type OpenBiOpener<R, W> = dyn Fn() -> OpenBiFuture<R, W> + Send + Sync;

// ---------------------------------------------------------------------------
// Conversation trait
// ---------------------------------------------------------------------------

/// The SSH3 session abstraction over a QUIC CONNECT stream.
pub(crate) trait Conversation {
    type Read: AsyncRead + Send + Unpin;
    type Write: AsyncWrite + Send + Unpin;

    /// Open a new channel by writing a [`ChannelHeader`] to a fresh
    /// bidirectional stream.
    ///
    /// Returns the read/write halves of the new stream (after the header
    /// has been written to the write half).
    fn open_channel(
        &self,
        channel_type: &str,
        max_message_size: u64,
    ) -> impl Future<Output = io::Result<(Self::Read, Self::Write)>> + Send;

    /// Accept a channel that was dispatched by the protocol layer.
    ///
    /// Returns `None` when the dispatch channel is closed.
    fn accept_channel(
        &self,
    ) -> impl Future<Output = Option<(ChannelHeader, Self::Read, Self::Write)>> + Send;

    /// Send an SSH_MSG_GLOBAL_REQUEST on the conversation stream.
    ///
    /// If `want_reply` is true, waits for SSH_MSG_REQUEST_SUCCESS(81) or
    /// SSH_MSG_REQUEST_FAILURE(82) and returns the reply data or an error.
    fn send_global_request(
        &self,
        request_type: &str,
        want_reply: bool,
        data: &[u8],
    ) -> impl Future<Output = io::Result<Option<Vec<u8>>>> + Send;

    /// Receive an SSH_MSG_GLOBAL_REQUEST from the conversation stream.
    ///
    /// Returns `(request_type, want_reply, data)`.
    fn recv_global_request(
        &self,
    ) -> impl Future<Output = io::Result<(String, bool, Vec<u8>)>> + Send;

    /// The QUIC stream ID of the CONNECT stream that carries this conversation.
    fn conversation_id(&self) -> u64;
}

// ---------------------------------------------------------------------------
// GlobalRequest — decoded SSH_MSG_GLOBAL_REQUEST message
// ---------------------------------------------------------------------------

/// A decoded SSH_MSG_GLOBAL_REQUEST(80) message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GlobalRequest {
    pub request_type: String,
    pub want_reply: bool,
    pub data: Vec<u8>,
}

impl<S: AsyncWrite + Send> EncodeInto<S> for &GlobalRequest {
    type Output = ();
    type Error = io::Error;

    /// Encode SSH_MSG_GLOBAL_REQUEST(80) onto a stream.
    async fn encode_into(self, stream: S) -> Result<(), io::Error> {
        let mut stream = std::pin::pin!(stream);
        SSH_MSG_GLOBAL_REQUEST.encode_into(&mut stream).await?;
        SshString(self.request_type.clone())
            .encode_into(&mut stream)
            .await?;
        SshBool(self.want_reply)
            .encode_into(&mut stream)
            .await?;
        SshBytes(self.data.clone())
            .encode_into(&mut stream)
            .await?;
        Ok(())
    }
}

impl GlobalRequest {
    /// Decode SSH_MSG_GLOBAL_REQUEST(80) body from a stream.
    ///
    /// Assumes the message type varint (80) has already been consumed.
    pub async fn decode_body<S: AsyncRead + Send + Unpin>(
        stream: &mut S,
    ) -> Result<Self, io::Error> {
        let request_type = SshString::decode_from(&mut *stream).await?;
        let want_reply = SshBool::decode_from(&mut *stream).await?;
        let data = SshBytes::decode_from(&mut *stream).await?;
        Ok(GlobalRequest {
            request_type: request_type.0,
            want_reply: want_reply.0,
            data: data.0,
        })
    }
}

// ---------------------------------------------------------------------------
// Reply helpers
// ---------------------------------------------------------------------------

/// Encode SSH_MSG_REQUEST_SUCCESS(81) with optional data.
pub(crate) async fn encode_request_success<S: AsyncWrite + Send + Unpin>(
    stream: &mut S,
    data: &[u8],
) -> Result<(), io::Error> {
    SSH_MSG_REQUEST_SUCCESS.encode_into(&mut *stream).await?;
    SshBytes(data.to_vec()).encode_into(&mut *stream).await?;
    Ok(())
}

/// Encode SSH_MSG_REQUEST_FAILURE(82) — no payload.
pub(crate) async fn encode_request_failure<S: AsyncWrite + Send + Unpin>(
    stream: &mut S,
) -> Result<(), io::Error> {
    SSH_MSG_REQUEST_FAILURE.encode_into(&mut *stream).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// LocalConversation
// ---------------------------------------------------------------------------

/// Server-side conversation backed by a CONNECT stream and an mpsc dispatch
/// queue for inbound channels.
#[allow(clippy::type_complexity)]
pub(crate) struct LocalConversation<R, W>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    conversation_id: u64,
    /// Read half of the conversation (CONNECT) stream.
    conversation_reader: tokio::sync::Mutex<R>,
    /// Write half of the conversation (CONNECT) stream.
    conversation_writer: tokio::sync::Mutex<W>,
    /// Receiver for dispatched channel streams.
    channel_rx: tokio::sync::Mutex<mpsc::Receiver<(ChannelHeader, R, W)>>,
    opener: Arc<OpenBiOpener<R, W>>,
}

impl<R, W> LocalConversation<R, W>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    /// Create a new `LocalConversation`.
    pub fn new<O>(
        conversation_id: u64,
        conversation_reader: R,
        conversation_writer: W,
        channel_rx: mpsc::Receiver<(ChannelHeader, R, W)>,
        opener: O,
    ) -> Self
    where
        O: Fn() -> OpenBiFuture<R, W> + Send + Sync + 'static,
    {
        Self {
            conversation_id,
            conversation_reader: tokio::sync::Mutex::new(conversation_reader),
            conversation_writer: tokio::sync::Mutex::new(conversation_writer),
            channel_rx: tokio::sync::Mutex::new(channel_rx),
            opener: Arc::new(opener),
        }
    }
}

/// Signal value for channel headers written by `open_channel`.
const CHANNEL_SIGNAL_VALUE: u32 = 0xaf3627e6;

impl<R, W> Conversation for LocalConversation<R, W>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    type Read = R;
    type Write = W;

    async fn open_channel(
        &self,
        channel_type: &str,
        max_message_size: u64,
    ) -> io::Result<(Self::Read, Self::Write)> {
        let (read, mut write) = (self.opener.as_ref())().await?;

        let header = ChannelHeader {
            signal_value: CHANNEL_SIGNAL_VALUE,
            conversation_id: self.conversation_id,
            channel_type: channel_type.to_string(),
            max_message_size,
        };
        header.encode_into(&mut write).await?;

        Ok((read, write))
    }

    async fn accept_channel(&self) -> Option<(ChannelHeader, Self::Read, Self::Write)> {
        let mut rx = self.channel_rx.lock().await;
        rx.recv().await
    }

    async fn send_global_request(
        &self,
        request_type: &str,
        want_reply: bool,
        data: &[u8],
    ) -> io::Result<Option<Vec<u8>>> {
        // Write the request on the conversation stream.
        {
            let mut writer = self.conversation_writer.lock().await;
            let req = GlobalRequest {
                request_type: request_type.to_string(),
                want_reply,
                data: data.to_vec(),
            };
            req.encode_into(&mut *writer).await?;
            writer.flush().await?;
        }

        if !want_reply {
            return Ok(None);
        }

        // Read the reply from the conversation stream.
        let mut reader = self.conversation_reader.lock().await;
        let msg_type: VarInt = reader.deref_mut().decode_one().await?;
        let msg_type = msg_type.into_inner();

        match msg_type {
            v if v == SSH_MSG_REQUEST_SUCCESS.into_inner() => {
                let payload = SshBytes::decode_from(&mut *reader).await?;
                Ok(Some(payload.0))
            }
            v if v == SSH_MSG_REQUEST_FAILURE.into_inner() => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "global request rejected",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected message type {other} in global request reply"),
            )),
        }
    }

    async fn recv_global_request(&self) -> io::Result<(String, bool, Vec<u8>)> {
        let mut reader = self.conversation_reader.lock().await;
        let msg_type: VarInt = reader.deref_mut().decode_one().await?;
        let msg_type = msg_type.into_inner();

        if msg_type != SSH_MSG_GLOBAL_REQUEST.into_inner() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected SSH_MSG_GLOBAL_REQUEST(80), got message type {msg_type}"
                ),
            ));
        }

        let req = GlobalRequest::decode_body(&mut *reader).await?;
        Ok((req.request_type, req.want_reply, req.data))
    }

    fn conversation_id(&self) -> u64 {
        self.conversation_id
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, DuplexStream};

    /// Helper: build a [`LocalConversation`] wired to duplex streams.
    ///
    /// Returns:
    /// - the conversation
    /// - remote write half (writes arrive at conversation reader)
    /// - remote read half (reads from conversation writer)
    /// - channel dispatch sender
    #[allow(clippy::type_complexity)]
    fn make_conversation() -> (
        LocalConversation<DuplexStream, DuplexStream>,
        DuplexStream,
        DuplexStream,
        mpsc::Sender<(ChannelHeader, DuplexStream, DuplexStream)>,
        mpsc::Sender<(DuplexStream, DuplexStream)>,
    ) {
        // Conversation stream: two duplex pairs to simulate bidi
        let (conv_local_write, conv_remote_read) = duplex(8192);
        let (conv_remote_write, conv_local_read) = duplex(8192);

        let (ch_tx, ch_rx) = mpsc::channel(16);
        let (stream_tx, stream_rx) = mpsc::channel(16);
        let stream_rx = Arc::new(tokio::sync::Mutex::new(stream_rx));
        let stream_rx_for_opener = Arc::clone(&stream_rx);

        let conv = LocalConversation::new(
            42,
            conv_local_read,
            conv_local_write,
            ch_rx,
            move || {
                let stream_rx = Arc::clone(&stream_rx_for_opener);
                Box::pin(async move {
                    let mut rx = stream_rx.lock().await;
                    rx.recv().await.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "open stream source closed")
                    })
                })
            },
        );

        (conv, conv_remote_write, conv_remote_read, ch_tx, stream_tx)
    }

    // -----------------------------------------------------------------------
    // open_channel: writes correct ChannelHeader bytes
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn open_channel_writes_correct_header_bytes() {
        let (conv, _remote_write, _remote_read, _ch_tx, stream_tx) = make_conversation();

        // Pre-load the factory: create two duplex pairs for the channel stream
        let (local_write_half, mut remote_read_half) = duplex(8192);
        let (_remote_write_half, local_read_half) = duplex(8192);
        stream_tx
            .send((local_read_half, local_write_half))
            .await
            .unwrap();

        // Open a channel
        let (_read, _write) = conv.open_channel("session", 65535).await.unwrap();

        // Verify the header was written by decoding from the remote read half
        let decoded = ChannelHeader::decode_from(&mut remote_read_half).await.unwrap();
        assert_eq!(decoded.signal_value, CHANNEL_SIGNAL_VALUE);
        assert_eq!(decoded.conversation_id, 42);
        assert_eq!(decoded.channel_type, "session");
        assert_eq!(decoded.max_message_size, 65535);
    }

    // -----------------------------------------------------------------------
    // accept_channel: receives from dispatch queue
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn accept_channel_receives_from_dispatch() {
        let (conv, _remote_write, _remote_read, ch_tx, _stream_tx) = make_conversation();

        // Dispatch a channel
        let (read_half, write_half) = duplex(8192);
        let header = ChannelHeader {
            signal_value: CHANNEL_SIGNAL_VALUE,
            conversation_id: 42,
            channel_type: "direct-tcpip".into(),
            max_message_size: 1024,
        };
        ch_tx
            .send((header.clone(), read_half, write_half))
            .await
            .unwrap();

        // Accept it
        let (received_header, _r, _w) = conv.accept_channel().await.unwrap();
        assert_eq!(received_header, header);
    }

    #[tokio::test]
    async fn accept_channel_returns_none_when_closed() {
        let (conv, _remote_write, _remote_read, ch_tx, _stream_tx) = make_conversation();

        // Close the sender
        drop(ch_tx);

        // accept_channel should return None
        let result = conv.accept_channel().await;
        assert!(result.is_none());
    }

    // -----------------------------------------------------------------------
    // Global request roundtrip
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn global_request_roundtrip_with_reply() {
        let (conv, mut remote_write, mut remote_read, _ch_tx, _stream_tx) = make_conversation();

        // Spawn a task to handle the request on the "remote" side
        let handle = tokio::spawn(async move {
            // Read the global request
            let msg_type: VarInt = remote_read.decode_one().await.unwrap();
            assert_eq!(msg_type, SSH_MSG_GLOBAL_REQUEST);

            let req = GlobalRequest::decode_body(&mut remote_read).await.unwrap();
            assert_eq!(req.request_type, "tcpip-forward");
            assert!(req.want_reply);
            assert_eq!(req.data, b"payload");

            // Send success reply
            encode_request_success(&mut remote_write, b"ok")
                .await
                .unwrap();
            remote_write.flush().await.unwrap();
        });

        // Send a global request with want_reply=true
        let reply = conv
            .send_global_request("tcpip-forward", true, b"payload")
            .await
            .unwrap();
        assert_eq!(reply, Some(b"ok".to_vec()));

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn global_request_no_reply() {
        let (conv, _remote_write, mut remote_read, _ch_tx, _stream_tx) = make_conversation();

        // Send without want_reply
        let reply = conv
            .send_global_request("keepalive", false, b"")
            .await
            .unwrap();
        assert!(reply.is_none());

        // Verify the message was written correctly
        let msg_type: VarInt = remote_read.decode_one().await.unwrap();
        assert_eq!(msg_type, SSH_MSG_GLOBAL_REQUEST);

        let req = GlobalRequest::decode_body(&mut remote_read).await.unwrap();
        assert_eq!(req.request_type, "keepalive");
        assert!(!req.want_reply);
    }

    #[tokio::test]
    async fn global_request_failure_reply() {
        let (conv, mut remote_write, mut remote_read, _ch_tx, _stream_tx) = make_conversation();

        // Spawn a task to drain the request and reply with failure
        let handle = tokio::spawn(async move {
            let msg_type: VarInt = remote_read.decode_one().await.unwrap();
            assert_eq!(msg_type, SSH_MSG_GLOBAL_REQUEST);
            let _req = GlobalRequest::decode_body(&mut remote_read).await.unwrap();

            // Reply with failure
            encode_request_failure(&mut remote_write).await.unwrap();
            remote_write.flush().await.unwrap();
        });

        let result = conv
            .send_global_request("bad-request", true, b"")
            .await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn recv_global_request_decodes_correctly() {
        let (conv, mut remote_write, _remote_read, _ch_tx, _stream_tx) = make_conversation();

        // Write a global request from the "remote" side
        let req = GlobalRequest {
            request_type: "env".to_string(),
            want_reply: false,
            data: b"LANG=en_US.UTF-8".to_vec(),
        };
        req.encode_into(&mut remote_write).await.unwrap();
        remote_write.flush().await.unwrap();

        // Receive it
        let (request_type, want_reply, data) = conv.recv_global_request().await.unwrap();
        assert_eq!(request_type, "env");
        assert!(!want_reply);
        assert_eq!(data, b"LANG=en_US.UTF-8");
    }

    // -----------------------------------------------------------------------
    // conversation_id
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn conversation_id_returns_correct_value() {
        let (conv, _remote_write, _remote_read, _ch_tx, _stream_tx) = make_conversation();
        assert_eq!(conv.conversation_id(), 42);
    }
}
