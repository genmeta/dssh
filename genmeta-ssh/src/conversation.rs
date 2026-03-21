//! SSH3 conversation (session) abstraction.
//!
//! A *conversation* is the SSH3 equivalent of an SSH2 session — it manages
//! channels and global requests over a QUIC CONNECT stream.
//!
//! [`LocalConversation`] is the server-side implementation that wraps the
//! conversation stream plus an mpsc receiver for dispatched channel streams.

use std::future::Future;

use h3x::{
    codec::{DecodeExt, EncodeExt},
    quic::{self, GetStreamIdExt, ReadStream, WriteStream},
    stream_id::StreamId,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::{
    GlobalRequest,
    channel::RequestSuccess,
    forward::ForwardError,
    message::MessageError,
    message::SshMessage,
};

const SSH_MSG_REQUEST_SUCCESS: h3x::varint::VarInt = h3x::varint::VarInt::from_u32(81);
const SSH_MSG_REQUEST_FAILURE: h3x::varint::VarInt = h3x::varint::VarInt::from_u32(82);

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum ConversationError {
    #[snafu(display("conversation stream read failed"))]
    ReadIo { source: std::io::Error },

    #[snafu(display("conversation stream write failed"))]
    WriteIo { source: std::io::Error },

    #[snafu(display("conversation message codec failed"))]
    Message { source: MessageError },

    #[snafu(display("conversation forward codec failed"))]
    Forward { source: ForwardError },

    #[snafu(display("global request failed"))]
    GlobalRequestFailed,

    #[snafu(display("unexpected control-stream reply type"))]
    UnexpectedControlReplyType { message_type: u64 },

    #[snafu(display("unexpected control-stream request"))]
    UnexpectedControlRequest { message: String },
}

// ---------------------------------------------------------------------------
// Conversation trait
// ---------------------------------------------------------------------------

pub trait ManageSessionStream {
    type StreamReader: AsyncRead + ReadStream + Unpin;
    type StreamWriter: AsyncWrite + WriteStream + Unpin;
    type Error;

    fn open_stream(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Self::Error>> + Send;

    fn accept_stream(
        &self,
    ) -> impl Future<Output = Result<(Self::StreamReader, Self::StreamWriter), Self::Error>> + Send;
}

mod chmoc {
    use h3x::{
        codec::{SinkWriter, StreamReader},
        dhttp::protocol::{BoxDynQuicStreamReader, BoxDynQuicStreamWriter},
        quic,
        remoc::quic::{ReadStreamClient, WriteStreamClient},
    };

    #[remoc::rtc::remote]
    trait ManageSessionStream {
        async fn open_stream(
            &self,
        ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError>;

        async fn accept_stream(
            &self,
        ) -> Result<(ReadStreamClient, WriteStreamClient), quic::ConnectionError>;
    }

    impl super::ManageSessionStream for ManageSessionStreamClient {
        type StreamReader = StreamReader<BoxDynQuicStreamReader>;

        type StreamWriter = SinkWriter<BoxDynQuicStreamWriter>;

        type Error = quic::ConnectionError;

        async fn open_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            ManageSessionStream::open_stream(self).await.map(|(r, w)| {
                let r = StreamReader::new(r.into_boxed_quic());
                let w = SinkWriter::new(w.into_boxed_quic());
                (r, w)
            })
        }

        async fn accept_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            ManageSessionStream::accept_stream(self)
                .await
                .map(|(r, w)| {
                    let r = StreamReader::new(r.into_boxed_quic());
                    let w = SinkWriter::new(w.into_boxed_quic());
                    (r, w)
                })
        }
    }
}

// ---------------------------------------------------------------------------
// LocalConversation
// ---------------------------------------------------------------------------

pub struct Conversation<M: ManageSessionStream> {
    id: StreamId,
    control_stream_reader: M::StreamReader,
    control_stream_writer: M::StreamWriter,
    _manage_stream: M,
}

impl<M: ManageSessionStream> Conversation<M> {
    pub async fn new(
        mut control_stream_reader: M::StreamReader,
        control_stream_writer: M::StreamWriter,
        manage_stream: M,
    ) -> Result<Self, quic::StreamError> {
        Ok(Self {
            id: StreamId(control_stream_reader.stream_id().await?),
            control_stream_reader,
            control_stream_writer,
            _manage_stream: manage_stream,
        })
    }

    pub fn id(&self) -> StreamId {
        self.id
    }

    pub async fn send_global_request(
        &mut self,
        request: GlobalRequest,
    ) -> Result<Option<RequestSuccess>, ConversationError> {
        let want_reply = request.want_reply().0;
        let expects_bound_port = matches!(request, GlobalRequest::TcpipForward { .. });
        self.control_stream_writer
            .encode_one(SshMessage::GlobalRequest(request))
            .await
            .context(conversation_error::MessageSnafu)?;
        self.control_stream_writer
            .flush()
            .await
            .context(conversation_error::WriteIoSnafu)?;

        if !want_reply {
            return Ok(None);
        }

        let msg_type = self
            .control_stream_reader
            .decode_one::<h3x::varint::VarInt>()
            .await
            .context(conversation_error::ReadIoSnafu)?;
        match msg_type {
            SSH_MSG_REQUEST_SUCCESS => {
                let success = if expects_bound_port {
                    RequestSuccess::TcpipForward(
                        self.control_stream_reader
                            .decode_one()
                            .await
                            .context(conversation_error::ForwardSnafu)?,
                    )
                } else {
                    RequestSuccess::Empty
                };
                Ok(Some(success))
            }
            SSH_MSG_REQUEST_FAILURE => Err(ConversationError::GlobalRequestFailed),
            other => Err(ConversationError::UnexpectedControlReplyType {
                message_type: other.into_inner(),
            }),
        }
    }

    pub async fn recv_global_request(&mut self) -> Result<GlobalRequest, ConversationError> {
        match self
            .control_stream_reader
            .decode_one::<SshMessage>()
            .await
            .context(conversation_error::MessageSnafu)?
        {
            SshMessage::GlobalRequest(request) => Ok(request),
            other => Err(ConversationError::UnexpectedControlRequest {
                message: format!("{other:?}"),
            }),
        }
    }

    pub async fn send_request_success(
        &mut self,
        success: RequestSuccess,
    ) -> Result<(), ConversationError> {
        self.control_stream_writer
            .encode_one(SshMessage::RequestSuccess(success))
            .await
            .context(conversation_error::MessageSnafu)?;
        self.control_stream_writer
            .flush()
            .await
            .context(conversation_error::WriteIoSnafu)
    }

    pub async fn send_request_failure(&mut self) -> Result<(), ConversationError> {
        self.control_stream_writer
            .encode_one(SshMessage::RequestFailure)
            .await
            .context(conversation_error::MessageSnafu)?;
        self.control_stream_writer
            .flush()
            .await
            .context(conversation_error::WriteIoSnafu)
    }
}

// TODO: tests

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use tokio::io::{DuplexStream, duplex};

//     /// Helper: build a [`LocalConversation`] wired to duplex streams.
//     ///
//     /// Returns:
//     /// - the conversation
//     /// - remote write half (writes arrive at conversation reader)
//     /// - remote read half (reads from conversation writer)
//     /// - channel dispatch sender
//     #[allow(clippy::type_complexity)]
//     fn make_conversation() -> (
//         LocalConversation<DuplexStream, DuplexStream>,
//         DuplexStream,
//         DuplexStream,
//         mpsc::Sender<(ChannelHeader, DuplexStream, DuplexStream)>,
//         mpsc::Sender<(DuplexStream, DuplexStream)>,
//     ) {
//         // Conversation stream: two duplex pairs to simulate bidi
//         let (conv_local_write, conv_remote_read) = duplex(8192);
//         let (conv_remote_write, conv_local_read) = duplex(8192);

//         let (ch_tx, ch_rx) = mpsc::channel(16);
//         let (stream_tx, stream_rx) = mpsc::channel(16);
//         let stream_rx = Arc::new(tokio::sync::Mutex::new(stream_rx));
//         let stream_rx_for_opener = Arc::clone(&stream_rx);

//         let conv = LocalConversation::new(
//             VarInt::from_u32(42).into(),
//             conv_local_read,
//             conv_local_write,
//             ch_rx,
//             move || {
//                 let stream_rx = Arc::clone(&stream_rx_for_opener);
//                 Box::pin(async move {
//                     let mut rx = stream_rx.lock().await;
//                     rx.recv().await.ok_or_else(|| {
//                         io::Error::new(io::ErrorKind::BrokenPipe, "open stream source closed")
//                     })
//                 })
//             },
//         );

//         (conv, conv_remote_write, conv_remote_read, ch_tx, stream_tx)
//     }

//     // -----------------------------------------------------------------------
//     // open_channel: writes correct ChannelHeader bytes
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn open_channel_writes_correct_header_bytes() {
//         let (conv, _remote_write, _remote_read, _ch_tx, stream_tx) = make_conversation();

//         // Pre-load the factory: create two duplex pairs for the channel stream
//         let (local_write_half, mut remote_read_half) = duplex(8192);
//         let (_remote_write_half, local_read_half) = duplex(8192);
//         stream_tx
//             .send((local_read_half, local_write_half))
//             .await
//             .unwrap();

//         // Open a channel
//         let (_read, _write) = conv.open_channel("session", 65535).await.unwrap();

//         // Verify the header was written by decoding from the remote read half
//         let decoded = ChannelHeader::decode_from(&mut remote_read_half)
//             .await
//             .unwrap();
//         assert_eq!(decoded.signal_value, CHANNEL_SIGNAL_VALUE);
//         assert_eq!(decoded.conversation_id, 42);
//         assert_eq!(decoded.channel_type, "session");
//         assert_eq!(decoded.max_message_size, 65535);
//     }

//     // -----------------------------------------------------------------------
//     // accept_channel: receives from dispatch queue
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn accept_channel_receives_from_dispatch() {
//         let (conv, _remote_write, _remote_read, ch_tx, _stream_tx) = make_conversation();

//         // Dispatch a channel
//         let (read_half, write_half) = duplex(8192);
//         let header = ChannelHeader {
//             signal_value: CHANNEL_SIGNAL_VALUE,
//             conversation_id: 42,
//             channel_type: "direct-tcpip".into(),
//             max_message_size: 1024,
//         };
//         ch_tx
//             .send((header.clone(), read_half, write_half))
//             .await
//             .unwrap();

//         // Accept it
//         let (received_header, _r, _w) = conv.accept_channel().await.unwrap();
//         assert_eq!(received_header, header);
//     }

//     #[tokio::test]
//     async fn accept_channel_returns_none_when_closed() {
//         let (conv, _remote_write, _remote_read, ch_tx, _stream_tx) = make_conversation();

//         // Close the sender
//         drop(ch_tx);

//         // accept_channel should return None
//         let result = conv.accept_channel().await;
//         assert!(result.is_none());
//     }

//     // -----------------------------------------------------------------------
//     // Global request roundtrip
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn global_request_roundtrip_with_reply() {
//         let (conv, mut remote_write, mut remote_read, _ch_tx, _stream_tx) = make_conversation();

//         // Spawn a task to handle the request on the "remote" side
//         let handle = tokio::spawn(async move {
//             // Read the global request
//             let msg_type: VarInt = remote_read.decode_one().await.unwrap();
//             assert_eq!(msg_type, SSH_MSG_GLOBAL_REQUEST);

//             let req = GlobalRequest::decode_body(&mut remote_read).await.unwrap();
//             assert_eq!(req.request_type, "tcpip-forward");
//             assert!(req.want_reply);
//             assert_eq!(req.data, b"payload");

//             // Send success reply
//             encode_request_success(&mut remote_write, b"ok")
//                 .await
//                 .unwrap();
//             remote_write.flush().await.unwrap();
//         });

//         // Send a global request with want_reply=true
//         let reply = conv
//             .send_global_request("tcpip-forward", true, b"payload")
//             .await
//             .unwrap();
//         assert_eq!(reply, Some(b"ok".to_vec()));

//         handle.await.unwrap();
//     }

//     #[tokio::test]
//     async fn global_request_no_reply() {
//         let (conv, _remote_write, mut remote_read, _ch_tx, _stream_tx) = make_conversation();

//         // Send without want_reply
//         let reply = conv
//             .send_global_request("keepalive", false, b"")
//             .await
//             .unwrap();
//         assert!(reply.is_none());

//         // Verify the message was written correctly
//         let msg_type: VarInt = remote_read.decode_one().await.unwrap();
//         assert_eq!(msg_type, SSH_MSG_GLOBAL_REQUEST);

//         let req = GlobalRequest::decode_body(&mut remote_read).await.unwrap();
//         assert_eq!(req.request_type, "keepalive");
//         assert!(!req.want_reply);
//     }

//     #[tokio::test]
//     async fn global_request_failure_reply() {
//         let (conv, mut remote_write, mut remote_read, _ch_tx, _stream_tx) = make_conversation();

//         // Spawn a task to drain the request and reply with failure
//         let handle = tokio::spawn(async move {
//             let msg_type: VarInt = remote_read.decode_one().await.unwrap();
//             assert_eq!(msg_type, SSH_MSG_GLOBAL_REQUEST);
//             let _req = GlobalRequest::decode_body(&mut remote_read).await.unwrap();

//             // Reply with failure
//             encode_request_failure(&mut remote_write).await.unwrap();
//             remote_write.flush().await.unwrap();
//         });

//         let result = conv.send_global_request("bad-request", true, b"").await;
//         assert!(result.is_err());
//         assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionRefused);

//         handle.await.unwrap();
//     }

//     #[tokio::test]
//     async fn recv_global_request_decodes_correctly() {
//         let (conv, mut remote_write, _remote_read, _ch_tx, _stream_tx) = make_conversation();

//         // Write a global request from the "remote" side
//         let req = GlobalRequest {
//             request_type: "env".to_string(),
//             want_reply: false,
//             data: b"LANG=en_US.UTF-8".to_vec(),
//         };
//         req.encode_into(&mut remote_write).await.unwrap();
//         remote_write.flush().await.unwrap();

//         // Receive it
//         let (request_type, want_reply, data) = conv.recv_global_request().await.unwrap();
//         assert_eq!(request_type, "env");
//         assert!(!want_reply);
//         assert_eq!(data, b"LANG=en_US.UTF-8");
//     }

//     // -----------------------------------------------------------------------
//     // conversation_id
//     // -----------------------------------------------------------------------

//     #[tokio::test]
//     async fn conversation_id_returns_correct_value() {
//         let (conv, _remote_write, _remote_read, _ch_tx, _stream_tx) = make_conversation();
//         assert_eq!(conv.conversation_id(), 42);
//     }
// }
