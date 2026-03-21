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
    GlobalRequestNotice, GlobalRequestPayload, GlobalRequestRequest,
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

    #[snafu(display("expected request-success reply payload"))]
    UnexpectedRequestSuccessPayload,

    #[snafu(display("mismatched global request reply payload"))]
    MismatchedGlobalRequestReply { request_type: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobalRequestReply {
    TcpipForward(crate::TcpipForwardReply),
    Unknown(RequestSuccess),
}

pub enum IncomingGlobal<'a, M: ManageSessionStream> {
    Notify(GlobalRequestNotice),
    Request(IncomingGlobalRequest<'a, M>),
}

#[must_use = "incoming global requests must be answered with success() or failure()"]
pub struct IncomingGlobalRequest<'a, M: ManageSessionStream> {
    request: GlobalRequestRequest,
    conv: &'a mut Conversation<M>,
}

impl<'a, M: ManageSessionStream> IncomingGlobalRequest<'a, M> {
    pub fn request(&self) -> &GlobalRequestPayload {
        self.request.request()
    }

    pub async fn success(self, reply: GlobalRequestReply) -> Result<(), ConversationError> {
        self.validate_reply(&reply)?;
        self.conv.send_request_success(reply).await
    }

    pub async fn success_empty(self) -> Result<(), ConversationError> {
        self.success(GlobalRequestReply::Unknown(RequestSuccess::Empty)).await
    }

    pub async fn success_tcpip_forward(
        self,
        reply: crate::TcpipForwardReply,
    ) -> Result<(), ConversationError> {
        self.success(GlobalRequestReply::TcpipForward(reply)).await
    }

    pub async fn failure(self) -> Result<(), ConversationError> {
        self.conv.send_request_failure().await
    }

    fn validate_reply(&self, reply: &GlobalRequestReply) -> Result<(), ConversationError> {
        match (self.request.request(), reply) {
            (GlobalRequestPayload::TcpipForward(_), _) => Ok(()),
            (_, GlobalRequestReply::Unknown(_)) => Ok(()),
            (request, GlobalRequestReply::TcpipForward(_)) => {
                Err(ConversationError::MismatchedGlobalRequestReply {
                    request_type: request.request_type().to_string(),
                })
            }
        }
    }
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

    pub async fn request(
        &mut self,
        request: GlobalRequestRequest,
    ) -> Result<GlobalRequestReply, ConversationError> {
        let expects_bound_port = matches!(request.request(), GlobalRequestPayload::TcpipForward(_));
        self.control_stream_writer
            .encode_one(SshMessage::GlobalRequest(request.into_wire()))
            .await
            .context(conversation_error::MessageSnafu)?;
        self.control_stream_writer
            .flush()
            .await
            .context(conversation_error::WriteIoSnafu)?;

        let msg_type = self
            .control_stream_reader
            .decode_one::<h3x::varint::VarInt>()
            .await
            .context(conversation_error::ReadIoSnafu)?;
        match msg_type {
            SSH_MSG_REQUEST_SUCCESS => {
                if expects_bound_port {
                    Ok(GlobalRequestReply::TcpipForward(
                        self.control_stream_reader
                            .decode_one()
                            .await
                            .context(conversation_error::ForwardSnafu)?,
                    ))
                } else {
                    Ok(GlobalRequestReply::Unknown(RequestSuccess::Empty))
                }
            }
            SSH_MSG_REQUEST_FAILURE => Err(ConversationError::GlobalRequestFailed),
            other => Err(ConversationError::UnexpectedControlReplyType {
                message_type: other.into_inner(),
            }),
        }
    }

    pub async fn notify(
        &mut self,
        notice: GlobalRequestNotice,
    ) -> Result<(), ConversationError> {
        self.control_stream_writer
            .encode_one(SshMessage::GlobalRequest(notice.into_wire()))
            .await
            .context(conversation_error::MessageSnafu)?;
        self.control_stream_writer
            .flush()
            .await
            .context(conversation_error::WriteIoSnafu)
    }

    pub async fn accept(&mut self) -> Result<IncomingGlobal<'_, M>, ConversationError> {
        match self
            .control_stream_reader
            .decode_one::<SshMessage>()
            .await
            .context(conversation_error::MessageSnafu)?
        {
            SshMessage::GlobalRequest(request) => {
                let payload = request.payload();
                if request.want_reply().0 {
                    Ok(IncomingGlobal::Request(IncomingGlobalRequest {
                        request: GlobalRequestRequest::new(payload),
                        conv: self,
                    }))
                } else {
                    Ok(IncomingGlobal::Notify(GlobalRequestNotice::new(payload)))
                }
            }
            other => Err(ConversationError::UnexpectedControlRequest {
                message: format!("{other:?}"),
            }),
        }
    }

    async fn send_request_success(
        &mut self,
        reply: GlobalRequestReply,
    ) -> Result<(), ConversationError> {
        let success = match reply {
            GlobalRequestReply::TcpipForward(reply) => RequestSuccess::TcpipForward(reply),
            GlobalRequestReply::Unknown(success) => success,
        };
        self.control_stream_writer
            .encode_one(SshMessage::RequestSuccess(success))
            .await
            .context(conversation_error::MessageSnafu)?;
        self.control_stream_writer
            .flush()
            .await
            .context(conversation_error::WriteIoSnafu)
    }

    async fn send_request_failure(&mut self) -> Result<(), ConversationError> {
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
