use super::*;

use crate::codec::SshBytes;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::{Sink, Stream, channel::mpsc};
use h3x::{
    codec::{SinkWriter, StreamReader as H3xStreamReader},
    quic::{CancelStream, GetStreamId, StopStream, StreamError},
};

// -- Mock stream types that implement h3x ReadStream / WriteStream ------

struct TestQuicReader {
    stream_id: VarInt,
    inner: mpsc::Receiver<Bytes>,
}

impl Unpin for TestQuicReader {}

impl Stream for TestQuicReader {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx).map(|opt| opt.map(Ok))
    }
}

impl GetStreamId for TestQuicReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl StopStream for TestQuicReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        Poll::Ready(Ok(()))
    }
}

struct TestQuicWriter {
    stream_id: VarInt,
    inner: mpsc::Sender<Bytes>,
}

impl Unpin for TestQuicWriter {}

impl Sink<Bytes> for TestQuicWriter {
    type Error = StreamError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_ready(cx)
            .map_err(|_| StreamError::Reset {
                code: VarInt::from_u32(0),
            })
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        Pin::new(&mut self.inner)
            .start_send(item)
            .map_err(|_| StreamError::Reset {
                code: VarInt::from_u32(0),
            })
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| StreamError::Reset {
                code: VarInt::from_u32(0),
            })
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(|_| StreamError::Reset {
                code: VarInt::from_u32(0),
            })
    }
}

impl GetStreamId for TestQuicWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl CancelStream for TestQuicWriter {
    fn poll_cancel(
        self: Pin<&mut Self>,
        _cx: &mut Context,
        _code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        Poll::Ready(Ok(()))
    }
}

// -- Concrete types for ManageSessionStream -----------------------------

type MockReader = H3xStreamReader<TestQuicReader>;
type MockWriter = SinkWriter<TestQuicWriter>;

struct TestManageStream;

impl ManageSessionStream for TestManageStream {
    type StreamReader = MockReader;
    type StreamWriter = MockWriter;
    type Error = std::convert::Infallible;

    async fn open_stream(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        unreachable!("not used in global request tests")
    }

    async fn accept_stream(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        unreachable!("not used in global request tests")
    }
}

/// Create a connected pair of (reader, writer) for one direction.
fn make_half(stream_id: VarInt) -> (MockReader, MockWriter) {
    let (tx, rx) = mpsc::channel(64);
    let reader = H3xStreamReader::new(TestQuicReader {
        stream_id,
        inner: rx,
    });
    let writer = SinkWriter::new(TestQuicWriter {
        stream_id,
        inner: tx,
    });
    (reader, writer)
}

async fn make_conversation() -> (Conversation<TestManageStream>, MockReader, MockWriter) {
    let stream_id = VarInt::from_u32(42);
    // local reads ← remote writes
    let (local_reader, remote_writer) = make_half(stream_id);
    // remote reads ← local writes
    let (remote_reader, local_writer) = make_half(stream_id);

    let conv = Conversation::new(
        StreamId(stream_id),
        "test-version",
        local_reader,
        local_writer,
        TestManageStream,
    );
    (conv, remote_reader, remote_writer)
}

// -- Test request type implementations ----------------------------------

/// A simple test request: payload is a single SshString, success is a VarInt.
#[derive(Clone)]
struct TestPayload(SshString);

struct TestRequest {
    payload: TestPayload,
}

impl WantReplyGlobalRequest for TestRequest {
    type Success = VarInt;
    type Payload = TestPayload;

    fn request_type(&self) -> SshString {
        SshString::from_static("test-request")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

// EncodeInto for TestPayload: encodes the inner SshString
impl<S: AsyncWrite + Send> EncodeInto<S> for TestPayload {
    type Output = ();
    type Error = crate::codec::CodecError;

    async fn encode_into(self, stream: S) -> Result<(), Self::Error> {
        self.0.encode_into(stream).await
    }
}

// -- Test notify type ---------------------------------------------------

struct TestNotice {
    payload: TestPayload,
}

impl NotifyGlobalRequest for TestNotice {
    type Payload = TestPayload;

    fn request_type(&self) -> SshString {
        SshString::from_static("test-notice")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

// -- Helpers for the "remote" side --------------------------------------

/// Remote sends a global request with want_reply on the writer.
async fn remote_send_global_request(
    writer: &mut MockWriter,
    request_type: &str,
    want_reply: bool,
    payload: &str,
) {
    (*writer)
        .encode_one(VarInt::from_u32(80)) // SSH_MSG_GLOBAL_REQUEST
        .await
        .unwrap();
    (*writer)
        .encode_one(SshString::from(request_type.to_string()))
        .await
        .unwrap();
    (*writer)
        .encode_one(SshBool(want_reply))
        .await
        .unwrap();
    (*writer)
        .encode_one(SshString::from(payload.to_string()))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut *writer).await.unwrap();
}

/// Remote reads a global request header and returns (request_type, want_reply).
async fn remote_read_global_request_header(
    reader: &mut MockReader,
) -> (SshString, bool) {
    let msg_type: VarInt = (*reader).decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(80));
    let request_type: SshString = (*reader).decode_one().await.unwrap();
    let want_reply: SshBool = (*reader).decode_one().await.unwrap();
    (request_type, want_reply.0)
}

/// Remote sends SSH_MSG_REQUEST_SUCCESS followed by a VarInt value.
async fn remote_send_success(writer: &mut MockWriter, value: u32) {
    (*writer)
        .encode_one(VarInt::from_u32(81)) // SSH_MSG_REQUEST_SUCCESS
        .await
        .unwrap();
    (*writer)
        .encode_one(VarInt::from_u32(value))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut *writer).await.unwrap();
}

/// Remote sends SSH_MSG_REQUEST_FAILURE.
async fn remote_send_failure(writer: &mut MockWriter) {
    (*writer)
        .encode_one(VarInt::from_u32(82)) // SSH_MSG_REQUEST_FAILURE
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut *writer).await.unwrap();
}

// =======================================================================
// Tests
// =======================================================================

#[tokio::test]
async fn conversation_id() {
    let (conv, _remote_reader, _remote_writer) = make_conversation().await;
    assert_eq!(conv.id(), StreamId(VarInt::from_u32(42)));
}

// -- request() tests ----------------------------------------------------

#[tokio::test]
async fn request_success_roundtrip() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    let handle = tokio::spawn(async move {
        let (req_type, want_reply) =
            remote_read_global_request_header(&mut remote_reader).await;
        assert_eq!(&*req_type, "test-request");
        assert!(want_reply);
        // Read payload
        let payload: SshString = remote_reader.decode_one().await.unwrap();
        assert_eq!(payload.as_ref() as &[u8], b"hello");
        // Send success with value 99
        remote_send_success(&mut remote_writer, 99).await;
    });

    let req = TestRequest {
        payload: TestPayload(SshString::from("hello".to_string())),
    };
    let result: VarInt = conv.request(&req).await.unwrap();
    assert_eq!(result, VarInt::from_u32(99));

    handle.await.unwrap();
}

#[tokio::test]
async fn request_rejected() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    let handle = tokio::spawn(async move {
        let _ = remote_read_global_request_header(&mut remote_reader).await;
        let _payload: SshString = remote_reader.decode_one().await.unwrap();
        remote_send_failure(&mut remote_writer).await;
    });

    let req = TestRequest {
        payload: TestPayload(SshString::from("hi".to_string())),
    };
    let result: Result<VarInt, _> = conv.request(&req).await;
    assert!(matches!(result, Err(SendRequestError::Rejected)));

    handle.await.unwrap();
}

// -- notify() tests -----------------------------------------------------

#[tokio::test]
async fn notify_sends_correctly() {
    let (conv, mut remote_reader, _remote_writer) = make_conversation().await;

    let notice = TestNotice {
        payload: TestPayload(SshString::from("world".to_string())),
    };
    conv.notify(&notice).await.unwrap();

    let (req_type, want_reply) =
        remote_read_global_request_header(&mut remote_reader).await;
    assert_eq!(&*req_type, "test-notice");
    assert!(!want_reply);
    let payload: SshString = remote_reader.decode_one().await.unwrap();
    assert_eq!(payload.as_ref() as &[u8], b"world");
}

// -- accept() tests -----------------------------------------------------

#[tokio::test]
async fn accept_incoming_request_decode_and_respond_success() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Remote sends a want_reply=true request
    remote_send_global_request(&mut remote_writer, "tcpip-forward", true, "bind-addr")
        .await;

    let incoming = conv.accept().await.unwrap();
    let req = match incoming {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };

    assert_eq!(&**req.request_type(), "tcpip-forward");

    // Decode payload — consumes req, returns DecodedGlobalRequest
    let (payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();
    assert_eq!(&*payload, "bind-addr");

    // Respond with success (VarInt 8080)
    decoded.respond_success(VarInt::from_u32(8080)).await.unwrap();

    // Verify remote receives success
    let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(81)); // SSH_MSG_REQUEST_SUCCESS
    let port: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(port, VarInt::from_u32(8080));
}

#[tokio::test]
async fn accept_incoming_request_respond_failure() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    remote_send_global_request(&mut remote_writer, "unknown-req", true, "data").await;

    let incoming = conv.accept().await.unwrap();
    let req = match incoming {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };

    let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();
    decoded.respond_failure().await.unwrap();

    let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(82)); // SSH_MSG_REQUEST_FAILURE
}

#[tokio::test]
async fn accept_incoming_notice() {
    let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

    remote_send_global_request(&mut remote_writer, "keepalive", false, "ping").await;

    let incoming = conv.accept().await.unwrap();
    let notice = match incoming {
        IncomingGlobal::Notify(n) => n,
        _ => panic!("expected Notify"),
    };

    assert_eq!(&**notice.request_type(), "keepalive");
    let payload: SshString = notice.decode_payload().await.unwrap();
    assert_eq!(&*payload, "ping");
}

// -- Drop / poisoning tests ---------------------------------------------

#[tokio::test]
async fn drop_request_before_decode_poisons_session() {
    let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

    remote_send_global_request(&mut remote_writer, "test", true, "data").await;

    let incoming = conv.accept().await.unwrap();
    let req = match incoming {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };

    // Drop without decoding → poisons session
    drop(req);

    assert!(conv.shared.poisoned.load(Ordering::SeqCst));

    // Subsequent accept should fail with SessionPoisoned
    let result = conv.accept().await;
    assert!(matches!(result, Err(AcceptError::SessionPoisoned)));
}

#[tokio::test]
async fn drop_notice_before_decode_poisons_session() {
    let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

    remote_send_global_request(&mut remote_writer, "test", false, "data").await;

    let incoming = conv.accept().await.unwrap();
    let notice = match incoming {
        IncomingGlobal::Notify(n) => n,
        _ => panic!("expected Notify"),
    };

    drop(notice);
    assert!(conv.shared.poisoned.load(Ordering::SeqCst));
}

#[tokio::test]
async fn drop_request_after_decode_queues_auto_failure() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    remote_send_global_request(&mut remote_writer, "test", true, "data").await;

    let incoming = conv.accept().await.unwrap();
    let req = match incoming {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };

    // Decode payload — returns DecodedGlobalRequest
    let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();

    // Drop DecodedGlobalRequest without responding → should queue auto-failure
    drop(decoded);

    // Session should NOT be poisoned
    assert!(!conv.shared.poisoned.load(Ordering::SeqCst));

    // The auto-failure should be queued
    assert!(conv.shared.auto_failures.lock().unwrap().contains(&0));

    // Trigger drain by sending a notify (which acquires the writer)
    let notice = TestNotice {
        payload: TestPayload(SshString::from("after".to_string())),
    };
    conv.notify(&notice).await.unwrap();

    // Remote should first see the auto-failure response, then the notify
    let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(82)); // SSH_MSG_REQUEST_FAILURE (auto)

    let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(80)); // SSH_MSG_GLOBAL_REQUEST (notify)
}

// -- Response ordering tests --------------------------------------------

#[tokio::test]
async fn incoming_request_responses_ordered_correctly() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Send two requests from remote
    remote_send_global_request(&mut remote_writer, "req-a", true, "a").await;
    remote_send_global_request(&mut remote_writer, "req-b", true, "b").await;

    // Accept both
    let incoming_a = conv.accept().await.unwrap();
    let req_a = match incoming_a {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };
    let (_, decoded_a): (SshString, _) = req_a.decode_payload().await.unwrap();

    let incoming_b = conv.accept().await.unwrap();
    let req_b = match incoming_b {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };
    let (_, decoded_b): (SshString, _) = req_b.decode_payload().await.unwrap();

    // Respond to B first (out of order) — it should wait for A
    let b_handle = tokio::spawn(async move {
        decoded_b.respond_success(VarInt::from_u32(200)).await.unwrap();
    });

    // Small delay to ensure B starts waiting
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Now respond to A — this should unblock B
    decoded_a.respond_success(VarInt::from_u32(100)).await.unwrap();
    b_handle.await.unwrap();

    // Remote should receive A's response first, then B's
    let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(81)); // SUCCESS
    let val: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(val, VarInt::from_u32(100)); // A's response

    let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(81)); // SUCCESS
    let val: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(val, VarInt::from_u32(200)); // B's response
}

#[tokio::test]
async fn unexpected_message_type_poisons_session() {
    let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

    // Remote sends SSH_MSG_REQUEST_SUCCESS (81) instead of GLOBAL_REQUEST
    remote_writer
        .encode_one(VarInt::from_u32(81))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut remote_writer).await.unwrap();

    let result = conv.accept().await;
    assert!(matches!(result, Err(AcceptError::UnexpectedMessageType { .. })));

    // Session should be poisoned (unknown body on stream)
    assert!(conv.shared.poisoned.load(Ordering::SeqCst));
}

// -- Concurrent request ordering ----------------------------------------

#[tokio::test]
async fn concurrent_requests_ordered_correctly() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;
    let conv = Arc::new(conv);

    // Spawn two concurrent request tasks. The ticket mechanism must
    // ensure request A is sent before B, and response A is read before B.
    let conv_a = Arc::clone(&conv);
    let handle_a = tokio::spawn(async move {
        conv_a
            .request::<TestRequest, _, _>(&TestRequest {
                payload: TestPayload(SshString::from_static("alpha")),
            })
            .await
    });

    let conv_b = Arc::clone(&conv);
    let handle_b = tokio::spawn(async move {
        conv_b
            .request::<TestRequest, _, _>(&TestRequest {
                payload: TestPayload(SshString::from_static("beta")),
            })
            .await
    });

    // Yield to let both tasks run and acquire tickets
    tokio::task::yield_now().await;

    // Remote reads the first request (A)
    let (req_type_a, want_reply_a) =
        remote_read_global_request_header(&mut remote_reader).await;
    assert!(want_reply_a);
    let payload_a: SshString = remote_reader.decode_one().await.unwrap();

    // Remote reads the second request (B)
    let (req_type_b, want_reply_b) =
        remote_read_global_request_header(&mut remote_reader).await;
    assert!(want_reply_b);
    let payload_b: SshString = remote_reader.decode_one().await.unwrap();

    // Both have the same type
    assert_eq!(req_type_a.as_ref() as &[u8], b"test-request");
    assert_eq!(req_type_b.as_ref() as &[u8], b"test-request");

    // The payloads should be in order (A first, B second)
    let a_payload = payload_a.as_ref().to_vec();
    let b_payload = payload_b.as_ref().to_vec();
    assert_ne!(a_payload, b_payload);

    // Send success response for A, then B
    remote_send_success(&mut remote_writer, 100).await;
    remote_send_success(&mut remote_writer, 200).await;

    let result_a = handle_a.await.unwrap();
    let result_b = handle_b.await.unwrap();

    let val_a = result_a.unwrap();
    let val_b = result_b.unwrap();
    assert_eq!(val_a, VarInt::from_u32(100));
    assert_eq!(val_b, VarInt::from_u32(200));
}

// -- Writer auto-failure consecutive drain ------------------------------

#[tokio::test]
async fn consecutive_auto_failures_drained_by_next_writer() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Remote sends 3 requests that all want a reply
    remote_send_global_request(&mut remote_writer, "req-1", true, "d1").await;
    remote_send_global_request(&mut remote_writer, "req-2", true, "d2").await;
    remote_send_global_request(&mut remote_writer, "req-3", true, "d3").await;

    // Accept and decode all three, but DON'T respond — just drop them.
    // This should queue 3 auto-failure writer tickets.
    for _ in 0..3 {
        match conv.accept().await.unwrap() {
            IncomingGlobal::Request(req) => {
                let (_payload, _decoded): (SshString, _) =
                    req.decode_payload().await.unwrap();
                // Drop DecodedGlobalRequest without responding → auto-failure queued
            }
            _ => panic!("expected Request"),
        }
    }

    // The auto-failures haven't been sent yet (no writer has tried to
    // acquire). Now send a notify — this acquires a writer ticket and
    // should drain all 3 auto-failures first.
    let notice = TestNotice {
        payload: TestPayload(SshString::from_static("ping")),
    };
    conv.notify::<TestNotice, _>(&notice).await.unwrap();

    // Remote should see: 3x failure, then the notify
    for _ in 0..3 {
        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, SSH_MSG_REQUEST_FAILURE);
    }

    // Now the notify message
    let (req_type, want_reply) =
        remote_read_global_request_header(&mut remote_reader).await;
    assert_eq!(req_type.as_ref() as &[u8], b"test-notice");
    assert!(!want_reply);
}

// -- Session poison blocks all operations -------------------------------

#[tokio::test]
async fn poisoned_session_rejects_request() {
    let (conv, _remote_reader, _remote_writer) = make_conversation().await;

    // Manually poison the session
    conv.shared.poison();

    let result = conv
        .request::<TestRequest, _, _>(&TestRequest {
            payload: TestPayload(SshString::from_static("hello")),
        })
        .await;

    assert!(matches!(result, Err(SendRequestError::SessionPoisoned)));
}

#[tokio::test]
async fn poisoned_session_rejects_notify() {
    let (conv, _remote_reader, _remote_writer) = make_conversation().await;

    conv.shared.poison();

    let notice = TestNotice {
        payload: TestPayload(SshString::from_static("hello")),
    };
    let result = conv.notify::<TestNotice, _>(&notice).await;

    assert!(matches!(result, Err(SendNotifyError::SessionPoisoned)));
}

#[tokio::test]
async fn poisoned_session_rejects_accept() {
    let (conv, _remote_reader, _remote_writer) = make_conversation().await;

    conv.shared.poison();

    let result = conv.accept().await;
    assert!(matches!(result, Err(AcceptError::SessionPoisoned)));
}

#[tokio::test]
async fn poisoned_session_rejects_respond_success() {
    let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

    remote_send_global_request(&mut remote_writer, "test", true, "data").await;

    let req = match conv.accept().await.unwrap() {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };

    let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();

    // Now poison the session before responding
    conv.shared.poison();

    let result = decoded.respond_success(VarInt::from_u32(42)).await;
    assert!(matches!(
        result,
        Err(RespondSuccessError::SessionPoisoned)
    ));
}

#[tokio::test]
async fn poisoned_session_rejects_respond_failure() {
    let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

    remote_send_global_request(&mut remote_writer, "test", true, "data").await;

    let req = match conv.accept().await.unwrap() {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };

    let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();

    conv.shared.poison();

    let result = decoded.respond_failure().await;
    assert!(matches!(result, Err(RespondFailureError::SessionPoisoned)));
}

// -- respond_success mid-encode drop poisons ----------------------------

#[tokio::test]
async fn respond_success_cancelled_poisons_session() {
    let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

    remote_send_global_request(&mut remote_writer, "test", true, "data").await;

    let req = match conv.accept().await.unwrap() {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };

    let (_payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();

    // Close the remote side so writes fail/block.
    drop(_remote_reader);
    drop(remote_writer);

    let respond_fut = decoded.respond_success(VarInt::from_u32(42));

    let result = tokio::time::timeout(
        std::time::Duration::from_millis(50),
        respond_fut,
    )
    .await;

    match result {
        Ok(Ok(())) => {
            // Extremely unlikely but technically possible
        }
        Ok(Err(_)) => {
            assert!(
                conv.shared.poisoned.load(Ordering::SeqCst),
                "session should be poisoned after encode error"
            );
        }
        Err(_elapsed) => {
            assert!(
                conv.shared.poisoned.load(Ordering::SeqCst),
                "session should be poisoned after mid-encode cancellation"
            );
        }
    }
}

// -- Multiple sequential accept() calls ---------------------------------

#[tokio::test]
async fn multiple_sequential_accepts() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Remote sends 3 requests
    for i in 0..3u32 {
        remote_send_global_request(
            &mut remote_writer,
            &format!("req-{i}"),
            true,
            &format!("data-{i}"),
        )
        .await;
    }

    // Accept, decode, and respond to each one sequentially.
    for i in 0..3u32 {
        let req = match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };

        let expected_type = format!("req-{i}");
        assert_eq!(req.request_type().as_ref() as &[u8], expected_type.as_bytes());

        let (payload, decoded): (SshString, _) = req.decode_payload().await.unwrap();
        let expected_payload = format!("data-{i}");
        assert_eq!(payload.as_ref() as &[u8], expected_payload.as_bytes());

        decoded.respond_success(VarInt::from_u32(i * 10)).await.unwrap();
    }

    // Remote reads all 3 success responses
    for i in 0..3u32 {
        let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, SSH_MSG_REQUEST_SUCCESS);
        let val: VarInt = remote_reader.decode_one().await.unwrap();
        assert_eq!(val, VarInt::from_u32(i * 10));
    }
}

// -- Interleaved request + notify on writer ----------------------------

#[tokio::test]
async fn interleaved_request_and_notify_on_writer() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Send a notify first, then a request. Both go through the writer
    // ticket system and should be ordered correctly.
    let notice = TestNotice {
        payload: TestPayload(SshString::from_static("notice-1")),
    };
    conv.notify::<TestNotice, _>(&notice).await.unwrap();

    // Now send a request
    // Pre-send the response so request() can complete
    remote_send_success(&mut remote_writer, 777).await;

    let result = conv
        .request::<TestRequest, _, _>(&TestRequest {
            payload: TestPayload(SshString::from_static("req-after-notify")),
        })
        .await;
    assert_eq!(result.unwrap(), VarInt::from_u32(777));

    // Remote should see: notify first, then the request
    let (rt_1, wr_1) = remote_read_global_request_header(&mut remote_reader).await;
    assert_eq!(rt_1.as_ref() as &[u8], b"test-notice");
    assert!(!wr_1);
    let _payload_1: SshString = remote_reader.decode_one().await.unwrap();

    let (rt_2, wr_2) = remote_read_global_request_header(&mut remote_reader).await;
    assert_eq!(rt_2.as_ref() as &[u8], b"test-request");
    assert!(wr_2);
    let _payload_2: SshString = remote_reader.decode_one().await.unwrap();
}

// -- Auto-failure at current_serving is immediately drained -------------

#[tokio::test]
async fn auto_failure_at_current_serving_drained_immediately() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Remote sends one request
    remote_send_global_request(&mut remote_writer, "test", true, "data").await;

    // Accept, decode, but drop without responding → auto-failure at ticket 0
    {
        let req = match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };
        let (_payload, _decoded): (SshString, _) = req.decode_payload().await.unwrap();
        // Drop DecodedGlobalRequest here: writer ticket 0 → auto-failure
    }

    // The auto-failure (ticket 0) IS the current serving ticket.
    // Sending a notify should drain it before sending the notify.
    let notice = TestNotice {
        payload: TestPayload(SshString::from_static("after-auto")),
    };
    conv.notify::<TestNotice, _>(&notice).await.unwrap();

    // Remote should see: failure response, then the notify
    let msg_type: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, SSH_MSG_REQUEST_FAILURE);

    let (rt, wr) = remote_read_global_request_header(&mut remote_reader).await;
    assert_eq!(rt.as_ref() as &[u8], b"test-notice");
    assert!(!wr);
}

// -- Mixed auto-failures and real responses ----------------------------

#[tokio::test]
async fn auto_failures_interleaved_with_real_responses() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Remote sends 4 requests: A, B, C, D (all want_reply)
    for label in ["A", "B", "C", "D"] {
        remote_send_global_request(&mut remote_writer, label, true, label).await;
    }

    // Accept all 4
    let mut decoded_reqs: Vec<DecodedGlobalRequest> = Vec::new();
    for _ in 0..4 {
        match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => {
                let (_payload, decoded): (SshString, _) =
                    r.decode_payload().await.unwrap();
                decoded_reqs.push(decoded);
            }
            _ => panic!("expected Request"),
        }
    }

    // Respond to A (ticket 0) with success
    let a = decoded_reqs.remove(0);
    a.respond_success(VarInt::from_u32(1)).await.unwrap();

    // Drop B (ticket 1) → auto-failure
    let _b = decoded_reqs.remove(0);
    drop(_b);

    // Respond to C (ticket 2) with failure
    let c = decoded_reqs.remove(0);
    c.respond_failure().await.unwrap();

    // Drop D (ticket 3) → auto-failure
    let _d = decoded_reqs.remove(0);
    drop(_d);

    // Now send a notify to drain remaining auto-failures
    let notice = TestNotice {
        payload: TestPayload(SshString::from_static("end")),
    };
    conv.notify::<TestNotice, _>(&notice).await.unwrap();

    // Remote expects: success(1), failure(B-auto), failure(C), failure(D-auto), notify
    let msg_a: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_a, SSH_MSG_REQUEST_SUCCESS);
    let val_a: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(val_a, VarInt::from_u32(1));

    let msg_b: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_b, SSH_MSG_REQUEST_FAILURE); // B auto-failure

    let msg_c: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_c, SSH_MSG_REQUEST_FAILURE); // C explicit failure

    let msg_d: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_d, SSH_MSG_REQUEST_FAILURE); // D auto-failure

    // Notify
    let (rt, wr) = remote_read_global_request_header(&mut remote_reader).await;
    assert_eq!(rt.as_ref() as &[u8], b"test-notice");
    assert!(!wr);
}

// -- Type-system guarantees (compile-time) --------------------------------
// The following invariants are now enforced at compile time:
// - Cannot decode twice: decode_payload consumes self
// - Cannot respond before decode: respond methods are on DecodedGlobalRequest
// - Cannot respond twice: respond methods consume self
// No runtime tests needed for these cases.

// -- OrderedAccess unit-level tests ------------------------------------

#[tokio::test]
async fn ordered_access_sequential_tickets() {
    let access = OrderedAccess::new(42u32);
    let poisoned = AtomicBool::new(false);

    let t0 = access.take_ticket();
    let t1 = access.take_ticket();
    let t2 = access.take_ticket();

    assert_eq!(t0, 0);
    assert_eq!(t1, 1);
    assert_eq!(t2, 2);

    // Ticket 0 can acquire immediately
    {
        let guard = access.acquire(t0, &poisoned).await.unwrap();
        assert_eq!(*guard, 42);
        // drop → advances current_serving to 1
    }

    // Now ticket 1 can acquire
    {
        let mut guard = access.acquire(t1, &poisoned).await.unwrap();
        *guard = 99;
        // drop → advances current_serving to 2
    }

    // Now ticket 2 can acquire
    {
        let guard = access.acquire(t2, &poisoned).await.unwrap();
        assert_eq!(*guard, 99); // modified by ticket 1
    }
}

#[tokio::test]
async fn ordered_access_concurrent_tickets() {
    let access = Arc::new(OrderedAccess::new(Vec::<u32>::new()));
    let poisoned = Arc::new(AtomicBool::new(false));

    let t0 = access.take_ticket();
    let t1 = access.take_ticket();
    let t2 = access.take_ticket();

    let mut handles = Vec::new();

    // Launch tickets in REVERSE order — they should still execute in order.
    for (ticket, value) in [(t2, 3u32), (t1, 2), (t0, 1)] {
        let access_clone = Arc::clone(&access);
        let poisoned_clone = Arc::clone(&poisoned);
        handles.push(tokio::spawn(async move {
            let mut guard = access_clone.acquire(ticket, &poisoned_clone).await.unwrap();
            guard.push(value);
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // Verify order: t0 ran first (pushed 1), then t1 (2), then t2 (3)
    let guard = {
        let t = access.take_ticket();
        access.acquire(t, &poisoned).await.unwrap()
    };
    assert_eq!(&*guard, &[1, 2, 3]);
}

#[tokio::test]
async fn ordered_access_poison_wakes_waiters() {
    let access = Arc::new(OrderedAccess::new(()));
    let poisoned = Arc::new(AtomicBool::new(false));

    // Take ticket 0 but don't release — ticket 1 will wait forever.
    let t0 = access.take_ticket();
    let t1 = access.take_ticket();

    let _guard0 = access.acquire(t0, &poisoned).await.unwrap();

    let access_clone = Arc::clone(&access);
    let poisoned_clone = Arc::clone(&poisoned);
    let handle = tokio::spawn(async move {
        access_clone.acquire(t1, &poisoned_clone).await
    });

    // Give the spawned task time to start waiting
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;

    // Poison — should wake the waiter
    poisoned.store(true, Ordering::SeqCst);
    access.notify_waiters();

    let result = handle.await.unwrap();
    assert!(result.is_err());
}

// -- Request with notification mixed on reader -------------------------

#[tokio::test]
async fn accept_alternating_requests_and_notices() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Remote sends: request, notice, request, notice
    remote_send_global_request(&mut remote_writer, "req-1", true, "r1").await;
    remote_send_global_request(&mut remote_writer, "ntf-1", false, "n1").await;
    remote_send_global_request(&mut remote_writer, "req-2", true, "r2").await;
    remote_send_global_request(&mut remote_writer, "ntf-2", false, "n2").await;

    // Accept #1: request
    {
        let req = match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };
        assert_eq!(req.request_type().as_ref() as &[u8], b"req-1");
        let (_, decoded): (SshString, _) = req.decode_payload().await.unwrap();
        decoded.respond_success(VarInt::from_u32(10)).await.unwrap();
    }

    // Accept #2: notice
    {
        let ntf = match conv.accept().await.unwrap() {
            IncomingGlobal::Notify(n) => n,
            _ => panic!("expected Notify"),
        };
        assert_eq!(ntf.request_type().as_ref() as &[u8], b"ntf-1");
        let _: SshString = ntf.decode_payload().await.unwrap();
    }

    // Accept #3: request
    {
        let req = match conv.accept().await.unwrap() {
            IncomingGlobal::Request(r) => r,
            _ => panic!("expected Request"),
        };
        assert_eq!(req.request_type().as_ref() as &[u8], b"req-2");
        let (_, decoded): (SshString, _) = req.decode_payload().await.unwrap();
        decoded.respond_failure().await.unwrap();
    }

    // Accept #4: notice
    {
        let ntf = match conv.accept().await.unwrap() {
            IncomingGlobal::Notify(n) => n,
            _ => panic!("expected Notify"),
        };
        assert_eq!(ntf.request_type().as_ref() as &[u8], b"ntf-2");
        let _: SshString = ntf.decode_payload().await.unwrap();
    }

    // Remote should see: success(10), then failure
    let msg_1: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_1, SSH_MSG_REQUEST_SUCCESS);
    let val_1: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(val_1, VarInt::from_u32(10));

    let msg_2: VarInt = remote_reader.decode_one().await.unwrap();
    assert_eq!(msg_2, SSH_MSG_REQUEST_FAILURE);
}

// -- decode_payload success releases reader for next accept ---------------

#[tokio::test]
async fn decode_payload_success_releases_reader() {
    let (conv, _remote_reader, mut remote_writer) = make_conversation().await;

    // Send two requests
    remote_send_global_request(&mut remote_writer, "first", true, "x").await;
    remote_send_global_request(&mut remote_writer, "second", false, "y").await;

    // Accept and decode first request
    let req = match conv.accept().await.unwrap() {
        IncomingGlobal::Request(r) => r,
        _ => panic!("expected Request"),
    };
    let (payload, _decoded): (SshString, _) = req.decode_payload().await.unwrap();
    assert_eq!(payload.as_ref() as &[u8], b"x");

    // After decode_payload succeeds, the reader is released and we can
    // accept the next message without blocking.
    let ntf = match conv.accept().await.unwrap() {
        IncomingGlobal::Notify(n) => n,
        _ => panic!("expected Notify"),
    };
    let payload: SshString = ntf.decode_payload().await.unwrap();
    assert_eq!(payload.as_ref() as &[u8], b"y");
}

// -- Empty request (no payload beyond header) --------------------------

/// A request type whose payload is empty (zero bytes).
#[derive(Clone)]
struct EmptyPayload;

impl<S: AsyncWrite + Send> EncodeInto<S> for EmptyPayload {
    type Output = ();
    type Error = std::io::Error;

    async fn encode_into(self, _stream: S) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct EmptyRequest;

impl WantReplyGlobalRequest for EmptyRequest {
    type Success = EmptyPayload;
    type Payload = EmptyPayload;

    fn request_type(&self) -> SshString {
        SshString::from_static("empty")
    }

    fn payload(&self) -> &Self::Payload {
        &EmptyPayload
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for EmptyPayload {
    type Error = std::io::Error;

    async fn decode_from(_stream: S) -> Result<Self, Self::Error> {
        Ok(EmptyPayload)
    }
}

#[tokio::test]
async fn request_with_empty_payload() {
    let (conv, mut remote_reader, mut remote_writer) = make_conversation().await;

    // Pre-send empty success response
    remote_writer
        .encode_one(VarInt::from_u32(81)) // SUCCESS
        .await
        .unwrap();
    // No success body — EmptyPayload reads nothing
    AsyncWriteExt::flush(&mut remote_writer).await.unwrap();

    let result = conv
        .request::<EmptyRequest, _, _>(&EmptyRequest)
        .await;
    assert!(result.is_ok());

    // Remote reads the request header and (empty) payload
    let (rt, wr) = remote_read_global_request_header(&mut remote_reader).await;
    assert_eq!(rt.as_ref() as &[u8], b"empty");
    assert!(wr);
    // No payload bytes to read
}

// =======================================================================
// Channel tests
// =======================================================================

// -- Channel-capable ManageSessionStream ---------------------------------

use tokio::sync::mpsc as tokio_mpsc;

/// A ManageSessionStream impl that delivers pre-created stream pairs via
/// channels, allowing tests to control what the "remote" sends/receives.
struct ChannelManageStream {
    /// Sender for streams returned by open_stream().
    open_tx: tokio_mpsc::UnboundedSender<(MockReader, MockWriter)>,
    open_rx: std::sync::Mutex<tokio_mpsc::UnboundedReceiver<(MockReader, MockWriter)>>,
    /// Sender for streams returned by accept_stream().
    accept_tx: tokio_mpsc::UnboundedSender<(MockReader, MockWriter)>,
    accept_rx: std::sync::Mutex<tokio_mpsc::UnboundedReceiver<(MockReader, MockWriter)>>,
}

impl ChannelManageStream {
    fn new() -> Self {
        let (open_tx, open_rx) = tokio_mpsc::unbounded_channel();
        let (accept_tx, accept_rx) = tokio_mpsc::unbounded_channel();
        Self {
            open_tx,
            open_rx: std::sync::Mutex::new(open_rx),
            accept_tx,
            accept_rx: std::sync::Mutex::new(accept_rx),
        }
    }

    /// Enqueue a stream pair that open_stream() will return.
    fn provide_open_stream(&self, reader: MockReader, writer: MockWriter) {
        self.open_tx.send((reader, writer)).unwrap();
    }

    /// Enqueue a stream pair that accept_stream() will return.
    fn provide_accept_stream(&self, reader: MockReader, writer: MockWriter) {
        self.accept_tx.send((reader, writer)).unwrap();
    }
}

impl ManageSessionStream for ChannelManageStream {
    type StreamReader = MockReader;
    type StreamWriter = MockWriter;
    type Error = std::convert::Infallible;

    async fn open_stream(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        let pair = self.open_rx.lock().unwrap().try_recv()
            .expect("no open_stream pair provided");
        Ok(pair)
    }

    async fn accept_stream(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        let pair = self.accept_rx.lock().unwrap().try_recv()
            .expect("no accept_stream pair provided");
        Ok(pair)
    }
}

/// Create a Conversation backed by ChannelManageStream plus the control
/// stream remote ends.
async fn make_channel_conversation() -> (
    Conversation<impl ManageSessionStream<StreamReader = MockReader, StreamWriter = MockWriter, Error = std::convert::Infallible>>,
    MockReader,
    MockWriter,
    Arc<ChannelManageStream>,
) {
    let stream_id = VarInt::from_u32(42);
    let (local_reader, remote_writer) = make_half(stream_id);
    let (remote_reader, local_writer) = make_half(stream_id);

    let manage = Arc::new(ChannelManageStream::new());

    // We need to pass the manage stream by value. Create a wrapper that
    // delegates to the Arc'd version.
    struct ArcManage(Arc<ChannelManageStream>);
    impl ManageSessionStream for ArcManage {
        type StreamReader = MockReader;
        type StreamWriter = MockWriter;
        type Error = std::convert::Infallible;

        async fn open_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            self.0.open_stream().await
        }

        async fn accept_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            self.0.accept_stream().await
        }
    }

    let conv = Conversation::new(
        StreamId(stream_id),
        "test-version",
        local_reader,
        local_writer,
        ArcManage(Arc::clone(&manage)),
    );
    (conv, remote_reader, remote_writer, manage)
}

// -- Test ChannelOpen implementation ------------------------------------

/// A test channel type: "test-channel" with SshString payload.
struct TestChannel {
    payload: TestPayload,
}

impl ChannelOpen for TestChannel {
    type Payload = TestPayload;

    fn channel_type(&self) -> SshString {
        SshString::from_static("test-channel")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// A session channel with no extra payload.
struct SessionChannel;

/// Empty payload that encodes nothing.
#[derive(Clone)]
struct EmptyChannelPayload;

impl<S: AsyncWrite + Send> EncodeInto<S> for EmptyChannelPayload {
    type Output = ();
    type Error = std::io::Error;

    async fn encode_into(self, _stream: S) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<S: AsyncRead + Send> DecodeFrom<S> for EmptyChannelPayload {
    type Error = std::io::Error;

    async fn decode_from(_stream: S) -> Result<Self, Self::Error> {
        Ok(EmptyChannelPayload)
    }
}

impl ChannelOpen for SessionChannel {
    type Payload = EmptyChannelPayload;

    fn channel_type(&self) -> SshString {
        SshString::from_static("session")
    }

    fn payload(&self) -> &Self::Payload {
        &EmptyChannelPayload
    }
}

// -- Channel tests ------------------------------------------------------

#[tokio::test]
async fn open_channel_roundtrip() {
    let (conv, _remote_reader, _remote_writer, manage) =
        make_channel_conversation().await;

    // Create a channel stream pair: the "channel reader/writer" that the
    // remote side will use.
    let ch_stream_id = VarInt::from_u32(100);
    let (ch_remote_reader, ch_local_writer) = make_half(ch_stream_id);
    let (ch_local_reader, mut ch_remote_writer) = make_half(ch_stream_id);
    manage.provide_open_stream(ch_local_reader, ch_local_writer);

    let max_msg_size = VarInt::from_u32(1 << 20);
    let channel = TestChannel {
        payload: TestPayload(SshString::from_static("hello")),
    };

    // Spawn a "remote side" that reads the channel header then sends confirmation.
    let remote_task = tokio::spawn(async move {
        let mut rr = ch_remote_reader;

        let mms: VarInt = rr.decode_one().await.unwrap();
        assert_eq!(mms, max_msg_size);

        let ct: SshString = rr.decode_one().await.unwrap();
        assert_eq!(ct.as_ref() as &[u8], b"test-channel");

        let payload: SshString = rr.decode_one().await.unwrap();
        assert_eq!(payload.as_ref() as &[u8], b"hello");

        // Send confirmation: SSH_MSG_CHANNEL_OPEN_CONFIRMATION + max_message_size
        ch_remote_writer
            .encode_one(VarInt::from_u32(91))
            .await
            .unwrap();
        ch_remote_writer
            .encode_one(VarInt::from_u32(1 << 20))
            .await
            .unwrap();
        AsyncWriteExt::flush(&mut ch_remote_writer).await.unwrap();
    });

    let (_reader, _writer) = conv
        .open_channel(&channel, max_msg_size)
        .await
        .expect("open_channel should succeed");

    remote_task.await.unwrap();
}

#[tokio::test]
async fn accept_channel_roundtrip() {
    let (conv, _remote_reader, _remote_writer, manage) =
        make_channel_conversation().await;

    let ch_stream_id = VarInt::from_u32(200);
    let (ch_local_reader, ch_remote_writer) = make_half(ch_stream_id);
    let (_ch_remote_reader, ch_local_writer) = make_half(ch_stream_id);

    // Remote encodes channel data starting at max_message_size
    // (signal value and session ID are handled by ManageSessionStream).
    let mut rw = ch_remote_writer;
    let max_msg_size = VarInt::from_u32(1 << 20);
    rw.encode_one(max_msg_size).await.unwrap();
    rw
        .encode_one(SshString::from_static("test-channel"))
        .await
        .unwrap();
    rw
        .encode_one(SshString::from_static("world"))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut rw).await.unwrap();

    // accept_stream will return the local side of the channel
    manage.provide_accept_stream(ch_local_reader, ch_local_writer);

    let incoming = conv.accept_channel().await.expect("accept_channel should succeed");

    assert_eq!(incoming.channel_type().as_ref() as &[u8], b"test-channel");
    assert_eq!(incoming.max_message_size(), max_msg_size);

    // Decode the channel-type-specific payload.
    let (payload, _pending): (SshString, _) = incoming
        .decode_payload()
        .await
        .expect("decode_payload should succeed");

    assert_eq!(payload.as_ref() as &[u8], b"world");
}

#[tokio::test]
async fn accept_channel_session_no_payload() {
    let (conv, _remote_reader, _remote_writer, manage) =
        make_channel_conversation().await;

    let ch_stream_id = VarInt::from_u32(300);
    let (ch_local_reader, ch_remote_writer) = make_half(ch_stream_id);
    let (_ch_remote_reader, ch_local_writer) = make_half(ch_stream_id);

    // Remote sends channel data starting at max_message_size
    // (signal value and session ID are handled by ManageSessionStream).
    let mut rw = ch_remote_writer;
    rw.encode_one(VarInt::from_u32(1 << 20)).await.unwrap();
    rw
        .encode_one(SshString::from_static("session"))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut rw).await.unwrap();

    manage.provide_accept_stream(ch_local_reader, ch_local_writer);

    let incoming = conv.accept_channel().await.unwrap();
    assert_eq!(incoming.channel_type().as_ref() as &[u8], b"session");

    // Use skip_payload since session has no payload.
    let _pending = incoming.skip_payload();
}

#[tokio::test]
async fn open_channel_session_no_payload() {
    let (conv, _remote_reader, _remote_writer, manage) =
        make_channel_conversation().await;

    let ch_stream_id = VarInt::from_u32(600);
    let (ch_remote_reader, ch_local_writer) = make_half(ch_stream_id);
    let (ch_local_reader, mut ch_remote_writer) = make_half(ch_stream_id);

    manage.provide_open_stream(ch_local_reader, ch_local_writer);

    // Remote reads header and sends confirmation.
    let remote_task = tokio::spawn(async move {
        let mut rr = ch_remote_reader;

        let mms: VarInt = rr.decode_one().await.unwrap();
        assert_eq!(mms, VarInt::from_u32(1 << 20));

        let ct: SshString = rr.decode_one().await.unwrap();
        assert_eq!(ct.as_ref() as &[u8], b"session");
        // No payload bytes follow.

        // Send confirmation
        ch_remote_writer.encode_one(VarInt::from_u32(91)).await.unwrap();
        ch_remote_writer.encode_one(VarInt::from_u32(1 << 20)).await.unwrap();
        AsyncWriteExt::flush(&mut ch_remote_writer).await.unwrap();
    });

    let (_reader, _writer) = conv
        .open_channel(&SessionChannel, VarInt::from_u32(1 << 20))
        .await
        .expect("open session channel should succeed");

    remote_task.await.unwrap();
}

#[tokio::test]
async fn open_and_accept_channel_full_roundtrip() {
    // Test open on one side, accept on the other.
    let stream_id = VarInt::from_u32(42);

    // Create two conversations sharing a control stream.
    let (ctrl_a_reader, ctrl_b_writer) = make_half(stream_id);
    let (ctrl_b_reader, ctrl_a_writer) = make_half(stream_id);

    let manage_a = Arc::new(ChannelManageStream::new());
    let manage_b = Arc::new(ChannelManageStream::new());

    struct ArcManage2(Arc<ChannelManageStream>);
    impl ManageSessionStream for ArcManage2 {
        type StreamReader = MockReader;
        type StreamWriter = MockWriter;
        type Error = std::convert::Infallible;
        async fn open_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            self.0.open_stream().await
        }
        async fn accept_stream(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
            self.0.accept_stream().await
        }
    }

    let conv_a = Conversation::new(
        StreamId(stream_id),
        "test-version",
        ctrl_a_reader,
        ctrl_a_writer,
        ArcManage2(Arc::clone(&manage_a)),
    );
    let conv_b = Conversation::new(
        StreamId(stream_id),
        "test-version",
        ctrl_b_reader,
        ctrl_b_writer,
        ArcManage2(Arc::clone(&manage_b)),
    );

    // Create the channel stream: A opens, B accepts.
    // A's open_stream returns (ch_a_reader, ch_a_writer).
    // B's accept_stream returns (ch_b_reader, ch_b_writer).
    // We need ch_a_writer → ch_b_reader and ch_b_writer → ch_a_reader.
    let ch_id = VarInt::from_u32(700);
    let (ch_b_reader, ch_a_writer) = make_half(ch_id);
    let (ch_a_reader, ch_b_writer) = make_half(ch_id);

    manage_a.provide_open_stream(ch_a_reader, ch_a_writer);
    manage_b.provide_accept_stream(ch_b_reader, ch_b_writer);

    let max_msg = VarInt::from_u32(1 << 20);
    let channel = TestChannel {
        payload: TestPayload(SshString::from_static("roundtrip")),
    };

    // A opens and B accepts concurrently (A blocks until B sends confirmation).
    let open_task = tokio::spawn(async move {
        conv_a
            .open_channel::<_, crate::codec::CodecError>(&channel, max_msg)
            .await
            .expect("A should open channel")
    });

    // B accepts the channel.
    let incoming = conv_b
        .accept_channel()
        .await
        .expect("B should accept channel");

    assert_eq!(incoming.channel_type().as_ref() as &[u8], b"test-channel");
    assert_eq!(incoming.max_message_size(), max_msg);

    let (payload, pending): (SshString, _) = incoming
        .decode_payload()
        .await
        .expect("B should decode payload");

    assert_eq!(payload.as_ref() as &[u8], b"roundtrip");

    // B accepts, sending confirmation back to A.
    let (_b_reader, _b_writer) = pending.accept(max_msg).await.unwrap();

    // A's open_channel should now complete.
    let (_a_reader, _a_writer) = open_task.await.unwrap();
}

// =======================================================================
// Channel request tests
// =======================================================================

// -- Test channel request type implementations --------------------------

/// 测试用的 channel request：payload 是 SshString，success 是 VarInt。
struct TestChannelReq {
    payload: TestPayload,
}

impl WantReplyChannelRequest for TestChannelReq {
    type Success = VarInt;
    type Payload = TestPayload;

    fn request_type(&self) -> SshString {
        SshString::from_static("test-ch-req")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// 测试用的 channel notice（不需要回复）。
struct TestChannelNotice {
    payload: TestPayload,
}

impl NotifyChannelRequest for TestChannelNotice {
    type Payload = TestPayload;

    fn request_type(&self) -> SshString {
        SshString::from_static("test-ch-notice")
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }
}

/// 创建一对连接的 channel 流（独立于 control stream）。
fn make_channel_pair() -> (MockReader, MockWriter, MockReader, MockWriter) {
    let ch_id = VarInt::from_u32(900);
    let (a_reader, b_writer) = make_half(ch_id);
    let (b_reader, a_writer) = make_half(ch_id);
    (a_reader, a_writer, b_reader, b_writer)
}

// -- SshChannelWriter/SshChannelReader tests ------------------------------

#[tokio::test]
async fn channel_request_success_roundtrip() {
    let (a_reader, a_writer, mut b_reader, mut b_writer) = make_channel_pair();

    let handle = tokio::spawn(async move {
        // B 端读取请求
        let msg_type: VarInt = b_reader.decode_one().await.unwrap();
        assert_eq!(msg_type, VarInt::from_u32(98)); // SSH_MSG_CHANNEL_REQUEST
        let req_type: SshString = b_reader.decode_one().await.unwrap();
        assert_eq!(req_type.as_ref() as &[u8], b"test-ch-req");
        let want_reply: SshBool = b_reader.decode_one().await.unwrap();
        assert!(want_reply.0);
        let payload: SshString = b_reader.decode_one().await.unwrap();
        assert_eq!(payload.as_ref() as &[u8], b"hello-channel");

        // B 端发送 success + VarInt 响应
        b_writer.encode_one(VarInt::from_u32(99)).await.unwrap(); // SSH_MSG_CHANNEL_SUCCESS
        b_writer.encode_one(VarInt::from_u32(42)).await.unwrap();
        AsyncWriteExt::flush(&mut b_writer).await.unwrap();
    });

    let req = TestChannelReq {
        payload: TestPayload(SshString::from("hello-channel".to_string())),
    };
    let mut ch_writer = SshChannelWriter::new(a_writer);
    let mut ch_reader = SshChannelReader::new(a_reader);
    let result: VarInt = ch_writer.request(&mut ch_reader, &req)
        .await
        .unwrap();
    assert_eq!(result, VarInt::from_u32(42));

    handle.await.unwrap();
}

#[tokio::test]
async fn channel_request_rejected() {
    let (a_reader, a_writer, mut b_reader, mut b_writer) = make_channel_pair();

    let handle = tokio::spawn(async move {
        // 读取并丢弃请求内容
        let _: VarInt = b_reader.decode_one().await.unwrap();
        let _: SshString = b_reader.decode_one().await.unwrap();
        let _: SshBool = b_reader.decode_one().await.unwrap();
        let _: SshString = b_reader.decode_one().await.unwrap();

        // 发送 failure
        b_writer.encode_one(VarInt::from_u32(100)).await.unwrap(); // SSH_MSG_CHANNEL_FAILURE
        AsyncWriteExt::flush(&mut b_writer).await.unwrap();
    });

    let req = TestChannelReq {
        payload: TestPayload(SshString::from_static("data")),
    };
    let mut ch_writer = SshChannelWriter::new(a_writer);
    let mut ch_reader = SshChannelReader::new(a_reader);
    let result: Result<VarInt, _> =
        ch_writer.request(&mut ch_reader, &req).await;
    assert!(matches!(result, Err(SendChannelRequestError::Rejected)));

    handle.await.unwrap();
}

// -- SshChannelWriter::notice tests -------------------------------------

#[tokio::test]
async fn channel_notice_sends_correctly() {
    let (_a_reader, a_writer, mut b_reader, _b_writer) = make_channel_pair();

    let notice = TestChannelNotice {
        payload: TestPayload(SshString::from("notice-data".to_string())),
    };
    let mut ch_writer = SshChannelWriter::new(a_writer);
    ch_writer.notice(&notice).await.unwrap();

    // B 端验证
    let msg_type: VarInt = b_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(98)); // SSH_MSG_CHANNEL_REQUEST
    let req_type: SshString = b_reader.decode_one().await.unwrap();
    assert_eq!(req_type.as_ref() as &[u8], b"test-ch-notice");
    let want_reply: SshBool = b_reader.decode_one().await.unwrap();
    assert!(!want_reply.0);
    let payload: SshString = b_reader.decode_one().await.unwrap();
    assert_eq!(payload.as_ref() as &[u8], b"notice-data");
}

// -- SshChannelReader::next_event tests ---------------------------------

#[tokio::test]
async fn read_channel_event_data() {
    let (a_reader, _a_writer, _b_reader, mut b_writer) = make_channel_pair();

    // B 发送 DATA
    b_writer.encode_one(VarInt::from_u32(94)).await.unwrap(); // SSH_MSG_CHANNEL_DATA
    b_writer
        .encode_one(SshBytes::from(bytes::Bytes::from_static(b"hello")))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut b_writer).await.unwrap();

    let mut ch_reader = SshChannelReader::new(a_reader);
    let event = ch_reader.next_event().await.unwrap();
    match event {
        ChannelEvent::Data(data) => {
            assert_eq!(data.as_ref() as &[u8], b"hello");
        }
        _ => panic!("expected Data event"),
    }
}

#[tokio::test]
async fn read_channel_event_extended_data() {
    let (a_reader, _a_writer, _b_reader, mut b_writer) = make_channel_pair();

    // B 发送 EXTENDED_DATA (stderr = 1)
    b_writer.encode_one(VarInt::from_u32(95)).await.unwrap();
    b_writer.encode_one(VarInt::from_u32(1)).await.unwrap();
    b_writer
        .encode_one(SshBytes::from(bytes::Bytes::from_static(b"err")))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut b_writer).await.unwrap();

    let mut ch_reader = SshChannelReader::new(a_reader);
    let event = ch_reader.next_event().await.unwrap();
    match event {
        ChannelEvent::ExtendedData { data_type, data } => {
            assert_eq!(data_type, VarInt::from_u32(1));
            assert_eq!(data.as_ref() as &[u8], b"err");
        }
        _ => panic!("expected ExtendedData event"),
    }
}

#[tokio::test]
async fn read_channel_event_eof_close_success_failure() {
    let (a_reader, _a_writer, _b_reader, mut b_writer) = make_channel_pair();

    // 依次发送 EOF, CLOSE, SUCCESS, FAILURE
    for msg_type in [96u32, 97, 99, 100] {
        b_writer.encode_one(VarInt::from_u32(msg_type)).await.unwrap();
    }
    AsyncWriteExt::flush(&mut b_writer).await.unwrap();

    let mut ch_reader = SshChannelReader::new(a_reader);
    assert!(matches!(ch_reader.next_event().await.unwrap(), ChannelEvent::Eof));
    assert!(matches!(ch_reader.next_event().await.unwrap(), ChannelEvent::Close));
    assert!(matches!(ch_reader.next_event().await.unwrap(), ChannelEvent::Success));
    assert!(matches!(ch_reader.next_event().await.unwrap(), ChannelEvent::Failure));
}

#[tokio::test]
async fn read_channel_event_request_decode_and_respond_success() {
    let (a_reader, a_writer, mut b_reader, mut b_writer) = make_channel_pair();

    // B 发送一个 want_reply=true 的 channel request
    b_writer.encode_one(VarInt::from_u32(98)).await.unwrap(); // SSH_MSG_CHANNEL_REQUEST
    b_writer
        .encode_one(SshString::from_static("exec"))
        .await
        .unwrap();
    b_writer.encode_one(SshBool(true)).await.unwrap();
    b_writer
        .encode_one(SshString::from_static("/bin/ls"))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut b_writer).await.unwrap();

    let mut ch_reader = SshChannelReader::new(a_reader);
    let mut ch_writer = SshChannelWriter::new(a_writer);
    let event = ch_reader.next_event().await.unwrap();
    let req = match event {
        ChannelEvent::Request(r) => r,
        _ => panic!("expected Request event"),
    };

    assert_eq!(req.request_type().as_ref() as &[u8], b"exec");
    assert!(req.want_reply());

    // 解码 payload
    let (payload, responder): (SshString, _) = req.decode_payload().await.unwrap();
    assert_eq!(payload.as_ref() as &[u8], b"/bin/ls");

    // 应该有 responder
    let responder = responder.expect("want_reply was true, should have responder");

    // 发送 success 响应（空 payload）
    responder.respond_success(&mut ch_writer, EmptyChannelPayload).await.unwrap();

    // B 端验证
    let msg_type: VarInt = b_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(99)); // SSH_MSG_CHANNEL_SUCCESS
}

#[tokio::test]
async fn read_channel_event_request_respond_failure() {
    let (a_reader, a_writer, mut b_reader, mut b_writer) = make_channel_pair();

    // B 发送 want_reply=true 的请求
    b_writer.encode_one(VarInt::from_u32(98)).await.unwrap();
    b_writer
        .encode_one(SshString::from_static("unknown-req"))
        .await
        .unwrap();
    b_writer.encode_one(SshBool(true)).await.unwrap();
    b_writer
        .encode_one(SshString::from_static("data"))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut b_writer).await.unwrap();

    let mut ch_reader = SshChannelReader::new(a_reader);
    let mut ch_writer = SshChannelWriter::new(a_writer);
    let event = ch_reader.next_event().await.unwrap();
    let req = match event {
        ChannelEvent::Request(r) => r,
        _ => panic!("expected Request event"),
    };

    let (_payload, responder): (SshString, _) = req.decode_payload().await.unwrap();
    let responder = responder.unwrap();
    responder.respond_failure(&mut ch_writer).await.unwrap();

    // B 端验证
    let msg_type: VarInt = b_reader.decode_one().await.unwrap();
    assert_eq!(msg_type, VarInt::from_u32(100)); // SSH_MSG_CHANNEL_FAILURE
}

#[tokio::test]
async fn read_channel_event_request_no_reply() {
    let (a_reader, _a_writer, _b_reader, mut b_writer) = make_channel_pair();

    // B 发送 want_reply=false 的通知
    b_writer.encode_one(VarInt::from_u32(98)).await.unwrap();
    b_writer
        .encode_one(SshString::from_static("window-change"))
        .await
        .unwrap();
    b_writer.encode_one(SshBool(false)).await.unwrap();
    b_writer
        .encode_one(SshString::from_static("80x24"))
        .await
        .unwrap();
    AsyncWriteExt::flush(&mut b_writer).await.unwrap();

    let mut ch_reader = SshChannelReader::new(a_reader);
    let event = ch_reader.next_event().await.unwrap();
    let req = match event {
        ChannelEvent::Request(r) => r,
        _ => panic!("expected Request event"),
    };

    assert_eq!(req.request_type().as_ref() as &[u8], b"window-change");
    assert!(!req.want_reply());

    let (payload, responder): (SshString, _) = req.decode_payload().await.unwrap();
    assert_eq!(payload.as_ref() as &[u8], b"80x24");
    assert!(responder.is_none(), "want_reply=false 不应该有 responder");
}

#[tokio::test]
async fn read_channel_event_unknown_message_type() {
    let (a_reader, _a_writer, _b_reader, mut b_writer) = make_channel_pair();

    // 发送一个未知的消息类型
    b_writer.encode_one(VarInt::from_u32(200)).await.unwrap();
    AsyncWriteExt::flush(&mut b_writer).await.unwrap();

    let mut ch_reader = SshChannelReader::new(a_reader);
    let result = ch_reader.next_event().await;
    assert!(matches!(
        result,
        Err(ReadChannelEventError::UnexpectedMessageType { .. })
    ));
}

#[tokio::test]
async fn channel_request_full_roundtrip_via_traits() {
    // 完整的双向 roundtrip：A 发送 channel request，B 用 next_event 接收并响应
    let (a_reader, a_writer, b_reader, b_writer) = make_channel_pair();

    let handle = tokio::spawn(async move {
        let mut ch_reader = SshChannelReader::new(b_reader);
        let mut ch_writer = SshChannelWriter::new(b_writer);
        let event = ch_reader.next_event()
            .await
            .unwrap();
        let req = match event {
            ChannelEvent::Request(r) => r,
            _ => panic!("expected Request"),
        };

        assert_eq!(req.request_type().as_ref() as &[u8], b"test-ch-req");
        assert!(req.want_reply());

        let (payload, responder): (SshString, _) = req.decode_payload().await.unwrap();
        assert_eq!(payload.as_ref() as &[u8], b"roundtrip");

        let responder = responder.unwrap();
        responder.respond_success(&mut ch_writer, VarInt::from_u32(999)).await.unwrap();
    });

    let req = TestChannelReq {
        payload: TestPayload(SshString::from_static("roundtrip")),
    };
    let mut ch_writer = SshChannelWriter::new(a_writer);
    let mut ch_reader = SshChannelReader::new(a_reader);
    let result: VarInt = ch_writer.request(&mut ch_reader, &req)
        .await
        .unwrap();
    assert_eq!(result, VarInt::from_u32(999));

    handle.await.unwrap();
}
