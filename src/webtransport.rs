//! DSSH over WebTransport stream adaptation.
//!
//! A WebTransport session provides bidirectional streams. DSSH reserves the
//! first field on each WebTransport bidirectional stream for a DSSH stream kind:
//!
//! - [`DSSH_CONTROL_STREAM_KIND`] — the conversation control stream
//! - [`DSSH_CHANNEL_STREAM_KIND`] — SSH channel streams managed by
//!   [`ManageSessionStream`](crate::conversation::ManageSessionStream)
//!
//! The WebTransport CONNECT stream is not used as a DSSH control stream. The
//! control stream is an ordinary WebTransport bidirectional stream marked with
//! the control kind.

use h3x::{
    codec::{DecodeExt, EncodeExt, SinkWriter, StreamReader},
    quic,
    varint::VarInt,
};
use snafu::{ResultExt, Snafu};
use tokio::io::AsyncWriteExt;

use crate::conversation::ManageSessionStream;

/// DSSH-over-WebTransport stream kind for the conversation control stream.
pub const DSSH_CONTROL_STREAM_KIND: VarInt = VarInt::from_u32(0);

/// DSSH-over-WebTransport stream kind for SSH channel streams.
pub const DSSH_CHANNEL_STREAM_KIND: VarInt = VarInt::from_u32(1);

/// Stream manager backed by a WebTransport session.
///
/// `open_stream` / `accept_stream` implement SSH channel stream management.
/// The control stream is handled explicitly through [`Self::open_control`] and
/// [`Self::accept_control`].
#[derive(Debug)]
pub struct WebTransportStreamManager<S> {
    session: S,
}

impl<S> WebTransportStreamManager<S> {
    pub fn new(session: S) -> Self {
        Self { session }
    }

    pub fn into_inner(self) -> S {
        self.session
    }

    pub fn session(&self) -> &S {
        &self.session
    }
}

impl<S> WebTransportStreamManager<S>
where
    S: h3x::webtransport::Session,
    S::StreamReader: Unpin,
    S::StreamWriter: Unpin,
{
    /// Open the DSSH control stream on this WebTransport session.
    pub async fn open_control(
        &self,
    ) -> Result<(StreamReader<S::StreamReader>, SinkWriter<S::StreamWriter>), WebTransportStreamError>
    {
        let (reader, writer) = self
            .session
            .open_bi()
            .await
            .context(web_transport_stream_error::OpenBiSnafu)?;
        let writer = write_stream_kind(writer, DSSH_CONTROL_STREAM_KIND).await?;
        Ok((StreamReader::new(reader), SinkWriter::new(writer)))
    }

    /// Accept the DSSH control stream on this WebTransport session.
    pub async fn accept_control(
        &self,
    ) -> Result<(StreamReader<S::StreamReader>, SinkWriter<S::StreamWriter>), WebTransportStreamError>
    {
        self.accept_kind(DSSH_CONTROL_STREAM_KIND).await
    }

    async fn accept_kind(
        &self,
        expected: VarInt,
    ) -> Result<(StreamReader<S::StreamReader>, SinkWriter<S::StreamWriter>), WebTransportStreamError>
    {
        let (reader, writer) = self
            .session
            .accept_bi()
            .await
            .context(web_transport_stream_error::AcceptBiSnafu)?;
        let mut reader = StreamReader::new(reader);
        let actual = reader
            .decode_one::<VarInt>()
            .await
            .context(web_transport_stream_error::DecodeStreamKindSnafu)?;
        if actual != expected {
            return Err(WebTransportStreamError::UnexpectedStreamKind { kind: actual });
        }
        Ok((reader, SinkWriter::new(writer)))
    }
}

impl<S> ManageSessionStream for WebTransportStreamManager<S>
where
    S: h3x::webtransport::Session,
    S::StreamReader: Unpin,
    S::StreamWriter: Unpin,
{
    type StreamReader = StreamReader<S::StreamReader>;
    type StreamWriter = SinkWriter<S::StreamWriter>;
    type Error = WebTransportStreamError;

    async fn open_stream(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        let (reader, writer) = self
            .session
            .open_bi()
            .await
            .context(web_transport_stream_error::OpenBiSnafu)?;
        let writer = write_stream_kind(writer, DSSH_CHANNEL_STREAM_KIND).await?;
        Ok((StreamReader::new(reader), SinkWriter::new(writer)))
    }

    async fn accept_stream(&self) -> Result<(Self::StreamReader, Self::StreamWriter), Self::Error> {
        self.accept_kind(DSSH_CHANNEL_STREAM_KIND).await
    }
}

/// Error returned by [`WebTransportStreamManager`] operations.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WebTransportStreamError {
    #[snafu(display("failed to open webtransport bidirectional stream"))]
    OpenBi {
        source: h3x::webtransport::OpenStreamError,
    },

    #[snafu(display("failed to accept webtransport bidirectional stream"))]
    AcceptBi { source: h3x::webtransport::Closed },

    #[snafu(display("failed to encode dssh webtransport stream kind"))]
    EncodeStreamKind { source: std::io::Error },

    #[snafu(display("failed to flush dssh webtransport stream kind"))]
    FlushStreamKind { source: std::io::Error },

    #[snafu(display("failed to decode dssh webtransport stream kind"))]
    DecodeStreamKind { source: std::io::Error },

    #[snafu(display("unexpected dssh webtransport stream kind {kind}"))]
    UnexpectedStreamKind { kind: VarInt },
}

async fn write_stream_kind<W>(writer: W, kind: VarInt) -> Result<W, WebTransportStreamError>
where
    W: quic::WriteStream + Unpin,
{
    let mut writer = SinkWriter::new(writer);
    writer
        .encode_one(kind)
        .await
        .context(web_transport_stream_error::EncodeStreamKindSnafu)?;
    AsyncWriteExt::flush(&mut writer)
        .await
        .context(web_transport_stream_error::FlushStreamKindSnafu)?;
    Ok(writer.into_inner())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        pin::Pin,
        sync::{Arc, Mutex},
        task::{Context, Poll},
    };

    use bytes::Bytes;
    use futures::{Sink, SinkExt, Stream};
    use h3x::quic::{CancelStream, GetStreamId, StopStream};
    use tokio::io::AsyncReadExt;

    use super::*;

    #[derive(Debug, Default)]
    struct StreamState {
        written: Mutex<Vec<u8>>,
    }

    impl StreamState {
        fn written(&self) -> Vec<u8> {
            self.written.lock().expect("written lock poisoned").clone()
        }
    }

    #[derive(Debug)]
    struct TestReadStream {
        chunks: VecDeque<Bytes>,
        stream_id: VarInt,
    }

    impl Stream for TestReadStream {
        type Item = Result<Bytes, quic::StreamError>;

        fn poll_next(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Ready(self.chunks.pop_front().map(Ok))
        }
    }

    impl GetStreamId for TestReadStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl StopStream for TestReadStream {
        fn poll_stop(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug)]
    struct TestWriteStream {
        state: Arc<StreamState>,
        stream_id: VarInt,
    }

    impl Sink<Bytes> for TestWriteStream {
        type Error = quic::StreamError;

        fn poll_ready(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
            self.state
                .written
                .lock()
                .expect("written lock poisoned")
                .extend_from_slice(&item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl GetStreamId for TestWriteStream {
        fn poll_stream_id(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<VarInt, quic::StreamError>> {
            Poll::Ready(Ok(self.stream_id))
        }
    }

    impl CancelStream for TestWriteStream {
        fn poll_cancel(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _code: VarInt,
        ) -> Poll<Result<(), quic::StreamError>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Debug, Default)]
    struct TestSession {
        open_state: Arc<StreamState>,
        accept_streams: Mutex<VecDeque<(TestReadStream, TestWriteStream)>>,
    }

    impl TestSession {
        fn with_accept_bytes(bytes: &'static [u8]) -> Self {
            let session = Self::default();
            session
                .accept_streams
                .lock()
                .expect("accept lock poisoned")
                .push_back(stream_pair_with_read(bytes, VarInt::from_u32(7)));
            session
        }
    }

    impl h3x::webtransport::Session for TestSession {
        type StreamReader = TestReadStream;
        type StreamWriter = TestWriteStream;

        fn session_id(&self) -> VarInt {
            VarInt::from_u32(4)
        }

        async fn open_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), h3x::webtransport::OpenStreamError>
        {
            Ok((
                TestReadStream {
                    chunks: VecDeque::new(),
                    stream_id: VarInt::from_u32(5),
                },
                TestWriteStream {
                    state: self.open_state.clone(),
                    stream_id: VarInt::from_u32(5),
                },
            ))
        }

        async fn open_uni(&self) -> Result<Self::StreamWriter, h3x::webtransport::OpenStreamError> {
            unreachable!("dssh webtransport manager uses only bidirectional streams")
        }

        async fn accept_bi(
            &self,
        ) -> Result<(Self::StreamReader, Self::StreamWriter), h3x::webtransport::Closed> {
            self.accept_streams
                .lock()
                .expect("accept lock poisoned")
                .pop_front()
                .ok_or(h3x::webtransport::Closed)
        }

        async fn accept_uni(&self) -> Result<Self::StreamReader, h3x::webtransport::Closed> {
            unreachable!("dssh webtransport manager uses only bidirectional streams")
        }
    }

    fn stream_pair_with_read(
        bytes: &'static [u8],
        stream_id: VarInt,
    ) -> (TestReadStream, TestWriteStream) {
        let state = Arc::new(StreamState::default());
        (
            TestReadStream {
                chunks: VecDeque::from([Bytes::from_static(bytes)]),
                stream_id,
            },
            TestWriteStream { state, stream_id },
        )
    }

    #[tokio::test]
    async fn open_control_and_channel_prefix_stream_kind() {
        let session = TestSession::default();
        let manager = WebTransportStreamManager::new(session);

        manager.open_control().await.expect("open control");
        assert_eq!(manager.session().open_state.written(), vec![0]);

        manager.open_stream().await.expect("open channel");
        assert_eq!(manager.session().open_state.written(), vec![0, 1]);
    }

    #[tokio::test]
    async fn accept_control_consumes_control_kind_and_leaves_payload() {
        let session = TestSession::with_accept_bytes(b"\x00hello");
        let manager = WebTransportStreamManager::new(session);

        let (mut reader, _writer) = manager.accept_control().await.expect("accept control");
        let mut payload = Vec::new();
        reader
            .read_to_end(&mut payload)
            .await
            .expect("read payload");

        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn accept_stream_consumes_channel_kind_and_leaves_payload() {
        let session = TestSession::with_accept_bytes(b"\x01payload");
        let manager = WebTransportStreamManager::new(session);

        let (mut reader, _writer) = manager.accept_stream().await.expect("accept channel");
        let mut payload = Vec::new();
        reader
            .read_to_end(&mut payload)
            .await
            .expect("read payload");

        assert_eq!(payload, b"payload");
    }

    #[tokio::test]
    async fn accept_stream_rejects_unexpected_kind() {
        let session = TestSession::with_accept_bytes(b"\x00control");
        let manager = WebTransportStreamManager::new(session);

        let error = match manager.accept_stream().await {
            Ok(_) => panic!("control stream is not a channel stream"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            WebTransportStreamError::UnexpectedStreamKind { kind }
                if kind == DSSH_CONTROL_STREAM_KIND
        ));
    }

    #[tokio::test]
    async fn accepted_writer_remains_usable_after_kind_decode() {
        let session = TestSession::with_accept_bytes(b"\x01");
        let manager = WebTransportStreamManager::new(session);

        let (_reader, mut writer) = manager.accept_stream().await.expect("accept channel");
        writer
            .send(Bytes::from_static(b"reply"))
            .await
            .expect("write reply");
        SinkExt::flush(&mut writer).await.expect("flush reply");
    }

    #[tokio::test]
    async fn decode_kind_error_is_structured() {
        let session = TestSession::with_accept_bytes(b"");
        let manager = WebTransportStreamManager::new(session);

        let error = match manager.accept_control().await {
            Ok(_) => panic!("empty stream cannot carry kind"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            WebTransportStreamError::DecodeStreamKind { .. }
        ));
    }
}
