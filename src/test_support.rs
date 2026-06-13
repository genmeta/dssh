use std::{
    collections::VecDeque,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use bytes::Bytes;
use futures::{Sink, Stream, channel::mpsc};
use h3x::{
    codec::{SinkWriter, StreamReader as H3xStreamReader},
    quic::{GetStreamId, ResetStream, StopStream, StreamError},
    stream_id::StreamId,
    varint::VarInt,
};

pub(crate) struct MockQuicReader {
    stream_id: VarInt,
    inner: mpsc::Receiver<Bytes>,
}

impl Unpin for MockQuicReader {}

impl Stream for MockQuicReader {
    type Item = Result<Bytes, StreamError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner)
            .poll_next(cx)
            .map(|opt| opt.map(Ok))
    }
}

impl GetStreamId for MockQuicReader {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl StopStream for MockQuicReader {
    fn poll_stop(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) struct MockQuicWriter {
    stream_id: VarInt,
    inner: mpsc::Sender<Bytes>,
}

impl Unpin for MockQuicWriter {}

impl Sink<Bytes> for MockQuicWriter {
    type Error = StreamError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
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

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_flush(cx)
            .map_err(|_| StreamError::Reset {
                code: VarInt::from_u32(0),
            })
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.inner)
            .poll_close(cx)
            .map_err(|_| StreamError::Reset {
                code: VarInt::from_u32(0),
            })
    }
}

impl GetStreamId for MockQuicWriter {
    fn poll_stream_id(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Result<VarInt, StreamError>> {
        Poll::Ready(Ok(self.stream_id))
    }
}

impl ResetStream for MockQuicWriter {
    fn poll_reset(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _code: VarInt,
    ) -> Poll<Result<(), StreamError>> {
        Poll::Ready(Ok(()))
    }
}

pub(crate) type MockReader = H3xStreamReader<MockQuicReader>;
pub(crate) type MockWriter = SinkWriter<MockQuicWriter>;

pub(crate) fn stream_pair(stream_id: VarInt) -> (MockReader, MockWriter) {
    let (tx, rx) = mpsc::channel(64);
    let reader = H3xStreamReader::new(MockQuicReader {
        stream_id,
        inner: rx,
    });
    let writer = SinkWriter::new(MockQuicWriter {
        stream_id,
        inner: tx,
    });
    (reader, writer)
}

pub(crate) fn stream_with_read_bytes(stream_id: VarInt, bytes: Bytes) -> (MockReader, MockWriter) {
    let (mut read_tx, read_rx) = mpsc::channel(64);
    read_tx
        .try_send(bytes)
        .expect("preloaded test stream should have capacity");
    drop(read_tx);

    let (write_tx, _write_rx) = mpsc::channel(64);
    let reader = H3xStreamReader::new(MockQuicReader {
        stream_id,
        inner: read_rx,
    });
    let writer = SinkWriter::new(MockQuicWriter {
        stream_id,
        inner: write_tx,
    });
    (reader, writer)
}

#[derive(Clone)]
pub(crate) struct MockWebTransportSession {
    state: Arc<MockWebTransportSessionState>,
}

struct MockWebTransportSessionState {
    id: StreamId,
    open_streams: Mutex<VecDeque<(MockReader, MockWriter)>>,
    accept_streams: Mutex<VecDeque<(MockReader, MockWriter)>>,
    open_count: AtomicUsize,
    drained: AtomicBool,
    close: Mutex<Option<h3x::webtransport::CloseSession>>,
}

impl MockWebTransportSession {
    pub(crate) fn new(id: StreamId) -> Self {
        Self {
            state: Arc::new(MockWebTransportSessionState {
                id,
                open_streams: Mutex::new(VecDeque::new()),
                accept_streams: Mutex::new(VecDeque::new()),
                open_count: AtomicUsize::new(0),
                drained: AtomicBool::new(false),
                close: Mutex::new(None),
            }),
        }
    }

    pub(crate) fn provide_open_stream(&self, reader: MockReader, writer: MockWriter) {
        self.state
            .open_streams
            .lock()
            .expect("open stream queue lock poisoned")
            .push_back((reader, writer));
    }

    pub(crate) fn provide_accept_stream(&self, reader: MockReader, writer: MockWriter) {
        self.state
            .accept_streams
            .lock()
            .expect("accept stream queue lock poisoned")
            .push_back((reader, writer));
    }

    pub(crate) fn provide_accept_bytes(&self, stream_id: VarInt, bytes: Bytes) {
        let (reader, writer) = stream_with_read_bytes(stream_id, bytes);
        self.provide_accept_stream(reader, writer);
    }

    pub(crate) fn open_called(&self) -> bool {
        self.state.open_count.load(Ordering::SeqCst) > 0
    }
}

impl h3x::webtransport::Session for MockWebTransportSession {
    type StreamReader = MockQuicReader;
    type StreamWriter = MockQuicWriter;

    fn id(&self) -> h3x::webtransport::WebTransportSessionId {
        h3x::webtransport::WebTransportSessionId::try_from(self.state.id)
            .expect("test session id must be client-initiated bidirectional")
    }

    async fn drain(&self) -> Result<(), h3x::webtransport::DrainSessionError> {
        self.state.drained.store(true, Ordering::SeqCst);
        Ok(())
    }

    async fn close(
        &self,
        close: h3x::webtransport::CloseSession,
    ) -> Result<(), h3x::webtransport::CloseSessionError> {
        *self.state.close.lock().expect("close lock poisoned") = Some(close);
        Ok(())
    }

    async fn drained(&self) -> h3x::webtransport::SessionDrain {
        if self.state.drained.load(Ordering::SeqCst) {
            h3x::webtransport::SessionDrain::Requested(h3x::webtransport::DrainReason::Session(
                h3x::webtransport::SessionDrainReason::Local,
            ))
        } else {
            h3x::webtransport::SessionDrain::Closed(self.closed().await)
        }
    }

    async fn closed(&self) -> h3x::webtransport::CloseReason {
        match self
            .state
            .close
            .lock()
            .expect("close lock poisoned")
            .clone()
        {
            Some(close) => h3x::webtransport::CloseReason::Session(
                h3x::webtransport::SessionCloseReason::Local(close),
            ),
            None => h3x::webtransport::CloseReason::Session(
                h3x::webtransport::SessionCloseReason::ControlStreamError,
            ),
        }
    }

    async fn open_bi(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), h3x::webtransport::OpenStreamError> {
        self.state.open_count.fetch_add(1, Ordering::SeqCst);
        let (reader, writer) = self
            .state
            .open_streams
            .lock()
            .expect("open stream queue lock poisoned")
            .pop_front()
            .expect("no open_bi pair provided");
        Ok((reader.into_inner(), writer.into_inner()))
    }

    async fn open_uni(&self) -> Result<Self::StreamWriter, h3x::webtransport::OpenStreamError> {
        unreachable!("dssh tests use only bidirectional streams")
    }

    async fn accept_bi(
        &self,
    ) -> Result<(Self::StreamReader, Self::StreamWriter), h3x::webtransport::AcceptStreamError>
    {
        let (reader, writer) = self
            .state
            .accept_streams
            .lock()
            .expect("accept stream queue lock poisoned")
            .pop_front()
            .expect("no accept_bi pair provided");
        Ok((reader.into_inner(), writer.into_inner()))
    }

    async fn accept_uni(&self) -> Result<Self::StreamReader, h3x::webtransport::AcceptStreamError> {
        unreachable!("dssh tests use only bidirectional streams")
    }
}
