use std::{
    backtrace::Backtrace,
    error::Error,
    fmt::Debug,
    marker::PhantomData,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering::SeqCst},
    },
    task::{Context, Poll, ready},
};

use bytes::Bytes;
use dashmap::{DashMap, Entry};
use derive_more::{Deref, Display};
use futures::{Sink, SinkExt, Stream, StreamExt, channel::mpsc, stream::BoxStream};
use serde::{Deserialize, Serialize};
use snafu::{Report, ResultExt, Snafu, ensure};
use tokio::{io, sync::Notify, time};
use tokio_util::{
    codec,
    io::{CopyToBytes, SinkWriter, StreamReader},
    task::AbortOnDropHandle,
};
use tracing::Instrument;

use crate::{
    cbor_codec,
    messages::{Message, Request},
};

#[derive(Debug, Display, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Token(u64);

#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Client,
    Server,
}

impl Token {
    pub fn new(role: Role, seq: u64) -> Self {
        let mut token = seq << 1;
        match role {
            Role::Client => token |= 0b01,
            Role::Server => token |= 0b00,
        }
        Token(token)
    }

    pub fn seq(&self) -> u64 {
        self.0 >> 1
    }

    pub fn role(&self) -> Role {
        if self.0 & 0b01 == 0 {
            Role::Server
        } else {
            Role::Client
        }
    }

    pub fn into_inner(self) -> u64 {
        self.0
    }

    pub fn next(&self) -> Self {
        Token(self.0 + 2)
    }
}

pub struct Mux {
    token_gen: AtomicU64,
    channels: Arc<DashMap<Token, mpsc::Sender<io::Result<Bytes>>>>,
    message_sender: mpsc::Sender<Message>,
}

#[derive(Debug, Snafu)]
pub enum ChannelError {
    #[snafu(display("Peer has the same role with local when routing for {token}"))]
    SameRole { token: Token },
    #[snafu(display("Channel {token} already be opened"))]
    ChannelAlreadyOpen { token: Token },
    #[snafu(display("Channel {token} already be closed"))]
    ChannelClosed { token: Token },
    #[snafu(display("Failed to send request message for {token}"))]
    SendRequest { token: Token },
    #[snafu(display("Failed to send close message for {token}"))]
    SendClose { token: Token },
}

#[derive(Debug, Snafu)]
pub enum ReceiveError<Oe: snafu::Error + 'static> {
    #[snafu(display("Accept channel failed"))]
    AcceptChannel {
        source: ChannelError,
        backtrace: Backtrace,
    },
    #[snafu(display("Message stream closed"))]
    StreamClosed { source: Oe },
}

impl Mux {
    fn token(&self) -> Token {
        Token(self.token_gen.load(SeqCst))
    }

    fn next_token(&self) -> Token {
        let token = self.token_gen.fetch_add(2, SeqCst);
        Token(token)
    }

    async fn receive(
        self: &Arc<Self>,
        message: Message,
    ) -> Result<Option<NewChannel>, ChannelError> {
        tracing::trace!(target: "mux", ?message, "Received message");
        match message {
            Message::Request { token, request } => {
                ensure!(token.role() != self.token().role(), SameRoleSnafu { token });
                let (sender, recver) = mpsc::channel(8);
                let entry = self.channels.entry(token);
                if let Entry::Occupied(..) = &entry {
                    return ChannelAlreadyOpenSnafu { token }.fail();
                }
                entry.insert(sender);

                let recver = Recver {
                    token,
                    mux: self.clone(),
                    stream: recver,
                };
                let sender = Sender {
                    token,
                    mux: self.clone(),
                    sink: self.message_sender.clone(),
                };

                let channel = NewChannel {
                    token,
                    sender,
                    recver,
                    request,
                };
                Ok(Some(channel))
            }
            Message::Data { token, data } => {
                if data.is_empty() {
                    return Ok(None);
                }
                let channel = self.channels.entry(token);
                if let Entry::Occupied(mut channel) = channel
                    && channel.get_mut().send(Ok(data)).await.is_err()
                {
                    channel.remove();
                }
                Ok(None)
            }
            Message::Error { token, error } => {
                let channel = self.channels.entry(token);
                let item = Err(io::Error::other(error));
                // kept channel is successfully sent
                if let Entry::Occupied(mut channel) = channel
                    && let Err(error) = channel.get_mut().send(item).await
                {
                    tracing::debug!(target: "mux", ?token, "Failed to forward error message to channel: {}", Report::from_error(error));
                }
                Ok(None)
            }
            Message::Close { token } => {
                if let Some(mut channel) = self.channels.get(&token).map(|entry| entry.clone()) {
                    tracing::debug!(target: "mux", ?token, "Channel closed by peer");
                    if let Err(error) = channel.send(Ok(Bytes::new())).await {
                        tracing::debug!(target: "mux", ?token, "Failed to close channel: {}", Report::from_error(error));
                    }
                }
                Ok(None)
            }
            Message::Headrbeat {} => {
                tracing::debug!(target: "mux", "Received heartbeat");
                Ok(None)
            }
        }
    }

    pub async fn request(
        self: &Arc<Self>,
        request: Request,
    ) -> Result<(Token, Recver, Sender), ChannelError> {
        let token = self.next_token();
        let mut message_sender = self.message_sender.clone();
        let (sender, recver) = mpsc::channel(8);

        let entry = self.channels.entry(token);
        ensure!(
            matches!(entry, Entry::Vacant(..)),
            ChannelAlreadyOpenSnafu { token }
        );
        entry.insert(sender);

        let request = Message::Request { token, request };

        if message_sender.send(request).await.is_err() {
            // unknown reason
            return SendRequestSnafu { token }.fail();
        };

        let recver = Recver {
            token,
            mux: self.clone(),
            stream: recver,
        };
        let sender = Sender {
            token,
            mux: self.clone(),
            sink: message_sender,
        };
        Ok((token, recver, sender))
    }
}

impl Debug for Mux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mux")
            .field("token_gen", &self.token_gen)
            .field("channels", &self.channels)
            .field("message_sender", &"...")
            .finish()
    }
}

impl Drop for Mux {
    fn drop(&mut self) {
        self.channels.clear();
        self.message_sender.close_channel();
    }
}

#[derive(Debug, Deref)]
pub struct MuxContext {
    #[deref]
    inner: Arc<Mux>,
    task: AbortOnDropHandle<()>,
    shutdown: Arc<Notify>,
}

pub type Incomings<StE = io::Error> = mpsc::Receiver<Result<NewChannel, ReceiveError<StE>>>;
pub type IncomingStream<'s, StE = io::Error> = BoxStream<'s, Result<NewChannel, ReceiveError<StE>>>;

impl MuxContext {
    pub fn new<St, StE, Si>(role: Role, mut stream: St, mut sink: Si) -> (Self, Incomings<StE>)
    where
        St: Stream<Item = Result<Message, StE>> + Send + Unpin + 'static,
        StE: snafu::Error + Send,
        Si: Sink<Message, Error: Error> + Send + Unpin + 'static,
    {
        let (message_sender, mut pending_messages) = mpsc::channel::<Message>(8);
        let mut headrbeat_sender = message_sender.clone();
        let (mut incoming_forwarder, incomings) = mpsc::channel(8);
        let shutdown = Arc::new(Notify::new());
        let (shutdown_tx, shutdown_rx) = (shutdown.clone(), shutdown);

        let this = Arc::new(Mux {
            token_gen: AtomicU64::new(Token::new(role, 0).into_inner()),
            channels: Arc::new(DashMap::new()),
            message_sender,
        });

        let mux = this.clone();
        let task = async move {
            let recv_messages = async {
                while let Some(item) = stream.next().await {
                    let new_channel = match item {
                        Ok(item) => mux.receive(item).await.context(AcceptChannelSnafu),
                        Err(error) => Err(error).context(StreamClosedSnafu),
                    };

                    let is_err = new_channel.is_err();
                    if let Some(new_channel) = new_channel.transpose() {
                        _ = incoming_forwarder.send(new_channel).await;
                    }
                    if is_err {
                        break;
                    }
                }
                tracing::debug!(target: "mux", "Incoming stream closed");
            };
            let send_messages = async {
                while let Some(message) = pending_messages.next().await {
                    tracing::trace!(target: "mux", ?message, "Send message");
                    if let Err(error) = sink.send(message).await {
                        tracing::debug!(target: "mux", "Failed to send message: {}", Report::from_error(error));
                        return;
                    }
                }
            };
            let headrbeat = async move {
                let mut interval = time::interval(time::Duration::from_secs(5));
                loop {
                    interval.tick().await;
                    _ = headrbeat_sender.send(Message::Headrbeat {}).await
                }
            };
            tracing::debug!(target: "mux", "Mux receiving task started");
            tokio::select! {
                _ = recv_messages => {},
                _ = send_messages => {},
                _ = headrbeat => {},
                _ = shutdown_rx.notified() => {
                    tracing::debug!(target: "mux", "Mux shutdown notified");
                    while let Ok(pending_message) = pending_messages.try_recv() {
                        _ = sink.send(pending_message).await;
                    }
                }
            }
            _ = sink.close().await;
            tracing::debug!(target: "mux", "Sink closed");
        };

        let task = AbortOnDropHandle::new(tokio::spawn(task.in_current_span()));
        (
            MuxContext {
                inner: this,
                task,
                shutdown: shutdown_tx,
            },
            incomings,
        )
    }

    pub fn mux(&self) -> &Arc<Mux> {
        &self.inner
    }

    pub async fn shutdown(&mut self) {
        self.shutdown.notify_waiters();
        _ = (&mut self.task).await;
    }
}

#[derive(Debug)]
pub struct NewChannel {
    pub token: Token,
    pub request: Request,
    pub sender: Sender,
    pub recver: Recver,
}

impl NewChannel {
    pub async fn relay(mut self, slave: Arc<MuxContext>) -> io::Result<()> {
        let (slave_token, slave_recver, mut slave_sender) = slave
            .request(self.request)
            .await
            .map_err(io::Error::other)?;

        tracing::debug!(target: "mux", token=?self.token, ?slave_token, "Opened relay channel");

        tokio::try_join!(
            slave_recver.forward(&mut self.sender),
            slave_sender.send_all(&mut self.recver)
        )?;

        tracing::debug!(target: "mux", token=?self.token, ?slave_token, "End relay channel(no error)");

        Ok(())
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub struct Recver {
        token: Token,
        mux: Arc<Mux>,
        #[pin]
        stream: mpsc::Receiver<io::Result<Bytes>>,
    }

    impl PinnedDrop for Recver {
        fn drop(this: Pin<&mut Self>) {
            let project = this.project();
            project.mux.channels.remove(project.token);
        }
    }
}

pub type StreamingRecver = StreamReader<Recver, Bytes>;
pub type FramedRecver<T> = codec::FramedRead<StreamingRecver, cbor_codec::CborDecoder<'static, T>>;

impl Recver {
    pub fn streaming(self) -> StreamReader<Self, Bytes> {
        StreamReader::new(self)
    }

    pub fn framed<T: Deserialize<'static>>(self) -> FramedRecver<T> {
        codec::FramedRead::new(self.streaming(), cbor_codec::CborDecoder::default())
    }
}

impl Stream for Recver {
    type Item = io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().stream.poll_next(cx).map(|opt| match opt {
            Some(Ok(data)) if data.is_empty() => None,
            other => other,
        })
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug, Clone)]
    pub struct Sender {
        token: Token,
        mux: Arc<Mux>,
        #[pin]
        sink: mpsc::Sender<Message>,
    }
}

pub type StreamingSender = SinkWriter<CopyToBytes<Sender>>;
// pub type FramedSender<T> =

impl Sender {
    pub async fn cancel(&mut self, error: impl ToString) -> Result<(), ChannelError> {
        self.sink
            .send(Message::Error {
                token: self.token,
                error: error.to_string(),
            })
            .await
            .map_err(|_se| SendCloseSnafu { token: self.token }.build())
    }

    pub fn token(&self) -> Token {
        self.token
    }

    pub fn streaming(self) -> SinkWriter<CopyToBytes<Self>> {
        SinkWriter::new(CopyToBytes::new(self))
    }

    pub fn framed<T: Serialize>(self) -> FramedSender<T> {
        FramedSender {
            sender: self,
            _t: PhantomData,
        }
    }
}

impl Sink<Bytes> for Sender {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .sink
            .poll_ready(cx)
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let project = self.project();
        project
            .sink
            .start_send(Message::Data {
                token: *project.token,
                data: item,
            })
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let project = self.project();
        project
            .sink
            .poll_flush(cx)
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut project = self.project();
        ready!(
            (project.sink.as_mut().poll_ready(cx)).map_err(|se| io::Error::other(format!(
                "Mux sender failed to ready for Close: {se:?}"
            )))?
        );
        Poll::Ready(
            project
                .sink
                .start_send(Message::Close {
                    token: *project.token,
                })
                .map_err(|_se| io::ErrorKind::BrokenPipe.into()),
        )
    }
}

impl Sink<Message> for Sender {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.project()
            .sink
            .poll_ready(cx)
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        let project = self.project();
        project
            .sink
            .start_send(item)
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let project = self.project();
        project
            .sink
            .poll_flush(cx)
            .map_err(|_se| io::ErrorKind::BrokenPipe.into())
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut project = self.project();
        ready!(
            (project.sink.as_mut().poll_ready(cx)).map_err(|se| io::Error::other(format!(
                "Mux sender failed to ready for Close: {se:?}"
            )))?
        );
        Poll::Ready(
            project
                .sink
                .start_send(Message::Close {
                    token: *project.token,
                })
                .map_err(|_se| io::ErrorKind::BrokenPipe.into()),
        )
    }
}

pin_project_lite::pin_project! {
    #[derive(Debug)]
    pub struct FramedSender<T> {
        #[pin]
        sender: Sender,
        _t: PhantomData<T>
    }
}

impl<T> FramedSender<T> {
    pub async fn cancel(&mut self, error: impl ToString) -> Result<(), ChannelError> {
        self.sender.cancel(error).await
    }
}

impl<T> Clone for FramedSender<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            _t: PhantomData,
        }
    }
}

impl<T: Serialize> Sink<T> for FramedSender<T> {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Sender as Sink<Bytes>>::poll_ready(self.project().sender, cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        <Sender as Sink<Bytes>>::start_send(
            self.project().sender,
            serde_cbor::to_vec(&item)
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Failed to serialize: {e}"),
                    )
                })?
                .into(),
        )
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Sender as Sink<Bytes>>::poll_flush(self.project().sender, cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <Sender as Sink<Bytes>>::poll_close(self.project().sender, cx)
    }
}
