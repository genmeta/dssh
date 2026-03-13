//! Adapters that bridge remoc byte channels to tokio's `AsyncRead`/`AsyncWrite` traits.
//!
//! [`ChannelReader`] wraps a `remoc::rch::mpsc::Receiver<Vec<u8>>` into `AsyncRead`.
//! [`ChannelWriter`] wraps a `remoc::rch::mpsc::Sender<Vec<u8>>` into `AsyncWrite`.
//!
//! These adapters let code that operates on generic `AsyncRead`/`AsyncWrite`
//! (e.g. session handling, forwarding) work transparently over remoc byte channels.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn missing_receiver_error() -> io::Error {
    io::Error::other("ChannelReader missing receiver without active recv future")
}

fn broken_pipe_error<E>(error: E) -> io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}

// ---------------------------------------------------------------------------
// ChannelReader
// ---------------------------------------------------------------------------

/// Result returned from the in-flight recv future: the receiver is returned
/// alongside the result so we can re-use it for subsequent polls.
type RecvResult = (
    remoc::rch::mpsc::Receiver<Vec<u8>>,
    Result<Option<Vec<u8>>, remoc::rch::mpsc::RecvError>,
);

type RecvFuture = Pin<Box<dyn Future<Output = RecvResult> + Send>>;

/// Wraps a `remoc::rch::mpsc::Receiver<Vec<u8>>` to implement [`AsyncRead`].
///
/// When the sender side is dropped (channel closed), reads return EOF (0 bytes).
pub struct ChannelReader {
    /// The receiver — `None` while a recv future is in flight.
    rx: Option<remoc::rch::mpsc::Receiver<Vec<u8>>>,
    /// Buffered data from the last received chunk.
    buf: Vec<u8>,
    /// Current read position within `buf`.
    pos: usize,
    /// In-flight `recv()` future, created when buffer is exhausted.
    recv_fut: Option<RecvFuture>,
    /// Set to true when the channel has closed (EOF).
    eof: bool,
}

impl ChannelReader {
    /// Create a new `ChannelReader` wrapping the given receiver.
    pub fn new(rx: remoc::rch::mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx: Some(rx),
            buf: Vec::new(),
            pos: 0,
            recv_fut: None,
            eof: false,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If there is buffered data, copy it out first.
        if this.pos < this.buf.len() {
            let remaining = &this.buf[this.pos..];
            let to_copy = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..to_copy]);
            this.pos += to_copy;

            // If we consumed the entire buffer, free it.
            if this.pos >= this.buf.len() {
                this.buf.clear();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Already at EOF — return immediately with 0 bytes.
        if this.eof {
            return Poll::Ready(Ok(()));
        }

        // Buffer exhausted — poll for the next chunk.
        // Create the recv future if we don't have one yet.
        if this.recv_fut.is_none() {
            let Some(mut rx) = this.rx.take() else {
                return Poll::Ready(Err(missing_receiver_error()));
            };
            this.recv_fut = Some(Box::pin(async move {
                let result = rx.recv().await;
                (rx, result)
            }));
        }

        // Poll the in-flight recv future.
        let Some(fut) = this.recv_fut.as_mut() else {
            return Poll::Ready(Err(missing_receiver_error()));
        };
        match fut.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready((rx, result)) => {
                // Future completed — take back the receiver and clear the future.
                this.rx = Some(rx);
                this.recv_fut = None;

                match result {
                    Ok(Some(data)) if data.is_empty() => {
                        // Empty chunk — treat as no-op, re-poll (tail-recurse).
                        Pin::new(this).poll_read(cx, buf)
                    }
                    Ok(Some(data)) => {
                        // Got data — buffer it and copy what we can.
                        let to_copy = data.len().min(buf.remaining());
                        buf.put_slice(&data[..to_copy]);
                        if to_copy < data.len() {
                            // Store the remainder for next read.
                            this.buf = data;
                            this.pos = to_copy;
                        }
                        Poll::Ready(Ok(()))
                    }
                    Ok(None) => {
                        // Channel closed — EOF.
                        this.eof = true;
                        Poll::Ready(Ok(()))
                    }
                    Err(e) => Poll::Ready(Err(broken_pipe_error(e))),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ChannelWriter
// ---------------------------------------------------------------------------

/// Result from the in-flight send future.
type SendFuture = Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>>;

/// Wraps a `remoc::rch::mpsc::Sender<Vec<u8>>` to implement [`AsyncWrite`].
///
/// Dropping the writer drops the underlying sender, which closes the channel.
pub struct ChannelWriter {
    /// The sender — cloned for each send operation (`remoc::rch::mpsc::Sender`
    /// implements `Clone` and `send` takes `&self`).
    tx: remoc::rch::mpsc::Sender<Vec<u8>>,
    /// In-flight send future.
    send_fut: Option<SendFuture>,
}

impl ChannelWriter {
    /// Create a new `ChannelWriter` wrapping the given sender.
    pub fn new(tx: remoc::rch::mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            tx,
            send_fut: None,
        }
    }
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // If there is an in-flight send, poll it to completion first.
        if let Some(fut) = this.send_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    this.send_fut = None;
                    result?;
                }
            }
        }

        // Start a new send.
        let data = buf.to_vec();
        let len = data.len();
        let tx = this.tx.clone();
        this.send_fut = Some(Box::pin(async move {
            tx.send(data).await.map_err(|e| {
                io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    format!("remoc send error: {e}"),
                )
            })?;
            Ok(())
        }));

        // Poll the future we just created — it might complete immediately.
        let Some(fut) = this.send_fut.as_mut() else {
            return Poll::Ready(Err(io::Error::other(
                "ChannelWriter missing send future after initialization",
            )));
        };
        match fut.as_mut().poll(cx) {
            Poll::Pending => {
                // The send is in flight. We report the bytes as written because
                // they have been buffered into the future.
                Poll::Ready(Ok(len))
            }
            Poll::Ready(result) => {
                this.send_fut = None;
                Poll::Ready(result.map(|()| len))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If there is an in-flight send, wait for it.
        if let Some(fut) = this.send_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    this.send_fut = None;
                    return Poll::Ready(result);
                }
            }
        }

        // No buffered data — remoc channels don't buffer.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Flush any pending send first.
        let result = self.poll_flush(cx);
        if result.is_pending() {
            return Poll::Pending;
        }
        // Dropping the sender will close the channel. We don't actually drop here
        // because `poll_shutdown` only signals intent; the Drop impl handles cleanup.
        result
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Create a local in-process remoc mpsc channel pair and wrap in adapters.
    fn channel_pair(buffer: usize) -> (ChannelWriter, ChannelReader) {
        let (tx, rx) = remoc::rch::mpsc::channel(buffer);
        (ChannelWriter::new(tx), ChannelReader::new(rx))
    }

    #[tokio::test]
    async fn roundtrip() {
        let (mut writer, mut reader) = channel_pair(16);

        let data = b"hello, byte channel!";
        writer.write_all(data).await.unwrap();
        // Drop the writer to signal EOF so the reader can finish.
        drop(writer);

        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();
        assert_eq!(output, data);
    }

    #[tokio::test]
    async fn eof_on_sender_drop() {
        let (writer, mut reader) = channel_pair(16);

        // Drop sender immediately.
        drop(writer);

        let mut buf = [0u8; 64];
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "expected EOF (0 bytes)");
    }

    #[tokio::test]
    async fn partial_reads() {
        let (tx, rx) = remoc::rch::mpsc::channel(16);
        let mut reader = ChannelReader::new(rx);

        // Send a large chunk via the raw sender.
        let big_data: Vec<u8> = (0..=255).cycle().take(1024).collect();
        tx.send(big_data.clone()).await.unwrap();
        drop(tx); // Close after sending.

        // Read with a small buffer (64 bytes at a time).
        let mut output = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            output.extend_from_slice(&buf[..n]);
        }
        assert_eq!(output, big_data);
    }

    #[tokio::test]
    async fn multiple_chunks() {
        let (tx, rx) = remoc::rch::mpsc::channel(16);
        let mut reader = ChannelReader::new(rx);

        let chunks: Vec<Vec<u8>> = vec![
            b"chunk1".to_vec(),
            b"chunk2".to_vec(),
            b"chunk3".to_vec(),
        ];

        // Send multiple chunks.
        for chunk in &chunks {
            tx.send(chunk.clone()).await.unwrap();
        }
        drop(tx);

        let mut output = Vec::new();
        reader.read_to_end(&mut output).await.unwrap();

        let expected: Vec<u8> = chunks.into_iter().flatten().collect();
        assert_eq!(output, expected);
    }
}
