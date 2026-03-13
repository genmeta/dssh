//! Adapters that bridge remoc byte channels to tokio's `AsyncRead`/`AsyncWrite` traits.
//!
//! [`ChannelReader`] wraps a `remoc::rch::mpsc::Receiver<Vec<u8>>` into `AsyncRead`.
//! [`ChannelWriter`] wraps a `remoc::rch::mpsc::Sender<Vec<u8>>` into `AsyncWrite`.
//!
//! These adapters let code that operates on generic `AsyncRead`/`AsyncWrite`
//! (e.g. session handling, forwarding) work transparently over remoc byte channels.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures::{Sink, Stream, sink, stream};
use h3x::codec::{SinkWriter as H3xSinkWriter, StreamReader as H3xStreamReader};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn broken_pipe_error<E>(error: E) -> io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}

type ChannelByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>;
type ChannelByteSink = Pin<Box<dyn Sink<Bytes, Error = io::Error> + Send>>;

/// Wraps a `remoc::rch::mpsc::Receiver<Vec<u8>>` to implement [`AsyncRead`].
pub struct ChannelReader(H3xStreamReader<ChannelByteStream>);

impl ChannelReader {
    pub fn new(rx: remoc::rch::mpsc::Receiver<Vec<u8>>) -> Self {
        let stream = stream::unfold(rx, |mut rx| async move {
            loop {
                match rx.recv().await {
                    Ok(Some(data)) if data.is_empty() => continue,
                    Ok(Some(data)) => return Some((Ok(Bytes::from(data)), rx)),
                    Ok(None) => return None,
                    Err(error) => return Some((Err(broken_pipe_error(error)), rx)),
                }
            }
        });
        Self(H3xStreamReader::new(Box::pin(stream)))
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

/// Wraps a `remoc::rch::mpsc::Sender<Vec<u8>>` to implement [`AsyncWrite`].
pub struct ChannelWriter(H3xSinkWriter<ChannelByteSink>);

impl ChannelWriter {
    pub fn new(tx: remoc::rch::mpsc::Sender<Vec<u8>>) -> Self {
        let sink = sink::unfold(tx, |tx, bytes: Bytes| async move {
            tx.send(bytes.to_vec()).await.map_err(broken_pipe_error)?;
            Ok::<_, io::Error>(tx)
        });
        Self(H3xSinkWriter::new(Box::pin(sink)))
    }
}

impl AsyncWrite for ChannelWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let writer = &mut self.get_mut().0;
        match AsyncWrite::poll_write(Pin::new(writer), cx, buf) {
            Poll::Ready(Ok(written)) => match AsyncWrite::poll_flush(Pin::new(writer), cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(written)),
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Pending => Poll::Pending,
            },
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().0), cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
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
