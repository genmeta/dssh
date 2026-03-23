pub mod direct;
pub mod reverse;
pub mod socks5;

use crate::conversation::{
    read_channel_open_response, ChannelOpenResponse, ReadChannelOpenResponseError,
};
use snafu::{ResultExt, Snafu};
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum ForwardRuntimeError {
    #[snafu(display("forward runtime I/O failed"))]
    Io { source: std::io::Error },

    #[snafu(display("forward relay task failed"))]
    RelayTaskJoin { source: tokio::task::JoinError },

    #[snafu(display("failed to read channel open response"))]
    ReadResponse { source: ReadChannelOpenResponseError },
}

pub async fn relay<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let n = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(n)
}

/// Wait for channel open confirmation, then relay bytes bidirectionally
/// between the channel stream and the provided I/O stream.
///
/// Works for any forwarded channel type (TCP, streamlocal, etc.).
pub async fn finish_forwarded_channel<R, W, S>(
    mut reader: R,
    writer: W,
    stream: S,
) -> Result<(), ForwardRuntimeError>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let response = read_channel_open_response(&mut reader)
        .await
        .context(forward_runtime_error::ReadResponseSnafu)?;

    match response {
        ChannelOpenResponse::Confirmation { .. } => {}
        ChannelOpenResponse::Failure(_) => return Ok(()),
    }

    let (stream_reader, stream_writer) = tokio::io::split(stream);
    let ch2s = tokio::spawn(relay(reader, stream_writer));
    let s2ch = tokio::spawn(relay(stream_reader, writer));
    let (r1, r2) = tokio::join!(ch2s, s2ch);
    r1.context(forward_runtime_error::RelayTaskJoinSnafu)?
        .context(forward_runtime_error::IoSnafu)?;
    r2.context(forward_runtime_error::RelayTaskJoinSnafu)?
        .context(forward_runtime_error::IoSnafu)?;
    Ok(())
}
