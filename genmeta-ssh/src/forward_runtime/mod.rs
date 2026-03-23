pub mod direct;
pub mod reverse;
pub mod socks5;

use snafu::Snafu;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum ForwardRuntimeError {
    #[snafu(display("forward runtime I/O failed"))]
    Io { source: std::io::Error },

    #[snafu(display("forward relay task failed"))]
    RelayTaskJoin { source: tokio::task::JoinError },
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
