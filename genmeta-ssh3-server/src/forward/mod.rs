//! TCP and Unix domain socket forwarding channels.
//!
//! This module implements SSH3 forwarding channel types:
//! - `direct-tcpip` — client-initiated TCP port forwarding (RFC 4254 §7.2)
//! - `reverse-tcp` — server-side reverse TCP forwarding (`tcpip-forward`)
//! - `streamlocal` — Unix domain socket forwarding (`direct-streamlocal@openssh.com` / `forwarded-streamlocal@openssh.com`)

pub mod direct_tcp;
pub mod reverse_tcp;
pub mod streamlocal;
pub mod socks5;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

/// Copy all bytes from `reader` to `writer`, then shut down `writer`.
///
/// Shared relay helper used by both direct and reverse TCP forwarding.
pub(crate) async fn relay<R, W>(mut reader: R, mut writer: W) -> io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let n = tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    Ok(n)
}

/// Factory for opening server-initiated QUIC bidirectional streams.
/// Returns (reader, writer) halves for a new stream.
pub type StreamFactory = Arc<
    dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<(
        Box<dyn AsyncRead + Send + Unpin>,
        Box<dyn AsyncWrite + Send + Unpin>,
    )>> + Send>>
    + Send + Sync
>;
