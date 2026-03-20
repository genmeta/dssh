use std::os::fd::AsRawFd;

use genmeta_ssh::{ChannelEvent, SignalRequest, SshMessage, open_session_channel, run_session_request_loop};
use h3x::codec::EncodeExt;
use tokio::{
    io::{self, AsyncRead, AsyncWrite, AsyncWriteExt},
    sync::mpsc,
};

pub mod request;
pub mod pty;

use crate::session::pty::{PtyPair, allocate_pty, set_window_size};
use crate::session::request::{run_exec, run_shell};

pub async fn handle_session_channel<R, W>(
    _header: genmeta_ssh::ChannelHeader,
    reader: R,
    writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    let (event_rx, writer) = handle_server_session_channel(reader, writer).await?;
    session_request_loop(event_rx, writer).await
}

pub async fn handle_server_session_channel<R, W>(
    reader: R,
    writer: W,
) -> io::Result<(mpsc::Receiver<ChannelEvent>, W)>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    open_session_channel(reader, writer).await
}

pub async fn session_request_loop<W>(
    event_rx: mpsc::Receiver<ChannelEvent>,
    writer: W,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    struct ServerSessionState {
        pty_pair: Option<PtyPair>,
    }

    run_session_request_loop(
        event_rx,
        writer,
        ServerSessionState { pty_pair: None },
        |req, want_reply, writer, state| {
            Box::pin(async move {
                match allocate_pty(&req) {
                    Ok(pair) => {
                        state.pty_pair = Some(pair);
                        tracing::info!(term = %req.term_type);
                        if want_reply {
                            writer.encode_one(&SshMessage::ChannelSuccess).await?;
                            writer.flush().await?;
                        }
                        Ok(())
                    }
                    Err(error) => {
                        tracing::warn!("PTY allocation failed: {error}");
                        if want_reply {
                            writer.encode_one(&SshMessage::ChannelFailure).await?;
                            writer.flush().await?;
                        }
                        Ok(())
                    }
                }
            })
        },
        |req, state| {
            Box::pin(async move {
                if let Some(ref pair) = state.pty_pair
                    && let Err(error) = set_window_size(pair.master.as_raw_fd(), &req)
                {
                    tracing::warn!("window-change resize failed, keeping current size: {error}");
                }
                Ok(())
            })
        },
        |command, writer, event_rx, state| {
            Box::pin(async move {
                let shell = std::env::var_os("SHELL")
                    .unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"));
                run_exec(shell.as_os_str(), &command, writer, event_rx, state.pty_pair.take()).await
            })
        },
        |writer, event_rx, state| {
            Box::pin(async move {
                let shell = std::env::var_os("SHELL")
                    .unwrap_or_else(|| std::ffi::OsString::from("/bin/sh"));
                run_shell(shell.as_os_str(), writer, event_rx, state.pty_pair.take()).await
            })
        },
        |_signal: SignalRequest, _state| Box::pin(async move { Ok(()) }),
    )
    .await
}
