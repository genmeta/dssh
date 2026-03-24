//! Server-side session dispatcher.
//!
//! Drives an SSH3 session by concurrently accepting channels and global
//! requests from a [`Conversation`], dispatching each to the appropriate
//! handler.
//!
//! # Channel dispatch
//!
//! | Channel type | Handler |
//! |---|---|
//! | `"session"` | [`run_piped`](super::process::run_piped) / [`run_pty`](super::process::run_pty) |
//! | `"direct-tcpip"` | [`handle_direct_tcpip`](crate::forward::direct::handle_direct_tcpip) |
//! | `"direct-streamlocal@openssh.com"` | [`handle_direct_streamlocal`](crate::forward::direct::handle_direct_streamlocal) |
//! | `"socks5"` | [`handle_socks5`](crate::forward::socks5::handle_socks5) |
//! | unknown | reject with `UNKNOWN_CHANNEL_TYPE` |
//!
//! # Global request dispatch
//!
//! | Request type | Action |
//! |---|---|
//! | `"tcpip-forward"` | Start TCP listener via [`DecodedGlobalRequest::accept_tcp_forward`] |
//! | `"cancel-tcpip-forward"` | Stop TCP listener |
//! | `"streamlocal-forward@openssh.com"` | Start Unix socket listener |
//! | `"cancel-streamlocal-forward@openssh.com"` | Stop Unix socket listener |
//! | unknown | respond failure |

use std::sync::Arc;

use std::collections::HashMap;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::{AbortHandle, JoinSet};

use crate::channel::reason_code;
use crate::conversation::{Conversation, IncomingGlobal, ManageSessionStream};
use crate::forward::{
    CancelStreamlocalForwardRequest, CancelTcpipForwardRequest, ForwardError,
    StreamlocalForwardRequest, TcpipForwardRequest,
};
use crate::session::process::CommandMode;
use h3x::varint::VarInt;
use tracing::Instrument;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the session dispatcher.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Path to the user's login shell (e.g. `/bin/bash`).
    pub shell: std::path::PathBuf,
    /// Maximum SSH message size for session channels.
    pub max_message_size: VarInt,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            shell: std::path::PathBuf::from("/bin/sh"),
            max_message_size: crate::constants::DEFAULT_MAX_MESSAGE_SIZE,
        }
    }
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Run the server-side session loop.
///
/// Concurrently accepts channels and global requests from the conversation,
/// dispatching each to the appropriate handler. Returns when the conversation
/// is closed (both accept methods return errors indicating shutdown).
pub async fn run_session<M, R, W>(conversation: Arc<Conversation<M, R, W>>, config: SessionConfig)
where
    M: ManageSessionStream + 'static,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
    M::Error: Send + Sync + 'static,
{
    let mut tcp_forwards: HashMap<(String, u16), AbortHandle> = HashMap::new();
    let mut unix_forwards: HashMap<String, AbortHandle> = HashMap::new();
    let mut channel_tasks: JoinSet<()> = JoinSet::new();
    let mut forward_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            channel_result = conversation.accept_channel() => {
                let incoming = match channel_result {
                    Ok(ch) => ch,
                    Err(e) => {
                        tracing::debug!(error = %snafu::Report::from_error(&e), "accept_channel ended");
                        break;
                    }
                };

                let channel_type = incoming.channel_type().clone();
                let config = config.clone();
                let max_msg = config.max_message_size;

                match &*channel_type {
                    "session" => {
                        let pending = incoming.skip_payload();
                        channel_tasks.spawn(async move {
                            let channel = match pending.accept(max_msg).await {
                                Ok(ch) => ch,
                                Err(e) => {
                                    tracing::warn!(error = %snafu::Report::from_error(&e), "failed to accept session channel");
                                    return;
                                }
                            };
                            let mode = CommandMode::Shell { shell: config.shell.as_os_str() };
                            if let Err(e) = super::process::run_piped(channel, mode).await {
                                tracing::warn!(error = %snafu::Report::from_error(&e), "session channel error");
                            }
                        }.instrument(tracing::info_span!("session")));
                    }
                    "direct-tcpip" => {
                        let (reader, writer) = incoming.into_raw_parts();
                        channel_tasks.spawn(async move {
                            if let Err(e) = crate::forward::direct::handle_direct_tcpip(reader, writer).await {
                                tracing::warn!(error = %snafu::Report::from_error(&e), "direct-tcpip error");
                            }
                        }.instrument(tracing::info_span!("direct-tcpip")));
                    }
                    "direct-streamlocal@openssh.com" => {
                        let (reader, writer) = incoming.into_raw_parts();
                        channel_tasks.spawn(async move {
                            if let Err(e) = crate::forward::direct::handle_direct_streamlocal(reader, writer).await {
                                tracing::warn!(error = %snafu::Report::from_error(&e), "direct-streamlocal error");
                            }
                        }.instrument(tracing::info_span!("direct-streamlocal")));
                    }
                    "socks5" => {
                        let (reader, writer) = incoming.into_raw_parts();
                        channel_tasks.spawn(async move {
                            if let Err(e) = crate::forward::socks5::handle_socks5(reader, writer).await {
                                tracing::warn!(error = %snafu::Report::from_error(&e), "socks5 error");
                            }
                        }.instrument(tracing::info_span!("socks5")));
                    }
                    _ => {
                        tracing::warn!(channel_type = %&*channel_type, "rejecting unknown channel type");
                        let pending = incoming.skip_payload();
                        if let Err(e) = pending.reject(
                            reason_code::UNKNOWN_CHANNEL_TYPE,
                            "unsupported channel type".to_owned().into(),
                        ).await {
                            tracing::warn!(error = %snafu::Report::from_error(&e), "failed to reject channel");
                        }
                    }
                }
            }

            global_result = conversation.accept() => {
                match global_result {
                    Ok(incoming) => {
                        dispatch_global(incoming, &conversation, &mut tcp_forwards, &mut unix_forwards, &mut forward_tasks).await;
                    }
                    Err(e) => {
                        tracing::debug!(error = %snafu::Report::from_error(&e), "accept global ended");
                        break;
                    }
                }
            }

            // Reap completed channel tasks (prevents unbounded growth).
            Some(result) = channel_tasks.join_next() => {
                if let Err(e) = result {
                    tracing::warn!(error = %e, "channel task panicked");
                }
            }

            // Reap completed forward listener tasks.
            Some(result) = forward_tasks.join_next() => {
                if let Err(e) = result && !e.is_cancelled() {
                    tracing::warn!(error = %e, "forward task panicked");
                }
            }
        }
    }

    // Wait for all remaining channel tasks.
    while let Some(result) = channel_tasks.join_next().await {
        if let Err(e) = result {
            tracing::warn!(error = %e, "channel task panicked during shutdown");
        }
    }
}

// ---------------------------------------------------------------------------
// Global request dispatch
// ---------------------------------------------------------------------------

async fn dispatch_global<M, R, W>(
    incoming: IncomingGlobal<R, W>,
    conversation: &Arc<Conversation<M, R, W>>,
    tcp_forwards: &mut HashMap<(String, u16), AbortHandle>,
    unix_forwards: &mut HashMap<String, AbortHandle>,
    forward_tasks: &mut JoinSet<()>,
)
where
    M: ManageSessionStream + 'static,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
{
    match incoming {
        IncomingGlobal::Request(req) => {
            let request_type = req.request_type().clone();
            match &*request_type {
                "tcpip-forward" => {
                    match req
                        .decode_payload::<TcpipForwardRequest, ForwardError>()
                        .await
                    {
                        Ok(decoded) => {
                            let bind_addr = decoded.payload().bind_address.to_string();
                            match decoded.accept_tcp_forward().await {
                                Ok(listener) => {
                                    let port = listener.bound_addr().port();
                                    let abort = forward_tasks.spawn(
                                        listener.run(conversation.clone()).instrument(
                                            tracing::info_span!("tcp-forward", port),
                                        ),
                                    );
                                    tcp_forwards.insert((bind_addr, port), abort);
                                }
                                Err(e) => {
                                    tracing::warn!(error = %snafu::Report::from_error(&e), "tcpip-forward failed");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %snafu::Report::from_error(&e), "failed to decode tcpip-forward");
                        }
                    }
                }
                "cancel-tcpip-forward" => {
                    match req
                        .decode_payload::<CancelTcpipForwardRequest, ForwardError>()
                        .await
                    {
                        Ok(decoded) => {
                            let bind_addr = decoded.payload().bind_address.to_string();
                            let bind_port = match u16::try_from(decoded.payload().bind_port.into_inner()) {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!(port = decoded.payload().bind_port.into_inner(), "cancel-tcpip-forward port overflow");
                                    let _ = decoded.respond_failure().await;
                                    return;
                                }
                            };
                            if let Some(abort) = tcp_forwards.remove(&(bind_addr.clone(), bind_port)) {
                                abort.abort();
                                let _ = decoded
                                    .respond_success(crate::conversation::EmptyPayload)
                                    .await;
                            } else {
                                let _ = decoded.respond_failure().await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %snafu::Report::from_error(&e), "failed to decode cancel-tcpip-forward");
                        }
                    }
                }
                "streamlocal-forward@openssh.com" => {
                    match req
                        .decode_payload::<StreamlocalForwardRequest, ForwardError>()
                        .await
                    {
                        Ok(decoded) => {
                            let socket_path = decoded.payload().socket_path.to_string();
                            match decoded.accept_unix_forward().await {
                                Ok(listener) => {
                                    let abort = forward_tasks.spawn(
                                        listener.run(conversation.clone()).instrument(
                                            tracing::info_span!("unix-forward", path = &*socket_path),
                                        ),
                                    );
                                    unix_forwards.insert(socket_path, abort);
                                }
                                Err(e) => {
                                    tracing::warn!(error = %snafu::Report::from_error(&e), "streamlocal-forward failed");
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %snafu::Report::from_error(&e), "failed to decode streamlocal-forward");
                        }
                    }
                }
                "cancel-streamlocal-forward@openssh.com" => {
                    match req
                        .decode_payload::<CancelStreamlocalForwardRequest, ForwardError>()
                        .await
                    {
                        Ok(decoded) => {
                            let socket_path = decoded.payload().socket_path.to_string();
                            if let Some(abort) = unix_forwards.remove(&*socket_path) {
                                abort.abort();
                                let _ = decoded
                                    .respond_success(crate::conversation::EmptyPayload)
                                    .await;
                            } else {
                                let _ = decoded.respond_failure().await;
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %snafu::Report::from_error(&e), "failed to decode cancel-streamlocal-forward");
                        }
                    }
                }
                _ => {
                    tracing::warn!(request_type = %&*request_type, "poisoning session: unknown global request type");
                    req.poison();
                }
            }
        }
        IncomingGlobal::Notify(notice) => {
            tracing::warn!(
                request_type = %notice.request_type(),
                "poisoning session: unknown global notice type"
            );
            notice.poison();
        }
    }
}
