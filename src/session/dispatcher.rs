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
//! | `"tcpip-forward"` | Start TCP listener via [`ReverseForwarder`](crate::forward::reverse::ReverseForwarder) |
//! | `"cancel-tcpip-forward"` | Stop TCP listener |
//! | `"streamlocal-forward@openssh.com"` | Start Unix socket listener |
//! | `"cancel-streamlocal-forward@openssh.com"` | Stop Unix socket listener |
//! | unknown | respond failure |

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinSet;

use crate::channel::reason_code;
use crate::conversation::{Conversation, IncomingGlobal, ManageSessionStream};
use crate::forward::{
    CancelStreamlocalForwardRequest, CancelTcpipForwardRequest, ForwardError,
    StreamlocalForwardRequest, TcpipForwardReply, TcpipForwardRequest,
};
use crate::forward::reverse::ReverseForwarder;
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
pub async fn run_session<M>(conversation: Arc<Conversation<M>>, config: SessionConfig)
where
    M: ManageSessionStream + 'static,
    M::StreamReader: AsyncRead + Send + Unpin + 'static,
    M::StreamWriter: AsyncWrite + Send + Unpin + 'static,
    M::Error: Send + Sync + 'static,
{
    let mut forwarder = ReverseForwarder::new(Arc::clone(&conversation));
    let mut channel_tasks: JoinSet<()> = JoinSet::new();

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
                        dispatch_global(incoming, &mut forwarder).await;
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
        }
    }

    // Shut down reverse forwarders.
    forwarder.shutdown();

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

async fn dispatch_global<M>(incoming: IncomingGlobal, forwarder: &mut ReverseForwarder<M>)
where
    M: ManageSessionStream + 'static,
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
                        Ok((payload, decoded)) => {
                            let bind_addr: &str = &payload.bind_address;
                            let bind_port = match u16::try_from(payload.bind_port.into_inner()) {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!(port = payload.bind_port.into_inner(), "tcpip-forward port overflow");
                                    let _ = decoded.respond_failure().await;
                                    return;
                                }
                            };
                            match forwarder.start_tcp(bind_addr, bind_port).await {
                                Ok(actual_port) => {
                                    let reply = TcpipForwardReply {
                                        allocated_port: VarInt::from(actual_port as u32),
                                    };
                                    if let Err(e) = decoded.respond_success(reply).await {
                                        tracing::warn!(error = %snafu::Report::from_error(&e), "failed to send tcpip-forward reply");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(error = %snafu::Report::from_error(&e), "tcpip-forward bind failed");
                                    let _ = decoded.respond_failure().await;
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
                        Ok((payload, decoded)) => {
                            let bind_addr: &str = &payload.bind_address;
                            let bind_port = match u16::try_from(payload.bind_port.into_inner()) {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::warn!(port = payload.bind_port.into_inner(), "cancel-tcpip-forward port overflow");
                                    let _ = decoded.respond_failure().await;
                                    return;
                                }
                            };
                            if forwarder.stop_tcp(bind_addr, bind_port) {
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
                        Ok((payload, decoded)) => {
                            let socket_path: &str = &payload.socket_path;
                            match forwarder.start_unix(socket_path).await {
                                Ok(()) => {
                                    let _ = decoded
                                        .respond_success(crate::conversation::EmptyPayload)
                                        .await;
                                }
                                Err(e) => {
                                    tracing::warn!(error = %snafu::Report::from_error(&e), "streamlocal-forward bind failed");
                                    let _ = decoded.respond_failure().await;
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
                        Ok((payload, decoded)) => {
                            let socket_path: &str = &payload.socket_path;
                            if forwarder.stop_unix(socket_path) {
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
                    tracing::warn!(request_type = %&*request_type, "rejecting unknown global request");
                    match req.decode_payload::<crate::conversation::EmptyPayload, std::convert::Infallible>().await {
                        Ok((_, decoded)) => { let _ = decoded.respond_failure().await; }
                        Err(e) => match e {}
                    }
                }
            }
        }
        IncomingGlobal::Notify(notice) => {
            tracing::debug!(
                request_type = %notice.request_type(),
                "ignoring global notice"
            );
            // Notices don't need a response; just consume the payload.
            let _ = notice
                .decode_payload::<crate::conversation::EmptyPayload, std::convert::Infallible>()
                .await;
        }
    }
}
