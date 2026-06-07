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

use std::collections::HashMap;
use std::os::fd::AsFd;
use std::sync::Arc;

use snafu::prelude::*;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::{AbortHandle, JoinSet};

use crate::channel::reason_code;
use crate::conversation::channel::{ChannelEvent, ReadChannelEventError, SshChannel};
use crate::conversation::global::IncomingGlobal;
use crate::conversation::{Conversation, EmptyPayload};
use crate::forward::{
    CancelStreamlocalForwardRequest, CancelTcpipForwardRequest, ForwardError,
    StreamlocalForwardRequest, TcpipForwardRequest,
};
use crate::session::process::CommandMode;
use crate::session::pty::PtyPair;
use crate::session::{EnvRequest, ExecRequest, PtyRequest, SessionCodecError, UserInfo};
use h3x::varint::VarInt;
use tracing::Instrument;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Configuration for the session dispatcher.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Authenticated user identity (includes PAM environment).
    pub user: UserInfo,
    /// Maximum SSH message size for session channels.
    pub max_message_size: VarInt,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            user: UserInfo {
                username: String::from("nobody"),
                uid: 65534,
                gid: 65534,
                home: std::path::PathBuf::from("/"),
                shell: std::path::PathBuf::from("/bin/sh"),
                pam_env: Vec::new(),
            },
            max_message_size: crate::constants::DEFAULT_MAX_MESSAGE_SIZE,
        }
    }
}

/// Result of the server-side session dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunSessionOutcome {
    /// The conversation accept paths closed before a session channel completed.
    ConversationClosed,
    /// At least one session channel ran and all channel tasks completed.
    SessionFinished,
}

/// Error returned by [`run_session`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum RunSessionError {
    #[snafu(display("session channel failed"))]
    SessionChannel {
        source: crate::session::process::ProcessError,
    },
}

// ---------------------------------------------------------------------------
// Session setup — read exec/shell/pty-req before spawning a process
// ---------------------------------------------------------------------------

/// Error during the session setup phase.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SessionSetupError {
    #[snafu(display("failed to read channel event during session setup"))]
    ReadEvent { source: ReadChannelEventError },

    #[snafu(display("failed to decode '{request_type}' request payload"))]
    DecodePayload {
        request_type: String,
        source: SessionCodecError,
    },

    #[snafu(display("failed to respond to channel request"))]
    Respond {
        source: crate::conversation::channel::RespondChannelSuccessError<std::convert::Infallible>,
    },

    #[snafu(display("channel closed before exec or shell request"))]
    ChannelClosed,

    #[snafu(display("failed to allocate PTY"))]
    AllocPty {
        source: crate::session::pty::PtyError,
    },
}

/// Result of the session setup phase.
struct SessionSetup {
    command: Vec<u8>,
    is_shell: bool,
    pty: Option<PtyPair>,
    /// Terminal type from pty-req (e.g. "xterm-256color").
    term_type: Option<String>,
    /// Environment variables requested by the client via "env" requests.
    client_env: Vec<(String, String)>,
}

/// Read session channel requests (pty-req, exec, shell) and respond.
///
/// The SSH3 protocol expects the client to send setup requests before any
/// data. This function reads those requests using [`SshChannel::next_event`]
/// (which has writer access for sending replies), then returns the determined
/// command mode and optional PTY allocation.
async fn session_setup<R, W>(
    channel: &mut SshChannel<R, W>,
) -> Result<SessionSetup, SessionSetupError>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    use session_setup_error::*;

    let mut pty_request: Option<PtyRequest> = None;
    let mut command: Option<Vec<u8>> = None;
    let mut is_shell = false;
    let mut term_type: Option<String> = None;
    let mut client_env: Vec<(String, String)> = Vec::new();

    loop {
        let event = channel.next_event().await.context(ReadEventSnafu)?;

        match event {
            ChannelEvent::Request(incoming) => {
                let request_type = incoming.request_type().clone();
                match &*request_type {
                    "pty-req" => {
                        let (payload, responder) = incoming
                            .decode_payload::<PtyRequest, SessionCodecError>()
                            .await
                            .context(DecodePayloadSnafu {
                                request_type: "pty-req",
                            })?;
                        term_type = Some(payload.term_type.to_string());
                        pty_request = Some(payload);
                        if let Some(r) = responder {
                            // Respond with success; PTY allocation happens later.
                            let _ = r.respond_success(EmptyPayload).await.context(RespondSnafu);
                        }
                    }
                    "env" => {
                        let (payload, responder) = incoming
                            .decode_payload::<EnvRequest, SessionCodecError>()
                            .await
                            .context(DecodePayloadSnafu {
                                request_type: "env",
                            })?;
                        client_env.push((payload.name.to_string(), payload.value.to_string()));
                        if let Some(r) = responder {
                            let _ = r.respond_success(EmptyPayload).await.context(RespondSnafu);
                        }
                    }
                    "exec" => {
                        let (payload, responder) = incoming
                            .decode_payload::<ExecRequest, SessionCodecError>()
                            .await
                            .context(DecodePayloadSnafu {
                                request_type: "exec",
                            })?;
                        command = Some(bytes::Bytes::from(payload.command).to_vec());
                        if let Some(r) = responder {
                            let _ = r.respond_success(EmptyPayload).await.context(RespondSnafu);
                        }
                        break;
                    }
                    "shell" => {
                        // EmptyPayload::DecodeFrom is infallible.
                        let (_, responder) = incoming
                            .decode_payload::<EmptyPayload, std::convert::Infallible>()
                            .await
                            .unwrap();
                        is_shell = true;
                        if let Some(r) = responder {
                            let _ = r.respond_success(EmptyPayload).await.context(RespondSnafu);
                        }
                        break;
                    }
                    other => {
                        tracing::debug!(request_type = %other, "ignoring unknown session setup request");
                        if incoming.want_reply() {
                            // Decode an empty payload to get the responder.
                            if let Ok((_, Some(r))) = incoming
                                .decode_payload::<EmptyPayload, std::convert::Infallible>()
                                .await
                            {
                                let _ = r.respond_failure().await;
                            }
                        }
                    }
                }
            }
            ChannelEvent::Eof | ChannelEvent::Close => {
                return ChannelClosedSnafu.fail();
            }
            _ => {
                tracing::debug!("ignoring unexpected event during session setup");
            }
        }
    }

    // Allocate PTY if requested, then apply terminal modes to the slave.
    let pty = match pty_request {
        Some(req) => {
            let modes: Vec<u8> = req.terminal_modes.as_ref().to_vec();
            let pair = crate::session::pty::allocate_pty(&req).context(AllocPtySnafu)?;
            if !modes.is_empty()
                && let Err(e) =
                    crate::session::pty::apply_terminal_modes(pair.slave.as_fd(), &modes)
            {
                tracing::warn!(error = %snafu::Report::from_error(&e), "failed to apply terminal modes");
            }
            Some(pair)
        }
        None => None,
    };

    Ok(SessionSetup {
        command: command.unwrap_or_default(),
        is_shell,
        pty,
        term_type,
        client_env,
    })
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

/// Run the server-side session loop.
///
/// Concurrently accepts channels and global requests from the conversation,
/// dispatching each to the appropriate handler. Returns when the conversation
/// is closed (both accept methods return errors indicating shutdown).
pub async fn run_session<S>(
    conversation: Arc<Conversation<S>>,
    config: SessionConfig,
) -> Result<RunSessionOutcome, RunSessionError>
where
    S: h3x::webtransport::Session + 'static,
    S::StreamReader: 'static,
    S::StreamWriter: 'static,
{
    use run_session_error::*;

    let mut tcp_forwards: HashMap<(String, u16), AbortHandle> = HashMap::new();
    let mut unix_forwards: HashMap<String, AbortHandle> = HashMap::new();
    let mut channel_tasks: JoinSet<Result<(), crate::session::process::ProcessError>> =
        JoinSet::new();
    let mut forward_tasks: JoinSet<()> = JoinSet::new();
    let mut had_session = false;
    let mut outcome = RunSessionOutcome::ConversationClosed;

    // Pin the accept() future so it survives across select! iterations.
    // accept() is NOT cancellation-safe: it eagerly takes a reader ticket,
    // and if cancelled before completing, the ticket blocks subsequent reads.
    let mut accept_global = std::pin::pin!(conversation.accept_global_request());

    // Pin accept_channel() for the same reason: it calls accept_stream()
    // then decode_one(). If cancelled between the two, the stream is lost.
    let mut accept_channel = std::pin::pin!(conversation.accept_channel());

    tracing::debug!("run_session: entering main loop");

    loop {
        tokio::select! {
            channel_result = &mut accept_channel => {
                tracing::debug!("run_session: accept_channel returned");
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
                        had_session = true;
                        let pending = incoming.skip_payload();
                        channel_tasks.spawn(async move {
                            let mut channel = match pending.accept(max_msg).await {
                                Ok(ch) => ch,
                                Err(e) => {
                                    tracing::warn!(error = %snafu::Report::from_error(&e), "failed to accept session channel");
                                    return Ok(());
                                }
                            };

                            // Setup phase: read exec/shell/pty-req requests.
                            let setup = match session_setup(&mut channel).await {
                                Ok(s) => s,
                                Err(e) => {
                                    tracing::warn!(error = %snafu::Report::from_error(&e), "session setup failed");
                                    return Ok(());
                                }
                            };

                            let shell = config.user.shell.as_os_str();
                            let term = setup.term_type.as_deref();

                            // Display MOTD for interactive login shell with PTY.
                            if setup.is_shell && setup.pty.is_some() {
                                send_motd(&mut channel, &config.user.home).await;
                            }

                            if let Some(pty) = setup.pty {
                                let mode = if setup.is_shell {
                                    CommandMode::Shell { shell }
                                } else {
                                    CommandMode::Exec { shell, command: &setup.command }
                                };
                                super::process::run_pty(channel, mode, pty, &config, term, &setup.client_env).await
                            } else {
                                let mode = if setup.is_shell {
                                    CommandMode::Shell { shell }
                                } else {
                                    CommandMode::Exec { shell, command: &setup.command }
                                };
                                super::process::run_piped(channel, mode, &config, term, &setup.client_env).await
                            }
                        }.instrument(tracing::info_span!("session")));
                    }
                    "direct-tcpip" => {
                        let (reader, writer) = incoming.into_raw_parts();
                        channel_tasks.spawn(async move {
                            if let Err(e) = crate::forward::direct::handle_direct_tcpip(reader, writer).await {
                                tracing::warn!(error = %snafu::Report::from_error(&e), "direct-tcpip error");
                            }
                            Ok(())
                        }.instrument(tracing::info_span!("direct-tcpip")));
                    }
                    "direct-streamlocal@openssh.com" => {
                        let (reader, writer) = incoming.into_raw_parts();
                        channel_tasks.spawn(async move {
                            if let Err(e) = crate::forward::direct::handle_direct_streamlocal(reader, writer).await {
                                tracing::warn!(error = %snafu::Report::from_error(&e), "direct-streamlocal error");
                            }
                            Ok(())
                        }.instrument(tracing::info_span!("direct-streamlocal")));
                    }
                    "socks5" => {
                        let pending = incoming.skip_payload();
                        let (reader, writer) = match pending.accept(config.max_message_size).await {
                            Ok(ch) => ch.into_inner(),
                            Err(e) => {
                                tracing::warn!(error = %snafu::Report::from_error(&e), "socks5 accept failed");
                                continue;
                            }
                        };
                        channel_tasks.spawn(async move {
                            if let Err(e) = crate::forward::socks5::handle_socks5(reader, writer).await {
                                tracing::warn!(error = %snafu::Report::from_error(&e), "socks5 error");
                            }
                            Ok(())
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
                // Reset the pinned future for the next channel.
                accept_channel.set(conversation.accept_channel());
            }

            global_result = &mut accept_global => {
                match global_result {
                    Ok(incoming) => {
                        dispatch_global(incoming, &conversation, &mut tcp_forwards, &mut unix_forwards, &mut forward_tasks).await;
                        // Reset the pinned future for the next global request.
                        accept_global.set(conversation.accept_global_request());
                    }
                    Err(e) => {
                        tracing::debug!(error = %snafu::Report::from_error(&e), "accept global ended");
                        break;
                    }
                }
            }

            // Reap completed channel tasks (prevents unbounded growth).
            Some(result) = channel_tasks.join_next() => {
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error).context(SessionChannelSnafu),
                    Err(e) => {
                        tracing::warn!(error = %snafu::Report::from_error(&e), "channel task panicked");
                    }
                }
                if had_session && channel_tasks.is_empty() {
                    tracing::debug!("run_session: all channel tasks completed, exiting");
                    outcome = RunSessionOutcome::SessionFinished;
                    break;
                }
            }

            // Reap completed forward listener tasks.
            Some(result) = forward_tasks.join_next() => {
                if let Err(e) = result && !e.is_cancelled() {
                    tracing::warn!(error = %snafu::Report::from_error(&e), "forward task panicked");
                }
            }
        }
    }

    // Wait for all remaining channel tasks.
    while let Some(result) = channel_tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(error).context(SessionChannelSnafu),
            Err(e) => {
                tracing::warn!(error = %snafu::Report::from_error(&e), "channel task panicked during shutdown");
            }
        }
    }

    Ok(outcome)
}

// ---------------------------------------------------------------------------
// MOTD
// ---------------------------------------------------------------------------

/// Send the message of the day to the channel, unless `~/.hushlogin` exists.
async fn send_motd<R, W>(channel: &mut SshChannel<R, W>, home: &std::path::Path)
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    if home.join(".hushlogin").exists() {
        return;
    }
    let motd = match std::fs::read("/etc/motd") {
        Ok(data) if !data.is_empty() => data,
        _ => return,
    };
    if let Err(e) = channel.data(&motd).await {
        tracing::debug!(error = %snafu::Report::from_error(&e), "failed to send MOTD");
    }
}

// ---------------------------------------------------------------------------
// Global request dispatch
// ---------------------------------------------------------------------------

async fn dispatch_global<S, R, W>(
    incoming: IncomingGlobal<R, W>,
    conversation: &Arc<Conversation<S>>,
    tcp_forwards: &mut HashMap<(String, u16), AbortHandle>,
    unix_forwards: &mut HashMap<String, AbortHandle>,
    forward_tasks: &mut JoinSet<()>,
) where
    S: h3x::webtransport::Session + 'static,
    S::StreamReader: 'static,
    S::StreamWriter: 'static,
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
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
                                        listener
                                            .run(conversation.clone())
                                            .instrument(tracing::info_span!("tcp-forward", port)),
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
                            let bind_port =
                                match u16::try_from(decoded.payload().bind_port.into_inner()) {
                                    Ok(p) => p,
                                    Err(_) => {
                                        tracing::warn!(
                                            port = decoded.payload().bind_port.into_inner(),
                                            "cancel-tcpip-forward port overflow"
                                        );
                                        let _ = decoded.respond_failure().await;
                                        return;
                                    }
                                };
                            if let Some(abort) =
                                tcp_forwards.remove(&(bind_addr.clone(), bind_port))
                            {
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
                                            tracing::info_span!(
                                                "unix-forward",
                                                path = &*socket_path
                                            ),
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
