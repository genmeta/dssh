//! [`SshSession`] trait implementation for the ssh3-session child process.
//!
//! This module provides [`Ssh3SessionImpl`], which implements the RTC
//! [`SshSession`] trait. The ssh3-session child process performs privilege
//! dropping (setgid/setuid) and runs the session dispatch loop (PTY, shell,
//! exec) over byte-channel adapters bridging remoc channels to `AsyncRead`/`AsyncWrite`.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use genmeta_ssh3_proto::codec::ChannelHeader;
use genmeta_ssh3_proto::message::SshMessage;
use genmeta_ssh3_proto::session::{SessionError, SessionInit, SshSession};
use h3x::codec::{DecodeFrom, EncodeInto};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::byte_channel::{ChannelReader, ChannelWriter};
use crate::channel::{run_message_loop_with_sender, ChannelEvent, GlobalRequestContext, DEFAULT_MAX_MESSAGE_SIZE};
use crate::forward;
use crate::forward::reverse_tcp::ReverseTcpForwarder;
use crate::forward::streamlocal::ReverseStreamlocalForwarder;
use crate::session::pty::{allocate_pty, set_window_size, PtyPair};
use crate::session::request::{handle_request, run_exec, run_shell, RequestAction};
/// Drop root privileges by switching to the given uid/gid.
///
/// **Order matters:** `setgid` must be called before `setuid`, because once
/// we drop root via `setuid` we can no longer change the group.
#[cfg(not(test))]
fn drop_privileges(uid: u32, gid: u32) -> Result<(), SessionError> {
    unsafe {
        if libc::setgid(gid) != 0 {
            return Err(SessionError::new(format!(
                "setgid({gid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if libc::setuid(uid) != 0 {
            return Err(SessionError::new(format!(
                "setuid({uid}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    tracing::info!(uid, gid, "dropped privileges");
    Ok(())
}

/// No-op privilege drop for tests (requires root on real systems).
#[cfg(test)]
fn drop_privileges(_uid: u32, _gid: u32) -> Result<(), SessionError> {
    Ok(())
}

/// Implementation of the [`SshSession`] RTC trait.
///
/// This is the server-side object that receives remote calls from the parent
/// process. It handles privilege dropping (setgid/setuid) for the authenticated
/// user and runs the full session dispatch loop (exec, shell, PTY, signals)
/// over byte-channel adapters.
///
/// The `global_ctx` field is lazily initialized in `run_session` and consumed
/// by `handle_channel` for forwarding and global-request dispatch.
pub struct Ssh3SessionImpl {
    global_ctx: tokio::sync::OnceCell<Arc<GlobalRequestContext>>,
}

impl Ssh3SessionImpl {
    /// Create a new `Ssh3SessionImpl` with uninitialized global context.
    pub fn new() -> Self {
        Self {
            global_ctx: tokio::sync::OnceCell::new(),
        }
    }
}

impl Default for Ssh3SessionImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl SshSession for Ssh3SessionImpl {
    async fn run_session(
        &self,
        init: SessionInit,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
        open_channel_tx: remoc::rch::mpsc::Sender<genmeta_ssh3_proto::session::OpenChannelRequest>,
    ) -> Result<(), SessionError> {
        // 1. Drop privileges: setgid first, then setuid.
        drop_privileges(init.uid, init.gid)?;

        // Build StreamFactory from open_channel_tx so reverse forwarders can
        // request new QUIC streams from the parent process.
        let stream_factory = build_stream_factory(open_channel_tx);

        // Create GlobalRequestContext for handle_channel dispatch.
        let global_ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder: Arc::new(ReverseTcpForwarder::default()),
            streamlocal_forwarder: Arc::new(ReverseStreamlocalForwarder::default()),
            stream_factory,
            conversation_id: init.conversation_id,
        });
        let _ = self.global_ctx.set(global_ctx);

        // 2. Wrap byte channels as AsyncRead/AsyncWrite adapters.
        let reader = ChannelReader::new(from_client);
        let mut writer = ChannelWriter::new(to_client);

        // 3. Send ChannelOpenConfirmation(91).
        let confirm = SshMessage::ChannelOpenConfirmation {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        };
        confirm
            .encode_into(&mut writer)
            .await
            .map_err(|e| SessionError::new(e.to_string()))?;

        // 4. Spawn the message-loop reader, producing events into the channel.
        let (event_tx, mut event_rx) = mpsc::channel(64);
        tokio::spawn(async move {
            let _ = run_message_loop_with_sender(reader, event_tx).await;
        });

        // 5. Dispatch loop: consume events until an exec/shell request arrives.
        //    Tracks PTY allocation state: None (idle) or Some(PtyPair) (PTY allocated).
        let mut pty_pair: Option<PtyPair> = None;

        while let Some(event) = event_rx.recv().await {
            match event {
                ChannelEvent::Request { .. } => {
                    match handle_request(&event, &mut writer)
                        .await
                        .map_err(|e| SessionError::new(e.to_string()))?
                    {
                        Some(RequestAction::Exec(cmd)) => {
                            run_exec(&cmd, &mut writer, event_rx, pty_pair.take())
                                .await
                                .map_err(|e| SessionError::new(e.to_string()))?;
                            return Ok(());
                        }
                        Some(RequestAction::Shell) => {
                            let shell = init.shell.to_string_lossy();
                            run_shell(&shell, &mut writer, event_rx, pty_pair.take())
                                .await
                                .map_err(|e| SessionError::new(e.to_string()))?;
                            return Ok(());
                        }
                        Some(RequestAction::AllocatePty(req)) => match allocate_pty(&req) {
                            Ok(pair) => {
                                pty_pair = Some(pair);
                                tracing::info!(term = %req.term_type, "PTY allocated");
                            }
                            Err(e) => {
                                tracing::error!(%e, "PTY allocation failed");
                                // PTY failure is non-fatal — exec/shell will use piped stdio
                            }
                        },
                        Some(RequestAction::WindowChange(req)) => {
                            if let Some(ref pair) = pty_pair {
                                let _ = set_window_size(pair.master.as_raw_fd(), &req);
                            }
                        }
                        Some(RequestAction::Signal(_)) => {
                            // Signal before exec/shell — no process to signal yet
                            tracing::debug!("ignoring signal before exec/shell");
                        }
                        None => { /* unrecognized request, continue loop */ }
                    }
                }
                ChannelEvent::Eof => {
                    SshMessage::ChannelEof
                        .encode_into(&mut writer)
                        .await
                        .map_err(|e| SessionError::new(e.to_string()))?;
                    tokio::io::AsyncWriteExt::shutdown(&mut writer)
                        .await
                        .map_err(|e| SessionError::new(e.to_string()))?;
                    break;
                }
                ChannelEvent::Close => {
                    SshMessage::ChannelClose
                        .encode_into(&mut writer)
                        .await
                        .map_err(|e| SessionError::new(e.to_string()))?;
                    break;
                }
                ChannelEvent::Data(_) | ChannelEvent::ExtendedData { .. } => {
                    // No exec/shell running yet — data before a request is meaningless.
                }
            }
        }

        Ok(())
    }

    async fn open_channel(
        &self,
        _header_bytes: Vec<u8>,
    ) -> Result<
        (
            remoc::rch::mpsc::Receiver<Vec<u8>>,
            remoc::rch::mpsc::Sender<Vec<u8>>,
        ),
        SessionError,
    > {
        Err(SessionError::new(
            "open_channel not yet implemented".to_string(),
        ))
    }

    async fn handle_channel(
        &self,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), SessionError> {
        let mut reader = ChannelReader::new(from_client);
        let writer = ChannelWriter::new(to_client);

        // Read ChannelHeader from first bytes (the parent serialized it via handle_channel_byte_bridge).
        let header = ChannelHeader::decode_from(&mut reader)
            .await
            .map_err(|e| SessionError::new(e.to_string()))?;

        match header.channel_type.as_str() {
            "direct-tcpip" => {
                crate::forward::direct_tcp::handle_direct_tcp(header, reader, writer)
                    .await
                    .map_err(|e| SessionError::new(e.to_string()))
            }
            "direct-streamlocal@openssh.com" => {
                crate::forward::streamlocal::handle_direct_streamlocal(header, reader, writer)
                    .await
                    .map_err(|e| SessionError::new(e.to_string()))
            }
            "socks5" => {
                crate::forward::socks5::handle_socks5(header, reader, writer)
                    .await
                    .map_err(|e| SessionError::new(e.to_string()))
            }
            "global-request" => {
                let ctx = self
                    .global_ctx
                    .get()
                    .ok_or_else(|| {
                        SessionError::new("global context not initialized")
                    })?
                    .clone();
                crate::channel::handle_global_request_channel(reader, writer, Some(ctx))
                    .await
                    .map_err(|e| SessionError::new(e.to_string()))
            }
            other => {
                tracing::warn!(channel_type = %other, "unknown channel type in child");
                Err(SessionError::new(format!("unknown channel type: {other}")))
            }
        }
    }
}

/// Build a [`StreamFactory`] backed by the `open_channel_tx` RPC channel.
///
/// When called, the factory sends an [`OpenChannelRequest`] to the parent
/// process with empty `header_bytes` (callers write their own headers
/// through the byte bridge). The parent opens a QUIC bidirectional stream,
/// creates byte bridges, and returns remoc channel endpoints.
fn build_stream_factory(
    open_channel_tx: remoc::rch::mpsc::Sender<genmeta_ssh3_proto::session::OpenChannelRequest>,
) -> forward::StreamFactory {
    Arc::new(move || {
        let caller = open_channel_tx.clone();
        Box::pin(async move {
            let (response_tx, response_rx) = remoc::rch::oneshot::channel();

            let request = genmeta_ssh3_proto::session::OpenChannelRequest {
                header_bytes: vec![],
                response_tx,
            };

            caller
                .send(request)
                .await
                .map_err(|e| io::Error::other(e.to_string()))?;

            let (from_remote_rx, to_remote_tx) = response_rx
                .await
                .map_err(|e| io::Error::other(e.to_string()))?
                .map_err(|e| io::Error::other(e.to_string()))?;

            let reader = Box::new(ChannelReader::new(from_remote_rx))
                as Box<dyn AsyncRead + Send + Unpin>;
            let writer = Box::new(ChannelWriter::new(to_remote_tx))
                as Box<dyn AsyncWrite + Send + Unpin>;
            Ok((reader, writer))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_init() -> SessionInit {
        SessionInit {
            conversation_id: 42,
            username: "alice".into(),
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/bash"),
        }
    }

    #[tokio::test]
    async fn run_session_happy_path() {
        let session = Ssh3SessionImpl::new();
        // Two separate channel pairs to avoid loopback: from_client direction and to_client direction.
        let (_from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        // Drop from_tx immediately so reader gets EOF → message loop ends → event_rx returns None.
        drop(_from_tx);
        let (oc_tx, _oc_rx) = remoc::rch::mpsc::channel(16);
        let result = session.run_session(sample_init(), from_rx, to_tx, oc_tx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_session_fields_accessible() {
        let session = Ssh3SessionImpl::new();
        let init = SessionInit {
            conversation_id: 99,
            username: "bob".into(),
            uid: 2000,
            gid: 2000,
            home: PathBuf::from("/home/bob"),
            shell: PathBuf::from("/bin/zsh"),
        };
        // Verify we can access all fields and run_session succeeds.
        assert_eq!(init.conversation_id, 99);
        assert_eq!(init.username, "bob");
        assert_eq!(init.uid, 2000);
        assert_eq!(init.gid, 2000);
        // Two separate channel pairs to avoid loopback.
        let (_from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(_from_tx);
        let (oc_tx, _oc_rx) = remoc::rch::mpsc::channel(16);
        assert!(session.run_session(init, from_rx, to_tx, oc_tx).await.is_ok());
    }

    #[test]
    fn impl_type_is_sync_send() {
        fn assert_sync_send<T: Sync + Send>() {}
        assert_sync_send::<Ssh3SessionImpl>();
    }

    /// Verify that [`Ssh3SessionImpl`] compiles as a valid target for
    /// [`SshSessionServerShared`].
    #[tokio::test]
    async fn compatible_with_server_shared() {
        use genmeta_ssh3_proto::session::{SshSessionClient, SshSessionServerShared};
        use remoc::rtc::ServerShared;
        use std::sync::Arc;

        let target = Arc::new(Ssh3SessionImpl::new());
        let (_server, _client): (
            SshSessionServerShared<Ssh3SessionImpl>,
            SshSessionClient,
        ) = SshSessionServerShared::new(target, 16);
        // If this compiles, the impl is compatible with the RTC server wrapper.
    }
}
