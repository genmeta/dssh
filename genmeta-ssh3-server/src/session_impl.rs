//! [`SshSession`] trait implementation for the ssh3-session child process.
//!
//! This module provides [`Ssh3SessionImpl`], which implements the RTC
//! [`SshSession`] trait. The ssh3-session child process performs privilege
//! dropping (setgid/setuid) and runs the session dispatch loop (PTY, shell,
//! exec) over byte-channel adapters bridging remoc channels to `AsyncRead`/`AsyncWrite`.

use std::os::fd::AsRawFd;

use genmeta_ssh3_proto::message::SshMessage;
use genmeta_ssh3_proto::session::{SessionError, SessionInit, SshSession};
use h3x::codec::EncodeInto;
use tokio::sync::mpsc;

use crate::byte_channel::{ChannelReader, ChannelWriter};
use crate::channel::{run_message_loop_with_sender, ChannelEvent, DEFAULT_MAX_MESSAGE_SIZE};
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
pub struct Ssh3SessionImpl;

impl SshSession for Ssh3SessionImpl {
    async fn run_session(
        &self,
        init: SessionInit,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), SessionError> {
        // 1. Drop privileges: setgid first, then setuid.
        drop_privileges(init.uid, init.gid)?;

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
        _from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        _to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), SessionError> {
        // T10 will implement full dispatch. For now, stub.
        tracing::warn!("handle_channel called but not yet implemented (T10)");
        Ok(())
    }
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
        let session = Ssh3SessionImpl;
        // Two separate channel pairs to avoid loopback: from_client direction and to_client direction.
        let (_from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        // Drop from_tx immediately so reader gets EOF → message loop ends → event_rx returns None.
        drop(_from_tx);
        let result = session.run_session(sample_init(), from_rx, to_tx).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_session_fields_accessible() {
        let session = Ssh3SessionImpl;
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
        assert!(session.run_session(init, from_rx, to_tx).await.is_ok());
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

        let target = Arc::new(Ssh3SessionImpl);
        let (_server, _client): (
            SshSessionServerShared<Ssh3SessionImpl>,
            SshSessionClient,
        ) = SshSessionServerShared::new(target, 16);
        // If this compiles, the impl is compatible with the RTC server wrapper.
    }
}
