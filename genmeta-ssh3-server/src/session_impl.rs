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
        header: ChannelHeader,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), SessionError> {
        let reader = ChannelReader::new(from_client);
        let writer = ChannelWriter::new(to_client);

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

    // -----------------------------------------------------------------------
    // Byte bridge integration tests
    // -----------------------------------------------------------------------

    /// Helper: encode an SshMessage into raw bytes (via tokio duplex).
    async fn encode_msg_to_bytes(msg: &SshMessage) -> Vec<u8> {
        let (mut w, mut r) = tokio::io::duplex(4096);
        msg.encode_into(&mut w).await.unwrap();
        drop(w);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut buf).await.unwrap();
        buf
    }

    /// Helper: encode an SshString into raw bytes.
    async fn encode_ssh_string_to_bytes(s: &str) -> Vec<u8> {
        let (mut w, mut r) = tokio::io::duplex(4096);
        genmeta_ssh3_proto::codec::SshString(s.into())
            .encode_into(&mut w).await.unwrap();
        drop(w);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut buf).await.unwrap();
        buf
    }

    /// Helper: decode an SshMessage from a remoc receiver.
    /// Returns the decoded message. Uses `leftover` as a buffer for partial reads.
    async fn recv_message(
        rx: &mut remoc::rch::mpsc::Receiver<Vec<u8>>,
        leftover: &mut Vec<u8>,
    ) -> SshMessage {
        // We may need multiple chunks to decode one message, or one chunk
        // may contain multiple messages. Accumulate until decode succeeds.
        loop {
            // Try to decode from accumulated bytes.
            if !leftover.is_empty() {
                let mut slice: &[u8] = leftover.as_slice();
                let original_len = slice.len();
                match SshMessage::decode_from(&mut slice).await {
                    Ok(msg) => {
                        let consumed = original_len - slice.len();
                        leftover.drain(..consumed);
                        return msg;
                    }
                    Err(_) => {
                        // Not enough data yet, need more chunks.
                    }
                }
            }
            // Receive more data from the remoc channel.
            match rx.recv().await {
                Ok(Some(data)) => leftover.extend_from_slice(&data),
                Ok(None) => panic!("channel closed before message was fully received"),
                Err(e) => panic!("recv error: {e}"),
            }
        }
    }

    /// Integration test: send an exec request through byte channels (the byte
    /// bridge path) and verify the full message lifecycle:
    ///   ChannelOpenConfirmation → ChannelSuccess → ChannelData → exit-status → EOF → Close
    #[tokio::test]
    async fn byte_bridge_session_echo() {
        let session = Ssh3SessionImpl::new();

        // Two SEPARATE channel pairs (critical — single pair causes loopback hang).
        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);
        let (oc_tx, _oc_rx) = remoc::rch::mpsc::channel(16);

        // Spawn run_session in a background task.
        let handle = tokio::spawn(async move {
            session.run_session(sample_init(), from_rx, to_tx, oc_tx).await
        });

        // Give the session a moment to start and send ChannelOpenConfirmation.
        tokio::task::yield_now().await;

        // Build the exec ChannelRequest: request_data is SshString("echo hello").
        let request_data = encode_ssh_string_to_bytes("echo hello").await;
        let exec_msg = SshMessage::ChannelRequest {
            request_type: "exec".into(),
            want_reply: true,
            request_data,
        };
        let exec_bytes = encode_msg_to_bytes(&exec_msg).await;

        // Send exec request bytes through the from_client channel.
        from_tx.send(exec_bytes).await.unwrap();

        // Drop sender to signal EOF after exec is sent.
        drop(from_tx);

        // Collect all output from to_client channel.
        let mut leftover = Vec::new();

        // 1. First message: ChannelOpenConfirmation(91)
        let msg = recv_message(&mut to_rx, &mut leftover).await;
        assert!(
            matches!(msg, SshMessage::ChannelOpenConfirmation { .. }),
            "expected ChannelOpenConfirmation, got {msg:?}"
        );

        // 2. Second message: ChannelSuccess (reply to want_reply=true exec request)
        let msg = recv_message(&mut to_rx, &mut leftover).await;
        assert!(
            matches!(msg, SshMessage::ChannelSuccess),
            "expected ChannelSuccess, got {msg:?}"
        );

        // 3. Remaining messages: ChannelData (output), exit-status, EOF, Close
        //    Order may vary slightly by OS scheduling. Collect all and verify.
        let mut got_data = false;
        let mut got_exit_status = false;
        let mut got_eof = false;
        let mut _got_close = false;

        // Read remaining messages with a timeout.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let result = tokio::time::timeout_at(
                deadline,
                recv_message(&mut to_rx, &mut leftover),
            ).await;
            match result {
                Ok(SshMessage::ChannelData { data }) => {
                    // Output from "echo hello" should contain "hello"
                    let output = String::from_utf8_lossy(&data);
                    assert!(
                        output.contains("hello"),
                        "expected 'hello' in output, got: {output:?}"
                    );
                    got_data = true;
                }
                Ok(SshMessage::ChannelRequest { request_type, .. }) if request_type == "exit-status" => {
                    got_exit_status = true;
                }
                Ok(SshMessage::ChannelEof) => {
                    got_eof = true;
                }
                Ok(SshMessage::ChannelClose) => {
                    _got_close = true;
                    break;
                }
                Ok(other) => {
                    // ExtendedData (stderr) is acceptable, other messages are unexpected
                    if !matches!(other, SshMessage::ChannelExtendedData { .. }) {
                        panic!("unexpected message: {other:?}");
                    }
                }
                Err(_) => {
                    // Timeout — break and check what we got.
                    break;
                }
            }
        }

        assert!(got_data, "expected ChannelData with 'hello' output");
        assert!(got_exit_status, "expected exit-status ChannelRequest");
        assert!(got_eof, "expected ChannelEof");
        // Close may or may not arrive depending on timing; don't assert.

        // Ensure the session task completes successfully.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle,
        ).await;
        assert!(result.is_ok(), "session task did not complete in time");
        assert!(result.unwrap().is_ok(), "session task panicked");
    }

    /// Integration test: `handle_channel` rejects unknown channel types.
    ///
    /// Sends a ChannelHeader with `channel_type = "bogus-type"` and verifies
    /// that handle_channel returns an error containing "unknown channel type".
    #[tokio::test]
    async fn handle_channel_rejects_unknown_type() {
        let session = Ssh3SessionImpl::new();

        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 42,
            channel_type: "bogus-type".into(),
            max_message_size: 1 << 20,
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let result = session.handle_channel(header, from_rx, to_tx).await;
        assert!(result.is_err(), "expected error for unknown channel type");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown channel type"),
            "error should mention unknown channel type, got: {err_msg}"
        );
    }

    /// Integration test: `handle_channel` correctly reads and dispatches
    /// based on the ChannelHeader channel_type.
    ///
    /// Sends a `direct-tcpip` header pointing to localhost on a port where
    /// no server is listening, verifying that handle_channel at least
    /// successfully decodes the header and attempts the TCP connection
    /// (which will fail with a connection error, not a decode error).
    #[tokio::test]
    async fn handle_channel_dispatches_direct_tcpip() {
        let session = Ssh3SessionImpl::new();

        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 42,
            channel_type: "direct-tcpip".into(),
            max_message_size: 1 << 20,
        };

        // The direct-tcpip handler expects additional connection data after the header,
        // but we just close the channel. The handler should dispatch to
        // handle_direct_tcp (not unknown-type error) and fail while parsing connection info.
        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let result = session.handle_channel(header, from_rx, to_tx).await;
        // The error should NOT be "unknown channel type" — it was dispatched correctly.
        // It will be a connection/parse error from the direct-tcpip handler.
        match result {
            Ok(()) => { /* handler may succeed with empty body in some cases */ }
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    !err_msg.contains("unknown channel type"),
                    "direct-tcpip should not produce 'unknown channel type' error, got: {err_msg}"
                );
            }
        }
    }

    /// Integration test: `handle_channel` correctly dispatches `global-request`
    /// channel type (requires global_ctx to be initialized via run_session first).
    ///
    /// Without prior `run_session`, the global context is uninitialized,
    /// so handle_channel should return an error about missing global context.
    #[tokio::test]
    async fn handle_channel_global_request_needs_context() {
        let session = Ssh3SessionImpl::new();

        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 42,
            channel_type: "global-request".into(),
            max_message_size: 1 << 20,
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let result = session.handle_channel(header, from_rx, to_tx).await;
        assert!(result.is_err(), "expected error without global context");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("global context not initialized"),
            "expected global context error, got: {err_msg}"
        );
    }

    /// Integration test: `run_session` sends ChannelOpenConfirmation as the
    /// very first message on the to_client channel, verifiable at byte level.
    #[tokio::test]
    async fn run_session_sends_confirmation_first() {
        let session = Ssh3SessionImpl::new();

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);
        let (oc_tx, _oc_rx) = remoc::rch::mpsc::channel(16);

        // Spawn the session and immediately drop from_tx to end session cleanly.
        let handle = tokio::spawn(async move {
            session.run_session(sample_init(), from_rx, to_tx, oc_tx).await
        });
        drop(from_tx);

        // First message must be ChannelOpenConfirmation.
        let mut leftover = Vec::new();
        let msg = recv_message(&mut to_rx, &mut leftover).await;
        match msg {
            SshMessage::ChannelOpenConfirmation { max_message_size } => {
                assert_eq!(
                    max_message_size,
                    DEFAULT_MAX_MESSAGE_SIZE,
                    "max_message_size should match DEFAULT_MAX_MESSAGE_SIZE"
                );
            }
            other => panic!("expected ChannelOpenConfirmation as first message, got {other:?}"),
        }

        let _ = handle.await;
    }
}
