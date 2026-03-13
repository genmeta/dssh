//! SSH3 session implementation for the ssh3-session child process.
//!
//! This module provides [`Ssh3Session`], which drives the session lifecycle
//! by pulling channels from an [`Ssh3TransportClient`]. The child process
//! performs privilege dropping (setgid/setuid) and runs the session dispatch
//! loop (PTY, shell, exec) over byte-channel adapters bridging remoc channels
//! to `AsyncRead`/`AsyncWrite`.

use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use genmeta_ssh3_proto::codec::ChannelHeader;
use genmeta_ssh3_proto::message::SshMessage;
use genmeta_ssh3_proto::session::{SessionError, SessionInit, Ssh3Transport, Ssh3TransportClient};
use h3x::codec::EncodeInto;
use snafu::Report;
use tokio::{io::AsyncWrite, sync::mpsc, task::JoinSet};
use tracing::Instrument;

use crate::byte_channel::{ChannelReader, ChannelWriter};
use crate::channel::{open_session_channel, ChannelEvent, GlobalRequestContext};
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

/// SSH3 session driver that pulls channels from a transport client.
///
/// The child process creates one `Ssh3Session`, then calls [`run()`] with
/// the transport client received from the parent. The `run()` method consumes
/// `self` since each child process runs exactly one session.
pub struct Ssh3Session;

impl Ssh3Session {
    pub fn new() -> Self {
        Self
    }

    /// Run the session by pulling channels from the transport.
    ///
    /// 1. Drops privileges to the authenticated user.
    /// 3. Enters the channel-accept loop, dispatching session and non-session channels.
    pub async fn run(self, transport: Ssh3TransportClient, init: SessionInit) -> Result<(), SessionError> {
        drop_privileges(init.uid, init.gid)?;

        let global_ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder: Arc::new(ReverseTcpForwarder::default()),
            streamlocal_forwarder: Arc::new(ReverseStreamlocalForwarder::default()),
            transport: transport.clone(),
            conversation_id: init.conversation_id,
        });
        let mut channel_tasks = JoinSet::new();
        let shell = init.shell;

        while let Ok(Some((header, from_client_rx, to_client_tx))) = transport.accept_channel().await {
            Self::spawn_channel_task(
                &mut channel_tasks,
                header,
                from_client_rx,
                to_client_tx,
                Arc::clone(&global_ctx),
                shell.clone(),
            );
        }

        while let Some(result) = channel_tasks.join_next().await {
            if let Err(error) = result {
                tracing::warn!(error = %Report::from_error(error), "channel task panicked");
            }
        }
        Ok(())
    }

    fn spawn_channel_task(
        channel_tasks: &mut JoinSet<()>,
        header: ChannelHeader,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
        ctx: Arc<GlobalRequestContext>,
        shell: PathBuf,
    ) {
        let channel_type = header.channel_type.clone();
        let conversation_id = ctx.conversation_id;
        let span = tracing::info_span!(
            "ssh3_channel",
            %conversation_id,
            channel_type = %channel_type,
        );
        channel_tasks.spawn(
            async move {
                if let Err(error) = Self::handle_channel(header, from_client, to_client, ctx, &shell).await {
                    tracing::warn!(
                        error = %Report::from_error(error),
                        %conversation_id,
                        channel_type = %channel_type,
                        "channel handling failed"
                    );
                }
            }
            .instrument(span),
        );
    }

    async fn handle_channel(
        header: ChannelHeader,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
        ctx: Arc<GlobalRequestContext>,
        shell: &Path,
    ) -> Result<(), SessionError> {
        if header.channel_type == "session" {
            return Self::handle_session_channel(from_client, to_client, shell).await;
        }

        Self::handle_non_session_channel(header, from_client, to_client, ctx).await
    }

    async fn handle_session_channel(
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
        shell: &Path,
    ) -> Result<(), SessionError> {
        let reader = ChannelReader::new(from_client);
        let writer = ChannelWriter::new(to_client);
        let (event_rx, writer) = open_session_channel(reader, writer)
            .await
            .map_err(SessionError::new)?;
        Self::run_session_requests(event_rx, writer, shell).await
    }

    async fn run_session_requests<W>(
        mut event_rx: mpsc::Receiver<ChannelEvent>,
        mut writer: W,
        shell: &Path,
    ) -> Result<(), SessionError>
    where
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let shell = shell.to_string_lossy().into_owned();
        let mut pty_pair: Option<PtyPair> = None;

        while let Some(event) = event_rx.recv().await {
            match event {
                ChannelEvent::Request { .. } => match handle_request(&event, &mut writer)
                    .await
                    .map_err(SessionError::new)?
                {
                    Some(RequestAction::Exec(cmd)) => {
                        run_exec(&cmd, &mut writer, event_rx, pty_pair.take())
                            .await
                            .map_err(SessionError::new)?;
                        return Ok(());
                    }
                    Some(RequestAction::Shell) => {
                        run_shell(&shell, &mut writer, event_rx, pty_pair.take())
                            .await
                            .map_err(SessionError::new)?;
                        return Ok(());
                    }
                    Some(RequestAction::AllocatePty(req)) => match allocate_pty(&req) {
                        Ok(pair) => {
                            pty_pair = Some(pair);
                            tracing::info!(term = %req.term_type, "PTY allocated");
                        }
                        Err(error) => {
                            tracing::error!(error = %Report::from_error(error), "PTY allocation failed");
                        }
                    },
                    Some(RequestAction::WindowChange(req)) => {
                        if let Some(ref pair) = pty_pair {
                            let _ = set_window_size(pair.master.as_raw_fd(), &req);
                        }
                    }
                    Some(RequestAction::Signal(_)) => {
                        tracing::debug!("ignoring signal before exec/shell");
                    }
                    None => {}
                },
                ChannelEvent::Eof => {
                    SshMessage::ChannelEof
                        .encode_into(&mut writer)
                        .await
                        .map_err(SessionError::new)?;
                    tokio::io::AsyncWriteExt::shutdown(&mut writer)
                        .await
                        .map_err(SessionError::new)?;
                    break;
                }
                ChannelEvent::Close => {
                    SshMessage::ChannelClose
                        .encode_into(&mut writer)
                        .await
                        .map_err(SessionError::new)?;
                    break;
                }
                ChannelEvent::Data(_) | ChannelEvent::ExtendedData { .. } => {}
            }
        }

        Ok(())
    }

    /// Handle a non-session channel dispatched from the transport.
    async fn handle_non_session_channel(
        header: ChannelHeader,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
        ctx: Arc<GlobalRequestContext>,
    ) -> Result<(), SessionError> {
        let reader = ChannelReader::new(from_client);
        let writer = ChannelWriter::new(to_client);

        match header.channel_type.as_str() {
            "direct-tcpip" => {
                crate::forward::direct_tcp::handle_direct_tcp(header, reader, writer)
                    .await
                    .map_err(SessionError::new)
            }
            "direct-streamlocal@openssh.com" => {
                crate::forward::streamlocal::handle_direct_streamlocal(header, reader, writer)
                    .await
                    .map_err(SessionError::new)
            }
            "socks5" => {
                crate::forward::socks5::handle_socks5(header, reader, writer)
                    .await
                    .map_err(SessionError::new)
            }
            "global-request" => {
                crate::channel::handle_global_request_channel(reader, writer, Some(ctx))
                    .await
                    .map_err(SessionError::new)
            }
            other => {
                tracing::warn!(channel_type = %other, "unknown channel type in child");
                Err(SessionError::new(format!("unknown channel type: {other}")))
            }
        }
    }
}

impl Default for Ssh3Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use h3x::stream_id::StreamId;
    use genmeta_ssh3_proto::session::TransportError;
    use h3x::codec::DecodeFrom;
    use std::path::PathBuf;
    use crate::channel::DEFAULT_MAX_MESSAGE_SIZE;

    struct MockSsh3Transport;

    impl genmeta_ssh3_proto::session::Ssh3Transport for MockSsh3Transport {
        async fn accept_channel(&self) -> Result<
            Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
            TransportError,
        > {
            Ok(None)
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
            TransportError,
        > {
            Err(TransportError::Other("mock: open_channel not available".into()))
        }
    }

    fn mock_transport_client() -> Ssh3TransportClient {
        use genmeta_ssh3_proto::session::Ssh3TransportServerShared;
        use remoc::rtc::ServerShared;
        let mock = std::sync::Arc::new(MockSsh3Transport);
        let (server, client) = Ssh3TransportServerShared::new(mock, 16);
        tokio::spawn(async move { let _ = server.serve(true).await; });
        client
    }

    /// A mock transport that feeds one session channel, then signals end.
    struct ChannelFeedingTransport {
        channel_tx: tokio::sync::Mutex<Option<(
            ChannelHeader,
            remoc::rch::mpsc::Receiver<Vec<u8>>,
            remoc::rch::mpsc::Sender<Vec<u8>>,
        )>>,
    }

    impl genmeta_ssh3_proto::session::Ssh3Transport for ChannelFeedingTransport {
        async fn accept_channel(&self) -> Result<
            Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
            TransportError,
        > {
            let mut guard = self.channel_tx.lock().await;
            Ok(guard.take())
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
            TransportError,
        > {
            Err(TransportError::Other("mock: open_channel not available".into()))
        }
    }

    fn mock_feeding_transport_client(
        header: ChannelHeader,
        from_client_rx: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client_tx: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) -> Ssh3TransportClient {
        use genmeta_ssh3_proto::session::Ssh3TransportServerShared;
        use remoc::rtc::ServerShared;
        let mock = std::sync::Arc::new(ChannelFeedingTransport {
            channel_tx: tokio::sync::Mutex::new(Some((header, from_client_rx, to_client_tx))),
        });
        let (server, client) = Ssh3TransportServerShared::new(mock, 16);
        tokio::spawn(async move { let _ = server.serve(true).await; });
        client
    }

    fn sample_init() -> SessionInit {
        SessionInit {
            conversation_id: StreamId(h3x::varint::VarInt::try_from(42u64).unwrap()),
            username: "alice".into(),
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/bash"),
        }
    }

    #[tokio::test]
    async fn run_session_happy_path() {
        let session = Ssh3Session::new();
        let transport = mock_transport_client();
        // Transport returns Ok(None) immediately, so run() completes.
        let result = session.run(transport, sample_init()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn run_session_fields_accessible() {
        let session = Ssh3Session::new();
        let init = SessionInit {
            conversation_id: StreamId(h3x::varint::VarInt::try_from(99u64).unwrap()),
            username: "bob".into(),
            uid: 2000,
            gid: 2000,
            home: PathBuf::from("/home/bob"),
            shell: PathBuf::from("/bin/zsh"),
        };
        assert_eq!(init.conversation_id, StreamId(h3x::varint::VarInt::try_from(99u64).unwrap()));
        assert_eq!(init.username, "bob");
        assert_eq!(init.uid, 2000);
        assert_eq!(init.gid, 2000);
        let transport = mock_transport_client();
        assert!(session.run(transport, init).await.is_ok());
    }

    #[test]
    fn impl_type_is_sync_send() {
        fn assert_sync_send<T: Sync + Send>() {}
        assert_sync_send::<Ssh3Session>();
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
    async fn recv_message(
        rx: &mut remoc::rch::mpsc::Receiver<Vec<u8>>,
        leftover: &mut Vec<u8>,
    ) -> SshMessage {
        loop {
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
            match rx.recv().await {
                Ok(Some(data)) => leftover.extend_from_slice(&data),
                Ok(None) => panic!("channel closed before message was fully received"),
                Err(e) => panic!("recv error: {e}"),
            }
        }
    }

    /// Integration test: send an exec request through a feeding transport and
    /// verify the full message lifecycle:
    ///   ChannelOpenConfirmation → ChannelSuccess → ChannelData → exit-status → EOF → Close
    #[tokio::test]
    async fn byte_bridge_session_echo() {
        let session = Ssh3Session::new();

        // Create remoc channel pairs for the session channel.
        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);

        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 42,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        let transport = mock_feeding_transport_client(header, from_rx, to_tx);

        let handle = tokio::spawn(async move {
            session.run(transport, sample_init()).await
        });

        tokio::task::yield_now().await;

        // Build the exec ChannelRequest: request_data is SshString("echo hello").
        let request_data = encode_ssh_string_to_bytes("echo hello").await;
        let exec_msg = SshMessage::ChannelRequest {
            request_type: "exec".into(),
            want_reply: true,
            request_data,
        };
        let exec_bytes = encode_msg_to_bytes(&exec_msg).await;

        from_tx.send(exec_bytes).await.unwrap();
        drop(from_tx);

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
        let mut got_data = false;
        let mut got_exit_status = false;
        let mut got_eof = false;
        let mut _got_close = false;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let result = tokio::time::timeout_at(
                deadline,
                recv_message(&mut to_rx, &mut leftover),
            ).await;
            match result {
                Ok(SshMessage::ChannelData { data }) => {
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
                    if !matches!(other, SshMessage::ChannelExtendedData { .. }) {
                        panic!("unexpected message: {other:?}");
                    }
                }
                Err(_) => {
                    break;
                }
            }
        }

        assert!(got_data, "expected ChannelData with 'hello' output");
        assert!(got_exit_status, "expected exit-status ChannelRequest");
        assert!(got_eof, "expected ChannelEof");

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            handle,
        ).await;
        assert!(result.is_ok(), "session task did not complete in time");
        assert!(result.unwrap().is_ok(), "session task panicked");
    }

    #[tokio::test]
    async fn handle_channel_rejects_unknown_type() {
        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 42,
            channel_type: "bogus-type".into(),
            max_message_size: 1 << 20,
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder: Arc::new(ReverseTcpForwarder::default()),
            streamlocal_forwarder: Arc::new(ReverseStreamlocalForwarder::default()),
            transport: mock_transport_client(),
            conversation_id: StreamId(h3x::varint::VarInt::try_from(42u64).unwrap()),
        });

        let result = Ssh3Session::handle_non_session_channel(header, from_rx, to_tx, ctx).await;
        assert!(result.is_err(), "expected error for unknown channel type");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown channel type"),
            "error should mention unknown channel type, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn handle_channel_dispatches_direct_tcpip() {
        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 42,
            channel_type: "direct-tcpip".into(),
            max_message_size: 1 << 20,
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder: Arc::new(ReverseTcpForwarder::default()),
            streamlocal_forwarder: Arc::new(ReverseStreamlocalForwarder::default()),
            transport: mock_transport_client(),
            conversation_id: StreamId(h3x::varint::VarInt::try_from(42u64).unwrap()),
        });

        let result = Ssh3Session::handle_non_session_channel(header, from_rx, to_tx, ctx).await;
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

    #[tokio::test]
    async fn handle_channel_global_request_needs_context() {
        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 42,
            channel_type: "global-request".into(),
            max_message_size: 1 << 20,
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder: Arc::new(ReverseTcpForwarder::default()),
            streamlocal_forwarder: Arc::new(ReverseStreamlocalForwarder::default()),
            transport: mock_transport_client(),
            conversation_id: StreamId(h3x::varint::VarInt::try_from(42u64).unwrap()),
        });

        let result = Ssh3Session::handle_non_session_channel(header, from_rx, to_tx, ctx).await;
        match result {
            Ok(()) => { /* handler may succeed with empty global-request channel */ }
            Err(e) => {
                let err_msg = e.to_string();
                assert!(
                    !err_msg.contains("unknown channel type"),
                    "global-request should not produce 'unknown channel type' error, got: {err_msg}"
                );
            }
        }
    }

    /// `run()` sends ChannelOpenConfirmation as the first message on a session channel.
    #[tokio::test]
    async fn run_session_sends_confirmation_first() {
        let session = Ssh3Session::new();

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);

        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 42,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        let transport = mock_feeding_transport_client(header, from_rx, to_tx);

        let handle = tokio::spawn(async move {
            session.run(transport, sample_init()).await
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

    // -----------------------------------------------------------------------
    // Transport RTC round-trip tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn accept_channel_round_trip() {
        use genmeta_ssh3_proto::session::Ssh3Transport;

        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 77,
            channel_type: "session".into(),
            max_message_size: 4096,
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);

        let client = mock_feeding_transport_client(header.clone(), from_rx, to_tx);

        // accept_channel via RTC should return the same header.
        let result = client.accept_channel().await.unwrap();
        let (got_header, mut got_rx, got_tx) = result.expect("expected Some channel");
        assert_eq!(got_header.conversation_id, 77);
        assert_eq!(got_header.channel_type, "session");
        assert_eq!(got_header.max_message_size, 4096);

        // Verify data flows: send through got_tx, receive via to_rx.
        got_tx.send(b"hello".to_vec()).await.unwrap();
        let data = to_rx.recv().await.unwrap().unwrap();
        assert_eq!(data, b"hello");

        // Verify data flows the other direction: from_tx → got_rx.
        from_tx.send(b"world".to_vec()).await.unwrap();
        let data = got_rx.recv().await.unwrap().unwrap();
        assert_eq!(data, b"world");

        // Second call should return None (feeding transport exhausted).
        let result = client.accept_channel().await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn open_channel_round_trip() {
        use genmeta_ssh3_proto::session::{Ssh3Transport, Ssh3TransportServerShared};
        use remoc::rtc::ServerShared;

        // Mock transport that captures the header and returns byte channels.
        struct OpenChannelMock {
            opened: tokio::sync::Mutex<Option<ChannelHeader>>,
        }

        impl Ssh3Transport for OpenChannelMock {
            async fn accept_channel(&self) -> Result<
                Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
                TransportError,
            > {
                Ok(None)
            }

            async fn open_channel(
                &self,
                header: Option<ChannelHeader>,
            ) -> Result<
                (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
                TransportError,
            > {
                if let Some(h) = header {
                    *self.opened.lock().await = Some(h);
                }
                let (tx, rx) = remoc::rch::mpsc::channel(16);
                Ok((rx, tx))
            }
        }

        let mock = std::sync::Arc::new(OpenChannelMock {
            opened: tokio::sync::Mutex::new(None),
        });
        let mock_ref = mock.clone();
        let (server, client): (_, Ssh3TransportClient) = Ssh3TransportServerShared::new(mock, 16);
        tokio::spawn(async move { let _ = server.serve(true).await; });

        let header = ChannelHeader {
            signal_value: 0,
            conversation_id: 88,
            channel_type: "direct-tcpip".into(),
            max_message_size: 8192,
        };

        let (mut rx, tx) = client.open_channel(Some(header)).await.unwrap();

        // Verify the mock received the header.
        let captured = mock_ref.opened.lock().await.take();
        let captured = captured.expect("mock should have received header");
        assert_eq!(captured.conversation_id, 88);
        assert_eq!(captured.channel_type, "direct-tcpip");

        // Verify data flows through the channels.
        tx.send(b"ping".to_vec()).await.unwrap();
        let data = rx.recv().await.unwrap().unwrap();
        assert_eq!(data, b"ping");
    }
}
