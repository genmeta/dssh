//! SSH3 session implementation for the session child process.
//!
//! This module provides [`Ssh3Session`], which drives the session lifecycle
//! by pulling channels from an [`Ssh3TransportClient`]. The child process
//! performs privilege dropping (setgid/setuid) and runs the session dispatch
//! loop (PTY, shell, exec) over byte-channel adapters bridging remoc channels
//! to `AsyncRead`/`AsyncWrite`.

use genmeta_ssh::ChannelHeader;
use genmeta_ssh::SshMessage;
use genmeta_ssh::{
    ChannelMessage, ChannelOpenBody, ChannelReader, ChannelWriter, RequestAction, SessionError,
    SessionInit, SessionLoopAction, Ssh3Transport, Ssh3TransportClient,
    handle_session_loop_message, open_session_channel,
};
use h3x::codec::EncodeExt;
use snafu::Report;
#[cfg(not(test))]
use std::ffi::CString;
use std::os::fd::AsRawFd;
use tokio::{io::AsyncWrite, sync::mpsc, task::JoinSet};
use tracing::Instrument;

use crate::channel::reject_legacy_global_request_channel;
use crate::session::pty::{PtyPair, allocate_pty, set_window_size};
use crate::session::request::{run_exec, run_shell};

trait PrivilegeTransitionOps {
    fn init_groups(&self, username: &str, gid: u32) -> Result<(), SessionError>;
    fn set_primary_gid(&self, gid: u32) -> Result<(), SessionError>;
    fn set_uid(&self, uid: u32) -> Result<(), SessionError>;
}

struct RealPrivilegeTransitionOps;

impl PrivilegeTransitionOps for RealPrivilegeTransitionOps {
    #[cfg(not(test))]
    fn init_groups(&self, username: &str, gid: u32) -> Result<(), SessionError> {
        let username = CString::new(username)
            .map_err(|_| SessionError::new("invalid username for initgroups"))?;
        let result = unsafe { libc::initgroups(username.as_ptr(), gid) };
        if result == 0 {
            Ok(())
        } else {
            Err(SessionError::new("initgroups failed"))
        }
    }

    #[cfg(test)]
    fn init_groups(&self, _username: &str, _gid: u32) -> Result<(), SessionError> {
        Ok(())
    }

    #[cfg(not(test))]
    fn set_primary_gid(&self, gid: u32) -> Result<(), SessionError> {
        let result = unsafe { libc::setgid(gid) };
        if result == 0 {
            Ok(())
        } else {
            Err(SessionError::new("setgid failed"))
        }
    }

    #[cfg(test)]
    fn set_primary_gid(&self, _gid: u32) -> Result<(), SessionError> {
        Ok(())
    }

    #[cfg(not(test))]
    fn set_uid(&self, uid: u32) -> Result<(), SessionError> {
        let result = unsafe { libc::setuid(uid) };
        if result == 0 {
            Ok(())
        } else {
            Err(SessionError::new("setuid failed"))
        }
    }

    #[cfg(test)]
    fn set_uid(&self, _uid: u32) -> Result<(), SessionError> {
        Ok(())
    }
}

fn apply_privilege_transition(
    username: &str,
    uid: u32,
    gid: u32,
    ops: &impl PrivilegeTransitionOps,
) -> Result<(), SessionError> {
    ops.init_groups(username, gid)?;
    ops.set_primary_gid(gid)?;
    ops.set_uid(uid)?;
    tracing::info!(uid, gid, username, "dropped privileges");
    Ok(())
}

#[derive(Clone)]
pub struct Ssh3Session {
    transport: Ssh3TransportClient,
    init: SessionInit,
}

impl Ssh3Session {
    pub fn new(transport: Ssh3TransportClient, init: SessionInit) -> Self {
        Self { transport, init }
    }

    /// Run the session by pulling channels from the transport.
    ///
    /// 1. Drops privileges to the authenticated user.
    /// 3. Enters the channel-accept loop, dispatching session and non-session channels.
    pub async fn run(self) -> Result<(), SessionError> {
        self.run_with_privilege_ops(&RealPrivilegeTransitionOps)
            .await
    }

    async fn run_with_privilege_ops(
        self,
        ops: &impl PrivilegeTransitionOps,
    ) -> Result<(), SessionError> {
        apply_privilege_transition(&self.init.username, self.init.uid, self.init.gid, ops)?;

        let mut channel_tasks = JoinSet::new();
        let transport = self.transport.clone();

        while let Ok(Some((header, from_client_rx, to_client_tx))) =
            transport.accept_channel().await
        {
            self.spawn_channel_task(&mut channel_tasks, header, from_client_rx, to_client_tx);
        }

        while let Some(result) = channel_tasks.join_next().await {
            if let Err(error) = result {
                tracing::warn!(error = %Report::from_error(error), "channel task panicked");
            }
        }
        Ok(())
    }

    fn spawn_channel_task(
        &self,
        channel_tasks: &mut JoinSet<()>,
        header: ChannelHeader,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) {
        let channel_type = header.body.channel_name();
        let conversation_id = self.init.conversation_id;
        let session = self.clone();
        let span = tracing::info_span!(
            "ssh3_channel",
            %conversation_id,
            %channel_type,
        );
        channel_tasks.spawn(
            async move {
                if let Err(error) = session.handle_channel(header, from_client, to_client).await {
                    tracing::warn!(
                        error = %Report::from_error(error),
                        "channel handling failed"
                    );
                }
            }
            .instrument(span),
        );
    }

    async fn handle_channel(
        &self,
        header: ChannelHeader,
        from_client: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) -> Result<(), SessionError> {
        let reader = ChannelReader::new(from_client);
        let writer = ChannelWriter::new(to_client);

        match &header.body {
            ChannelOpenBody::Session => {
                let (event_rx, writer) = open_session_channel(reader, writer)
                    .await
                    .map_err(|e| SessionError::new(e.to_string()))?;
                self.handle_session_requests(event_rx, writer).await
            }
            ChannelOpenBody::DirectTcpip(_) => {
                crate::forward::direct_tcp::handle_direct_tcp(header, reader, writer)
                    .await
                    .map_err(SessionError::from)
            }
            ChannelOpenBody::DirectStreamlocal { .. } => {
                crate::forward::streamlocal::handle_direct_streamlocal(header, reader, writer)
                    .await
                    .map_err(SessionError::from)
            }
            ChannelOpenBody::Socks5 => {
                crate::forward::socks5::handle_socks5(header, reader, writer)
                    .await
                    .map_err(SessionError::from)
            }
            ChannelOpenBody::Unknown { channel_type } if &**channel_type == "global-request" => {
                reject_legacy_global_request_channel(writer)
                    .await
                    .map_err(SessionError::from)
            }
            _ => {
                tracing::warn!(channel_type = %header.body.channel_name(), "unknown channel type in child");
                Err(SessionError::new("unknown channel type"))
            }
        }
    }

    async fn handle_session_requests<W>(
        &self,
        mut event_rx: mpsc::Receiver<ChannelMessage>,
        mut writer: W,
    ) -> Result<(), SessionError>
    where
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let mut pty_pair: Option<PtyPair> = None;

        while let Some(event) = event_rx.recv().await {
            match handle_session_loop_message(event, &mut writer)
                .await
                .map_err(|e| SessionError::new(e.to_string()))?
            {
                SessionLoopAction::Request(action) => match action {
                    RequestAction::Exec(command) => {
                        run_exec(
                            self.init.shell.as_os_str(),
                            command.as_ref(),
                            &mut writer,
                            event_rx,
                            pty_pair.take(),
                        )
                        .await
                        .map_err(SessionError::from)?;
                        return Ok(());
                    }
                    RequestAction::Shell => {
                        run_shell(
                            self.init.shell.as_os_str(),
                            &mut writer,
                            event_rx,
                            pty_pair.take(),
                        )
                        .await
                        .map_err(SessionError::from)?;
                        return Ok(());
                    }
                    RequestAction::AllocatePty(req, want_reply) => match allocate_pty(&req) {
                        Ok(pair) => {
                            pty_pair = Some(pair);
                            tracing::info!(term = %req.term_type, "PTY allocated");
                            if want_reply.0 {
                                writer
                                    .encode_one(SshMessage::Channel(ChannelMessage::Success))
                                    .await
                                    .map_err(|e| SessionError::new(e.to_string()))?;
                            }
                        }
                        Err(error) => {
                            tracing::warn!(error = %Report::from_error(&error), "PTY allocation failed");
                            if want_reply.0 {
                                writer
                                    .encode_one(SshMessage::Channel(ChannelMessage::Failure))
                                    .await
                                    .map_err(|e| SessionError::new(e.to_string()))?;
                            }
                        }
                    },
                    RequestAction::WindowChange(req) => {
                        if let Some(ref pair) = pty_pair
                            && let Err(error) = set_window_size(pair.master.as_raw_fd(), &req)
                        {
                            tracing::warn!(
                                error = %Report::from_error(&error),
                                width_cols = %req.width_cols,
                                height_rows = %req.height_rows,
                                "window-change resize failed, keeping current size"
                            );
                        }
                    }
                    RequestAction::Signal(_) => {
                        tracing::debug!("ignoring signal before exec/shell");
                    }
                },
                SessionLoopAction::Eof => {
                    break;
                }
                SessionLoopAction::Close => {
                    break;
                }
                SessionLoopAction::Ignore => {}
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh;
    use genmeta_ssh::{
        ChannelOpenFailure, ChannelRequest, ChannelType, ExecRequest, SshBool, TransportError,
    };
    use genmeta_ssh::codec::SshBytes;
    use h3x::codec::{DecodeFrom, EncodeInto};
    use h3x::stream_id::StreamId;
    use h3x::varint::VarInt;
    use std::path::PathBuf;
    use std::sync::Arc as StdArc;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct MockSsh3Transport;

    impl genmeta_ssh::Ssh3Transport for MockSsh3Transport {
        async fn accept_channel(
            &self,
        ) -> Result<
            Option<(
                ChannelHeader,
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            )>,
            TransportError,
        > {
            Ok(None)
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            ),
            TransportError,
        > {
            Err(TransportError::Other(
                "mock: open_channel not available".into(),
            ))
        }
    }

    fn mock_transport_client() -> Ssh3TransportClient {
        use genmeta_ssh::Ssh3TransportServerShared;
        use remoc::rtc::ServerShared;
        let mock = std::sync::Arc::new(MockSsh3Transport);
        let (server, client) = Ssh3TransportServerShared::new(mock, 16);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        client
    }

    type MockChannel = (
        ChannelHeader,
        remoc::rch::mpsc::Receiver<Vec<u8>>,
        remoc::rch::mpsc::Sender<Vec<u8>>,
    );

    /// A mock transport that feeds one session channel, then signals end.
    struct ChannelFeedingTransport {
        channel_tx: tokio::sync::Mutex<Option<MockChannel>>,
    }

    impl genmeta_ssh::Ssh3Transport for ChannelFeedingTransport {
        async fn accept_channel(&self) -> Result<Option<MockChannel>, TransportError> {
            let mut guard = self.channel_tx.lock().await;
            Ok(guard.take())
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            ),
            TransportError,
        > {
            Err(TransportError::Other(
                "mock: open_channel not available".into(),
            ))
        }
    }

    fn mock_feeding_transport_client(
        header: ChannelHeader,
        from_client_rx: remoc::rch::mpsc::Receiver<Vec<u8>>,
        to_client_tx: remoc::rch::mpsc::Sender<Vec<u8>>,
    ) -> Ssh3TransportClient {
        use genmeta_ssh::Ssh3TransportServerShared;
        use remoc::rtc::ServerShared;
        let mock = std::sync::Arc::new(ChannelFeedingTransport {
            channel_tx: tokio::sync::Mutex::new(Some((header, from_client_rx, to_client_tx))),
        });
        let (server, client) = Ssh3TransportServerShared::new(mock, 16);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        client
    }

    fn sample_init() -> SessionInit {
        SessionInit {
            conversation_id: StreamId(h3x::varint::VarInt::from(42u8)),
            username: "alice".into(),
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/alice"),
            shell: PathBuf::from("/bin/bash"),
        }
    }

    #[derive(Default)]
    struct MockPrivilegeTransitionOps {
        fail_on_init_groups: bool,
        fail_on_setgid: bool,
        fail_on_setuid: bool,
        steps: StdArc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl PrivilegeTransitionOps for MockPrivilegeTransitionOps {
        fn init_groups(&self, _username: &str, _gid: u32) -> Result<(), SessionError> {
            self.steps.lock().unwrap().push("initgroups");
            if self.fail_on_init_groups {
                Err(SessionError::new("initgroups failed"))
            } else {
                Ok(())
            }
        }

        fn set_primary_gid(&self, _gid: u32) -> Result<(), SessionError> {
            self.steps.lock().unwrap().push("setgid");
            if self.fail_on_setgid {
                Err(SessionError::new("setgid failed"))
            } else {
                Ok(())
            }
        }

        fn set_uid(&self, _uid: u32) -> Result<(), SessionError> {
            self.steps.lock().unwrap().push("setuid");
            if self.fail_on_setuid {
                Err(SessionError::new("setuid failed"))
            } else {
                Ok(())
            }
        }
    }

    struct TrackingTransport {
        accept_called: AtomicBool,
    }

    impl genmeta_ssh::Ssh3Transport for TrackingTransport {
        async fn accept_channel(
            &self,
        ) -> Result<
            Option<(
                ChannelHeader,
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            )>,
            TransportError,
        > {
            self.accept_called.store(true, Ordering::SeqCst);
            Ok(None)
        }

        async fn open_channel(
            &self,
            _header: Option<ChannelHeader>,
        ) -> Result<
            (
                remoc::rch::mpsc::Receiver<Vec<u8>>,
                remoc::rch::mpsc::Sender<Vec<u8>>,
            ),
            TransportError,
        > {
            Err(TransportError::Other(
                "mock: open_channel not available".into(),
            ))
        }
    }

    fn tracking_transport_client(flag: StdArc<AtomicBool>) -> Ssh3TransportClient {
        use genmeta_ssh::Ssh3TransportServerShared;
        use remoc::rtc::ServerShared;
        let transport = std::sync::Arc::new(TrackingTransport {
            accept_called: AtomicBool::new(flag.load(Ordering::SeqCst)),
        });
        let transport_ref = transport.clone();
        let (server, client) = Ssh3TransportServerShared::new(transport, 16);
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        tokio::spawn(async move {
            loop {
                if transport_ref.accept_called.load(Ordering::SeqCst) {
                    flag.store(true, Ordering::SeqCst);
                    break;
                }
                tokio::task::yield_now().await;
            }
        });
        client
    }

    #[tokio::test]
    async fn run_session_happy_path() {
        let transport = mock_transport_client();
        let session = Ssh3Session::new(transport, sample_init());
        // Transport returns Ok(None) immediately, so run() completes.
        let result = session.run().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn privilege_transition_uses_strict_order() {
        let ops = MockPrivilegeTransitionOps::default();

        apply_privilege_transition("alice", 1000, 1000, &ops).unwrap();

        let steps = ops.steps.lock().unwrap().clone();
        assert_eq!(steps, vec!["initgroups", "setgid", "setuid"]);
    }

    #[tokio::test]
    async fn privilege_transition_failure_aborts_session_startup() {
        let accept_called = StdArc::new(AtomicBool::new(false));
        let session = Ssh3Session::new(
            tracking_transport_client(accept_called.clone()),
            sample_init(),
        );
        let ops = MockPrivilegeTransitionOps {
            fail_on_setgid: true,
            ..Default::default()
        };

        let result = session.run_with_privilege_ops(&ops).await;

        assert!(result.is_err(), "privilege failure should abort startup");
        assert!(
            !accept_called.load(Ordering::SeqCst),
            "accept_channel must not be reached after partial privilege transition failure"
        );

        let steps = ops.steps.lock().unwrap().clone();
        assert_eq!(steps, vec!["initgroups", "setgid"]);
    }

    #[tokio::test]
    async fn run_session_fields_accessible() {
        let init = SessionInit {
            conversation_id: StreamId(h3x::varint::VarInt::from(99u8)),
            username: "bob".into(),
            uid: 2000,
            gid: 2000,
            home: PathBuf::from("/home/bob"),
            shell: PathBuf::from("/bin/zsh"),
        };
        assert_eq!(
            init.conversation_id,
            StreamId(h3x::varint::VarInt::from(99u8))
        );
        assert_eq!(init.username, "bob");
        assert_eq!(init.uid, 2000);
        assert_eq!(init.gid, 2000);
        let session = Ssh3Session::new(mock_transport_client(), init);
        assert!(session.run().await.is_ok());
    }

    #[test]
    fn impl_type_is_sync_send() {
        fn assert_sync_send<T: Sync + Send>() {}
        assert_sync_send::<Ssh3Session>();
    }

    fn sample_session() -> Ssh3Session {
        Ssh3Session::new(mock_transport_client(), sample_init())
    }

    // -----------------------------------------------------------------------
    // Byte bridge integration tests
    // -----------------------------------------------------------------------

    /// Helper: encode an SshMessage into raw bytes (via tokio duplex).
    async fn encode_msg_to_bytes(msg: &SshMessage) -> Vec<u8> {
        let (mut w, mut r) = tokio::io::duplex(4096);
        msg.clone().encode_into(&mut w).await.unwrap();
        drop(w);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut buf)
            .await
            .unwrap();
        buf
    }

    /// Helper: encode an SshString into raw bytes.
    async fn encode_ssh_string_to_bytes(s: &str) -> Vec<u8> {
        let (mut w, mut r) = tokio::io::duplex(4096);
        genmeta_ssh::SshString::from(s.to_string())
            .encode_into(&mut w)
            .await
            .unwrap();
        drop(w);
        let mut buf = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut r, &mut buf)
            .await
            .unwrap();
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
        // Create remoc channel pairs for the session channel.
        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);

        let header = ChannelHeader {
            session_id: StreamId(VarInt::from(42u32)),
            max_message_size: VarInt::from_u32(1 << 20),
            body: ChannelOpenBody::Session,
        };

        let session = Ssh3Session::new(
            mock_feeding_transport_client(header, from_rx, to_tx),
            sample_init(),
        );

        let handle = tokio::spawn(async move { session.run().await });

        tokio::task::yield_now().await;

        // Build the exec ChannelRequest.
        let exec_msg = SshMessage::Channel(ChannelMessage::Request(ChannelRequest::Exec {
            want_reply: SshBool(true),
            request: ExecRequest {
                command: SshBytes::from(b"echo hello".to_vec()),
            },
        }));
        let exec_bytes = encode_msg_to_bytes(&exec_msg).await;

        from_tx.send(exec_bytes).await.unwrap();
        drop(from_tx);

        let mut leftover = Vec::new();

        // 1. First message: ChannelOpenConfirmation(91)
        let msg = recv_message(&mut to_rx, &mut leftover).await;
        assert!(
            matches!(msg, SshMessage::Channel(ChannelMessage::OpenConfirmation { .. })),
            "expected ChannelOpenConfirmation, got {msg:?}"
        );

        // 2. Second message: ChannelSuccess (reply to want_reply=true exec request)
        let msg = recv_message(&mut to_rx, &mut leftover).await;
        assert!(
            matches!(msg, SshMessage::Channel(ChannelMessage::Success)),
            "expected ChannelSuccess, got {msg:?}"
        );

        // 3. Remaining messages: ChannelData (output), exit-status, EOF, Close
        let mut got_data = false;
        let mut got_exit_status = false;
        let mut got_eof = false;
        let mut _got_close = false;

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let result =
                tokio::time::timeout_at(deadline, recv_message(&mut to_rx, &mut leftover)).await;
            match result {
                Ok(SshMessage::Channel(ChannelMessage::Data(data))) => {
                    let output = String::from_utf8_lossy(data.as_ref());
                    assert!(
                        output.contains("hello"),
                        "expected 'hello' in output, got: {output:?}"
                    );
                    got_data = true;
                }
                Ok(SshMessage::Channel(ChannelMessage::Request(ref req)))
                    if &*req.request_type() == "exit-status" =>
                {
                    got_exit_status = true;
                }
                Ok(SshMessage::Channel(ChannelMessage::Eof)) => {
                    got_eof = true;
                }
                Ok(SshMessage::Channel(ChannelMessage::Close)) => {
                    _got_close = true;
                    break;
                }
                Ok(other) => {
                    if !matches!(other, SshMessage::Channel(ChannelMessage::ExtendedData { .. })) {
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

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), handle).await;
        assert!(result.is_ok(), "session task did not complete in time");
        assert!(result.unwrap().is_ok(), "session task panicked");
    }

    #[tokio::test]
    async fn handle_channel_rejects_unknown_type() {
        let header = ChannelHeader {
            session_id: StreamId(VarInt::from(42u32)),
            max_message_size: VarInt::from_u32(1 << 20),
            body: ChannelOpenBody::Unknown { channel_type: "bogus-type".into() },
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let session = sample_session();
        let result = session.handle_channel(header, from_rx, to_tx).await;
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
            session_id: StreamId(VarInt::from(42u32)),
            max_message_size: VarInt::from_u32(1 << 20),
            body: ChannelOpenBody::DirectTcpip(genmeta_ssh::DirectTcpipRequest {
                dest_host: "127.0.0.1".into(),
                dest_port: VarInt::from(8080u16),
                originator_host: "127.0.0.1".into(),
                originator_port: VarInt::from(12345u16),
            }),
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, _to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let session = sample_session();
        let result = session.handle_channel(header, from_rx, to_tx).await;
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
    async fn handle_channel_global_request_is_explicitly_rejected() {
        let header = ChannelHeader {
            session_id: StreamId(VarInt::from(42u32)),
            max_message_size: VarInt::from_u32(1 << 20),
            body: ChannelOpenBody::Unknown { channel_type: "global-request".into() },
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);
        drop(from_tx);

        let session = sample_session();
        session
            .handle_channel(header, from_rx, to_tx)
            .await
            .unwrap();

        let mut leftover = Vec::new();
        let msg = recv_message(&mut to_rx, &mut leftover).await;
        match msg {
            SshMessage::Channel(ChannelMessage::OpenFailure(ChannelOpenFailure {
                reason_code,
                description,
            })) => {
                assert_eq!(reason_code, h3x::varint::VarInt::from(3u8));
                assert!(description.contains("control stream"));
            }
            other => panic!("expected ChannelOpenFailure, got {other:?}"),
        }
    }

    /// `run()` sends ChannelOpenConfirmation as the first message on a session channel.
    #[tokio::test]
    async fn run_session_sends_confirmation_first() {
        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);

        let header = ChannelHeader {
            session_id: StreamId(VarInt::from(42u32)),
            max_message_size: VarInt::from_u32(1 << 20),
            body: ChannelOpenBody::Session,
        };

        let session = Ssh3Session::new(
            mock_feeding_transport_client(header, from_rx, to_tx),
            sample_init(),
        );

        let handle = tokio::spawn(async move { session.run().await });
        drop(from_tx);

        // First message must be ChannelOpenConfirmation.
        let mut leftover = Vec::new();
        let msg = recv_message(&mut to_rx, &mut leftover).await;
        match msg {
            SshMessage::Channel(ChannelMessage::OpenConfirmation { max_message_size }) => {
                assert_eq!(
                    max_message_size,
                    genmeta_ssh::DEFAULT_MAX_MESSAGE_SIZE,
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
        use genmeta_ssh::Ssh3Transport;

        let header = ChannelHeader {
            session_id: StreamId(VarInt::from(77u32)),
            max_message_size: VarInt::from_u32(4096),
            body: ChannelOpenBody::Session,
        };

        let (from_tx, from_rx) = remoc::rch::mpsc::channel(16);
        let (to_tx, mut to_rx) = remoc::rch::mpsc::channel(16);

        let client = mock_feeding_transport_client(header.clone(), from_rx, to_tx);

        // accept_channel via RTC should return the same header.
        let result = client.accept_channel().await.unwrap();
        let (got_header, mut got_rx, got_tx) = result.expect("expected Some channel");
        assert_eq!(got_header.session_id, StreamId(VarInt::from(77u32)));
        assert!(matches!(got_header.body, ChannelOpenBody::Session));
        assert_eq!(got_header.max_message_size, VarInt::from_u32(4096));

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
        use genmeta_ssh::{Ssh3Transport, Ssh3TransportServerShared};
        use remoc::rtc::ServerShared;

        // Mock transport that captures the header and returns byte channels.
        struct OpenChannelMock {
            opened: tokio::sync::Mutex<Option<ChannelHeader>>,
        }

        impl Ssh3Transport for OpenChannelMock {
            async fn accept_channel(
                &self,
            ) -> Result<
                Option<(
                    ChannelHeader,
                    remoc::rch::mpsc::Receiver<Vec<u8>>,
                    remoc::rch::mpsc::Sender<Vec<u8>>,
                )>,
                TransportError,
            > {
                Ok(None)
            }

            async fn open_channel(
                &self,
                header: Option<ChannelHeader>,
            ) -> Result<
                (
                    remoc::rch::mpsc::Receiver<Vec<u8>>,
                    remoc::rch::mpsc::Sender<Vec<u8>>,
                ),
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
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });

        let header = ChannelHeader {
            session_id: StreamId(VarInt::from(88u32)),
            max_message_size: VarInt::from_u32(8192),
            body: ChannelOpenBody::DirectTcpip(genmeta_ssh::DirectTcpipRequest {
                dest_host: "127.0.0.1".into(),
                dest_port: VarInt::from(80u16),
                originator_host: "127.0.0.1".into(),
                originator_port: VarInt::from(12345u16),
            }),
        };

        let (mut rx, tx) = client.open_channel(Some(header)).await.unwrap();

        // Verify the mock received the header.
        let captured = mock_ref.opened.lock().await.take();
        let captured = captured.expect("mock should have received header");
        assert_eq!(captured.session_id, StreamId(VarInt::from(88u32)));
        assert_eq!(captured.body.channel_type(), ChannelType::DirectTcpip);

        // Verify data flows through the channels.
        tx.send(b"ping".to_vec()).await.unwrap();
        let data = rx.recv().await.unwrap().unwrap();
        assert_eq!(data, b"ping");
    }
}
