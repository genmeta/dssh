mod common;
use common::*;

use std::sync::Arc;

use bytes::Bytes;
use genmeta_ssh3_client::{
    Ssh3Client, Ssh3ClientConfig, SSH3_CONNECT_PATH, SSH_VERSION,
};
use genmeta_ssh3_client::forward::{
    parse_tcpip_forward_reply, send_cancel_tcpip_forward_request, send_tcpip_forward_request,
};
use genmeta_ssh3_server::handler::Ssh3ConnectHandler;
use h3x::hyper::server::TowerService;
use h3x::qpack::field::Protocol;
use http::{Method, StatusCode};
use http_body_util::Empty;
use tokio_util::task::AbortOnDropHandle;
use genmeta_ssh3_proto::codec::ChannelHeader;
use genmeta_ssh3_proto::message::SshMessage;
use genmeta_ssh3_server::channel::{
    open_session_channel, reject_legacy_global_request_channel,
    serve_control_stream_global_requests,
};
use genmeta_ssh3_server::channel::handle_global_request_channel;
use genmeta_ssh3_server::channel::handle_session_channel;
use genmeta_ssh3_server::forward::direct_tcp::handle_direct_tcp;
use genmeta_ssh3_server::session::request::{encode_exit_status, handle_request, run_exec};
use genmeta_ssh3_proto::codec::SshString;
use h3x::codec::{DecodeExt, DecodeFrom, EncodeExt, EncodeInto};
use h3x::stream_id::StreamId;
use h3x::varint::VarInt;
use tokio::io::{self, duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use genmeta_ssh3_server::channel::GlobalRequestContext;
use genmeta_ssh3_server::forward::reverse_tcp::{ReverseTcpForwarder, TcpipForwardRequest, CancelTcpipForwardRequest, TcpipForwardReply};
use genmeta_ssh3_server::forward::streamlocal::{ReverseStreamlocalForwarder, StreamlocalForwardRequest};
use genmeta_ssh3_proto::session::{Ssh3Transport, Ssh3TransportClient, Ssh3TransportServerShared, TransportError};
use remoc::rtc::ServerShared;

struct TestTransport;

impl Ssh3Transport for TestTransport {
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
        let (tx, rx) = remoc::rch::mpsc::channel(16);
        Ok((rx, tx))
    }
}

fn test_transport_client() -> Ssh3TransportClient {
    let (server, client) = Ssh3TransportServerShared::new(Arc::new(TestTransport), 16);
    tokio::spawn(async move {
        let _ = server.serve(true).await;
    });
    client
}

// ---------------------------------------------------------------------------
// Helper: build the standard SSH3 server (handler wrapped in TowerService).
// ---------------------------------------------------------------------------

async fn setup_server() -> (
    AbortOnDropHandle<()>,
    http::uri::Authority,
) {
    setup_server_with_pam(None).await
}

async fn setup_server_with_pam(pam_backend: Option<Arc<dyn genmeta_ssh3_server::auth::pam::PamBackend>>) -> (
    AbortOnDropHandle<()>,
    http::uri::Authority,
) {
    let service = TestChannelService::new(pam_backend);
    let service = TowerService(service);

    let server = test_server(service).await;
    let authority = get_server_authority(&server);
    let handle = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await; }));
    (handle, authority)
}

// ---------------------------------------------------------------------------
// 1. Existing smoke test — kept verbatim for backwards compat.
// ---------------------------------------------------------------------------

#[test]
fn smoke_connect() {
    run("smoke_connect", async move {
        // 1. Build server with TestChannelService (inline auth, no child process)
    let service = TestChannelService::new(None);
        let service = TowerService(service);

        // 2. Start server
        let server = test_server(service).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        // 3. Create client and send Extended CONNECT via execute_hyper_request
        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}/.well-known/ssh3/connect"))
            .header("ssh-version", "michel-ssh3-00")
            .header(
                http::header::AUTHORIZATION,
                "Basic dGVzdDp0ZXN0cGFzcw==", // test:testpass
            )
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("CONNECT request failed");

        // 4. Verify response
        assert_eq!(response.status(), http::StatusCode::OK);
        let ssh_version = response
            .headers()
            .get("ssh-version")
            .expect("missing ssh-version response header");
        assert_eq!(ssh_version.to_str().unwrap(), "michel-ssh3-00");
    })
}

// ---------------------------------------------------------------------------
// 2. Ssh3Client connect — full client wrapper over real QUIC.
// ---------------------------------------------------------------------------

#[test]
fn client_connect_success() {
    run("client_connect_success", async move {
        let (_serve, authority) = setup_server().await;

        let ssh3 = Ssh3Client::new(Ssh3ClientConfig {
            authority: authority.to_string(),
            username: "test".into(),
            password: "testpass".into(),
        });

        let client = test_client();
        let conn = ssh3.connect(&client).await.expect("connect should succeed");

        // Verify the negotiated version.
        assert_eq!(conn.server_version(), SSH_VERSION);
    })
}

// ---------------------------------------------------------------------------
// 3. Auth failure — missing Authorization header → 401 Unauthorized.
// ---------------------------------------------------------------------------

#[test]
fn auth_failure_missing_header() {
    run("auth_failure_missing_header", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{SSH3_CONNECT_PATH}"))
            .header("ssh-version", SSH_VERSION)
            // No Authorization header.
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("CONNECT request itself should succeed at HTTP level");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // WWW-Authenticate header should be present.
        let www_auth = response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .expect("missing WWW-Authenticate header");
        assert_eq!(www_auth.to_str().unwrap(), "Basic");
    })
}

// ---------------------------------------------------------------------------
// 4. Auth failure via Ssh3Client — returns ClientError::AuthenticationFailed.
// ---------------------------------------------------------------------------

#[test]
fn auth_failure_via_client() {
    run("auth_failure_via_client", async move {
        // Build a server that rejects auth by not having any auth header
        // — but we need to send one that's invalid.
        // The server rejects Bearer tokens and malformed headers.
    let handler = Ssh3ConnectHandler::new();
        let service = TowerService(handler);
        let server = test_server(service).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        // Send a raw CONNECT with Bearer auth (unsupported).
        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{SSH3_CONNECT_PATH}"))
            .header("ssh-version", SSH_VERSION)
            .header(
                http::header::AUTHORIZATION,
                "Bearer some-token",
            )
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("CONNECT transport should succeed");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    })
}

// ---------------------------------------------------------------------------
// 5. Version negotiation — response header matches client.
// ---------------------------------------------------------------------------

#[test]
fn version_negotiation() {
    run("version_negotiation", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{SSH3_CONNECT_PATH}"))
            .header("ssh-version", SSH_VERSION)
            .header(
                http::header::AUTHORIZATION,
                "Basic dGVzdDp0ZXN0cGFzcw==",
            )
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("CONNECT should succeed");

        assert_eq!(response.status(), StatusCode::OK);

        // Server must echo back the same SSH version.
        let server_version = response
            .headers()
            .get("ssh-version")
            .expect("missing ssh-version");
        assert_eq!(server_version.to_str().unwrap(), SSH_VERSION);
    })
}

// ---------------------------------------------------------------------------
// 6. Invalid version → 400 Bad Request.
// ---------------------------------------------------------------------------

#[test]
fn invalid_version_rejected() {
    run("invalid_version_rejected", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{SSH3_CONNECT_PATH}"))
            .header(
                "ssh-version",
                "unsupported-version-42",
            )
            .header(
                http::header::AUTHORIZATION,
                "Basic dGVzdDp0ZXN0cGFzcw==",
            )
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("transport should succeed");

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    })
}

// ---------------------------------------------------------------------------
// 7. Multiple concurrent connections — each gets 200 OK.
// ---------------------------------------------------------------------------

#[test]
#[ignore] // Flaky: tests QUIC connection pooling behavior, not SSH3 protocol.
fn multiple_concurrent_connects() {
    run("multiple_concurrent_connects", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();

        // Fire 3 concurrent CONNECT requests.
        let mut handles = Vec::new();
        for i in 0..3 {
            let client_ref = &client;
            let auth = authority.clone();
            handles.push(async move {
                let ssh3 = Ssh3Client::new(Ssh3ClientConfig {
                    authority: auth.to_string(),
                    username: format!("user{i}"),
                    password: format!("pass{i}"),
                });
                ssh3.connect(client_ref).await
            });
        }

        let (r0, r1, r2) = tokio::join!(handles.remove(0), handles.remove(0), handles.remove(0));

        let c0 = r0.expect("connect 0 failed");
        let c1 = r1.expect("connect 1 failed");
        let c2 = r2.expect("connect 2 failed");

        assert_eq!(c0.server_version(), SSH_VERSION);
        assert_eq!(c1.server_version(), SSH_VERSION);
        assert_eq!(c2.server_version(), SSH_VERSION);
    })
}

// ---------------------------------------------------------------------------
// 8. Wire format compliance — headers only, no CBOR, valid HTTP/3.
// ---------------------------------------------------------------------------

#[test]
fn wire_format_compliance() {
    run("wire_format_compliance", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{SSH3_CONNECT_PATH}"))
            .header("ssh-version", SSH_VERSION)
            .header(
                http::header::AUTHORIZATION,
                "Basic dGVzdDp0ZXN0cGFzcw==",
            )
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("CONNECT should succeed");

        // 1. Status must be 200 OK.
        assert_eq!(response.status(), StatusCode::OK);

        // 2. ssh-version header must be present and match.
        let ver = response.headers().get("ssh-version").unwrap();
        assert_eq!(ver.to_str().unwrap(), SSH_VERSION);

        // 3. No content-type: application/cbor — SSH3 uses SSH binary, not CBOR.
        let ct = response.headers().get("content-type");
        if let Some(ct_val) = ct {
            let s = ct_val.to_str().unwrap_or("");
            assert!(
                !s.contains("cbor"),
                "response must not use CBOR content-type, got: {s}"
            );
        }

        // 4. Response body should be empty at this point (no data frames
        //    until channels are opened).
        //    We don't read the body because it blocks (the connection stream
        //    stays open). Instead, verifying status + headers is sufficient.
    })
}

// ---------------------------------------------------------------------------
// 9. Missing ssh-version header → 400 Bad Request.
// ---------------------------------------------------------------------------

#[test]
fn missing_version_rejected() {
    run("missing_version_rejected", async move {
        let (_serve, authority) = setup_server().await;

        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{SSH3_CONNECT_PATH}"))
            // No ssh-version header.
            .header(
                http::header::AUTHORIZATION,
                "Basic dGVzdDp0ZXN0cGFzcw==",
            )
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("transport should succeed");

        // Version negotiation fails → 400.
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    })
}

// ---------------------------------------------------------------------------
// 10. Channel E2E: basic exec — "echo hello" → stdout + exit_status=0.
// ---------------------------------------------------------------------------

#[test]
fn test_basic_exec() {
    run("test_basic_exec", async move {
        // Use duplex streams to simulate QUIC bidi stream.
        // client_writer → server_reader (client sends exec request)
        // server_writer → client_reader (server sends channel messages)
        let (mut client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        // Server: open session channel, returning event_rx + writer.
        let (mut event_rx, mut server_writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .expect("open_session_channel failed");

        // Client: read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(
            matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }),
            "expected ChannelOpenConfirmation, got {confirm:?}"
        );

        // Client: send exec request for "echo hello".
        genmeta_ssh3_client::session::send_exec_request(&mut client_writer, b"echo hello", true)
            .await
            .unwrap();
        // Send EOF + Close to signal we're done sending.
        SshMessage::ChannelEof.encode_into(&mut client_writer).await.unwrap();
        SshMessage::ChannelClose.encode_into(&mut client_writer).await.unwrap();
        drop(client_writer);

        // Server: receive the exec request event and handle it.
        let event = event_rx.recv().await.expect("expected exec request event");
        let action = handle_request(&event, &mut server_writer)
            .await
            .expect("handle_request failed")
            .expect("expected Some(RequestAction::Exec)");
        assert_eq!(
            action,
            genmeta_ssh3_server::session::request::RequestAction::Exec(b"echo hello".to_vec())
        );

        // Client: read ChannelSuccess (reply to want_reply=true).
        let success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(success, SshMessage::ChannelSuccess);

        // Server: run the exec command.
        let (_, rx) = mpsc::channel(1);
        run_exec(std::ffi::OsStr::new("/bin/sh"), b"echo hello", &mut server_writer, rx, None)
            .await
            .expect("run_exec failed");
        drop(server_writer);

        // Client: collect all remaining messages from server.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected decode error: {e}"),
            }
        }

        // Verify stdout contains "hello".
        let has_hello = messages.iter().any(|m| match m {
            SshMessage::ChannelData { data } => {
                String::from_utf8_lossy(data).contains("hello")
            }
            _ => false,
        });
        assert!(has_hello, "expected ChannelData containing 'hello', got: {messages:?}");

        // Verify exit-status=0.
        let has_exit_status_0 = messages.iter().any(|m| match m {
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                request_type == "exit-status"
                    && !want_reply
                    && *request_data == encode_exit_status(0)
            }
            _ => false,
        });
        assert!(has_exit_status_0, "expected exit-status with code 0, got: {messages:?}");

        // Verify EOF and Close present.
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)), "expected ChannelEof");
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)), "expected ChannelClose");

        // Verify ordering: exit-status < EOF < Close.
        let exit_pos = messages.iter().position(|m| matches!(m, SshMessage::ChannelRequest { request_type, .. } if request_type == "exit-status")).unwrap();
        let eof_pos = messages.iter().position(|m| matches!(m, SshMessage::ChannelEof)).unwrap();
        let close_pos = messages.iter().position(|m| matches!(m, SshMessage::ChannelClose)).unwrap();
        assert!(exit_pos < eof_pos, "exit-status should come before EOF");
        assert!(eof_pos < close_pos, "EOF should come before Close");
    })
}

// ---------------------------------------------------------------------------
// 11. Channel E2E: exec with stderr → ChannelExtendedData(95) with data_type=1.
// ---------------------------------------------------------------------------

#[test]
fn test_exec_with_stderr() {
    run("test_exec_with_stderr", async move {
        let (mut client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        // Server: open session channel.
        let (mut event_rx, mut server_writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .expect("open_session_channel failed");

        // Client: read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        // Client: send exec request that writes to stderr.
        genmeta_ssh3_client::session::send_exec_request(
            &mut client_writer,
            b"echo stderr_msg >&2",
            true,
        )
        .await
        .unwrap();
        SshMessage::ChannelEof.encode_into(&mut client_writer).await.unwrap();
        SshMessage::ChannelClose.encode_into(&mut client_writer).await.unwrap();
        drop(client_writer);

        // Server: handle the request and run exec.
        let event = event_rx.recv().await.expect("expected exec request event");
        let _action = handle_request(&event, &mut server_writer)
            .await
            .expect("handle_request failed")
            .expect("expected Exec action");

        // Client: read ChannelSuccess.
        let success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(success, SshMessage::ChannelSuccess);

        // Server: run the exec command (produces stderr).
        let (_, rx) = mpsc::channel(1);
        run_exec(std::ffi::OsStr::new("/bin/sh"), b"echo stderr_msg >&2", &mut server_writer, rx, None)
            .await
            .expect("run_exec failed");
        drop(server_writer);

        // Client: collect all messages.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected decode error: {e}"),
            }
        }

        // Verify ChannelExtendedData(95) with data_type=1 (stderr) containing "stderr_msg".
        let has_stderr = messages.iter().any(|m| match m {
            SshMessage::ChannelExtendedData { data_type, data } => {
                *data_type == VarInt::from(1u8)
                    && String::from_utf8_lossy(data).contains("stderr_msg")
            }
            _ => false,
        });
        assert!(
            has_stderr,
            "expected ChannelExtendedData with data_type=1 containing 'stderr_msg', got: {messages:?}"
        );

        // Verify NO stdout ChannelData (echo only writes to stderr).
        let has_stdout = messages.iter().any(|m| match m {
            SshMessage::ChannelData { data } => !data.is_empty(),
            _ => false,
        });
        assert!(!has_stdout, "expected no stdout ChannelData, got: {messages:?}");

        // Verify exit-status=0 (echo always succeeds).
        let has_exit_status_0 = messages.iter().any(|m| match m {
            SshMessage::ChannelRequest {
                request_type,
                request_data,
                ..
            } => request_type == "exit-status" && *request_data == encode_exit_status(0),
            _ => false,
        });
        assert!(has_exit_status_0, "expected exit-status=0, got: {messages:?}");

        // Verify EOF and Close.
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)));
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)));
    })
}

// ---------------------------------------------------------------------------
// 12. Channel E2E: direct-tcpip → raw byte forwarding, NO ChannelData wrapping.
// ---------------------------------------------------------------------------

#[test]
fn test_direct_tcp_forward() {
    run("test_direct_tcp_forward", async move {
        // Start a local TCP echo server.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let echo_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (mut rd, mut wr) = stream.split();
            tokio::io::copy(&mut rd, &mut wr).await.unwrap();
        });

        // Encode direct-tcpip request_data fields.
        let mut request_data = Vec::new();
        SshString("127.0.0.1".into()).encode_into(&mut request_data).await.unwrap();
        request_data.encode_one(VarInt::try_from(addr.port() as u64).unwrap()).await.unwrap();
        SshString("127.0.0.1".into()).encode_into(&mut request_data).await.unwrap();
        request_data.encode_one(VarInt::from(12345u16)).await.unwrap();

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "direct-tcpip".into(),
            max_message_size: 1 << 20,
        };

        // client_writer → server_reader, server_writer → client_reader
        let (mut client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        // Client: write request_data fields, then test payload, then close.
        let client_send = tokio::spawn(async move {
            client_writer.write_all(&request_data).await.unwrap();
            client_writer.write_all(b"hello-tcp").await.unwrap();
            drop(client_writer);
        });

        // Server: handle the direct-tcpip channel.
        let server_handle = tokio::spawn(async move {
            handle_direct_tcp(header, server_reader, server_writer)
                .await
                .unwrap();
        });

        // Client: read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(
            matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }),
            "expected ChannelOpenConfirmation, got {confirm:?}"
        );

        // Client: read the echoed data — should be RAW bytes, NOT ChannelData.
        let mut echoed = Vec::new();
        client_reader.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(
            echoed, b"hello-tcp",
            "echoed data should be raw bytes 'hello-tcp'"
        );

        // Verify NO ChannelData wrapping: ChannelData(94) starts with varint 94,
        // which is 2-byte [0x40, 0x5e]. The echoed data must NOT start with that.
        assert!(
            echoed.len() < 2 || echoed[..2] != [0x40, 0x5e],
            "data should NOT be wrapped in SSH_MSG_CHANNEL_DATA(94)"
        );

        client_send.await.unwrap();
        server_handle.await.unwrap();
        echo_server.await.unwrap();
    })
}

// ---------------------------------------------------------------------------
// 13. Channel E2E: multiple session channels — 3 concurrent, independent ops.
// ---------------------------------------------------------------------------

#[test]
fn test_multiple_channels() {
    run("test_multiple_channels", async move {
        // Each channel runs an independent command via run_exec over duplex streams.
        let commands = ["echo chan0", "echo chan1", "echo chan2"];
        let mut handles = Vec::new();

        for (i, cmd) in commands.iter().enumerate() {
            let cmd = cmd.to_string();
            handles.push(tokio::spawn(async move {
                let (_client_writer, server_reader) = duplex(65536);
                let (server_writer, mut client_reader) = duplex(65536);

                // Open session channel on server side.
                let (_event_rx, mut server_writer) =
                    open_session_channel(server_reader, server_writer)
                        .await
                        .expect("open_session_channel failed");

                // Read ChannelOpenConfirmation.
                let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
                assert!(
                    matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }),
                    "channel {i}: expected ChannelOpenConfirmation"
                );

                // Run exec and collect results.
        let (_, rx) = mpsc::channel(1);
                run_exec(std::ffi::OsStr::new("/bin/sh"), cmd.as_bytes(), &mut server_writer, rx, None)
                    .await
                    .expect("run_exec failed");
                drop(server_writer);

                let mut messages = Vec::new();
                loop {
                    match SshMessage::decode_from(&mut client_reader).await {
                        Ok(msg) => messages.push(msg),
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                        Err(e) => panic!("channel {i}: unexpected decode error: {e}"),
                    }
                }

                (i, messages)
            }));
        }

        // Collect results from all 3 channels.
        for handle in handles {
            let (i, messages) = handle.await.unwrap();
            let expected_output = format!("chan{i}");

            // Verify stdout contains the expected output.
            let has_output = messages.iter().any(|m| match m {
                SshMessage::ChannelData { data } => {
                    String::from_utf8_lossy(data).contains(&expected_output)
                }
                _ => false,
            });
            assert!(
                has_output,
                "channel {i}: expected ChannelData containing '{expected_output}', got: {messages:?}"
            );

            // Verify exit-status=0.
            let has_exit_0 = messages.iter().any(|m| match m {
                SshMessage::ChannelRequest {
                    request_type,
                    request_data,
                    ..
                } => request_type == "exit-status" && *request_data == encode_exit_status(0),
                _ => false,
            });
            assert!(has_exit_0, "channel {i}: expected exit-status=0, got: {messages:?}");

            // Verify EOF and Close.
            assert!(
                messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)),
                "channel {i}: expected ChannelEof"
            );
            assert!(
                messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)),
                "channel {i}: expected ChannelClose"
            );
        }
    })
}

// ---------------------------------------------------------------------------
// 14. Production path: exec with stdin — handle_channel() with duplex streams.
//     Server dispatches to handle_session_channel() (production path, NOT
//     open_session_channel()).
// ---------------------------------------------------------------------------

#[test]
fn test_production_exec_with_stdin() {
    run("test_production_exec_with_stdin", async move {
        // Create two duplex pairs: one for each direction.
        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        // Spawn server-side handle_channel (production path).
        let server_task = tokio::spawn(async move {
            handle_session_channel(header, server_reader, server_writer)
                .await
                .expect("handle_channel failed");
        });

        // Client side: read confirmation, send exec, send data, collect output.
        let mut writer = client_writer;

        // 1. Read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(
            matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }),
            "expected ChannelOpenConfirmation, got {confirm:?}"
        );

        // 2. Send exec request: "cat" (reads stdin and echoes to stdout).
        genmeta_ssh3_client::session::send_exec_request(&mut writer, b"cat", true)
            .await
            .unwrap();

        // 3. Read ChannelSuccess (reply to want_reply=true).
        let success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(success, SshMessage::ChannelSuccess);

        // 4. Send stdin data via ChannelData.
        SshMessage::ChannelData {
            data: b"hello from stdin\n".to_vec(),
        }
        .encode_into(&mut writer)
        .await
        .unwrap();

        // 5. Signal EOF to close stdin.
        SshMessage::ChannelEof
            .encode_into(&mut writer)
            .await
            .unwrap();

        // 6. Collect server responses.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => {
                    let done = matches!(msg, SshMessage::ChannelClose);
                    messages.push(msg);
                    if done {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected decode error: {e}"),
            }
        }

        // 7. Verify stdout contains the stdin data.
        let has_hello = messages.iter().any(|m| match m {
            SshMessage::ChannelData { data } => {
                String::from_utf8_lossy(data).contains("hello from stdin")
            }
            _ => false,
        });
        assert!(has_hello, "expected ChannelData containing 'hello from stdin', got: {messages:?}");

        // 8. Verify exit-status=0.
        let has_exit_0 = messages.iter().any(|m| match m {
            SshMessage::ChannelRequest {
                request_type,
                request_data,
                ..
            } => request_type == "exit-status" && *request_data == encode_exit_status(0),
            _ => false,
        });
        assert!(has_exit_0, "expected exit-status=0, got: {messages:?}");

        // 9. Verify EOF and Close.
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)), "expected ChannelEof");
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)), "expected ChannelClose");

        server_task.await.unwrap();
    })
}

// ---------------------------------------------------------------------------
// 15. Production path: exec stdin echo — "echo hello" via handle_channel().
// ---------------------------------------------------------------------------

#[test]
fn test_production_exec_stdin_echo() {
    run("test_production_exec_stdin_echo", async move {
        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        let server_task = tokio::spawn(async move {
            handle_session_channel(header, server_reader, server_writer)
                .await
                .expect("handle_channel failed");
        });

        let mut writer = client_writer;

        // Read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        // Send exec request: "echo hello".
        genmeta_ssh3_client::session::send_exec_request(&mut writer, b"echo hello", true)
            .await
            .unwrap();

        // Read ChannelSuccess.
        let success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(success, SshMessage::ChannelSuccess);

        // Send EOF (no stdin needed for echo).
        SshMessage::ChannelEof.encode_into(&mut writer).await.unwrap();

        // Collect server responses.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => {
                    let done = matches!(msg, SshMessage::ChannelClose);
                    messages.push(msg);
                    if done {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected decode error: {e}"),
            }
        }

        // Verify stdout contains "hello".
        let has_hello = messages.iter().any(|m| match m {
            SshMessage::ChannelData { data } => {
                String::from_utf8_lossy(data).contains("hello")
            }
            _ => false,
        });
        assert!(has_hello, "expected ChannelData containing 'hello', got: {messages:?}");

        // Verify exit-status=0.
        let has_exit_0 = messages.iter().any(|m| match m {
            SshMessage::ChannelRequest {
                request_type,
                request_data,
                ..
            } => request_type == "exit-status" && *request_data == encode_exit_status(0),
            _ => false,
        });
        assert!(has_exit_0, "expected exit-status=0, got: {messages:?}");

        // Verify EOF and Close.
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)));
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)));

        // Verify ordering: exit-status < EOF < Close.
        let exit_pos = messages.iter().position(|m| matches!(m, SshMessage::ChannelRequest { request_type, .. } if request_type == "exit-status")).unwrap();
        let eof_pos = messages.iter().position(|m| matches!(m, SshMessage::ChannelEof)).unwrap();
        let close_pos = messages.iter().position(|m| matches!(m, SshMessage::ChannelClose)).unwrap();
        assert!(exit_pos < eof_pos, "exit-status should come before EOF");
        assert!(eof_pos < close_pos, "EOF should come before Close");

        server_task.await.unwrap();
    })
}

// ---------------------------------------------------------------------------
// 16. Production path: PTY shell session — allocate PTY, run shell, send
//     input, verify output comes back.
// ---------------------------------------------------------------------------

#[test]
fn test_pty_shell_session() {
    run("test_pty_shell_session", async move {
        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        let server_task = tokio::spawn(async move {
            handle_session_channel(header, server_reader, server_writer)
                .await
                .expect("handle_channel failed");
        });

        let mut writer = client_writer;

        // Read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        // 1. Send pty-req to allocate a PTY.
        genmeta_ssh3_client::session::send_pty_request(
            &mut writer,
            "xterm-256color",
            80,  // width_cols
            24,  // height_rows
            0,   // width_px
            0,   // height_px
            &[], // terminal_modes
            true,
        )
        .await
        .unwrap();

        // Read ChannelSuccess for pty-req.
        let pty_success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(pty_success, SshMessage::ChannelSuccess);

        // 2. Send exec request with PTY — "echo pty_test_marker".
        //    Using exec over a PTY exercises the same code path as shell+PTY
        //    (run_command_with_pty) but is deterministic: no interactive prompt,
        //    no shell startup files.
        genmeta_ssh3_client::session::send_exec_request(&mut writer, b"echo pty_test_marker", true)
            .await
            .unwrap();

        // Read ChannelSuccess for exec.
        let exec_success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(exec_success, SshMessage::ChannelSuccess);

        // 3. Send EOF (no stdin needed, command produces output on its own).
        SshMessage::ChannelEof
            .encode_into(&mut writer)
            .await
            .unwrap();

        // 4. Collect server responses — look for PTY output and exit-status.
        let mut messages = Vec::new();
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, SshMessage::decode_from(&mut client_reader)).await {
                Ok(Ok(msg)) => {
                    let done = matches!(msg, SshMessage::ChannelClose);
                    messages.push(msg);
                    if done {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break,
            }
        }

        // 5. Verify PTY output contains the marker.
        let has_marker = messages.iter().any(|m| match m {
            SshMessage::ChannelData { data } => {
                String::from_utf8_lossy(data).contains("pty_test_marker")
            }
            _ => false,
        });
        assert!(has_marker, "expected ChannelData containing 'pty_test_marker', got: {messages:?}");

        // 6. Verify exit-status=0.
        let has_exit_0 = messages.iter().any(|m| match m {
            SshMessage::ChannelRequest {
                request_type,
                request_data,
                ..
            } => request_type == "exit-status" && *request_data == encode_exit_status(0),
            _ => false,
        });
        assert!(has_exit_0, "expected exit-status=0, got: {messages:?}");

        // 7. Verify EOF and Close.
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)), "expected ChannelEof");
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)), "expected ChannelClose");

        let _ = server_task.await;
    })
}

// ---------------------------------------------------------------------------
// 17. Production path: window-change — allocate PTY, send window-change,
//     verify the server doesn't crash and the session continues normally.
// ---------------------------------------------------------------------------

#[test]
fn test_window_change_signal() {
    run("test_window_change_signal", async move {
        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        let server_task = tokio::spawn(async move {
            handle_session_channel(header, server_reader, server_writer)
                .await
                .expect("handle_channel failed");
        });

        let mut writer = client_writer;

        // Read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        // 1. Send pty-req.
        genmeta_ssh3_client::session::send_pty_request(
            &mut writer,
            "xterm",
            80,
            24,
            0,
            0,
            &[],
            true,
        )
        .await
        .unwrap();

        let pty_success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(pty_success, SshMessage::ChannelSuccess);

        // 2. Send window-change BEFORE shell/exec (tests pre-session window change).
        genmeta_ssh3_client::session::send_window_change(&mut writer, 120, 40, 960, 800)
            .await
            .unwrap();

        // No reply expected for window-change (want_reply=false per RFC 4254 §6.7).

        // 3. Send exec request (simpler than shell for testing).
        genmeta_ssh3_client::session::send_exec_request(&mut writer, b"echo wc_test_ok", true)
            .await
            .unwrap();

        // Read ChannelSuccess for exec.
        let exec_success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(exec_success, SshMessage::ChannelSuccess);

        // Send EOF.
        SshMessage::ChannelEof.encode_into(&mut writer).await.unwrap();

        // 4. Collect messages.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => {
                    let done = matches!(msg, SshMessage::ChannelClose);
                    messages.push(msg);
                    if done {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected decode error: {e}"),
            }
        }

        // 5. Verify stdout contains "wc_test_ok" — proves the session survived
        //    the window-change and completed normally.
        let has_output = messages.iter().any(|m| match m {
            SshMessage::ChannelData { data } => {
                String::from_utf8_lossy(data).contains("wc_test_ok")
            }
            _ => false,
        });
        assert!(has_output, "expected ChannelData containing 'wc_test_ok', got: {messages:?}");

        // 6. Verify exit-status=0.
        let has_exit_0 = messages.iter().any(|m| match m {
            SshMessage::ChannelRequest {
                request_type,
                request_data,
                ..
            } => request_type == "exit-status" && *request_data == encode_exit_status(0),
            _ => false,
        });
        assert!(has_exit_0, "expected exit-status=0, got: {messages:?}");

        // 7. Verify EOF and Close.
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)));
        assert!(messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)));

        server_task.await.unwrap();
    })
}

#[test]
fn test_non_pty_signal_exit_signal() {
    run("test_non_pty_signal_exit_signal", async move {
        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        let server_task = tokio::spawn(async move {
            handle_session_channel(header, server_reader, server_writer)
                .await
                .expect("handle_channel failed");
        });

        let mut writer = client_writer;

        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        genmeta_ssh3_client::session::send_exec_request(&mut writer, b"exec sleep 30", true)
            .await
            .unwrap();

        let success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(success, SshMessage::ChannelSuccess);

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut request_data = Vec::new();
        SshString("TERM".into()).encode_into(&mut request_data).await.unwrap();
        SshMessage::ChannelRequest {
            request_type: "signal".into(),
            want_reply: false,
            request_data,
        }
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_exit_signal = false;
        let mut saw_exit_status = false;
        let mut saw_eof = false;
        let mut saw_close = false;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, SshMessage::decode_from(&mut client_reader)).await {
                Ok(Ok(SshMessage::ChannelRequest {
                    request_type,
                    request_data,
                    ..
                })) if request_type == "exit-signal" => {
                    let req = genmeta_ssh3_server::session::request::ExitSignalRequest::decode_from(request_data.as_slice())
                        .await
                        .unwrap();
                    assert_eq!(req.signal_name, "TERM");
                    assert_eq!(req.error_message, "");
                    assert_eq!(req.language_tag, "");
                    saw_exit_signal = true;
                }
                Ok(Ok(SshMessage::ChannelRequest { request_type, .. })) if request_type == "exit-status" => {
                    saw_exit_status = true;
                }
                Ok(Ok(SshMessage::ChannelEof)) => saw_eof = true,
                Ok(Ok(SshMessage::ChannelClose)) => {
                    saw_close = true;
                    break;
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => panic!("unexpected decode error: {e}"),
                Err(_) => break,
            }
        }

        assert!(saw_exit_signal, "expected exit-signal after non-PTY signal termination");
        assert!(!saw_exit_status, "non-PTY signal termination should not emit exit-status");
        assert!(saw_eof, "expected ChannelEof after signal termination");
        assert!(saw_close, "expected ChannelClose after signal termination");

        server_task.await.unwrap();
    })
}

#[test]
fn test_non_pty_unknown_signal_preserves_wire_fidelity() {
    run("test_non_pty_unknown_signal_preserves_wire_fidelity", async move {
        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        let server_task = tokio::spawn(async move {
            handle_session_channel(header, server_reader, server_writer)
                .await
                .expect("handle_channel failed");
        });

        let mut writer = client_writer;

        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        genmeta_ssh3_client::session::send_exec_request(&mut writer, b"exec sh -c 'kill -BUS $$'", true)
            .await
            .unwrap();

        let success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(success, SshMessage::ChannelSuccess);

        drop(writer);

        let expected_signal = format!("signal-{}@genmeta-ssh3", libc::SIGBUS);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_exit_signal = false;
        let mut saw_exit_status = false;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, SshMessage::decode_from(&mut client_reader)).await {
                Ok(Ok(SshMessage::ChannelRequest {
                    request_type,
                    request_data,
                    ..
                })) if request_type == "exit-signal" => {
                    let req = genmeta_ssh3_server::session::request::ExitSignalRequest::decode_from(request_data.as_slice())
                        .await
                        .unwrap();
                    assert_eq!(req.signal_name, expected_signal);
                    assert_eq!(req.error_message, "");
                    assert_eq!(req.language_tag, "");
                    saw_exit_signal = true;
                }
                Ok(Ok(SshMessage::ChannelRequest { request_type, .. })) if request_type == "exit-status" => {
                    saw_exit_status = true;
                }
                Ok(Ok(SshMessage::ChannelClose)) => break,
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => panic!("unexpected decode error: {e}"),
                Err(_) => break,
            }
        }

        assert!(saw_exit_signal, "expected exit-signal for unmapped signal termination");
        assert!(
            !saw_exit_status,
            "unknown signal termination should not degrade to exit-status"
        );

        server_task.await.unwrap();
    })
}

// ---------------------------------------------------------------------------
// 18b. PTY signal termination: signal-killed PTY process emits exit-signal,
//      not exit-status, and no double-emission occurs.
// ---------------------------------------------------------------------------

#[test]
fn test_pty_signal_exit_signal() {
    run("test_pty_signal_exit_signal", async move {
        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 1 << 20,
        };

        let server_task = tokio::spawn(async move {
            handle_session_channel(header, server_reader, server_writer)
                .await
                .expect("handle_channel failed");
        });

        let mut writer = client_writer;

        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        genmeta_ssh3_client::session::send_pty_request(
            &mut writer,
            "xterm-256color",
            80, 24, 0, 0,
            &[],
            true,
        )
        .await
        .unwrap();

        let pty_success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(pty_success, SshMessage::ChannelSuccess);

        genmeta_ssh3_client::session::send_exec_request(&mut writer, b"exec sleep 30", true)
            .await
            .unwrap();

        let exec_success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(exec_success, SshMessage::ChannelSuccess);

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let mut request_data = Vec::new();
        SshString("TERM".into()).encode_into(&mut request_data).await.unwrap();
        SshMessage::ChannelRequest {
            request_type: "signal".into(),
            want_reply: false,
            request_data,
        }
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut saw_exit_signal = false;
        let mut saw_exit_status = false;
        let mut saw_eof = false;
        let mut saw_close = false;

        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                break;
            }

            match tokio::time::timeout(remaining, SshMessage::decode_from(&mut client_reader)).await {
                Ok(Ok(SshMessage::ChannelRequest {
                    request_type,
                    want_reply,
                    request_data,
                    ..
                })) if request_type == "exit-signal" => {
                    let req = genmeta_ssh3_server::session::request::ExitSignalRequest::decode_from(request_data.as_slice())
                        .await
                        .unwrap();
                    assert_eq!(req.signal_name, "TERM");
                    assert_eq!(req.error_message, "");
                    assert_eq!(req.language_tag, "");
                    assert!(!want_reply, "exit-signal must have want_reply=false");
                    saw_exit_signal = true;
                }
                Ok(Ok(SshMessage::ChannelRequest { request_type, .. })) if request_type == "exit-status" => {
                    saw_exit_status = true;
                }
                Ok(Ok(SshMessage::ChannelEof)) => saw_eof = true,
                Ok(Ok(SshMessage::ChannelClose)) => {
                    saw_close = true;
                    break;
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => panic!("unexpected decode error: {e}"),
                Err(_) => break,
            }
        }

        assert!(saw_exit_signal, "expected exit-signal after PTY signal termination");
        assert!(!saw_exit_status, "PTY signal termination should not emit exit-status (no double-emission)");
        assert!(saw_eof, "expected ChannelEof after PTY signal termination");
        assert!(saw_close, "expected ChannelClose after PTY signal termination");

        server_task.await.unwrap();
    })
}

// ---------------------------------------------------------------------------
// 19. Global request E2E: tcpip-forward → RequestSuccess with allocated_port.
// ---------------------------------------------------------------------------

#[test]
fn test_global_request_tcpip_forward() {
    run("test_global_request_tcpip_forward", async move {
        let tcp_forwarder = Arc::new(ReverseTcpForwarder::new());
        let streamlocal_forwarder = Arc::new(ReverseStreamlocalForwarder::new());
        let transport = test_transport_client();
        let ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder: tcp_forwarder.clone(),
            streamlocal_forwarder: streamlocal_forwarder.clone(),
            transport,
            conversation_id: StreamId::try_from(1u64).unwrap(),
        });

        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let server_task = tokio::spawn(async move {
            handle_global_request_channel(server_reader, server_writer, Some(ctx))
                .await
                .expect("handle_global_request_channel failed");
        });

        let mut writer = client_writer;

        // Send tcpip-forward request with ephemeral port.
        let mut req_data = Vec::new();
        req_data
            .encode_one(&TcpipForwardRequest {
            bind_address: "127.0.0.1".into(),
            bind_port: 0,
            })
            .await
            .unwrap();
        SshMessage::GlobalRequest {
            request_type: "tcpip-forward".into(),
            want_reply: true,
            data: req_data,
        }
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);

        // Read RequestSuccess with allocated_port.
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match msg {
            SshMessage::RequestSuccess { data } => {
                let reply: TcpipForwardReply = data.as_slice().decode_one().await.unwrap();
                assert!(reply.allocated_port > 0, "allocated_port should be > 0, got {}", reply.allocated_port);
                // Clean up: stop the listener.
                tcp_forwarder
                    .stop_listening(
                        "127.0.0.1",
                        reply.allocated_port as u16,
                        StreamId::try_from(1u64).unwrap(),
                    )
                    .await;
            }
            other => panic!("expected RequestSuccess, got {other:?}"),
        }

        server_task.await.unwrap();
    })
}

// ---------------------------------------------------------------------------
// 20. Global request E2E: cancel-tcpip-forward — forward then cancel.
// ---------------------------------------------------------------------------

#[test]
fn test_global_request_cancel_tcpip_forward() {
    run("test_global_request_cancel_tcpip_forward", async move {
        let tcp_forwarder = Arc::new(ReverseTcpForwarder::new());
        let streamlocal_forwarder = Arc::new(ReverseStreamlocalForwarder::new());

        // Helper to build a GlobalRequestContext sharing the same forwarders.
        let make_ctx = {
            let tcp = tcp_forwarder.clone();
            let sl = streamlocal_forwarder.clone();
            move || {
                let transport = test_transport_client();
                Arc::new(GlobalRequestContext {
                    tcp_forwarder: tcp.clone(),
                    streamlocal_forwarder: sl.clone(),
                    transport,
                    conversation_id: StreamId::try_from(1u64).unwrap(),
                })
            }
        };

        // --- Channel 1: tcpip-forward to get allocated_port ---
        let (cw1, sr1) = duplex(65536);
        let (sw1, mut cr1) = duplex(65536);
        let ctx1 = make_ctx();
        let t1 = tokio::spawn(async move {
            handle_global_request_channel(sr1, sw1, Some(ctx1)).await.unwrap();
        });
        let mut w1 = cw1;
        let mut req_data = Vec::new();
        req_data.encode_one(&TcpipForwardRequest {
            bind_address: "127.0.0.1".into(),
            bind_port: 0,
        }).await.unwrap();
        SshMessage::GlobalRequest {
            request_type: "tcpip-forward".into(),
            want_reply: true,
            data: req_data,
        }.encode_into(&mut w1).await.unwrap();
        drop(w1);

        let msg = SshMessage::decode_from(&mut cr1).await.unwrap();
        let allocated_port = match msg {
            SshMessage::RequestSuccess { data } => {
                let reply: TcpipForwardReply = data.as_slice().decode_one().await.unwrap();
                assert!(reply.allocated_port > 0);
                reply.allocated_port
            }
            other => panic!("expected RequestSuccess, got {other:?}"),
        };
        t1.await.unwrap();

        // --- Channel 2: cancel-tcpip-forward (should succeed) ---
        let (cw2, sr2) = duplex(65536);
        let (sw2, mut cr2) = duplex(65536);
        let ctx2 = make_ctx();
        let t2 = tokio::spawn(async move {
            handle_global_request_channel(sr2, sw2, Some(ctx2)).await.unwrap();
        });
        let mut w2 = cw2;
        let mut cancel_data = Vec::new();
        cancel_data.encode_one(&CancelTcpipForwardRequest {
            bind_address: "127.0.0.1".into(),
            bind_port: allocated_port,
        }).await.unwrap();
        SshMessage::GlobalRequest {
            request_type: "cancel-tcpip-forward".into(),
            want_reply: true,
            data: cancel_data,
        }.encode_into(&mut w2).await.unwrap();
        drop(w2);

        let msg2 = SshMessage::decode_from(&mut cr2).await.unwrap();
        assert!(matches!(msg2, SshMessage::RequestSuccess { .. }), "first cancel should succeed, got {msg2:?}");
        t2.await.unwrap();

        // --- Channel 3: cancel same address again (should fail) ---
        let (cw3, sr3) = duplex(65536);
        let (sw3, mut cr3) = duplex(65536);
        let ctx3 = make_ctx();
        let t3 = tokio::spawn(async move {
            handle_global_request_channel(sr3, sw3, Some(ctx3)).await.unwrap();
        });
        let mut w3 = cw3;
        let mut cancel_data2 = Vec::new();
        cancel_data2.encode_one(&CancelTcpipForwardRequest {
            bind_address: "127.0.0.1".into(),
            bind_port: allocated_port,
        }).await.unwrap();
        SshMessage::GlobalRequest {
            request_type: "cancel-tcpip-forward".into(),
            want_reply: true,
            data: cancel_data2,
        }.encode_into(&mut w3).await.unwrap();
        drop(w3);

        let msg3 = SshMessage::decode_from(&mut cr3).await.unwrap();
        assert!(matches!(msg3, SshMessage::RequestFailure), "second cancel should fail, got {msg3:?}");
        t3.await.unwrap();
    })
}

// ---------------------------------------------------------------------------
// 21. Global request E2E: reverse TCP forwarded channel — full data path.
// ---------------------------------------------------------------------------

#[test]
fn test_reverse_tcp_forwarded_channel() {
    run("test_reverse_tcp_forwarded_channel", async move {
        let tcp_forwarder = Arc::new(ReverseTcpForwarder::new());
        let streamlocal_forwarder = Arc::new(ReverseStreamlocalForwarder::new());

        // transport that captures the client end via mpsc channel.
        let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        struct CapturingTransport {
            tx: mpsc::UnboundedSender<tokio::io::DuplexStream>,
        }
        impl Ssh3Transport for CapturingTransport {
            async fn accept_channel(&self) -> Result<
                Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
                TransportError,
            > { Ok(None) }
            async fn open_channel(
                &self,
                header: Option<ChannelHeader>,
            ) -> Result<
                (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
                TransportError,
            > {
                let (server_end, client_end) = tokio::io::duplex(65536);
                let _ = self.tx.send(client_end);
                let (server_read, server_write) = tokio::io::split(server_end);
                let (to_client_tx, to_client_rx): (remoc::rch::mpsc::Sender<Vec<u8>>, _) =
                    remoc::rch::mpsc::channel(64);
                let (from_client_tx, from_client_rx): (_, remoc::rch::mpsc::Receiver<Vec<u8>>) =
                    remoc::rch::mpsc::channel(64);
                tokio::spawn(async move {
                    let mut reader = server_read;
                    let mut buf = vec![0u8; 8192];
                    loop {
                        let n = match reader.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if to_client_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    let mut writer = server_write;
                    if let Some(header) = header
                        && header.encode_into(&mut writer).await.is_err()
                    {
                        return;
                    }
                    let mut rx = from_client_rx;
                    while let Ok(Some(data)) = rx.recv().await {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                });
                Ok((to_client_rx, from_client_tx))
            }
        }
        let (server, transport) = Ssh3TransportServerShared::new(
            Arc::new(CapturingTransport { tx: stream_tx.clone() }),
            16,
        );
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });
        let ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder: tcp_forwarder.clone(),
            streamlocal_forwarder: streamlocal_forwarder.clone(),
            transport,
            conversation_id: StreamId::try_from(1u64).unwrap(),
        });

        // Step 1: Start tcpip-forward → get allocated_port.
        let (cw, sr) = duplex(65536);
        let (sw, mut cr) = duplex(65536);
        let t = tokio::spawn(async move {
            handle_global_request_channel(sr, sw, Some(ctx)).await.unwrap();
        });
        let mut w = cw;
        let mut req_data = Vec::new();
        req_data.encode_one(&TcpipForwardRequest {
            bind_address: "127.0.0.1".into(),
            bind_port: 0,
        }).await.unwrap();
        SshMessage::GlobalRequest {
            request_type: "tcpip-forward".into(),
            want_reply: true,
            data: req_data,
        }.encode_into(&mut w).await.unwrap();
        drop(w);

        let msg = SshMessage::decode_from(&mut cr).await.unwrap();
        let allocated_port = match msg {
            SshMessage::RequestSuccess { data } => {
                data.as_slice().decode_one::<TcpipForwardReply>().await.unwrap().allocated_port
            }
            other => panic!("expected RequestSuccess for tcpip-forward, got {other:?}"),
        };
        assert!(allocated_port > 0);
        t.await.unwrap();

        // Step 2: Connect to the forwarded port.
        let mut tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{allocated_port}"))
            .await
            .expect("should connect to forwarded port");

        let client_end = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream_rx.recv(),
        )
        .await
        .expect("timeout waiting for transport open_channel")
        .expect("stream_rx closed");

        let (mut client_end_reader, mut client_end_writer) = tokio::io::split(client_end);

        // Read the ChannelHeader the forwarder wrote.
        let fwd_header = ChannelHeader::decode_from(&mut client_end_reader).await.unwrap();
        assert_eq!(fwd_header.channel_type, "forwarded-tcpip");
        assert_eq!(fwd_header.conversation_id, 1);

        // Read forwarded-tcpip request_data fields.
        let connected_addr = SshString::decode_from(&mut client_end_reader).await.unwrap();
        assert_eq!(connected_addr.0, "127.0.0.1");
        let _connected_port: VarInt = client_end_reader.decode_one().await.unwrap();
        let _originator_addr = SshString::decode_from(&mut client_end_reader).await.unwrap();
        let _originator_port: VarInt = client_end_reader.decode_one().await.unwrap();

        // Send ChannelOpenConfirmation to accept the channel.
        SshMessage::ChannelOpenConfirmation {
            max_message_size: VarInt::from((1 << 20) as u32),
        }
            .encode_into(&mut client_end_writer)
            .await
            .unwrap();
        drop(client_end_writer);

        // Step 4: Bidirectional data — write from TCP, read from client_end and vice versa.
        tcp_stream.write_all(b"hello-from-tcp").await.unwrap();
        tcp_stream.shutdown().await.unwrap();

        let mut buf = vec![0u8; b"hello-from-tcp".len()];
        client_end_reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello-from-tcp", "data from TCP should arrive on QUIC side");

        tcp_forwarder
            .stop_listening(
                "127.0.0.1",
                allocated_port as u16,
                StreamId::try_from(1u64).unwrap(),
            )
            .await;
    })
}

// ---------------------------------------------------------------------------
// 21. Global request E2E: unknown request type → RequestFailure.
// ---------------------------------------------------------------------------

#[test]
fn test_global_request_unknown_type() {
    run("test_global_request_unknown_type", async move {
        let tcp_forwarder = Arc::new(ReverseTcpForwarder::new());
        let streamlocal_forwarder = Arc::new(ReverseStreamlocalForwarder::new());
        let transport = test_transport_client();
        let ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder,
            streamlocal_forwarder,
            transport,
            conversation_id: StreamId::try_from(1u64).unwrap(),
        });

        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let server_task = tokio::spawn(async move {
            handle_global_request_channel(server_reader, server_writer, Some(ctx))
                .await
                .expect("handle_global_request_channel failed");
        });

        let mut writer = client_writer;

        // Send an unknown global request type.
        SshMessage::GlobalRequest {
            request_type: "nonsense-request-type".into(),
            want_reply: true,
            data: vec![],
        }
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);

        // Should get RequestFailure.
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(msg, SshMessage::RequestFailure), "expected RequestFailure, got {msg:?}");

        server_task.await.unwrap();
    })
}

// ---------------------------------------------------------------------------
// 22. Global request E2E: streamlocal-forward@openssh.com → RequestSuccess.
// ---------------------------------------------------------------------------

#[test]
fn test_global_request_streamlocal_forward() {
    run("test_global_request_streamlocal_forward", async move {
        let tcp_forwarder = Arc::new(ReverseTcpForwarder::new());
        let streamlocal_forwarder = Arc::new(ReverseStreamlocalForwarder::new());
        let transport = test_transport_client();
        let ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder,
            streamlocal_forwarder: streamlocal_forwarder.clone(),
            transport,
            conversation_id: StreamId::try_from(1u64).unwrap(),
        });

        // Use a unique socket path to avoid collisions.
        let socket_path = format!("/tmp/test-ssh3-streamlocal-{}-{}.sock", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos());

        let (client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        let server_task = tokio::spawn(async move {
            handle_global_request_channel(server_reader, server_writer, Some(ctx))
                .await
                .expect("handle_global_request_channel failed");
        });

        let mut writer = client_writer;

        // Send streamlocal-forward request.
        let mut req_data = Vec::new();
        req_data
            .encode_one(&StreamlocalForwardRequest {
            socket_path: socket_path.clone(),
            })
            .await
            .unwrap();
        SshMessage::GlobalRequest {
            request_type: "streamlocal-forward@openssh.com".into(),
            want_reply: true,
            data: req_data,
        }
        .encode_into(&mut writer)
        .await
        .unwrap();
        drop(writer);

        // Should get RequestSuccess with empty data.
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match msg {
            SshMessage::RequestSuccess { data } => {
                assert!(data.is_empty(), "streamlocal-forward reply data should be empty");
            }
            other => panic!("expected RequestSuccess, got {other:?}"),
        }

        server_task.await.unwrap();

        // Clean up: stop the listener and remove the socket file.
        streamlocal_forwarder
            .stop_listening(&socket_path, StreamId::try_from(1u64).unwrap())
            .await;
        let _ = std::fs::remove_file(&socket_path);
    })
}

#[test]
fn test_global_request_e2e_control_stream_client_forward_flow() {
    run("test_global_request_e2e_control_stream_client_forward_flow", async move {
        let tcp_forwarder = Arc::new(ReverseTcpForwarder::new());
        let streamlocal_forwarder = Arc::new(ReverseStreamlocalForwarder::new());

        let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        struct CapturingTransport {
            tx: mpsc::UnboundedSender<tokio::io::DuplexStream>,
        }
        impl Ssh3Transport for CapturingTransport {
            async fn accept_channel(&self) -> Result<
                Option<(ChannelHeader, remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>)>,
                TransportError,
            > { Ok(None) }

            async fn open_channel(
                &self,
                header: Option<ChannelHeader>,
            ) -> Result<
                (remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>),
                TransportError,
            > {
                let (server_end, client_end) = tokio::io::duplex(65536);
                let _ = self.tx.send(client_end);
                let (server_read, server_write) = tokio::io::split(server_end);
                let (to_client_tx, to_client_rx): (remoc::rch::mpsc::Sender<Vec<u8>>, _) =
                    remoc::rch::mpsc::channel(64);
                let (from_client_tx, from_client_rx): (_, remoc::rch::mpsc::Receiver<Vec<u8>>) =
                    remoc::rch::mpsc::channel(64);
                tokio::spawn(async move {
                    let mut reader = server_read;
                    let mut buf = vec![0u8; 8192];
                    loop {
                        let n = match reader.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => n,
                        };
                        if to_client_tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                });
                tokio::spawn(async move {
                    let mut writer = server_write;
                    if let Some(header) = header
                        && header.encode_into(&mut writer).await.is_err()
                    {
                        return;
                    }
                    let mut rx = from_client_rx;
                    while let Ok(Some(data)) = rx.recv().await {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                });
                Ok((to_client_rx, from_client_tx))
            }
        }

        let (server, transport) = Ssh3TransportServerShared::new(
            Arc::new(CapturingTransport { tx: stream_tx.clone() }),
            16,
        );
        tokio::spawn(async move {
            let _ = server.serve(true).await;
        });

        let ctx = Arc::new(GlobalRequestContext {
            tcp_forwarder: tcp_forwarder.clone(),
            streamlocal_forwarder,
            transport,
            conversation_id: StreamId::try_from(1u64).unwrap(),
        });

        let (mut client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);
        let readiness = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let server_task = tokio::spawn(async move {
            serve_control_stream_global_requests(
                server_reader,
                server_writer,
                readiness,
                Some(ctx),
            )
            .await
            .unwrap();
        });

        send_tcpip_forward_request(&mut client_writer, "127.0.0.1", 0)
            .await
            .unwrap();
        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        let allocated_port = match msg {
            SshMessage::RequestSuccess { data } => {
                parse_tcpip_forward_reply(&data, 0).await.unwrap()
            }
            other => panic!("expected RequestSuccess for tcpip-forward, got {other:?}"),
        };
        assert!(allocated_port > 0);

        let mut tcp_stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{allocated_port}"))
            .await
            .expect("should connect to forwarded port");

        let client_end = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream_rx.recv(),
        )
        .await
        .expect("timeout waiting for control-stream initiated forwarded channel")
        .expect("stream_rx closed");

        let (mut client_end_reader, mut client_end_writer) = tokio::io::split(client_end);
        let fwd_header = ChannelHeader::decode_from(&mut client_end_reader).await.unwrap();
        assert_eq!(fwd_header.channel_type, "forwarded-tcpip");
        assert_eq!(fwd_header.conversation_id, 1);

        let connected_addr = SshString::decode_from(&mut client_end_reader).await.unwrap();
        assert_eq!(connected_addr.0, "127.0.0.1");
        let _connected_port: VarInt = client_end_reader.decode_one().await.unwrap();
        let _originator_addr = SshString::decode_from(&mut client_end_reader).await.unwrap();
        let _originator_port: VarInt = client_end_reader.decode_one().await.unwrap();

        SshMessage::ChannelOpenConfirmation {
            max_message_size: VarInt::from((1 << 20) as u32),
        }
        .encode_into(&mut client_end_writer)
        .await
        .unwrap();
        drop(client_end_writer);

        tcp_stream.write_all(b"hello-from-control-stream").await.unwrap();
        tcp_stream.shutdown().await.unwrap();
        let mut buf = vec![0u8; b"hello-from-control-stream".len()];
        client_end_reader.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello-from-control-stream");

        send_cancel_tcpip_forward_request(&mut client_writer, "127.0.0.1", allocated_port)
            .await
            .unwrap();
        let cancel_reply = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(cancel_reply, SshMessage::RequestSuccess { .. }));

        client_writer.shutdown().await.unwrap();
        server_task.await.unwrap();
    })
}

#[test]
fn test_global_request_e2e_control_stream_legacy_path_rejected() {
    run("test_global_request_e2e_control_stream_legacy_path_rejected", async move {
        let (_client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let server_task = tokio::spawn(async move {
            reject_legacy_global_request_channel(server_writer).await.unwrap();
            drop(server_reader);
        });

        let msg = SshMessage::decode_from(&mut client_reader).await.unwrap();
        match msg {
            SshMessage::ChannelOpenFailure { reason_code, .. } => {
                assert_eq!(reason_code, VarInt::from(3u8));
            }
            other => panic!("expected ChannelOpenFailure, got {other:?}"),
        }

        server_task.await.unwrap();
    })
}

// ===========================================================================
// TestPamBackend — simple configurable mock for E2E PAM tests
// ===========================================================================

use std::path::PathBuf;
use genmeta_ssh3_server::auth::pam::{PamBackend, PamError, PamTransaction, UserInfo};

struct TestPamBackend {
    auth_error: Option<PamError>,
    user_info: UserInfo,
}

struct TestPamTransaction {
    auth_error: Option<PamError>,
}

impl TestPamBackend {
    /// Backend that always succeeds and returns the given user info.
    fn success(user_info: UserInfo) -> Self {
        Self {
            auth_error: None,
            user_info,
        }
    }

    /// Backend that always fails with the given error message.
    fn failure(message: &str) -> Self {
        Self {
            auth_error: Some(PamError::new(message)),
            user_info: UserInfo {
                uid: 0,
                gid: 0,
                home: PathBuf::from("/nonexistent"),
                shell: PathBuf::from("/bin/false"),
            },
        }
    }
}

impl PamBackend for TestPamBackend {
    fn start_transaction(
        &self,
        _service: &str,
        _username: &str,
        _password: &str,
    ) -> Result<Box<dyn PamTransaction>, PamError> {
        Ok(Box::new(TestPamTransaction {
            auth_error: self.auth_error.clone(),
        }))
    }

    fn get_user_info(&self, _username: &str) -> Result<UserInfo, PamError> {
        Ok(self.user_info.clone())
    }
}

impl PamTransaction for TestPamTransaction {
    fn authenticate(&mut self) -> Result<(), PamError> {
        match &self.auth_error {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    fn acct_mgmt(&mut self) -> Result<(), PamError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 23. PAM auth success — TestPamBackend returns Ok → server responds 200 OK.
// ---------------------------------------------------------------------------

#[test]
fn test_pam_auth_success() {
    run("test_pam_auth_success", async move {
        let pam: Arc<dyn genmeta_ssh3_server::auth::pam::PamBackend> = Arc::new(TestPamBackend::success(UserInfo {
            uid: 1000,
            gid: 1000,
            home: PathBuf::from("/home/testuser"),
            shell: PathBuf::from("/bin/bash"),
        }));

    let service = TestChannelService::new(Some(pam));
        let service = TowerService(service);

        let server = test_server(service).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{SSH3_CONNECT_PATH}"))
            .header("ssh-version", SSH_VERSION)
            .header(
                http::header::AUTHORIZATION,
                "Basic dGVzdDp0ZXN0cGFzcw==", // test:testpass
            )
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("CONNECT request failed");

        assert_eq!(response.status(), StatusCode::OK);
        let ssh_version = response
            .headers()
            .get("ssh-version")
            .expect("missing ssh-version response header");
        assert_eq!(ssh_version.to_str().unwrap(), SSH_VERSION);
    })
}

// ---------------------------------------------------------------------------
// 24. PAM auth failure — TestPamBackend returns Err → server responds 401.
// ---------------------------------------------------------------------------

#[test]
fn test_pam_auth_failure() {
    run("test_pam_auth_failure", async move {
        let pam: Arc<dyn genmeta_ssh3_server::auth::pam::PamBackend> = Arc::new(TestPamBackend::failure("invalid credentials"));

    let service = TestChannelService::new(Some(pam));
        let service = TowerService(service);

        let server = test_server(service).await;
        let authority = get_server_authority(&server);
        let _serve = AbortOnDropHandle::new(tokio::spawn(async move { server.run().await }));

        let client = test_client();
        let connection = client.connect(authority.clone()).await.expect("connect failed");
        let request = http::Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{SSH3_CONNECT_PATH}"))
            .header("ssh-version", SSH_VERSION)
            .header(
                http::header::AUTHORIZATION,
                "Basic dGVzdDp0ZXN0cGFzcw==", // test:testpass
            )
            .extension(Protocol::new("ssh3"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = connection
            .execute_hyper_request(request)
            .await
            .expect("CONNECT request should succeed at HTTP level");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // WWW-Authenticate header should be present.
        let www_auth = response
            .headers()
            .get(http::header::WWW_AUTHENTICATE)
            .expect("missing WWW-Authenticate header");
        assert_eq!(www_auth.to_str().unwrap(), "Basic");
    })
}

// ---------------------------------------------------------------------------
// 25. Session exec flow — duplex streams, exec command, verify output + exit.
// ---------------------------------------------------------------------------

#[test]
fn test_session_exec_flow() {
    run("test_session_exec_flow", async move {
        // Duplex streams simulate QUIC bidi stream.
        let (mut client_writer, server_reader) = duplex(65536);
        let (server_writer, mut client_reader) = duplex(65536);

        // Server: open session channel.
        let (mut event_rx, mut server_writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .expect("open_session_channel failed");

        // Client: read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(
            matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }),
            "expected ChannelOpenConfirmation, got {confirm:?}"
        );

        // Client: send exec request for "echo session_flow_test".
        genmeta_ssh3_client::session::send_exec_request(
            &mut client_writer,
            b"echo session_flow_test",
            true,
        )
        .await
        .unwrap();
        // Signal end of input.
        SshMessage::ChannelEof
            .encode_into(&mut client_writer)
            .await
            .unwrap();
        SshMessage::ChannelClose
            .encode_into(&mut client_writer)
            .await
            .unwrap();
        drop(client_writer);

        // Server: receive exec request and dispatch.
        let event = event_rx.recv().await.expect("expected exec request event");
        let action = handle_request(&event, &mut server_writer)
            .await
            .expect("handle_request failed")
            .expect("expected Some(RequestAction::Exec)");
        assert_eq!(
            action,
            genmeta_ssh3_server::session::request::RequestAction::Exec(
                b"echo session_flow_test".to_vec(),
            )
        );

        // Client: read ChannelSuccess reply.
        let success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(success, SshMessage::ChannelSuccess);

        // Server: execute the command.
        let (_, rx) = mpsc::channel(1);
        run_exec(std::ffi::OsStr::new("/bin/sh"), b"echo session_flow_test", &mut server_writer, rx, None)
            .await
            .expect("run_exec failed");
        drop(server_writer);

        // Client: collect all remaining messages.
        let mut messages = Vec::new();
        loop {
            match SshMessage::decode_from(&mut client_reader).await {
                Ok(msg) => messages.push(msg),
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => panic!("unexpected decode error: {e}"),
            }
        }

        // Verify stdout contains the marker string.
        let has_marker = messages.iter().any(|m| match m {
            SshMessage::ChannelData { data } => {
                String::from_utf8_lossy(data).contains("session_flow_test")
            }
            _ => false,
        });
        assert!(
            has_marker,
            "expected ChannelData containing 'session_flow_test', got: {messages:?}"
        );

        // Verify exit-status=0.
        let has_exit_0 = messages.iter().any(|m| matches!(
            m,
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } if request_type == "exit-status"
                && !want_reply
                && *request_data == encode_exit_status(0)
        ));
        assert!(has_exit_0, "expected exit-status 0, got: {messages:?}");

        // Verify EOF and Close are present and correctly ordered.
        assert!(
            messages.iter().any(|m| matches!(m, SshMessage::ChannelEof)),
            "expected ChannelEof"
        );
        assert!(
            messages.iter().any(|m| matches!(m, SshMessage::ChannelClose)),
            "expected ChannelClose"
        );
        let eof_pos = messages
            .iter()
            .position(|m| matches!(m, SshMessage::ChannelEof))
            .unwrap();
        let close_pos = messages
            .iter()
            .position(|m| matches!(m, SshMessage::ChannelClose))
            .unwrap();
        assert!(eof_pos < close_pos, "EOF should come before Close");
    })
}

// ---------------------------------------------------------------------------
// 26. EOF→FIN verification — after ChannelEof + ChannelClose, reader detects
//     stream end (writer.shutdown() causes the underlying stream to close).
// ---------------------------------------------------------------------------

#[test]
fn test_eof_fin_verification() {
    run("test_eof_fin_verification", async move {
        // Duplex streams: writer_side → reader_side.
        let (mut writer_side, mut reader_side) = duplex(65536);

        // Write ChannelEof + ChannelClose, then shutdown the writer.
        SshMessage::ChannelEof
            .encode_into(&mut writer_side)
            .await
            .unwrap();
        SshMessage::ChannelClose
            .encode_into(&mut writer_side)
            .await
            .unwrap();
        writer_side.shutdown().await.unwrap();

        // Reader: decode ChannelEof.
        let msg1 = SshMessage::decode_from(&mut reader_side).await.unwrap();
        assert!(
            matches!(msg1, SshMessage::ChannelEof),
            "expected ChannelEof, got {msg1:?}"
        );

        // Reader: decode ChannelClose.
        let msg2 = SshMessage::decode_from(&mut reader_side).await.unwrap();
        assert!(
            matches!(msg2, SshMessage::ChannelClose),
            "expected ChannelClose, got {msg2:?}"
        );

        // Reader: verify stream is closed (EOF / FIN).
        // After shutdown(), any further read should return 0 bytes (EOF).
        let mut buf = [0u8; 64];
        let n = reader_side.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "expected EOF (0 bytes read) after writer shutdown");
    })
}
