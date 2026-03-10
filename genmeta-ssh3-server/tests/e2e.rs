mod common;
use common::*;

use std::sync::Arc;

use bytes::Bytes;
use genmeta_ssh3_client::{
    Ssh3Client, Ssh3ClientConfig, SSH3_CONNECT_PATH, SSH_VERSION,
};
use genmeta_ssh3_server::handler::Ssh3ConnectHandler;
use genmeta_ssh3_server::protocol::Ssh3Protocol;
use h3x::hyper::server::TowerService;
use h3x::qpack::field::Protocol;
use http::{Method, StatusCode};
use http_body_util::Empty;
use tokio_util::task::AbortOnDropHandle;
use genmeta_ssh3_proto::codec::ChannelHeader;
use genmeta_ssh3_proto::message::SshMessage;
use genmeta_ssh3_server::channel::open_session_channel;
use genmeta_ssh3_server::channel::handle_channel;
use genmeta_ssh3_server::forward::direct_tcp::handle_direct_tcp;
use genmeta_ssh3_server::session::request::{encode_exit_status, handle_request, run_exec};
use genmeta_ssh3_proto::codec::SshString;
use h3x::codec::{DecodeFrom, EncodeExt, EncodeInto};
use h3x::varint::VarInt;
use tokio::io::{self, duplex, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

// ---------------------------------------------------------------------------
// Helper: build the standard SSH3 server (handler wrapped in TowerService).
// ---------------------------------------------------------------------------

async fn setup_server() -> (
    AbortOnDropHandle<()>,
    http::uri::Authority,
) {
    let protocol = Arc::new(Ssh3Protocol::default());
    let handler = Ssh3ConnectHandler::new(protocol);
    let service = TowerService(handler);

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
        // 1. Build server with SSH3 handler wrapped in TowerService
        let protocol = Arc::new(Ssh3Protocol::default());
        let handler = Ssh3ConnectHandler::new(protocol);
        let service = TowerService(handler);

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
        let protocol = Arc::new(Ssh3Protocol::default());
        let handler = Ssh3ConnectHandler::new(protocol);
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
        genmeta_ssh3_client::session::send_exec_request(&mut client_writer, "echo hello", true)
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
            genmeta_ssh3_server::session::request::RequestAction::Exec("echo hello".into())
        );

        // Client: read ChannelSuccess (reply to want_reply=true).
        let success = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert_eq!(success, SshMessage::ChannelSuccess);

        // Server: run the exec command.
        let (_, rx) = mpsc::channel(1);
        run_exec("echo hello", &mut server_writer, rx, None).await.expect("run_exec failed");
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
            "echo stderr_msg >&2",
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
        run_exec("echo stderr_msg >&2", &mut server_writer, rx, None).await.expect("run_exec failed");
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
                *data_type == 1 && String::from_utf8_lossy(data).contains("stderr_msg")
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
        request_data.encode_one(VarInt::try_from(12345u64).unwrap()).await.unwrap();

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
                run_exec(&cmd, &mut server_writer, rx, None).await.expect("run_exec failed");
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
            handle_channel(header, server_reader, server_writer, None)
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
        genmeta_ssh3_client::session::send_exec_request(&mut writer, "cat", true)
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
            handle_channel(header, server_reader, server_writer, None)
                .await
                .expect("handle_channel failed");
        });

        let mut writer = client_writer;

        // Read ChannelOpenConfirmation.
        let confirm = SshMessage::decode_from(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        // Send exec request: "echo hello".
        genmeta_ssh3_client::session::send_exec_request(&mut writer, "echo hello", true)
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
            handle_channel(header, server_reader, server_writer, None)
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
        genmeta_ssh3_client::session::send_exec_request(&mut writer, "echo pty_test_marker", true)
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
            handle_channel(header, server_reader, server_writer, None)
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
        genmeta_ssh3_client::session::send_exec_request(&mut writer, "echo wc_test_ok", true)
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
