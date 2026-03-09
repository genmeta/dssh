//! SSH3 channel lifecycle and message loop.
//!
//! Each QUIC bidirectional stream dispatched by [`Ssh3Protocol`] carries a
//! [`ChannelHeader`] identifying the channel type. This module handles:
//!
//! - Dispatching by `channel_type` (session, forwarding stubs, unknown)
//! - Sending `ChannelOpenConfirmation(91)` or `ChannelOpenFailure(92)`
//! - Running the session channel message loop (data, requests, EOF, close)

use genmeta_ssh3_proto::{codec::ChannelHeader, message::SshMessage};
use tokio::{
    io::{self, AsyncRead, AsyncWrite},
    sync::mpsc,
};

use crate::forward;

// ---------------------------------------------------------------------------
// Channel events dispatched via mpsc
// ---------------------------------------------------------------------------

/// Events produced by the channel message loop and sent to the session layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelEvent {
    /// ChannelData(94) — standard channel data.
    Data(Vec<u8>),
    /// ChannelExtendedData(95) — extended data (e.g., stderr when data_type=1).
    ExtendedData { data_type: u64, data: Vec<u8> },
    /// ChannelRequest(98) — channel request with type and opaque payload.
    Request {
        request_type: String,
        want_reply: bool,
        request_data: Vec<u8>,
    },
    /// ChannelEof(96) — remote side signals end of input.
    Eof,
    /// ChannelClose(97) — remote side closes the channel.
    Close,
}

/// Default maximum message size for session channels.
const DEFAULT_MAX_MESSAGE_SIZE: u64 = 1 << 20; // 1 MiB

// ---------------------------------------------------------------------------
// Channel dispatch by type
// ---------------------------------------------------------------------------

/// Handle a dispatched channel stream.
///
/// Reads the `channel_type` from the [`ChannelHeader`] and dispatches:
/// - `"session"` → confirm + run message loop
/// - TCP/streamlocal forwarding types → stub (returns `Ok(())`)
/// - Unknown → send `ChannelOpenFailure(92)` with reason_code=3
pub async fn handle_channel<R, W>(
    header: ChannelHeader,
    reader: R,
    writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    match header.channel_type.as_str() {
        "session" => handle_session_channel(header, reader, writer).await,
        "direct-tcpip" => forward::direct_tcp::handle_direct_tcp(header, reader, writer).await,
        "forwarded-tcpip" | "direct-streamlocal@openssh.com"
        | "forwarded-streamlocal@openssh.com" => {
            // Stub dispatch points — actual forwarding implemented in Tasks 19-20.
            Ok(())
        }
        _ => {
            handle_unknown_channel(header, writer).await
        }
    }
}

/// Handle an unknown channel type by sending `ChannelOpenFailure(92)`.
async fn handle_unknown_channel<W>(
    _header: ChannelHeader,
    mut writer: W,
) -> io::Result<()>
where
    W: AsyncWrite + Send + Unpin,
{
    let failure = SshMessage::ChannelOpenFailure {
        reason_code: 3,
        description: "unknown channel type".into(),
    };
    SshMessage::encode(&failure, &mut writer).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Session channel lifecycle
// ---------------------------------------------------------------------------

/// Handle a session channel: confirm opening, then run the message loop.
///
/// Returns `(event_rx, io::Result<()>)` via spawning, but for direct use
/// this function drives the loop to completion.
async fn handle_session_channel<R, W>(
    _header: ChannelHeader,
    reader: R,
    mut writer: W,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    // Send ChannelOpenConfirmation(91).
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    SshMessage::encode(&confirm, &mut writer).await?;

    // Run the message loop, discarding the event receiver.
    let (_event_rx, result) = run_message_loop(reader, writer).await;
    result
}

/// Open a session channel, send confirmation, and return the event receiver
/// along with a writer for sending messages back.
///
/// This is the public API for the session layer to consume channel events.
pub async fn open_session_channel<R, W>(
    reader: R,
    mut writer: W,
) -> io::Result<(mpsc::Receiver<ChannelEvent>, W)>
where
    R: AsyncRead + Send + Unpin + 'static,
    W: AsyncWrite + Send + Unpin + 'static,
{
    // Send ChannelOpenConfirmation(91).
    let confirm = SshMessage::ChannelOpenConfirmation {
        max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
    };
    SshMessage::encode(&confirm, &mut writer).await?;

    let (event_tx, event_rx) = mpsc::channel(64);
    tokio::spawn(async move {
        let _ = run_message_loop_with_sender(reader, event_tx).await;
    });
    Ok((event_rx, writer))
}

// ---------------------------------------------------------------------------
// Message loop
// ---------------------------------------------------------------------------

/// Run the channel message loop, returning an event receiver and the loop result.
async fn run_message_loop<R, W>(
    reader: R,
    _writer: W,
) -> (mpsc::Receiver<ChannelEvent>, io::Result<()>)
where
    R: AsyncRead + Send + Unpin,
    W: AsyncWrite + Send + Unpin,
{
    let (event_tx, event_rx) = mpsc::channel(64);
    let result = run_message_loop_with_sender(reader, event_tx).await;
    (event_rx, result)
}

/// Core message loop: reads `SshMessage` from the stream, dispatches to mpsc.
async fn run_message_loop_with_sender<R>(
    mut reader: R,
    event_tx: mpsc::Sender<ChannelEvent>,
) -> io::Result<()>
where
    R: AsyncRead + Send + Unpin,
{
    loop {
        let msg = match SshMessage::decode(&mut reader).await {
            Ok(msg) => msg,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Stream closed — normal termination.
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        match msg {
            SshMessage::ChannelData { data } => {
                let _ = event_tx.send(ChannelEvent::Data(data)).await;
            }
            SshMessage::ChannelExtendedData { data_type, data } => {
                let _ = event_tx
                    .send(ChannelEvent::ExtendedData { data_type, data })
                    .await;
            }
            SshMessage::ChannelRequest {
                request_type,
                want_reply,
                request_data,
            } => {
                let _ = event_tx
                    .send(ChannelEvent::Request {
                        request_type,
                        want_reply,
                        request_data,
                    })
                    .await;
            }
            SshMessage::ChannelEof => {
                let _ = event_tx.send(ChannelEvent::Eof).await;
            }
            SshMessage::ChannelClose => {
                let _ = event_tx.send(ChannelEvent::Close).await;
                return Ok(());
            }
            SshMessage::ChannelSuccess => {
                tracing::debug!("received ChannelSuccess(99)");
            }
            SshMessage::ChannelFailure => {
                tracing::debug!("received ChannelFailure(100)");
            }
            other => {
                tracing::warn!("unexpected message in channel loop: {other:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use genmeta_ssh3_proto::{codec::ChannelHeader, message::SshMessage};
    use tokio::io::duplex;

    /// Helper: encode messages into writer half, then drop to signal EOF.
    async fn encode_messages(mut writer: impl AsyncWrite + Send + Unpin, messages: &[SshMessage]) {
        for msg in messages {
            SshMessage::encode(msg, &mut writer).await.unwrap();
        }
        drop(writer);
    }

    // -----------------------------------------------------------------------
    // Test 1: session channel lifecycle — open → confirm → data → EOF → close
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_lifecycle() {
        let (client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "session".into(),
            max_message_size: 65536,
        };

        // Client sends: data → EOF → close
        let client_handle = tokio::spawn(async move {
            let messages = vec![
                SshMessage::ChannelData {
                    data: b"hello".to_vec(),
                },
                SshMessage::ChannelEof,
                SshMessage::ChannelClose,
            ];
            encode_messages(client_writer, &messages).await;
        });

        // Server handles the channel
        let server_handle = tokio::spawn(async move {
            handle_channel(header, server_reader, server_writer)
                .await
                .unwrap();
        });

        // Read the ChannelOpenConfirmation from the server
        let confirm = SshMessage::decode(&mut client_reader).await.unwrap();
        match confirm {
            SshMessage::ChannelOpenConfirmation { max_message_size } => {
                assert_eq!(max_message_size, DEFAULT_MAX_MESSAGE_SIZE);
            }
            other => panic!("expected ChannelOpenConfirmation, got {other:?}"),
        }

        client_handle.await.unwrap();
        server_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 2: unknown channel type → ChannelOpenFailure(92) with reason_code=3
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unknown_channel_type_sends_failure() {
        let (_client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let header = ChannelHeader {
            signal_value: 0xaf3627e6,
            conversation_id: 1,
            channel_type: "unknown-type".into(),
            max_message_size: 65536,
        };

        handle_channel(header, server_reader, server_writer)
            .await
            .unwrap();

        // Read the ChannelOpenFailure from the server
        let failure = SshMessage::decode(&mut client_reader).await.unwrap();
        match failure {
            SshMessage::ChannelOpenFailure {
                reason_code,
                description,
            } => {
                assert_eq!(reason_code, 3, "reason_code should be 3 (unknown channel type)");
                assert_eq!(description, "unknown channel type");
            }
            other => panic!("expected ChannelOpenFailure, got {other:?}"),
        }
    }

    // -----------------------------------------------------------------------
    // Test 3: session channel receives ChannelData → event dispatched
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_data_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        // Send data then close
        let client_handle = tokio::spawn(async move {
            SshMessage::encode(
                &SshMessage::ChannelData {
                    data: b"test-data".to_vec(),
                },
                &mut client_writer,
            )
            .await
            .unwrap();
            SshMessage::encode(&SshMessage::ChannelClose, &mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        // Use open_session_channel to get the event receiver
        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation from client side
        let confirm = SshMessage::decode(&mut client_reader).await.unwrap();
        assert!(matches!(confirm, SshMessage::ChannelOpenConfirmation { .. }));

        // Receive the data event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Data(b"test-data".to_vec()));

        // Receive close event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Close);

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 4: session channel receives ChannelRequest → event dispatched
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_request_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            SshMessage::encode(
                &SshMessage::ChannelRequest {
                    request_type: "exec".into(),
                    want_reply: true,
                    request_data: b"ls -la".to_vec(),
                },
                &mut client_writer,
            )
            .await
            .unwrap();
            SshMessage::encode(&SshMessage::ChannelClose, &mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode(&mut client_reader).await.unwrap();

        // Receive the request event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(
            event,
            ChannelEvent::Request {
                request_type: "exec".into(),
                want_reply: true,
                request_data: b"ls -la".to_vec(),
            }
        );

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 5: session channel receives ChannelEof → EOF event
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_eof_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            SshMessage::encode(&SshMessage::ChannelEof, &mut client_writer)
                .await
                .unwrap();
            SshMessage::encode(&SshMessage::ChannelClose, &mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode(&mut client_reader).await.unwrap();

        // Receive EOF event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Eof);

        // Receive close event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Close);

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 6: session channel receives ChannelClose → close event
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_close_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            SshMessage::encode(&SshMessage::ChannelClose, &mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode(&mut client_reader).await.unwrap();

        // Receive close event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Close);

        // Channel should be done — no more events
        assert!(event_rx.recv().await.is_none());

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 7: forwarding channel types are stub-accepted (return Ok)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn forwarding_channel_types_stub() {
        let forwarding_types = [
            "forwarded-tcpip",
            "direct-streamlocal@openssh.com",
            "forwarded-streamlocal@openssh.com",
        ];

        for channel_type in forwarding_types {
            let (_, server_reader) = duplex(8192);
            let (server_writer, _) = duplex(8192);

            let header = ChannelHeader {
                signal_value: 0xaf3627e6,
                conversation_id: 1,
                channel_type: channel_type.into(),
                max_message_size: 65536,
            };

            let result = handle_channel(header, server_reader, server_writer).await;
            assert!(
                result.is_ok(),
                "forwarding type {channel_type} should return Ok(())"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Test 8: ChannelExtendedData dispatched as ExtendedData event
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_extended_data_event() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            SshMessage::encode(
                &SshMessage::ChannelExtendedData {
                    data_type: 1, // stderr
                    data: b"error output".to_vec(),
                },
                &mut client_writer,
            )
            .await
            .unwrap();
            SshMessage::encode(&SshMessage::ChannelClose, &mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode(&mut client_reader).await.unwrap();

        // Receive extended data event
        let event = event_rx.recv().await.unwrap();
        assert_eq!(
            event,
            ChannelEvent::ExtendedData {
                data_type: 1,
                data: b"error output".to_vec(),
            }
        );

        client_handle.await.unwrap();
    }

    // -----------------------------------------------------------------------
    // Test 9: ChannelSuccess/ChannelFailure are logged, not dispatched
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn session_channel_success_failure_logged() {
        let (mut client_writer, server_reader) = duplex(8192);
        let (server_writer, mut client_reader) = duplex(8192);

        let client_handle = tokio::spawn(async move {
            // Send success and failure, then close
            SshMessage::encode(&SshMessage::ChannelSuccess, &mut client_writer)
                .await
                .unwrap();
            SshMessage::encode(&SshMessage::ChannelFailure, &mut client_writer)
                .await
                .unwrap();
            SshMessage::encode(
                &SshMessage::ChannelData {
                    data: b"after".to_vec(),
                },
                &mut client_writer,
            )
            .await
            .unwrap();
            SshMessage::encode(&SshMessage::ChannelClose, &mut client_writer)
                .await
                .unwrap();
            drop(client_writer);
        });

        let (mut event_rx, _writer) =
            open_session_channel(server_reader, server_writer)
                .await
                .unwrap();

        // Read confirmation
        let _confirm = SshMessage::decode(&mut client_reader).await.unwrap();

        // ChannelSuccess and ChannelFailure should NOT appear as events.
        // The next event should be the data message.
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Data(b"after".to_vec()));

        // Then close
        let event = event_rx.recv().await.unwrap();
        assert_eq!(event, ChannelEvent::Close);

        client_handle.await.unwrap();
    }
}
