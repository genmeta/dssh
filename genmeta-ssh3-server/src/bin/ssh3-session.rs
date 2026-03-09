//! SSH3 session child process binary.
//!
//! Spawned by the main server process to handle a single SSH3 conversation.
//! Communicates with the parent via remoc RTC over stdin/stdout.
//!
//! # Protocol
//!
//! 1. Parent spawns this binary with stdin/stdout piped.
//! 2. Child establishes a remoc connection over stdin (read) / stdout (write).
//! 3. Child creates an [`SshSessionServerShared`] wrapping [`Ssh3SessionImpl`].
//! 4. Child sends the [`SshSessionClient`] to the parent via the remoc base channel.
//! 5. Child serves RTC requests until the session terminates.

use std::sync::Arc;

use genmeta_ssh3_proto::session::{SshSessionClient, SshSessionServerShared};
use genmeta_ssh3_server::session_impl::Ssh3SessionImpl;
use remoc::rtc::ServerShared;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing to stderr (stdout is used for remoc transport).
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();

    tracing::info!("ssh3-session child process starting");

    // Establish remoc connection over stdin (read) / stdout (write).
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (conn, mut base_tx, _base_rx): (
        _,
        remoc::rch::base::Sender<_>,
        remoc::rch::base::Receiver<()>,
    ) = remoc::Connect::io(remoc::Cfg::default(), stdin, stdout).await?;
    tokio::spawn(conn);

    tracing::debug!("remoc connection established");

    // Create the session implementation and RTC server/client pair.
    let session_impl = Arc::new(Ssh3SessionImpl);
    let (server, client): (
        SshSessionServerShared<Ssh3SessionImpl>,
        SshSessionClient,
    ) = SshSessionServerShared::new(session_impl, 16);

    // Send the client proxy to the parent process.
    base_tx.send(client).await?;
    tracing::debug!("sent SshSessionClient to parent");

    // Serve RTC requests until the session ends (parent drops the client
    // or calls a terminal method).
    server.serve(true).await?;

    tracing::info!("ssh3-session child process exiting");
    Ok(())
}
