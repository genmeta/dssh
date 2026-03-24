//! SSH3 session child process example.
//!
//! Launched by the gateway (ssh3-server) as a privilege-separated subprocess.
//! Communicates with the parent via a remoc channel over stdin/stdout.
//!
//! Flow:
//! 1. Establish remoc channel over stdin/stdout
//! 2. Receive [`ChildBootstrap`] containing auth credential, conversation
//!    streams, and ManageSessionStream RPC handle
//! 3. Authenticate (verify credential)
//! 4. Drop privileges to the target user
//! 5. Construct [`Conversation`] from the remoc-proxied streams
//! 6. Run the session dispatcher until the session ends

use std::sync::Arc;

use genmeta_ssh::{
    Conversation,
    session::{
        dispatcher::{run_session, SessionConfig},
        privilege::drop_privileges,
        ChildBootstrap, SessionInit,
    },
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    // Establish remoc channel over stdin/stdout.
    let (conn, _tx, mut rx) =
        remoc::Connect::io::<_, _, (), ChildBootstrap, remoc::codec::Default>(
            remoc::Cfg::default(),
            stdin,
            stdout,
        )
        .await
        .expect("failed to establish remoc channel");
    tokio::spawn(conn);

    // Receive bootstrap payload from parent.
    let bootstrap: ChildBootstrap = rx
        .recv()
        .await
        .expect("remoc receive error")
        .expect("parent closed channel without sending bootstrap");

    tracing::info!(
        conversation_id = ?bootstrap.conversation_id,
        peer_version = %bootstrap.peer_version,
        "received bootstrap"
    );

    // TODO: PAM authentication using bootstrap.credential.
    // For now, assume auth succeeds with a fixed user.
    let session_init = SessionInit {
        conversation_id: bootstrap.conversation_id,
        username: "nobody".into(),
        uid: 65534,
        gid: 65534,
        home: "/nonexistent".into(),
        shell: "/bin/sh".into(),
    };

    // Drop privileges from root to target user.
    if nix::unistd::getuid().is_root() {
        drop_privileges(session_init.uid, session_init.gid, &session_init.username)
            .expect("failed to drop privileges");
        tracing::info!(
            uid = session_init.uid,
            gid = session_init.gid,
            "privileges dropped"
        );
    }

    // Convert control stream clients to AsyncRead/AsyncWrite via h3x codec wrappers.
    let control_reader = h3x::codec::StreamReader::new(
        bootstrap.control_reader.into_boxed_quic(),
    );
    let control_writer = h3x::codec::SinkWriter::new(
        bootstrap.control_writer.into_boxed_quic(),
    );

    let conversation = Arc::new(Conversation::new(
        bootstrap.conversation_id,
        bootstrap.peer_version,
        control_reader,
        control_writer,
        bootstrap.manage_stream,
    ));

    let config = SessionConfig {
        shell: session_init.shell,
        ..Default::default()
    };

    tracing::info!("session dispatcher starting");
    run_session(conversation, config).await;
    tracing::info!("session ended");
}
