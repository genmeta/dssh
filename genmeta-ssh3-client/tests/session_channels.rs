mod common;

use common::{TestChannelService, get_server_authority, run, test_client, test_server};
use genmeta_ssh3_client::{Ssh3Client, Ssh3ClientConfig};

#[test]
fn client_exec_channel_runs_command() {
    run("client_exec_channel_runs_command", async move {
        let service = h3x::hyper::server::TowerService(TestChannelService::new(None));
        let server = test_server(service).await;
        let authority = get_server_authority(&server);
        let _serve = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async move {
            server.run().await;
        }));

        let ssh3 = Ssh3Client::new(Ssh3ClientConfig {
            authority: authority.to_string(),
            username: "test".into(),
            password: "testpass".into(),
        });

        let client = test_client();
        let connection = ssh3.connect(&client).await.expect("connect should succeed");
        assert_eq!(connection.conversation_id(), 0, "conversation id should match the first CONNECT request stream id");

        let mut channel = connection
            .open_exec_channel(b"echo hello-from-client")
            .await
            .expect("open_exec_channel should succeed");
        channel.send_eof().await.expect("sending eof should succeed");

        let mut stdout = Vec::new();
        let mut exit_status = None;
        while let Some(event) = channel.recv_event().await.expect("reading session event should succeed") {
            match event {
                genmeta_ssh3_client::session::SessionEvent::Stdout(data) => stdout.extend(data),
                genmeta_ssh3_client::session::SessionEvent::ExitStatus(code) => exit_status = Some(code),
                genmeta_ssh3_client::session::SessionEvent::Close => break,
                genmeta_ssh3_client::session::SessionEvent::Stderr(_)
                | genmeta_ssh3_client::session::SessionEvent::ExitSignal { .. }
                | genmeta_ssh3_client::session::SessionEvent::Eof
                | genmeta_ssh3_client::session::SessionEvent::Success
                | genmeta_ssh3_client::session::SessionEvent::Failure => {}
            }
        }

        assert!(String::from_utf8_lossy(&stdout).contains("hello-from-client"));
        assert_eq!(exit_status, Some(0));
    })
}
