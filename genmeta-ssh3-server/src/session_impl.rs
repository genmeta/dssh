//! [`SshSession`] trait implementation for the ssh3-session child process.
//!
//! This module provides [`Ssh3SessionImpl`], which implements the RTC
//! [`SshSession`] trait. The ssh3-session child process performs privilege
//! dropping (setgid/setuid), while channel dispatch (PTY, shell, forwarding)
//! occurs in the main server process, since the child has no access to QUIC streams.

use genmeta_ssh3_proto::session::{SessionError, SessionInit, SshSession};

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
/// user; channel dispatch happens in the main server process.
pub struct Ssh3SessionImpl;

impl SshSession for Ssh3SessionImpl {
    async fn run_session(&self, init: SessionInit, _from_client: remoc::rch::mpsc::Receiver<Vec<u8>>, _to_client: remoc::rch::mpsc::Sender<Vec<u8>>) -> Result<(), SessionError> {
        // 1. Drop privileges: setgid first, then setuid.
        drop_privileges(init.uid, init.gid)?;

        // 2. Channel dispatch (PTY, shell, forwarding) occurs in the main server
        //    process; this child process handles privilege separation only.
        tracing::info!(
            conversation_id = init.conversation_id,
            username = %init.username,
            home = %init.home.display(),
            shell = %init.shell.display(),
            "session started"
        );

        Ok(())
    }

    async fn open_channel(&self, _header_bytes: Vec<u8>) -> Result<(remoc::rch::mpsc::Receiver<Vec<u8>>, remoc::rch::mpsc::Sender<Vec<u8>>), SessionError> {
        Err(SessionError::new("open_channel not yet implemented".to_string()))
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
        let (tx, rx) = remoc::rch::mpsc::channel(16);
        let result = session.run_session(sample_init(), rx, tx).await;
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
        let (tx, rx) = remoc::rch::mpsc::channel(16);
        assert!(session.run_session(init, rx, tx).await.is_ok());
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
