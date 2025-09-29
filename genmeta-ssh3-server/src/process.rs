use std::fmt::{Debug, Display};

use futures::FutureExt;
use nix::{
    sys::{signal, wait},
    unistd,
};
use tokio::io;

pub struct KillOnDrop {
    pub pid: unistd::Pid,
}

impl Debug for KillOnDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self.pid, f)
    }
}

impl Display for KillOnDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.pid, f)
    }
}

impl From<unistd::Pid> for KillOnDrop {
    fn from(pid: unistd::Pid) -> Self {
        Self { pid }
    }
}

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        tracing::debug!(target: "sshd", "Killing child process {}", self.pid);
        let _ = signal::kill(self.pid, signal::Signal::SIGKILL);
    }
}

pub async fn wait_child_exit(child: unistd::Pid) -> io::Result<i32> {
    tokio::task::spawn_blocking(move || {
        loop {
            match wait::waitpid(child, None)? {
                wait::WaitStatus::Exited(pid, code) => {
                    tracing::debug!(target: "sshd", "Child process {pid} exited with code {code}");
                    return Ok(code);
                }
                wait::WaitStatus::Signaled(pid, signal, coredump) => {
                    tracing::debug!(target: "sshd", coredump, "Child process {pid} was killed by signal {signal:?}");
                    return Ok(128 + signal as i32);
                }
                _ => continue,
            }
        }
    }).map(|res| res.unwrap_or_else(|e| Err(io::Error::other(e))))
    .await
}
