use std::{
    env,
    ffi::CString,
    os::unix::prelude::{AsFd, AsRawFd, CommandExt},
    pin::Pin,
    process::Command,
};

use crate::{
    Whatever, make_socketpair,
    process::{KillOnDrop, wait_child_exit},
};
use futures::{
    Sink, SinkExt, Stream, StreamExt, sink,
    stream::{self, BoxStream},
};
use nix::{NixPath, libc, pty, unistd};
use snafu::ResultExt;
use tokio::io::{self, AsyncWriteExt};
use tokio_util::{io::ReaderStream, task::AbortOnDropHandle};

use crate::auth;

pub mod record_login;

use super::{
    async_fd::{AsyncFd, OwnedReadHalf, OwnedWriteHalf},
    messages::session::{ClientSessionMessage, ServerSessionMessage},
    mux::{Recver, Sender},
};

type BoxSink<'s, T, E = io::Error> = Pin<Box<dyn Sink<T, Error = E> + Send + 's>>;

/// 启动一个子进程，并转发数据到Sender/Recver上
pub async fn relay<'e, I: Iterator<Item = (&'e str, &'e str)>>(
    clientname: &str,
    user: &auth::UserContext,
    pseudo: bool,
    cmds: Option<&str>,
    envs: I,
    sender: Sender,
    recver: Recver,
) -> Result<impl Future<Output = ()> + 'static, Whatever> {
    let relay = async move |child: KillOnDrop,
                            mut sink: BoxSink<'static, _>,
                            mut stream: BoxStream<'static, _>| {
        tracing::debug!(target: "session", "Child process {child} started");
        let mut close_sender = sender.clone().framed();
        let _send_terminal = AbortOnDropHandle::new(tokio::spawn(async move {
            sender.framed().send_all(&mut stream).await
        }));
        let recv_terminal = AbortOnDropHandle::new(tokio::spawn(async move {
            recver.framed().forward(&mut sink).await
        }));
        let child_exit = AbortOnDropHandle::new(tokio::spawn(wait_child_exit(child.pid)));
        tokio::select! {
            _ = recv_terminal => {
                tracing::debug!(target: "session", "Terminal receiver finished unexpectedly");
            },
            code = child_exit => match code.unwrap_or_else(|e| Err(io::Error::other(e))) {
                Ok(code) => {
                    close_sender
                        .send(ServerSessionMessage::Exit { code })
                        .await
                        .unwrap_or_else(|e| tracing::error!(target: "session", "Failed to send exit code: {e}"));
                }
                Err(e) => {
                    tracing::error!(target: "session", "Failed to wait child process exit: {e}");
                    close_sender
                        .cancel(io::Error::other("Server internal error"))
                        .await
                        .unwrap_or_else(|e| tracing::error!(target: "session", "Failed to cancel sender: {e}"));
                }
            }
        };
    };

    let command = new_command(user, cmds, envs)?;

    Ok(match pseudo {
        true => {
            let (child, sink, stream) = exec_pty(command, clientname, &user.user)?;
            relay(KillOnDrop::from(child), Box::pin(sink), Box::pin(stream))
        }
        false => {
            let (child, sink, stream) = exec_no_pty(command, clientname, &user.user)?;
            relay(KillOnDrop::from(child), Box::pin(sink), Box::pin(stream))
        }
    })
}

pub fn new_command<'e>(
    user: &auth::UserContext,
    exec: Option<&str>,
    environments: impl Iterator<Item = (&'e str, &'e str)>,
) -> Result<Command, Whatever> {
    let mut command = std::process::Command::new(&user.shell);

    const STDPATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

    let shell = if user.shell.is_empty() {
        "/bin/sh".as_ref()
    } else {
        user.shell.as_path()
    };

    command
        .current_dir(&user.dir)
        .arg0(shell.file_name().expect("path terminates wont be `..`."));

    unsafe {
        let username = CString::new(user.name.clone())
            .whatever_context("Failed to convert username to c-style string")?;
        let gid = user.gid;
        let uid = user.uid;
        command.pre_exec(move || {
            unistd::setgid(gid)?;
            // FIX ME: 对于macos, gid_t似乎是u32，但是此函数固定接受c_int?
            if libc::initgroups(username.as_c_str().as_ptr(), gid.as_raw() as _) != 0 {
                return Err(io::Error::last_os_error());
            }
            unistd::setuid(uid)?;
            Ok(())
        });
    }

    command
        .env_clear()
        // TODO: client environment
        .env("USER", &user.name)
        .env("LOGNAME", &user.name)
        .env("HOME", &user.dir)
        .env("PATH", STDPATH)
        // TODO: MAIL
        .env("SHELL", shell);

    if let Ok(tz) = env::var("TZ") {
        command.env("TZ", tz);
    }

    // TODO: TERM, DISPLAY

    // TODO: Pull in any environment variables that may have been set by PAM.
    // TODO: Set custom environment options from pubkey authentication.
    // TODO: read $HOME/.ssh/environment.
    // TODO: Environment specified by admin
    // TODO: SSH client...

    #[cfg(feature = "pam")]
    for (k, v) in user.pam.envlist().iter_tuples() {
        tracing::debug!(target: "session", "Set env from pam: {}={}", k.to_string_lossy(), v.to_string_lossy());
        command.env(k, v);
    }

    for custom in environments {
        tracing::debug!(target: "session", "Set custom env form client: {}={}", custom.0, custom.1);
        command.env(custom.0, custom.1);
    }

    if let Some(program) = exec {
        command.args(["-c", program]);
    }

    Ok(command)
}

pub fn exec_no_pty(
    mut command: Command,
    clientname: &str,
    user: &unistd::User,
) -> Result<
    (
        unistd::Pid,
        impl Sink<ClientSessionMessage, Error = io::Error> + Send + 'static + use<>,
        impl Stream<Item = Result<ServerSessionMessage, io::Error>> + Send + 'static + use<>,
    ),
    Whatever,
> {
    let (parent_stdin, child_stdin) =
        make_socketpair().whatever_context("Failed to create socket pair for stdin")?;
    let (child_stdout, parent_stdout) =
        make_socketpair().whatever_context("Failed to create socket pair for stdout")?;
    let (child_stderr, parent_stderr) =
        make_socketpair().whatever_context("Failed to create socket pair for stderr")?;

    let parent_stdin = AsyncFd::new(parent_stdin)
        .whatever_context("Failed to create async file descriptor for child stdin")?
        .split()
        .1;
    let parent_stdout = AsyncFd::new(parent_stdout)
        .whatever_context("Failed to create async file descriptor for child stdout")?
        .split()
        .0;
    let parent_stderr = AsyncFd::new(parent_stderr)
        .whatever_context("Failed to create async file descriptor for child stderr")?
        .split()
        .0;

    command.stdin(child_stdin);
    command.stdout(child_stdout);
    command.stderr(child_stderr);

    match unsafe { unistd::fork() }.whatever_context("Failed to fork subprocess")? {
        unistd::ForkResult::Parent { child } => {
            // record_login::record_login(clientname, user);
            _ = (clientname, user);
            Ok((
                child,
                terminal_sink(parent_stdin),
                stream::select(
                    terminal_stream(parent_stdout, false),
                    terminal_stream(parent_stderr, true),
                ),
            ))
        }
        unistd::ForkResult::Child => {
            if let Err(errno) = unistd::setsid() {
                eprintln!("Failed to setsid: {errno}");
                std::process::exit(1);
            }
            let error = command.exec();
            eprintln!("Failed to exec: {error}");
            std::process::exit(1)
        }
    }
}

pub fn exec_pty(
    mut command: Command,
    clientname: &str,
    user: &unistd::User,
) -> Result<
    (
        unistd::Pid,
        impl Sink<ClientSessionMessage, Error = std::io::Error> + use<>,
        impl Stream<Item = Result<ServerSessionMessage, std::io::Error>> + use<>,
    ),
    Whatever,
> {
    // 创建一个伪终端，frok子进程，设置终端为登录终端
    match unsafe { pty::forkpty(None, None) }.whatever_context("Failed to fork pty")? {
        pty::ForkptyResult::Parent { child, master } => {
            // record_login::yecord_login(clientname, user);
            _ = (clientname, user);

            let (pty_read_half, pty_write_half) = AsyncFd::new(master)
                .whatever_context("Failed to create async file descriptor")?
                .split();

            Ok((
                child,
                terminal_sink(pty_write_half),
                terminal_stream(pty_read_half, false),
            ))
        }
        pty::ForkptyResult::Child => {
            let error = command.exec();
            eprintln!("Failed to exec: {error}");
            std::process::exit(1)
        }
    }
}

fn terminal_sink(
    pty_write_half: OwnedWriteHalf,
) -> impl Sink<ClientSessionMessage, Error = io::Error> {
    sink::unfold(
        pty_write_half,
        |mut pty_write_half, msg: ClientSessionMessage| async move {
            if let Some(value) = handle_client_message(&mut pty_write_half, msg).await {
                return value;
            }
            Ok(pty_write_half)
        },
    )
}

async fn handle_client_message(
    pty_write_half: &mut OwnedWriteHalf,
    msg: ClientSessionMessage,
) -> Option<Result<OwnedWriteHalf, std::io::Error>> {
    match msg {
        ClientSessionMessage::WindowSize {
            rows,
            cols,
            width,
            height,
        } => {
            // 设置PTY窗口大小
            unsafe {
                let winsz = libc::winsize {
                    ws_row: rows,
                    ws_col: cols,
                    ws_xpixel: width,
                    ws_ypixel: height,
                };
                libc::ioctl(pty_write_half.as_fd().as_raw_fd(), libc::TIOCSWINSZ, &winsz);
            }
        }
        ClientSessionMessage::Terminal(sequence) => {
            // 发送数据到shell
            if let Err(e) = pty_write_half.write_all(&sequence).await {
                tracing::debug!(target: "session", "Failed to write sequence to PTY: {e}");
                return Some(Err(e));
            }
        }
    }
    None
}

fn terminal_stream(
    pty_read_half: OwnedReadHalf,
    stderr: bool,
) -> impl Stream<Item = Result<ServerSessionMessage, io::Error>> {
    let pty_read_stream = ReaderStream::new(pty_read_half);
    pty_read_stream.map(move |res| res.map(|data| ServerSessionMessage::Terminal { stderr, data }))
}
