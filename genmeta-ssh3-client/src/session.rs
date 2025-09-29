use std::{io::Read, sync::Arc};

use bytes::Bytes;
use crossterm::terminal;
use futures::{Sink, SinkExt, StreamExt, TryStreamExt};
use proto::{
    messages::{
        Request,
        session::{ClientSessionMessage, ServerSessionMessage},
    },
    mux::{self, FramedRecver},
};
use snafu::{ResultExt, Snafu};
use tokio::io;
use tokio_util::task::AbortOnDropHandle;

use crate::mux::Mux;

struct TerminalGuard(());

impl TerminalGuard {
    pub fn new() -> Self {
        tracing::debug!(target: "session", "Enable raw mode");
        crossterm::terminal::enable_raw_mode().expect("Failed to enable raw mode");
        TerminalGuard(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        tracing::debug!(target: "session", "Disable raw mode(RAII)");
        crossterm::terminal::disable_raw_mode().expect("Failed to disable raw mode");
    }
}

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to open session channel"))]
    #[snafu(context(false))]
    SendRequest { source: mux::ChannelError },

    #[snafu(display("Session closed"))]
    #[snafu(context(false))]
    ChannelClosed { source: io::Error },
}

pub async fn run(
    mux: &Arc<Mux>,
    commands: Option<String>,
    pseudo: bool,
    environments: Vec<(String, String)>,
) -> Result<i32, Error> {
    let (_token, recver, sender) = mux
        .request(Request::Exec {
            pseudo,
            commands,
            environments,
        })
        .await?;

    let _terminal_guard = TerminalGuard::new();

    let _update_winize =
        AbortOnDropHandle::new(tokio::spawn(update_winsize(sender.clone().framed())));
    let _send_terminal =
        AbortOnDropHandle::new(tokio::spawn(send_terminal(sender.clone().framed())));

    // stdin 关闭不代表流关闭，以recv为准
    recv_terminal(recver.framed()).await
}

#[derive(Debug, Snafu)]
pub enum UpdateWindowSizeError {
    #[cfg(unix)]
    #[snafu(display("Failed to register SIGWINCH listener, window size will not be updated"))]
    RegisterSignalListener { source: io::Error },

    #[snafu(display("Failed get terminal size"))]
    GetWindowSize { source: io::Error },
    #[snafu(display("Channel closed"))]
    ChannelClosed {},
}

async fn update_winsize(mut message_sender: impl Sink<ClientSessionMessage> + Unpin) {
    let mut update_winsize = async |window_size: crossterm::terminal::WindowSize| {
        let message = ClientSessionMessage::WindowSize {
            rows: window_size.rows,
            cols: window_size.columns,
            width: window_size.width,
            height: window_size.height,
        };

        if message_sender.send(message).await.is_err() {
            return Err(ChannelClosedSnafu.build());
        }
        Ok(())
    };

    #[cfg(unix)]
    let init_winsize_update_listener = || {
        use tokio::signal::unix::{SignalKind, signal};
        Result::<_, UpdateWindowSizeError>::Ok(futures::stream::unfold(
            signal(SignalKind::window_change()).context(RegisterSignalListenerSnafu)?,
            |mut signal| async move {
                signal.recv().await?;
                Some((terminal::window_size().context(GetWindowSizeSnafu), signal))
            },
        ))
    };

    #[cfg(not(unix))]
    let init_winsize_update_listener = || {
        tracing::debug!(target: "session", "Window size updates listener not available on this platform, using polling pre 10ms fallback");
        use tokio::time::{Duration, Interval, interval};

        let interval = interval(Duration::from_millis(10));
        let initial_size = terminal::window_size().context(GetWindowSizeSnafu)?;
        let fold = |(mut interval, current_size): (Interval, _)| async move {
            loop {
                _ = interval.tick().await;
                match terminal::size().context(GetWindowSizeSnafu) {
                    Ok(new_size) if new_size != current_size => {
                        return Some((Ok(new_size), (interval, new_size)));
                    }
                    Err(error) => {
                        return Some((Err(error), (interval, current_size)));
                    }
                    _ => (),
                }
            }
        };
        Result::<_, UpdateWindowSizeError>::Ok(futures::stream::unfold(
            (interval, initial_size),
            fold,
        ))
    };

    let update_winsize = async {
        update_winsize(terminal::window_size().context(GetWindowSizeSnafu)?).await?;

        let mut winsize_update_listener = init_winsize_update_listener()?.boxed();
        while let Some(new_size) = winsize_update_listener.try_next().await? {
            update_winsize(new_size).await?;
        }

        #[allow(unreachable_code)]
        Result::<_, UpdateWindowSizeError>::Ok(unreachable!("signal sender went away"))
    };

    let Err(error) = update_winsize.await;
    tracing::error!(target: "session", "Failed to update terminal size: {error}");
}

async fn send_terminal(mut message_sender: impl Sink<ClientSessionMessage> + Unpin) {
    // tokio::io::stdin() 不适合交互使用，读文档了解详情
    let tracing_span = tracing::Span::current();
    let (sequence_tx, mut sequence_rx) = tokio::sync::mpsc::channel::<Bytes>(32);
    std::thread::spawn(move || {
        let _entered = tracing_span.entered();
        loop {
            let mut buf = [0; 4096];
            match std::io::stdin().read(&mut buf) {
                Ok(nread) => {
                    if sequence_tx
                        .blocking_send(buf[..nread].to_vec().into())
                        .is_err()
                    {
                        return;
                    }
                }
                Err(e) => {
                    tracing::error!(target:"ssh", "Failed to read from stdin: {e}");
                    break;
                }
            }
        }
    });

    while let Some(sequence) = sequence_rx.recv().await {
        // read() -> Ok(0)
        if sequence.is_empty() {
            tracing::debug!(target: "session", "Read stdin EOF received");
            break;
        }

        let message = ClientSessionMessage::Terminal(sequence);
        if message_sender.send(message).await.is_err() {
            tracing::error!(target: "session", "Event channel closed");
            return;
        }
    }
}

fn write_to_stdout(sequence: Bytes) -> io::Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&sequence)?;
    stdout.flush()
}

fn write_to_stderr(sequence: Bytes) -> io::Result<()> {
    use std::io::Write;
    let mut stderr = std::io::stderr().lock();
    stderr.write_all(&sequence)?;
    stderr.flush()
}

async fn recv_terminal(mut recver: FramedRecver<ServerSessionMessage>) -> Result<i32, Error> {
    while let Some(message) = recver.try_next().await? {
        match message {
            ServerSessionMessage::Terminal { stderr, data } => {
                // 不知为何往tokio::stdin写时会缺少一行输出，所以使用stdio
                let write_to_stdout = tokio::task::spawn_blocking(move || match stderr {
                    true => write_to_stderr(data),
                    false => write_to_stdout(data),
                });
                if let Err(write_error) = write_to_stdout.await.expect("Write should never panic") {
                    tracing::error!(target: "session", "Failed to write to stdout: {write_error}");
                    // 不要因为 stdout 写入失败而终止程序，只记录错误
                }
            }
            ServerSessionMessage::Exit { code } => return Ok(code),
        }
    }
    tracing::debug!(target: "session", "recv_terminal: Recv EOF before received exit code");
    Err(io::Error::from(io::ErrorKind::UnexpectedEof).into())
}
