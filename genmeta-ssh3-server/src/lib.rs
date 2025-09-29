use std::{self, os::unix::prelude::OwnedFd, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::{Stream, StreamExt, future::Either};
use http::{Request, StatusCode};
use nix::{sys::socket, unistd};
use proto::{cbor_codec, messages, mux};
use snafu::{OptionExt, Report, ResultExt, Snafu, whatever};
use tokio::{
    io::{self, AsyncWriteExt},
    task::JoinSet,
};
use tokio_util::{codec, io::StreamReader};
use tracing::Instrument;

use crate::{
    async_fd::AsyncFd,
    auth::UserContext,
    process::{KillOnDrop, wait_child_exit},
};

pub mod async_fd;
pub mod auth;
pub mod forward;
pub mod process;
pub mod session;
pub mod socks;

type AnyError = dyn std::error::Error + Send + Sync + 'static;
type BoxError = Box<AnyError>;

#[derive(Debug, Snafu)]
#[snafu(whatever)]
#[snafu(display("{message}"))]
#[snafu(provide(opt, ref, chain, AnyError => source.as_deref()))]
pub struct Whatever {
    #[snafu(source(from(BoxError, Some)))]
    #[snafu(provide(false))]
    source: Option<BoxError>,
    message: String,
    backtrace: snafu::Backtrace,
}

pub struct Config {
    pub ssh_login: Vec<String>,
    pub ssh_deny: Vec<String>,
}

fn build_response(status: StatusCode) -> http::Response<()> {
    http::Response::builder().status(status).body(()).unwrap()
}

/// ``` conf
/// location /ssh {
///     ssh_login basic ssl; # ssl 需要结合防火墙使用
///     ssh_deny root;
/// }
/// ```
///
/// 配置精确locations匹配，既可免密登录
/// ``` shell
/// access domain "ssh.api.server" "= /ssh/ubuntu" allow "*.admin.api.server"
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn serve<R, W, E, Si, St>(
    config: Arc<Config>,
    request: Request<()>,
    final_pattern: String,
    exactly_matched: bool,
    // 真不想拖进来gm-quic，h3-shim，h3...
    client_name: String,
    recver: R,
    mut sender: W,
    response: impl AsyncFnOnce(&mut W, http::Response<()>) -> Result<(), E>,
) -> Result<(), E>
where
    E: snafu::FromString<Source = BoxError>,
    Si: From<W> + io::AsyncWrite + Send + Unpin + 'static,
    St: From<R> + Stream<Item = Result<Bytes, io::Error>> + Send + Unpin + 'static,
{
    if request.method() != http::Method::PUT {
        response(&mut sender, build_response(StatusCode::METHOD_NOT_ALLOWED)).await?;
        whatever!("Only PUT method is allowed");
    }

    let path = request.uri().path();
    if !path.starts_with(&final_pattern) {
        response(&mut sender, build_response(StatusCode::NOT_FOUND)).await?;
        whatever!("Request path {path} does not start with final pattern {final_pattern}");
    }

    assert!(
        !config.ssh_login.is_empty(),
        "Checked in configuration parsing phase"
    );

    response(&mut sender, build_response(StatusCode::OK)).await?;

    // 简单检查之后，准备进入子进程，处理所有事情
    let (gateway, sshd) = make_socketpair()
        .map_err(io::Error::from)
        .whatever_context("Failed to create socketpair for IPC")?;

    let (child, gateway) = tokio::task::spawn_blocking(move || {
        match unsafe { unistd::fork() }.map_err(io::Error::from)? {
            unistd::ForkResult::Parent { child } => io::Result::Ok((child, gateway)),
            unistd::ForkResult::Child => {
                drop(gateway);
                match sshd_main(&config, request, &final_pattern, exactly_matched, &client_name,sshd) {
                    Ok(()) => std::process::exit(0),
                    Err(error) => {
                        tracing::error!(target: "sshd", "Sshd child process exit with error: {}", Report::from_error(&error));
                        std::process::exit(1);
                    }
                }
            }
        }
    })
    .await
    .unwrap()
    .whatever_context("Failed to fork sshd session process")?;
    let child = KillOnDrop::from(child);

    let mut sshd_stream =
        AsyncFd::new(gateway).whatever_context("Failed to make sshd socket async")?;

    let mut h3_stream = io::join(StreamReader::new(St::from(recver)), Si::from(sender));
    let relay = async {
        if let Err(error) = io::copy_bidirectional(&mut sshd_stream, &mut h3_stream).await {
            tracing::error!(target: "sshd", "Failed to relay data between gateway and sshd: {}", Report::from_error(&error));
        }
        _ = sshd_stream.shutdown().await;
        drop(sshd_stream);
        // 等待一秒钟时间正常退出，否则自动触发SIGKILL（KillOnDrop）
        tokio::time::sleep(Duration::from_secs(1)).await;
    };
    let watch = async {
        if let Err(error) = wait_child_exit(child.pid).await {
            tracing::error!(target: "sshd", "Failed to wait for sshd child process exit: {}", Report::from_error(&error));
        }
    };

    tokio::select! {
        _ = relay => {},
        _ = watch => {},
    }

    Ok(())
}

#[tokio::main(flavor = "current_thread")]
pub async fn sshd_main(
    config: &Config,
    request: Request<()>,
    final_pattern: &str,
    exactly_matched: bool,
    clientname: &str,
    stream: OwnedFd,
) -> Result<(), SshdError> {
    unistd::setsid().whatever_context("Failed to create new session")?;

    let (read_stream, write_stream) = AsyncFd::new(stream)
        .whatever_context("Failed to make sshd socket async")?
        .split();

    let (mux, mut incomings) = mux::Mux::new(
        mux::Role::Server,
        codec::FramedRead::new(read_stream, cbor_codec::CborDecoder::default()),
        codec::FramedWrite::new(write_stream, cbor_codec::CborEncoder::default()),
    );

    let localhost = request.uri().host().unwrap_or_default();
    // THINK：Server不是.genemta.net结尾的情况?
    let localhost = trim_suffix_once(localhost, SUFFIX).unwrap_or(localhost);
    let path_username = request.uri().path()[final_pattern.len()..].trim_start_matches('/');

    let auth_channel = incomings
        .next()
        .await
        .context(auth::StreamClosedSnafu)
        .context(AuthSnafu { username: None })?
        .context(ReceiveMessageSnafu)?;

    let messages::Request::Auth { username } = auth_channel.request else {
        return UnexpectedRequestSnafu {
            expect: "Auth",
            request: auth_channel.request,
        }
        .fail();
    };
    let mut sender = auth_channel.sender.framed();
    let mut recver = auth_channel.recver.framed();
    let mut user: UserContext = async {
        auth::reject_deny(config, &username, &mut sender).await?;
        let user = auth::find_user(&username).await?;

        if config.ssh_login.iter().any(|auth| auth == "ssl")
            && exactly_matched
            && path_username == username
        {
            return UserContext::skip_verify(user, clientname, &mut sender).await;
        }

        if config.ssh_login.iter().any(|auth| auth == "basic") {
            return UserContext::verify_password(
                user,
                localhost,
                clientname,
                &mut sender,
                &mut recver,
            )
            .await;
        }

        unreachable!("No suitable auth method found, but this should have been caught earlier");
    }
    .await
    .context(AuthSnafu { username })?;

    #[cfg(feature = "pam")]
    let pam_session_token = {
        // in openssh/auth-pam.c:
        //
        // #ifdef PAM_TTY_KLUDGE
        // 	/*
        // 	 * Some silly PAM modules (e.g. pam_time) require a TTY to operate.
        // 	 * sshd doesn't set the tty until too late in the auth process and
        // 	 * may not even set one (for tty-less connections)
        // 	 */
        // 	debug("PAM: setting PAM_TTY to \"ssh\"");
        // 	sshpam_err = pam_set_item(sshpam_handle, PAM_TTY, "ssh");
        // 	if (sshpam_err != PAM_SUCCESS) {
        // 		pam_end(sshpam_handle, sshpam_err);
        // 		sshpam_handle = NULL;
        // 		return (-1);
        // 	}
        // #endif
        tracing::debug!(target: "sshd", "pam_set_item(PAM_PTY, ssh)");
        user.pam
            .set_tty(Some("ssh"))
            .whatever_context("Failed to set PAM item TTY to ssh")?;
        tracing::debug!(target: "sshd", "pam_set_item(PAM_RHOST, {clientname})");
        user.pam
            .set_rhost(Some(clientname))
            .whatever_context(format!("Failed to set PAM item RHOST to {clientname}"))?;
        tracing::debug!(target: "sshd", "pam_open_session()");
        user.pam
            .open_session(pam_client::Flag::NONE)
            .whatever_context("Failed to open PAM session")?
            .leak()
    };

    let mut tasks = JoinSet::new();
    let mut handle_new_channel =
        async |mux::NewChannel {
                   token,
                   request,
                   sender,
                   recver,
               }: mux::NewChannel| {
            match request.clone() {
                messages::Request::Auth { .. } => {
                    Err("Client send Auth request after  completed".into())
                        .context(HandleRequestSnafu { request })
                }
                messages::Request::Exec {
                    pseudo,
                    commands,
                    environments,
                } => {
                    let envs = environments.iter().map(|(k, v)| (k.as_str(), v.as_str()));
                    let cmds = commands.as_deref();
                    let relay =
                        session::relay(clientname, &user, pseudo, cmds, envs, sender, recver)
                            .await
                            .map_err(From::from)
                            .context(HandleRequestSnafu { request })?;
                    tokio::spawn(relay.in_current_span());
                    Ok(())
                }

                messages::Request::Direct { to: local } => {
                    let forward = forward::accept_forward(sender, recver, local.clone())
                        .await
                        .map_err(Into::into)
                        .context(HandleRequestSnafu { request })?;
                    tasks.spawn(
                        async move {
                            if let Err(error) = forward.await {
                                tracing::error!(
                                    target: "local_forward",
                                    "Failed to forward data to `{local}`: {}",
                                    Report::from_error(&error)
                                );
                            }
                        }
                        .in_current_span(),
                    );
                    Ok(())
                }
                messages::Request::Forward { listen, socks } => {
                    let mux = mux.clone();
                    let listen_result = if socks {
                        socks::listen_remote_forward(mux, token, sender, recver, listen.clone())
                            .await
                            .map(Either::Left)
                    } else {
                        forward::listen_remote_forward(mux, token, sender, recver, listen.clone())
                            .await
                            .map(Either::Right)
                    };

                    let accept_forward = listen_result
                        .map_err(Into::into)
                        .context(HandleRequestSnafu { request })?;

                    tasks.spawn(
                        async move {
                            if let Err(accept_error) = accept_forward.await {
                                tracing::error!(
                                    target: "remote_forward",
                                    "Failed to accept incoming connection to `{listen}`: {}",
                                    Report::from_error(&accept_error)
                                );
                            }
                        }
                        .in_current_span(),
                    );
                    Ok(())
                }
                request => UnexpectedRequestSnafu {
                    expect: "Shell, Exec, Direct or Forward",
                    request,
                }
                .fail(),
            }
        };

    let mut result = Ok(());

    while let Some(new_channel) = incomings
        .next()
        .await
        .transpose()
        .context(ReceiveMessageSnafu)?
    {
        let span =
            tracing::info_span!(target: "sshd", "handle_new_channel", request=%new_channel.request);
        if let Err(handle_error) = handle_new_channel(new_channel).instrument(span).await {
            tracing::warn!(target: "sshd", "Error occurs in handling new channel, ending tasks: {}", Report::from_error(&handle_error));
            tasks.detach_all();
            result = Err(handle_error);
            break;
        }
    }
    _ = tasks.join_all().await;

    #[cfg(feature = "pam")]
    {
        tracing::debug!(target: "sshd", "pam_close_session()");
        drop(user.pam.unleak_session(pam_session_token));
    }
    result
}

pub const SUFFIX: &str = ".genmeta.net";

pub fn trim_suffix_once<'s>(s: &'s str, suffix: &str) -> Option<&'s str> {
    if let Some(pos) = s.rfind(suffix)
        && pos + suffix.len() == s.len()
    {
        return Some(&s[..pos]);
    }
    None
}

fn make_socketpair() -> Result<(OwnedFd, OwnedFd), nix::errno::Errno> {
    socket::socketpair(
        socket::AddressFamily::Unix,
        socket::SockType::Stream,
        None,
        socket::SockFlag::empty(),
    )
}

#[derive(snafu::Snafu, Debug)]
pub enum SshdError {
    #[snafu(display("Auth for login `{}` failed", username.as_deref().unwrap_or("<unknown>")))]
    Auth {
        source: auth::Error,
        username: Option<String>,
    },
    #[snafu(display("An error occurred while processing the peer's request `{request}`"))]
    HandleRequest {
        request: messages::Request,
        #[snafu(source(from(BoxError, std::convert::identity)))]
        source: BoxError,
    },
    #[snafu(display("Unexpected request `{request}`, expect {expect}"))]
    UnexpectedRequest {
        expect: &'static str,
        request: messages::Request,
    },
    #[snafu(display("Failed to receive message"))]
    ReceiveMessage {
        source: mux::ReceiveError<io::Error>,
    },
    #[snafu(display("{message}"))]
    #[snafu(whatever)]
    Whatever {
        #[snafu(source(from(BoxError, Some)))]
        #[snafu(provide(false))]
        source: Option<BoxError>,
        message: String,
    },
}
