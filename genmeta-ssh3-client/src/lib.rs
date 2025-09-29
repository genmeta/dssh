use std::{fmt::Debug, sync::Arc};

pub mod auth;
pub mod error;
pub mod forward;
pub mod session;
pub mod socks;
pub use error::Error;
use error::*;
use forward::*;
use futures::{FutureExt, StreamExt};
pub use proto;
use proto::{
    cbor_codec, listener, messages,
    mux::{self, NewChannel},
};
use snafu::{Report, ResultExt};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
};
use tokio_util::codec;
use tracing::Instrument;

#[derive(Debug, Clone)]
pub struct Options<'o> {
    pub username: &'o str,
    pub commands: Option<&'o str>,
    pub pseudo: bool,
    pub dynamic_forward: &'o [DynamicForwardEndpoint],
    pub local_forwards: &'o [LocalForwardRule],
    pub remote_forwards: &'o [RemoteForwardRule],
}

pub async fn run(
    options: Options<'_>,
    reader: impl AsyncRead + Send + Unpin + 'static,
    writer: impl AsyncWrite + Send + Unpin + 'static,
) -> Result<(), Error> {
    let dynamic_forward_listeners = {
        let mut listeners = Vec::new();
        for &local_addr in options
            .dynamic_forward
            .iter()
            .flat_map(|endpoint| endpoint.addresses())
        {
            let listener = listener::Listener::bind(local_addr.into()).await.context(
                BindDynamicForwardSnafu {
                    endpoint: local_addr,
                },
            )?;
            listeners.push((local_addr, listener));
        }
        listeners
    };

    let local_forwards = {
        let mut forwards = Vec::new();
        for (local, remote) in options.local_forwards.iter().flat_map(|rule| rule.pairs()) {
            let listener =
                listener::Listener::bind(local.clone())
                    .await
                    .context(BindLocalForwardSnafu {
                        local: local.clone(),
                        remote: remote.clone(),
                    })?;
            forwards.push((local, listener, remote));
        }
        forwards
    };

    let (mux, mut incomings) = mux::Mux::new(
        mux::Role::Client,
        codec::FramedRead::new(reader, cbor_codec::CborDecoder::default()),
        codec::FramedWrite::new(writer, cbor_codec::CborEncoder::default()),
    );

    let remote_forwarders = Arc::new(forward::RemoteForwardAcceptor::new(mux.clone()));
    let handle_request = async |NewChannel {
                                    token: _token,
                                    request,
                                    sender,
                                    recver,
                                }| {
        match request.clone() {
            messages::Request::Forwarded { listen, to } => {
                let accept_forward = remote_forwarders
                    .accept(listen, to.clone(), recver, sender)
                    .await;
                let remote_forward_task = match accept_forward {
                    Ok(Some(forward_task)) => forward_task,
                    Ok(None) => {
                        tracing::debug!(
                            target: "remote_forward",
                            "Unknown token {listen}, reject forward request"
                        );
                        return Ok(());
                    }
                    Err(connect_local) => {
                        tracing::debug!(
                            target: "remote_forward",
                            "Failed to connect to local: {}", Report::from_error(connect_local)
                        );
                        return Ok(());
                    }
                };
                let future = async move {
                    if let Err(e) = remote_forward_task.await {
                        tracing::debug!(
                            target: "remote_forward",
                            "Error in remote forward task: {}", Report::from_error(&e)
                        );
                    }
                };
                tokio::spawn(future.in_current_span());
                Ok(())
            }
            _ => UnexpectedMessageSnafu { request }.fail(),
        }
    };

    let recv_requests = async move {
        while let Some(new_request) = incomings.next().await.transpose()? {
            let span = tracing::info_span!(
                target: "session", "handle_request", request=%new_request.request
            );
            handle_request(new_request).instrument(span).await?;
        }
        Result::<_, error::Error>::Ok(())
    };

    let run = async {
        auth::login(&mux, options.username, None).await?;

        let session = {
            let mux = mux.clone();
            let commands = options.commands.map(|s| s.to_owned());

            // TODO: support SetEnv, SendEnv keyword in ssh_config
            let environments = std::env::var("TERM")
                .into_iter()
                .map(|v| ("TERM".to_owned(), v));

            async move {
                let code =
                    session::run(&mux, commands, options.pseudo, environments.collect()).await?;
                std::process::exit(code)
            }
        };
        let session: JoinHandle<Result<(), session::Error>> =
            tokio::spawn(session.in_current_span());

        for (local, listener, remote) in local_forwards {
            let request = messages::Request::Direct { to: remote.clone() };
            let forwarder = forward::LocalForwarder::new(mux.clone(), request);
            let listen_task =
                listener.listen(move |reader, writer| forwarder.forward(reader, writer).boxed());

            let listen_task = async move {
                tracing::error!(
                    target: "local_forward",
                    "Failed to accept incoming connection to local: {}",
                    Report::from_error(listen_task.await)
                );
            };
            let span = tracing::info_span!(target: "local_forward", "listen", %local, %remote);
            tokio::spawn(listen_task.instrument(span));
        }

        for (local, remote) in options.remote_forwards.iter().flat_map(|rule| rule.pairs()) {
            // 远程转发，本地打开一个channel且不发送任何数据，仅仅保持channel存在
            // 对端凭借这个channel的token来将数据从远端转发到本地，而不知道本地的地址是啥（除非是动态远程转发）
            let keep_task = remote_forwarders
                .initial_forward(local.clone(), remote.clone())
                .await
                .context(OpenRemoteForwardChannelSnafu {
                    local: local.clone(),
                    remote: remote.clone(),
                })?;

            let span = tracing::info_span!(target: "remote_forward", "remote_forward", local = local.map_or("<dynamic address>".to_string(), |addr| addr.to_string()), %remote);
            let keep_task = async move {
                if let Err(error) = keep_task.await {
                    tracing::error!(
                        target: "remote_forward",
                        "Channel closed by peer with error: {}",
                        Report::from_error(&error)
                    );
                }
            };
            tokio::spawn(keep_task.instrument(span));
        }

        for (local, dynamic_forward_listener) in dynamic_forward_listeners {
            let listen_task = socks::listen_dynamic_forward(mux.clone(), dynamic_forward_listener);
            let listen_task = async move {
                tracing::error!(
                    target: "local_forward",
                    "Failed to accept incoming connection to local: {}",
                    Report::from_error(listen_task.await)
                );
            };
            let span = tracing::info_span!(target: "socks", "dynamic_forward", %local);
            tokio::spawn(listen_task.instrument(span));
        }

        Ok(session.await.expect("Never panic")?)
    };

    tokio::try_join!(recv_requests, run).map(|_| ())
}
