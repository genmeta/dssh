use std::sync::Arc;

use futures::{FutureExt, StreamExt};
pub use proto::forward::*;
use proto::{
    listener,
    messages::{self, BindAddress},
    mux::{Mux, Recver, Sender, Token},
};
use tokio::io;

pub async fn listen_remote_forward(
    mux: Arc<Mux>,
    token: Token,
    mut sender: Sender,
    mut recver: Recver,
    listen: BindAddress,
) -> io::Result<impl Future<Output = io::Result<()>>> {
    let remote_forwarder = LocalForwarder::new(
        mux.clone(),
        messages::Request::Forwarded {
            listen: token,
            to: None,
        },
    );
    let listener = match listener::Listener::bind(listen.clone()).await {
        Ok(listener) => {
            tracing::info!(target: "remote_forward", "Listening on {listen}");
            listener
        }
        Err(error) => {
            _ = sender
                .cancel(io::Error::other(format!(
                    "Peer failed to bind {listen}: {error:?}"
                )))
                .await;
            return Err(error);
        }
    };
    let fut = async move {
        tokio::select! {
            _ = recver.next() => Ok(()),
            error = listener.listen(move |reader, writer| remote_forwarder.forward(reader, writer).boxed()) => Err(error)
        }
    };
    Ok(fut)
}
