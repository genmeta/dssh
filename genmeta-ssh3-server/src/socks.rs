use std::{io, sync::Arc};

use futures::{FutureExt, StreamExt};
use proto::{
    listener,
    messages::BindAddress,
    mux::{Mux, Recver, Sender, Token},
    socks,
};

pub async fn listen_remote_forward(
    mux: Arc<Mux>,
    token: Token,
    mut sender: Sender,
    mut recver: Recver,
    listen: BindAddress,
) -> io::Result<impl Future<Output = io::Result<()>>> {
    let listener = match listener::Listener::bind(listen.clone()).await {
        Ok(listener) => {
            tracing::info!("Listening on {listen}");
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
    let listen_task = listener.listen(move |reader, writer| {
        let mux = mux.clone();
        async move { socks::accept_forward(reader, writer, mux, token).await }.boxed()
    });
    Ok(async move {
        tokio::select! {
            _ = recver.next() => Ok(()),
            error = listen_task => Err(error),
        }
    })
}
