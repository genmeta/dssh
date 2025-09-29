use std::sync::Arc;

use futures::FutureExt;
use proto::{listener::Listener, mux::Mux, socks};
use snafu::{IntoError, ResultExt, Snafu};
use tokio::io;

#[derive(Debug, Snafu)]
pub enum SocksError {
    #[snafu(display("Socks server error"))]
    Server { source: socks::Error },
    #[snafu(display("Failed to accept local connections"))]
    AcceptError { source: io::Error },
}

impl From<io::Error> for SocksError {
    fn from(source: io::Error) -> Self {
        AcceptSnafu {}.into_error(source)
    }
}

pub async fn listen_dynamic_forward(mux: Arc<Mux>, listener: Listener) -> io::Error {
    listener
        .listen(move |reader, writer| {
            let mux = mux.clone();
            async move {
                socks::accept_direct(reader, writer, mux)
                    .await
                    .context(ServerSnafu)
            }
            .boxed()
        })
        .await
}
