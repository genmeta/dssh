use std::{io, net::SocketAddr};

use proto::{
    messages::{BindAddress, Request},
    mux,
};
use snafu::prelude::*;

use crate::{auth, session};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    // === Stream Errors ===
    #[snafu(transparent)]
    Receive {
        source: mux::ReceiveError<io::Error>,
    },

    // === Authentication Errors ===
    #[snafu(transparent)]
    Auth { source: auth::Error },

    // === Session Errors ===
    #[snafu(transparent)]
    Session { source: session::Error },

    // === Forward Errors ===
    #[snafu(display(
        "Failed to bind to local forward endpoint `{local}` to forward data to remote `{remote}`"
    ))]
    BindLocalForward {
        local: BindAddress,
        remote: BindAddress,
        source: io::Error,
    },

    #[snafu(display(
        "Failed to bind to dynamic forward endpoint `{endpoint}` to forward data to remote"
    ))]
    BindDynamicForward {
        endpoint: SocketAddr,
        source: io::Error,
    },

    #[snafu(display(
        "Failed to open remote forward channel from remote `{remote}` to local `{}`",
        local.as_ref().map_or("<dynamic address>".to_string(), |addr| addr.to_string())
    ))]
    OpenRemoteForwardChannel {
        local: Option<BindAddress>,
        remote: BindAddress,
        source: proto::mux::ChannelError,
    },

    // === Protocol Errors ===
    #[snafu(display("Unexpected request `{request}` from server"))]
    UnexpectedMessage { request: Request },
}
