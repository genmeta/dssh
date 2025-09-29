use std::sync::Arc;

use futures::{SinkExt, TryStreamExt};
use proto::{
    messages::{
        Request,
        auth::{ClientAuthMessage, ServerAuthMessage},
    },
    mux,
};
use snafu::prelude::*;
use tokio::io;

use crate::mux::Mux;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to open authentication channel"))]
    OpenAuthChannel { source: mux::ChannelError },
    #[snafu(display("Auth channel closed with error"))]
    AuthAborted { source: io::Error },
    #[snafu(display("Authentication channel was closed unexpectedly"))]
    AuthChannelClosed {},
    #[snafu(display("Failed to read password"))]
    ReadPassword { source: io::Error },
    #[snafu(display("Failed to send password"))]
    SendPassword { source: io::Error },
}

pub async fn login(mux: &Arc<Mux>, user: &str, mut password: Option<&str>) -> Result<(), Error> {
    let (_token, recver, sender) = mux
        .request(Request::Auth {
            username: user.to_owned(),
        })
        .await
        .context(OpenAuthChannelSnafu)?;
    let mut recver = recver.framed();
    let mut sender = sender.framed();
    loop {
        let auth_message = recver.try_next().await;
        tracing::debug!(target: "auth", ?auth_message, "Received auth message");
        let message = match auth_message.context(AuthAbortedSnafu)? {
            Some(message) => message,
            None => return AuthChannelClosedSnafu.fail(),
        };
        match message {
            ServerAuthMessage::Accept => return Ok(()),
            ServerAuthMessage::Password { prompt } => {
                let password = match password.take() {
                    Some(password) => password.to_owned(),
                    None => tokio::task::spawn_blocking(|| rpassword::prompt_password(prompt))
                        .await
                        .expect("Never panic")
                        .context(ReadPasswordSnafu)?,
                };
                sender
                    .send(ClientAuthMessage::Password(password))
                    .await
                    .context(SendPasswordSnafu)?;
            }
        }
    }
}
