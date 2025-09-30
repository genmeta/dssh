mod pam;

use crate::Whatever;
use derive_more::Deref;
use futures::{SinkExt, TryStreamExt};
use nix::unistd;
use proto::messages::auth::{ClientAuthMessage, ServerAuthMessage};
use snafu::{OptionExt, ResultExt};
use tokio::{io, task};

use super::mux::{FramedRecver, FramedSender};
use crate::Config;

#[derive(snafu::Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum Error {
    #[snafu(display("User deny"))]
    Deny {},
    #[snafu(display("User not found"))]
    NotFound {},
    #[snafu(display("Cannot found user"))]
    CannotFoundUser { source: nix::errno::Errno },
    // TODO: merge send error into channel error?
    #[snafu(display("Send message failed"))]
    Send { source: io::Error },
    #[snafu(display("Recv message failed"))]
    Recv { source: io::Error },
    #[snafu(display("Auth channel closed before auth completed"))]
    ChannelClosed {},
    #[snafu(display("Stream closed before received request"))]
    StreamClosed {},
    #[snafu(display("Verify password is not supported"))]
    NotSupported {},
    #[snafu(display("PAM error"))]
    Pam { source: Whatever },
}

pub async fn find_user(username: &str) -> Result<unistd::User, Error> {
    match unistd::User::from_name(username).context(CannotFoundUserSnafu)? {
        Some(user) => Ok(user),
        None => NotFoundSnafu.fail(),
    }
}

pub async fn reject_deny(
    config: &Config,
    username: &str,
    sender: &mut FramedSender<ServerAuthMessage>,
) -> Result<(), Error> {
    if config.ssh_deny.iter().any(|deny| deny == username) {
        _ = sender.cancel("User not found").await;
        return DenySnafu.fail();
    }
    Ok(())
}

#[derive(Deref)]
pub struct UserContext {
    #[deref]
    pub user: unistd::User,
    #[cfg(feature = "pam")]
    pub pam: pam_client2::Context<pam::ConversationHandler>,
}

impl UserContext {
    #[allow(unused)]
    pub async fn verify_password(
        user: unistd::User,
        localhost: &str,
        clientname: &str,
        sender: &mut FramedSender<ServerAuthMessage>,
        recver: &mut FramedRecver<ClientAuthMessage>,
    ) -> Result<Self, Error> {
        #[cfg(feature = "pam")]
        {
            let pam = auth_password(&user.name, localhost, clientname, sender, recver).await?;
            return Ok(Self { user, pam });
        }

        _ = sender
            .cancel("Password auth is not supported, please enable PAM feature")
            .await;
        NotSupportedSnafu.fail()
    }

    pub async fn skip_verify(
        user: unistd::User,
        clientname: &str,
        sender: &mut FramedSender<ServerAuthMessage>,
    ) -> Result<Self, Error> {
        #[cfg(feature = "pam")]
        {
            use snafu::Report;
            let pam = match pam::skip_verify(clientname, &user.name).context(PamSnafu)? {
                Ok(pam) => pam,
                Err(error) => {
                    use snafu::{FromString, IntoError};

                    tracing::info!(target: "pam", "Verify password failed: {}", Report::from_error(&error));
                    _ = sender.cancel(format!("Login failed: {error}")).await;
                    return Err(PamSnafu {}.into_error(Whatever::with_source(
                        Box::new(error),
                        "Cert login Failed".to_owned(),
                    )));
                }
            };
            accept(sender).await?;
            Ok(Self { user, pam })
        }
        #[cfg(not(feature = "pam"))]
        {
            Ok(Self { user })
        }
    }
}

#[cfg(feature = "pam")]
pub async fn auth_password(
    username: &str,
    localhost: &str,
    clientname: &str,
    sender: &mut FramedSender<ServerAuthMessage>,
    recver: &mut FramedRecver<ClientAuthMessage>,
) -> Result<pam_client2::Context<pam::ConversationHandler>, Error> {
    let base_prompt = format!("{username}@{localhost}'s password: ");
    sender
        .send(ServerAuthMessage::Password {
            prompt: base_prompt.clone(),
        })
        .await
        .context(SendSnafu)?;

    loop {
        let message = recver
            .try_next()
            .await
            .context(RecvSnafu)?
            .context(ChannelClosedSnafu)?;
        match message {
            ClientAuthMessage::Password(password) => {
                let verify = task::spawn_blocking({
                    let clientname = clientname.to_owned();
                    let username = username.to_owned();
                    move || pam::verify_password(&clientname, &username, &password)
                });
                match verify.await.unwrap().context(PamSnafu)? {
                    Ok(context) => {
                        accept(sender).await?;
                        return Ok(context);
                    }
                    Err(error) => {
                        use snafu::Report;

                        tracing::info!(target: "pam", "Verify password failed: {}", Report::from_error(&error));
                        _ = sender
                            .send(ServerAuthMessage::Password {
                                prompt: format!(
                                    "Authentication failed({error}), try again!\n{base_prompt}"
                                ),
                            })
                            .await
                    }
                }
            }
        }
    }
}

pub async fn accept(sender: &mut FramedSender<ServerAuthMessage>) -> Result<(), Error> {
    sender
        .send(ServerAuthMessage::Accept)
        .await
        .context(SendSnafu)?;
    Ok(())
}
