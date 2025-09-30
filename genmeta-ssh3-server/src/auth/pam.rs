use std::ffi::{CStr, CString};

use pam_client2::conv_null;
use snafu::{Report, ResultExt};

use crate::Whatever;

pub struct PasswordConversation {
    username: String,
    password: String,
}

impl pam_client2::ConversationHandler for PasswordConversation {
    fn prompt_echo_on(&mut self, msg: &CStr) -> Result<CString, pam_client2::ErrorCode> {
        tracing::debug!(target: "pam", "Request username with prompt: {}", msg.to_string_lossy());
        CString::new(self.username.as_str())
            .inspect_err(|e| {
                tracing::error!(target: "pam", "Failed to convert username to C-Style String: {}", Report::from_error(e));
            })
            .map_err(|_| pam_client2::ErrorCode::CONV_ERR)
    }

    fn prompt_echo_off(&mut self, msg: &CStr) -> Result<CString, pam_client2::ErrorCode> {
        tracing::debug!(target: "pam", "Request password with prompt: {}", msg.to_string_lossy());
        CString::new(self.password.as_str())
            .inspect_err(|e| {
                tracing::error!(target: "pam", "Failed to convert password to C-Style String: {}", Report::from_error(e));
            })
            .map_err(|_| pam_client2::ErrorCode::CONV_ERR)
    }

    fn text_info(&mut self, msg: &CStr) {
        tracing::debug!(target: "pam", "PAM info: {}", msg.to_string_lossy());
    }

    fn error_msg(&mut self, msg: &CStr) {
        tracing::warn!(target: "pam", "PAM error: {}", msg.to_string_lossy());
    }
}

pub enum ConversationHandler {
    Password(PasswordConversation),
    Null(conv_null::Conversation),
}

impl pam_client2::ConversationHandler for ConversationHandler {
    fn prompt_echo_on(&mut self, msg: &CStr) -> Result<CString, pam_client2::ErrorCode> {
        match self {
            ConversationHandler::Password(c) => c.prompt_echo_on(msg),
            ConversationHandler::Null(c) => c.prompt_echo_on(msg),
        }
    }

    fn prompt_echo_off(&mut self, msg: &CStr) -> Result<CString, pam_client2::ErrorCode> {
        match self {
            ConversationHandler::Password(c) => c.prompt_echo_off(msg),
            ConversationHandler::Null(c) => c.prompt_echo_off(msg),
        }
    }

    fn text_info(&mut self, msg: &CStr) {
        match self {
            ConversationHandler::Password(c) => c.text_info(msg),
            ConversationHandler::Null(c) => c.text_info(msg),
        }
    }

    fn error_msg(&mut self, msg: &CStr) {
        match self {
            ConversationHandler::Password(c) => c.error_msg(msg),
            ConversationHandler::Null(c) => c.error_msg(msg),
        }
    }

    fn radio_prompt(&mut self, prompt: &CStr) -> Result<bool, pam_client2::ErrorCode> {
        match self {
            ConversationHandler::Password(c) => c.radio_prompt(prompt),
            ConversationHandler::Null(c) => c.radio_prompt(prompt),
        }
    }

    fn binary_prompt(
        &mut self,
        r#type: u8,
        data: &[u8],
    ) -> Result<(u8, Vec<u8>), pam_client2::ErrorCode> {
        match self {
            ConversationHandler::Password(c) => c.binary_prompt(r#type, data),
            ConversationHandler::Null(c) => c.binary_prompt(r#type, data),
        }
    }
}

#[allow(unused)]
pub fn verify_password<'s>(
    client_name: &str,
    username: &'s str,
    password: &'s str,
) -> Result<Result<pam_client2::Context<ConversationHandler>, pam_client2::Error>, Whatever> {
    let mut context = pam_client2::Context::new(
        "login",
        Some(username),
        ConversationHandler::Password(PasswordConversation {
            username: username.to_owned(),
            password: password.to_owned(),
        }),
    )
    .whatever_context("Failed to create PAM context")?;

    if let Err(error) = (|| {
        context.set_rhost(Some(client_name))?;
        context.authenticate(pam_client2::Flag::NONE)?;
        context.acct_mgmt(pam_client2::Flag::NONE)
    })() {
        return Ok(Err(error));
    }

    Ok(Ok(context))
}

pub fn skip_verify(
    client_name: &str,
    username: &str,
) -> Result<Result<pam_client2::Context<ConversationHandler>, pam_client2::Error>, Whatever> {
    let mut context = pam_client2::Context::new(
        "login",
        Some(username),
        ConversationHandler::Null(conv_null::Conversation::new()),
    )
    .whatever_context("Failed to create PAM context")?;

    if let Err(error) = (|| {
        context.set_rhost(Some(client_name))?;
        context.acct_mgmt(pam_client2::Flag::NONE)
    })() {
        return Ok(Err(error));
    }

    Ok(Ok(context))
}
