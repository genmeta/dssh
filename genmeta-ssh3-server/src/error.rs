use std::sync::PoisonError;

use h3x::stream_id::StreamId;
use snafu::Snafu;

#[derive(Debug, Snafu)]
pub enum ServerError {
    #[snafu(display("missing protocol registry in request extensions"))]
    MissingProtocols,

    #[snafu(display("SSH3 protocol not registered in request extensions"))]
    MissingSsh3Protocol,

    #[snafu(display("missing StreamId in request extensions"))]
    MissingStreamId,

    #[snafu(display(
        "invalid conversation transition for {conversation_id}: current state is {state:?}"
    ))]
    InvalidConversationState {
        conversation_id: StreamId,
        state: crate::protocol::ConversationState,
    },

    #[snafu(display("invalid conversation slot state: current state is {state:?}"))]
    InvalidConversationSlotState {
        state: crate::protocol::ConversationState,
    },

    #[snafu(display("conversation endpoint already consumed for {conversation_id}"))]
    ConsumedConversationEndpoint { conversation_id: StreamId },

    #[snafu(display("conversation registry lock poisoned"))]
    RegistryPoisoned,

    #[snafu(display("conversation state lock poisoned"))]
    StatePoisoned,

    #[snafu(display("failed to spawn ssh3-session child"))]
    SpawnChild { source: std::io::Error },

    #[snafu(display("failed to determine ssh3-session binary path"))]
    ResolveSessionBinary { source: std::io::Error },

    #[snafu(display("ssh3-session binary not found at {path}"))]
    MissingSessionBinary { path: String },

    #[snafu(display("failed to send bootstrap to child"))]
    SendBootstrap,

    #[snafu(display("failed to construct WWW-Authenticate header value '{value}'"))]
    InvalidAuthenticateHeader {
        value: String,
        source: http::header::InvalidHeaderValue,
    },

    #[snafu(display("failed to initialize SSH3 transport for {conversation_id}"))]
    InitTransport {
        conversation_id: StreamId,
        source: genmeta_ssh3_proto::session::TransportError,
    },
}

pub type ServerResult<T, E = ServerError> = Result<T, E>;

pub fn map_poison<T>(_error: PoisonError<T>, state_lock: bool) -> ServerError {
    if state_lock {
        ServerError::StatePoisoned
    } else {
        ServerError::RegistryPoisoned
    }
}
