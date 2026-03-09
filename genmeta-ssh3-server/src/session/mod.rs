//! SSH3 session-layer request handling.
//!
//! Processes `ChannelEvent::Request` payloads dispatched from the channel
//! message loop, including exec, shell, subsystem, exit-status, and
//! exit-signal request types.

pub mod request;
