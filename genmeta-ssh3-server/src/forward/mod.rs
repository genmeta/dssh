//! TCP and Unix domain socket forwarding channels.
//!
//! This module implements SSH3 forwarding channel types:
//! - `direct-tcpip` — client-initiated TCP port forwarding (RFC 4254 §7.2)

pub mod direct_tcp;
