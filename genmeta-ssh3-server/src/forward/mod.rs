//! TCP and Unix domain socket forwarding channels.
//!
//! This module implements SSH3 forwarding channel types:
//! - `direct-tcpip` — client-initiated TCP port forwarding (RFC 4254 §7.2)
//! - `reverse-tcp` — server-side reverse TCP forwarding (`tcpip-forward`)
//! - `streamlocal` — Unix domain socket forwarding (`direct-streamlocal@openssh.com` / `forwarded-streamlocal@openssh.com`)

pub mod direct_tcp;
pub mod reverse_tcp;
pub mod streamlocal;
pub mod socks5;
