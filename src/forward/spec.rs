//! CLI forwarding rule types with OpenSSH-compatible syntax.
//!
//! Provides [`Endpoint`], [`LocalForward`], [`RemoteForward`], and
//! [`DynamicForward`] types that model the `-L`, `-R`, `-D` options.
//!
//! When the **`cli`** feature is enabled, each type also implements
//! [`FromStr`] via a PEG parser, making them directly usable with
//! clap's `#[arg]` derive.

use std::fmt;

/// A network endpoint — either a TCP host:port or a Unix domain socket path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    Tcp { host: String, port: u16 },
    Unix { path: String },
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp { host, port } if host.is_empty() => write!(f, "*:{port}"),
            Self::Tcp { host, port } if host.contains(':') => write!(f, "[{host}]:{port}"),
            Self::Tcp { host, port } => write!(f, "{host}:{port}"),
            Self::Unix { path } => f.write_str(path),
        }
    }
}

/// Local forwarding specification (`-L`).
///
/// OpenSSH-compatible syntax:
/// - `[bind_address:]port:host:hostport` — TCP → TCP
/// - `[bind_address:]port:remote_socket` — TCP → Unix socket
/// - `local_socket:host:hostport` — Unix socket → TCP
/// - `local_socket:remote_socket` — Unix socket → Unix socket
#[derive(Debug, Clone)]
pub struct LocalForward {
    pub bind: Endpoint,
    pub connect: Endpoint,
}

impl fmt::Display for LocalForward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}→{}", self.bind, self.connect)
    }
}

/// Remote forwarding specification (`-R`).
///
/// OpenSSH-compatible syntax:
/// - `[bind_address:]port:host:hostport` — TCP → TCP
/// - `[bind_address:]port:local_socket` — TCP → Unix socket
/// - `remote_socket:host:hostport` — Unix socket → TCP
/// - `remote_socket:local_socket` — Unix socket → Unix socket
/// - `[bind_address:]port` — listen-only (dynamic remote forward)
#[derive(Debug, Clone)]
pub struct RemoteForward {
    pub bind: Endpoint,
    pub connect: Option<Endpoint>,
}

impl fmt::Display for RemoteForward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.connect {
            Some(c) => write!(f, "{}→{}", self.bind, c),
            None => write!(f, "{} (listen-only)", self.bind),
        }
    }
}

/// Dynamic forwarding specification (`-D`).
///
/// OpenSSH-compatible syntax: `[bind_address:]port`
#[derive(Debug, Clone)]
pub struct DynamicForward {
    pub host: String,
    pub port: u16,
}

impl fmt::Display for DynamicForward {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.host.is_empty() {
            write!(f, "*:{}", self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

// ============================================================================
// PEG parser (feature = "cli")
// ============================================================================

#[cfg(feature = "cli")]
peg::parser! {
    grammar forward_spec() for str {
        rule unix_path() -> &'input str
            = p:$("/" [^ ':']*) { p }

        rule port() -> u16
            = n:$(['0'..='9']+) {?
                n.parse::<u16>().or(Err("port number 0-65535"))
            }

        rule hostname() -> &'input str
            = h:$([^ ':' | '/' | '[' | ']']+) { h }

        rule bracketed_ipv6() -> &'input str
            = "[" h:$([^ ']']+) "]" { h }

        rule connect_endpoint() -> Endpoint
            = p:unix_path() {
                Endpoint::Unix { path: p.to_owned() }
            }
            / h:bracketed_ipv6() ":" p:port() {
                Endpoint::Tcp { host: h.to_owned(), port: p }
            }
            / h:hostname() ":" p:port() {
                Endpoint::Tcp { host: h.to_owned(), port: p }
            }

        pub rule local_forward() -> LocalForward
            = b:unix_path() ":" c:connect_endpoint() {
                LocalForward { bind: Endpoint::Unix { path: b.to_owned() }, connect: c }
            }
            / h:bracketed_ipv6() ":" bp:port() ":" c:connect_endpoint() {
                LocalForward {
                    bind: Endpoint::Tcp { host: h.to_owned(), port: bp },
                    connect: c,
                }
            }
            / "*:" bp:port() ":" c:connect_endpoint() {
                LocalForward {
                    bind: Endpoint::Tcp { host: String::new(), port: bp },
                    connect: c,
                }
            }
            / bh:hostname() ":" bp:port() ":" c:connect_endpoint() {
                LocalForward {
                    bind: Endpoint::Tcp { host: bh.to_owned(), port: bp },
                    connect: c,
                }
            }
            / bp:port() ":" c:connect_endpoint() {
                LocalForward {
                    bind: Endpoint::Tcp { host: "127.0.0.1".to_owned(), port: bp },
                    connect: c,
                }
            }

        pub rule remote_forward() -> RemoteForward
            // With connect target
            = b:unix_path() ":" c:connect_endpoint() {
                RemoteForward { bind: Endpoint::Unix { path: b.to_owned() }, connect: Some(c) }
            }
            / h:bracketed_ipv6() ":" bp:port() ":" c:connect_endpoint() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: h.to_owned(), port: bp },
                    connect: Some(c),
                }
            }
            / "*:" bp:port() ":" c:connect_endpoint() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: String::new(), port: bp },
                    connect: Some(c),
                }
            }
            / bh:hostname() ":" bp:port() ":" c:connect_endpoint() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: bh.to_owned(), port: bp },
                    connect: Some(c),
                }
            }
            / bp:port() ":" c:connect_endpoint() {
                RemoteForward {
                    bind: Endpoint::Tcp {
                        host: crate::forward::CANONICAL_REMOTE_LOOPBACK_HOST.to_owned(),
                        port: bp,
                    },
                    connect: Some(c),
                }
            }
            // Listen-only (no connect target)
            / h:bracketed_ipv6() ":" bp:port() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: h.to_owned(), port: bp },
                    connect: None,
                }
            }
            / "*:" bp:port() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: String::new(), port: bp },
                    connect: None,
                }
            }
            / bh:hostname() ":" bp:port() {
                RemoteForward {
                    bind: Endpoint::Tcp { host: bh.to_owned(), port: bp },
                    connect: None,
                }
            }
            / bp:port() {
                RemoteForward {
                    bind: Endpoint::Tcp {
                        host: crate::forward::CANONICAL_REMOTE_LOOPBACK_HOST.to_owned(),
                        port: bp,
                    },
                    connect: None,
                }
            }

        pub rule dynamic_forward() -> DynamicForward
            = h:bracketed_ipv6() ":" p:port() {
                DynamicForward { host: h.to_owned(), port: p }
            }
            / "*:" p:port() {
                DynamicForward { host: String::new(), port: p }
            }
            / h:hostname() ":" p:port() {
                DynamicForward { host: h.to_owned(), port: p }
            }
            / p:port() {
                DynamicForward { host: "127.0.0.1".to_owned(), port: p }
            }
    }
}

// ============================================================================
// FromStr (feature = "cli")
// ============================================================================

#[cfg(feature = "cli")]
impl std::str::FromStr for LocalForward {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_spec::local_forward(s).map_err(|e| format!("invalid local forward spec '{s}': {e}"))
    }
}

#[cfg(feature = "cli")]
impl std::str::FromStr for RemoteForward {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_spec::remote_forward(s)
            .map_err(|e| format!("invalid remote forward spec '{s}': {e}"))
    }
}

#[cfg(feature = "cli")]
impl std::str::FromStr for DynamicForward {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_spec::dynamic_forward(s)
            .map_err(|e| format!("invalid dynamic forward spec '{s}': {e}"))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::*;

    // --- LocalForward parsing ---

    #[test]
    fn local_tcp_3part() {
        let f: LocalForward = "8080:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_tcp_4part() {
        let f: LocalForward = "0.0.0.0:8080:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "0.0.0.0".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_tcp_ipv6_bind() {
        let f: LocalForward = "[::1]:8080:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "::1".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_tcp_ipv6_connect() {
        let f: LocalForward = "8080:[::1]:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "::1".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_wildcard_bind() {
        let f: LocalForward = "*:8080:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: String::new(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_tcp_to_unix() {
        let f: LocalForward = "8080:/tmp/remote.sock".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "127.0.0.1".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Unix {
                path: "/tmp/remote.sock".into()
            }
        );
    }

    #[test]
    fn local_unix_to_tcp() {
        let f: LocalForward = "/tmp/local.sock:remote:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Unix {
                path: "/tmp/local.sock".into()
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Tcp {
                host: "remote".into(),
                port: 80
            }
        );
    }

    #[test]
    fn local_unix_to_unix() {
        let f: LocalForward = "/tmp/local.sock:/tmp/remote.sock".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Unix {
                path: "/tmp/local.sock".into()
            }
        );
        assert_eq!(
            f.connect,
            Endpoint::Unix {
                path: "/tmp/remote.sock".into()
            }
        );
    }

    // --- RemoteForward parsing ---

    #[test]
    fn remote_tcp_3part() {
        let f: RemoteForward = "8080:localhost:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "localhost".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Some(Endpoint::Tcp {
                host: "localhost".into(),
                port: 80
            })
        );
    }

    #[test]
    fn remote_tcp_4part() {
        let f: RemoteForward = "0.0.0.0:8080:localhost:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "0.0.0.0".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Some(Endpoint::Tcp {
                host: "localhost".into(),
                port: 80
            })
        );
    }

    #[test]
    fn remote_listen_only_port() {
        let f: RemoteForward = "8080".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "localhost".into(),
                port: 8080
            }
        );
        assert_eq!(f.connect, None);
    }

    #[test]
    fn remote_listen_only_host_port() {
        let f: RemoteForward = "localhost:8080".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "localhost".into(),
                port: 8080
            }
        );
        assert_eq!(f.connect, None);
    }

    #[test]
    fn remote_unix_to_tcp() {
        let f: RemoteForward = "/tmp/remote.sock:localhost:80".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Unix {
                path: "/tmp/remote.sock".into()
            }
        );
        assert_eq!(
            f.connect,
            Some(Endpoint::Tcp {
                host: "localhost".into(),
                port: 80
            })
        );
    }

    #[test]
    fn remote_tcp_to_unix() {
        let f: RemoteForward = "8080:/tmp/local.sock".parse().unwrap();
        assert_eq!(
            f.bind,
            Endpoint::Tcp {
                host: "localhost".into(),
                port: 8080
            }
        );
        assert_eq!(
            f.connect,
            Some(Endpoint::Unix {
                path: "/tmp/local.sock".into()
            })
        );
    }

    // --- DynamicForward parsing ---

    #[test]
    fn dynamic_port_only() {
        let f: DynamicForward = "1080".parse().unwrap();
        assert_eq!(f.host, "127.0.0.1");
        assert_eq!(f.port, 1080);
    }

    #[test]
    fn dynamic_host_port() {
        let f: DynamicForward = "0.0.0.0:1080".parse().unwrap();
        assert_eq!(f.host, "0.0.0.0");
        assert_eq!(f.port, 1080);
    }

    #[test]
    fn dynamic_ipv6() {
        let f: DynamicForward = "[::1]:1080".parse().unwrap();
        assert_eq!(f.host, "::1");
        assert_eq!(f.port, 1080);
    }

    #[test]
    fn dynamic_wildcard() {
        let f: DynamicForward = "*:1080".parse().unwrap();
        assert_eq!(f.host, "");
        assert_eq!(f.port, 1080);
    }

    // --- Display ---

    #[test]
    fn display_endpoint_tcp() {
        assert_eq!(
            Endpoint::Tcp {
                host: "h".into(),
                port: 80
            }
            .to_string(),
            "h:80"
        );
        assert_eq!(
            Endpoint::Tcp {
                host: "::1".into(),
                port: 80
            }
            .to_string(),
            "[::1]:80"
        );
        assert_eq!(
            Endpoint::Tcp {
                host: String::new(),
                port: 80
            }
            .to_string(),
            "*:80"
        );
    }

    #[test]
    fn display_endpoint_unix() {
        assert_eq!(
            Endpoint::Unix {
                path: "/tmp/s".into()
            }
            .to_string(),
            "/tmp/s"
        );
    }
}
