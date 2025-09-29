use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

use peg::{error::ParseError, str::LineCol};

#[derive(Debug, Clone, PartialEq)]
pub enum LocalEndpoint {
    /// 本地端口，可能带有绑定地址
    Addr(SocketAddr),
    Port(u16),
    /// 本地 Unix socket 路径
    Unix(PathBuf),
}

#[derive(Debug, Clone, PartialEq)]
pub enum RemoteEndpoint {
    /// 远程主机和端口
    Host { host: String, port: u16 },
    /// 远程 Unix socket 路径
    Unix { path: PathBuf },
}

#[derive(Debug, Clone, PartialEq)]
pub struct LocalForwardRule {
    pub local: LocalEndpoint,
    pub remote: RemoteEndpoint,
}

pub struct RemoteForwardRule {
    pub local: Option<RemoteEndpoint>,
    pub remote: LocalEndpoint,
}

pub struct DynamicForwardRule {
    pub address: Option<IpAddr>,
    pub port: u16,
}

peg::parser! {
    grammar forward_parser() for str {
        rule ip_addr() -> IpAddr
            = addr:$([^ ':']+) {?
                addr.parse::<IpAddr>().or(Err("valid IP address"))
            }
            / "[" addr:$([^']']*) "]" {?
                // IPv6 地址解析，移除方括号后解析
                addr.parse::<IpAddr>().or(Err("valid IPv6 address"))
            }

        rule port() -> u16
            = n:$(['0'..='9']+) {? n.parse().or(Err("valid port number")) }

        pub rule dynamic_forward_rule() -> DynamicForwardRule
            = address:(address:ip_addr() ":" {address} )? port:port() {
                DynamicForwardRule { address, port }
            }

        rule specified_bind_address_port() -> LocalEndpoint
            = ip:ip_addr() ":" port:port() {
                LocalEndpoint::Addr(SocketAddr::new(ip, port))
            }

        rule unspecified_bind_address_port() -> LocalEndpoint
            = ("*" ":")? port:port() {
                LocalEndpoint::Port(port)
            }
        rule bind_address_port() -> LocalEndpoint
            = endpoint:(specified_bind_address_port() / unspecified_bind_address_port()) {
                endpoint
            }

        rule path_char() -> char
            = c:[^ ':'] { c }

        rule path() -> PathBuf
            = p:$(path_char()+) { PathBuf::from(p) }

        rule local_socket() -> LocalEndpoint
            = p:path() { LocalEndpoint::Unix(p) }

        rule host() -> String
            = h:$([^ ':']+) { h.to_string() }

        rule host_hostport() -> RemoteEndpoint
            = h:host() ":" p:port() {
                RemoteEndpoint::Host { host: h, port: p }
            }

        rule remote_socket() -> RemoteEndpoint
            = path:path() { RemoteEndpoint::Unix { path } }

        // 解析完整的转发规则
        pub rule local_forward_rule() -> LocalForwardRule
            = local:(bind_address_port() / local_socket()) ":" remote:(host_hostport() / remote_socket()) {
                LocalForwardRule { local, remote }
            }


        pub rule remote_forward_rule() -> RemoteForwardRule
            = remote:(bind_address_port() / local_socket()) local: (":" local:(host_hostport() / remote_socket()) { Some(local)}  / "" { None }) {
                RemoteForwardRule { remote, local }
            }


    }
}

impl FromStr for DynamicForwardRule {
    type Err = ParseError<LineCol>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_parser::dynamic_forward_rule(s)
    }
}

impl FromStr for LocalForwardRule {
    type Err = ParseError<LineCol>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_parser::local_forward_rule(s)
    }
}

impl FromStr for RemoteForwardRule {
    type Err = ParseError<LineCol>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        forward_parser::remote_forward_rule(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_local_port() {
        let rule = LocalForwardRule::from_str("8080:example.com:80").unwrap();
        assert_eq!(rule.local, LocalEndpoint::Port(8080));
        assert_eq!(
            rule.remote,
            RemoteEndpoint::Host {
                host: "example.com".to_string(),
                port: 80
            }
        );
    }

    #[test]
    fn test_parse_bind_address() {
        let rule = LocalForwardRule::from_str("127.0.0.1:8080:example.com:80").unwrap();
        assert_eq!(
            rule.local,
            LocalEndpoint::Addr("127.0.0.1:8080".parse().unwrap())
        );
    }

    #[test]
    fn test_parse_any_address() {
        let rule = LocalForwardRule::from_str("*:8080:example.com:80").unwrap();
        assert_eq!(rule.local, LocalEndpoint::Port(8080));
    }

    #[test]
    fn test_parse_unix_socket() {
        let rule = LocalForwardRule::from_str("/tmp/sock:example.com:80").unwrap();
        assert_eq!(rule.local, LocalEndpoint::Unix(PathBuf::from("/tmp/sock")));
    }

    #[test]
    fn test_parse_remote_socket() {
        let rule = LocalForwardRule::from_str("8080:/var/run/service.sock").unwrap();
        assert_eq!(
            rule.remote,
            RemoteEndpoint::Unix {
                path: PathBuf::from("/var/run/service.sock")
            }
        );
    }

    #[test]
    fn test_parse_remote_forward_rule() {
        let rule = RemoteForwardRule::from_str("8080").unwrap();
        assert_eq!(rule.remote, LocalEndpoint::Port(8080));
        assert_eq!(rule.local, None);
    }
}
