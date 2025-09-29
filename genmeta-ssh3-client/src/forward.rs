use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};
mod parser;
use peg::{error::ParseError, str::LineCol};
pub use proto::v0::forward::*;
use proto::v0::messages::BindAddress;
use snafu::ResultExt;

// use crate::error::Error;

#[derive(snafu::Snafu, Debug)]
#[snafu(display("Failed to parse {kind} forward rule `{rule}`"))]
pub struct Error {
    kind: &'static str,
    rule: String,
    source: ParseError<LineCol>,
}

/// 动态转发端点
#[derive(Debug, Clone, PartialEq)]
pub struct DynamicForwardEndpoint {
    pub addresses: Vec<SocketAddr>,
}

impl From<parser::DynamicForwardRule> for DynamicForwardEndpoint {
    fn from(rule: parser::DynamicForwardRule) -> Self {
        let port = rule.port;
        let addresses = match rule.address {
            Some(ipaddr) => vec![SocketAddr::new(ipaddr, port)],
            None => vec![
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), port),
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port),
            ],
        };

        DynamicForwardEndpoint { addresses }
    }
}

impl FromStr for DynamicForwardEndpoint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<parser::DynamicForwardRule>()
            .map(Self::from)
            .context(Snafu {
                kind: "dynamic",
                rule: s.to_string(),
            })
    }
}

/// 本地转发规则
#[derive(Debug, Clone, PartialEq)]
pub struct LocalForwardRule {
    pub local_addresses: Vec<BindAddress>,
    pub remote_address: BindAddress,
}

impl From<parser::LocalForwardRule> for LocalForwardRule {
    fn from(rule: parser::LocalForwardRule) -> Self {
        let remote_address = match rule.remote {
            parser::RemoteEndpoint::Host { host, port } => BindAddress::Host { host, port },
            parser::RemoteEndpoint::Unix { path } => BindAddress::Unix { path },
        };

        let local_addresses = match rule.local {
            parser::LocalEndpoint::Addr(socket_addr) => vec![BindAddress::Host {
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
            }],
            parser::LocalEndpoint::Port(port) => vec![
                BindAddress::Host {
                    host: Ipv4Addr::UNSPECIFIED.to_string(),
                    port,
                },
                BindAddress::Host {
                    host: Ipv6Addr::UNSPECIFIED.to_string(),
                    port,
                },
            ],
            parser::LocalEndpoint::Unix(path) => vec![BindAddress::Unix { path }],
        };

        LocalForwardRule {
            local_addresses,
            remote_address,
        }
    }
}

impl FromStr for LocalForwardRule {
    type Err = Error;

    fn from_str(rule: &str) -> Result<Self, Self::Err> {
        rule.parse::<parser::LocalForwardRule>()
            .map(Self::from)
            .context(Snafu {
                kind: "local",
                rule,
            })
    }
}

/// 远程转发规则
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteForwardRule {
    pub local_address: Option<BindAddress>,
    pub remote_addresses: Vec<BindAddress>,
}

impl From<parser::RemoteForwardRule> for RemoteForwardRule {
    fn from(value: parser::RemoteForwardRule) -> Self {
        let local_address = value.local.map(|local| match local {
            parser::RemoteEndpoint::Host { host, port } => BindAddress::Host { host, port },
            parser::RemoteEndpoint::Unix { path } => BindAddress::Unix { path },
        });

        let remote_addresses = match value.remote {
            parser::LocalEndpoint::Addr(socket_addr) => vec![BindAddress::Host {
                host: socket_addr.ip().to_string(),
                port: socket_addr.port(),
            }],
            parser::LocalEndpoint::Port(port) => vec![
                BindAddress::Host {
                    host: Ipv4Addr::UNSPECIFIED.to_string(),
                    port,
                },
                BindAddress::Host {
                    host: Ipv6Addr::UNSPECIFIED.to_string(),
                    port,
                },
            ],
            parser::LocalEndpoint::Unix(path) => vec![BindAddress::Unix { path }],
        };

        RemoteForwardRule {
            local_address,
            remote_addresses,
        }
    }
}

impl FromStr for RemoteForwardRule {
    type Err = Error;

    fn from_str(rule: &str) -> Result<Self, Self::Err> {
        rule.parse::<parser::RemoteForwardRule>()
            .map(Self::from)
            .context(Snafu {
                kind: "remote",
                rule,
            })
    }
}

impl DynamicForwardEndpoint {
    /// 获取所有地址的切片
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

impl LocalForwardRule {
    /// 获取所有本地地址和远程地址的配对
    pub fn pairs(&self) -> impl Iterator<Item = (BindAddress, BindAddress)> + '_ {
        self.local_addresses
            .iter()
            .map(|local| (local.clone(), self.remote_address.clone()))
    }
}

impl RemoteForwardRule {
    /// 获取所有本地地址和远程地址的配对
    pub fn pairs(&self) -> impl Iterator<Item = (Option<BindAddress>, BindAddress)> + '_ {
        self.remote_addresses
            .iter()
            .map(move |remote| (self.local_address.clone(), remote.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::*;

    #[test]
    fn test_dynamic_forward_endpoint_parsing() {
        // Test simple port
        let endpoint: DynamicForwardEndpoint = "8080".parse().unwrap();
        assert_eq!(endpoint.addresses.len(), 2);
        assert!(
            endpoint
                .addresses
                .contains(&SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 8080))
        );
        assert!(
            endpoint
                .addresses
                .contains(&SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 8080))
        );

        // Test with specific IP
        let endpoint: DynamicForwardEndpoint = "127.0.0.1:8080".parse().unwrap();
        assert_eq!(endpoint.addresses.len(), 1);
        assert_eq!(endpoint.addresses[0], "127.0.0.1:8080".parse().unwrap());

        // Test with wildcard
        let endpoint: DynamicForwardEndpoint = "*:8080".parse().unwrap();
        assert_eq!(endpoint.addresses.len(), 2);
    }

    #[test]
    fn test_local_forward_rule_parsing() {
        // Test basic local forward
        let rule: LocalForwardRule = "8080:example.com:80".parse().unwrap();
        assert_eq!(rule.local_addresses.len(), 2); // IPv4 and IPv6 unspecified
        assert_eq!(
            rule.remote_address,
            proto::messages::BindAddress::Host {
                host: "example.com".to_string(),
                port: 80
            }
        );

        // Test iterator functionality
        let pairs: Vec<_> = rule.pairs().collect();
        assert_eq!(pairs.len(), 2);

        // Test with specific bind address
        let rule: LocalForwardRule = "127.0.0.1:8080:example.com:80".parse().unwrap();
        assert_eq!(rule.local_addresses.len(), 1);
        assert_eq!(
            rule.local_addresses[0],
            proto::messages::BindAddress::Host {
                host: "127.0.0.1".to_string(),
                port: 8080
            }
        );

        // Test iterator functionality with single address
        let pairs: Vec<_> = rule.pairs().collect();
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn test_remote_forward_rule_parsing() {
        // Test SOCKS mode (no local endpoint)
        let rule: RemoteForwardRule = "8080".parse().unwrap();
        assert_eq!(rule.local_address, None);
        assert_eq!(rule.remote_addresses.len(), 2); // IPv4 and IPv6 unspecified

        // Test iterator functionality
        let pairs: Vec<_> = rule.pairs().collect();
        assert_eq!(pairs.len(), 2);
        // All pairs should have None as local address
        assert!(pairs.iter().all(|(local, _)| local.is_none()));

        // Test with local endpoint
        let rule: RemoteForwardRule = "8080:localhost:3000".parse().unwrap();
        assert_eq!(
            rule.local_address,
            Some(proto::messages::BindAddress::Host {
                host: "localhost".to_string(),
                port: 3000
            })
        );

        // Test iterator with local endpoint
        let pairs: Vec<_> = rule.pairs().collect();
        assert_eq!(pairs.len(), 2); // Should still have IPv4 and IPv6 remote addresses
        // All pairs should have the same local address
        assert!(pairs.iter().all(|(local, _)| local.is_some()));
    }
}
