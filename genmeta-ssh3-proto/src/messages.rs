use std::{fmt::Display, net::SocketAddr, path::PathBuf};

use bytes::Bytes;
use derive_more::From;
use serde::{Deserialize, Serialize};

use crate::mux::Token;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Message {
    Request { token: Token, request: Request },
    Data { token: Token, data: Bytes },
    Error { token: Token, error: String },
    Close { token: Token },
    Headrbeat {},
}

#[derive(Debug, From, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum BindAddress {
    /// 包括IP地址
    Host { host: String, port: u16 },
    /// UNIX socket的路径
    Unix { path: PathBuf },
}

impl From<SocketAddr> for BindAddress {
    fn from(addr: SocketAddr) -> Self {
        Self::Host {
            host: addr.ip().to_string(),
            port: addr.port(),
        }
    }
}

impl Display for BindAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindAddress::Host { host, port } => write!(f, "{host}:{port}"),
            BindAddress::Unix { path } => Display::fmt(&path.display(), f),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Request {
    /// 打开认证通道
    ///
    /// 通道使用[`auth`]模块的消息
    Auth { username: String },
    /// 执行一个命令
    ///
    /// 通道使用[`session`]模块的消息
    Exec {
        pseudo: bool,
        #[serde(default)]
        commands: Option<String>,
        #[serde(default)]
        environments: Vec<(String, String)>,
    },
    /// 初始化远程转发。让对端监听一个地址，接收到的连接通过Forwarded消息转发给本地
    ///
    /// 发起方关闭通道发送Close表示不希望Server继续监听
    ///
    /// 接收方关闭通道发送Error表示监听出错
    ///
    /// 当前客户端不接受此消息
    ///
    /// 通道不传输任何数据
    Forward {
        listen: BindAddress,
        /// 如果socks为false，Forwarded消息不携带to
        ///
        /// 如果socks为true，对端启动一个socks5代理服务器，Forwared携带代理连接期望连接到的地址
        socks: bool,
    },
    /// Forward的接受方从指定地址接收到连接，发送此消息请求转发
    ///
    /// 当前服务端不接受此消息
    ///
    /// 通道消息不序列化，使用streaming
    Forwarded {
        /// Forwarded接收方（Forward发送方）需要通过listen鉴权，listen应为对应Forward通道的token
        listen: Token,
        /// 远程转发可以不指定本地地址，对端就可以启动一个socks服务器，连接到*任意*本地地址
        ///
        /// 其他情况，接受连接的本地BindAddress不暴露给对面，to为None（本地知道）
        to: Option<BindAddress>,
    },
    /// 本地转发。转发数据到对端的某地址
    ///
    /// 不同于Forwarded，这个是客户端发出的。客户端不接受此消息
    ///
    /// 通道消息不序列化，使用streaming
    Direct { to: BindAddress },
    // todo: Signal
}

impl From<&Request> for Request {
    fn from(value: &Request) -> Self {
        value.clone()
    }
}

impl Display for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Auth { username } => write!(f, "Login {username}"),
            Request::Exec {
                pseudo,
                commands,
                environments,
            } => {
                write!(
                    f,
                    "Exec {} {}",
                    commands.as_deref().unwrap_or("shell"),
                    if *pseudo { "with pty" } else { "no pty" }
                )?;

                if !environments.is_empty() {
                    write!(f, " with environments")?;
                    for (key, value) in environments {
                        write!(f, " {key}={value}")?;
                    }
                }

                Ok(())
            }
            Request::Forward { listen, socks } => write!(
                f,
                "Remote forward data from remote {} (socks: {}) to local",
                listen,
                if *socks { "yes" } else { "no" }
            ),
            Request::Forwarded { listen, to } => write!(
                f,
                "Forwarded data to remote {} (channel permitted by client Forward channel with token {listen})",
                to.as_ref()
                    .map(|to| to.to_string())
                    .unwrap_or_else(|| "<unknwon address>".to_string())
            ),
            Request::Direct { to } => write!(f, "Local forward data to remote {to}"),
        }
    }
}

pub mod auth {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum ClientAuthMessage {
        Password(String),
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum ServerAuthMessage {
        Accept,
        Password { prompt: String },
        // Reject: Message::Error
    }
}

pub mod session {
    use super::*;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum ClientSessionMessage {
        WindowSize {
            rows: u16,
            cols: u16,
            width: u16,
            height: u16,
        },

        #[serde(alias = "Sequence")]
        Terminal(Bytes),
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub enum ServerSessionMessage {
        Terminal { stderr: bool, data: Bytes },
        Exit { code: i32 },
    }
}
