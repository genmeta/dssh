// //! Socks5 proxy server implementation.

use std::sync::Arc;

use snafu::Report;
pub use socks5_proto::Error;
use socks5_proto::{Address, ProtocolError, Reply, Request, Response, handshake};
use tokio::io::{self, AsyncRead, AsyncWrite};

use crate::{
    forward, messages,
    mux::{Mux, Recver, Sender, Token},
};

pub async fn accept(
    reader: &mut (impl AsyncRead + Unpin),
    writer: &mut (impl AsyncWrite + Unpin),
    connect: impl AsyncFnOnce(&str, u16) -> io::Result<(Recver, Sender)>,
) -> Result<(), Error> {
    let handshake_request = match handshake::Request::read_from(reader).await {
        Ok(handshake_request) => handshake_request,
        Err(error) => {
            tracing::debug!(target: "socks", "Failed to parse handshake request: {error:?}");
            return Err(error);
        }
    };

    if handshake_request.methods.contains(&handshake::Method::NONE) {
        handshake::Response::new(handshake::Method::NONE)
            .write_to(writer)
            .await?;
    } else {
        tracing::debug!(target: "socks", "No acceptable method, reject handshake request");
        handshake::Response::new(handshake::Method::UNACCEPTABLE)
            .write_to(writer)
            .await?;
        return Err(Error::Protocol(
            ProtocolError::NoAcceptableHandshakeMethod {
                version: socks5_proto::SOCKS_VERSION,
                chosen_method: handshake::Method::NONE,
                methods: handshake_request.methods,
            },
        ))?;
    }

    let request = match Request::read_from(reader).await {
        Ok(request) => request,
        Err(error) => {
            tracing::debug!(target: "socks", "Failed to parse request: {error:?}");
            Response::new(Reply::GeneralFailure, Address::unspecified())
                .write_to(writer)
                .await?;
            return Err(error);
        }
    };

    match request.command {
        socks5_proto::Command::Connect => {
            let connect = match request.address {
                Address::SocketAddress(socket_addr) => {
                    connect(&socket_addr.ip().to_string(), socket_addr.port()).await
                }
                Address::DomainAddress(ref domain, port) => {
                    let domain = String::from_utf8_lossy(domain);
                    connect(&domain, port).await
                }
            };
            let mut tcp_stream = match connect {
                Ok((recver, sender)) => io::join(recver.streaming(), sender.streaming()),
                Err(error) => {
                    let reply = match error.kind() {
                        io::ErrorKind::ConnectionRefused => Reply::ConnectionRefused,
                        io::ErrorKind::NetworkUnreachable => Reply::NetworkUnreachable,
                        io::ErrorKind::HostUnreachable => Reply::HostUnreachable,
                        io::ErrorKind::TimedOut => Reply::NetworkUnreachable,
                        _ => Reply::GeneralFailure,
                    };
                    tracing::debug!(
                        target: "socks", "Failed to connect to {}: {}",
                        request.address, Report::from_error(&error)
                    );
                    Response::new(reply, Address::unspecified())
                        .write_to(writer)
                        .await?;
                    return Err(error.into());
                }
            };

            Response::new(Reply::Succeeded, Address::unspecified())
                .write_to(writer)
                .await?;

            tracing::debug!(target: "socks", "Connected to {}", request.address);
            io::copy_bidirectional(&mut tcp_stream, &mut io::join(reader, writer)).await?;
            tracing::debug!(target: "socks", "Shutdown connect to {}", request.address);
            Ok(())
        }
        socks5_proto::Command::Bind | socks5_proto::Command::Associate => {
            tracing::debug!(target: "socks", "BIND and ASSOCIATE commands are not supported");
            Response::new(Reply::CommandNotSupported, Address::unspecified())
                .write_to(writer)
                .await?;
            Ok(())
        }
    }
}

pub async fn accept_direct(
    mut reader: &mut (impl AsyncRead + Unpin + ?Sized),
    mut writer: &mut (impl AsyncWrite + Unpin + ?Sized),
    mux: Arc<Mux>,
) -> Result<(), Error> {
    accept(&mut reader, &mut writer, async |host, port| {
        let open = messages::Request::Direct {
            to: (host.to_owned(), port).into(),
        };
        forward::LocalForwarder::new(mux, open)
            .open_channel()
            .await
            .map(|(_, r, s)| (r, s))
            .map_err(io::Error::other)
    })
    .await
}

pub async fn accept_forward(
    mut reader: &mut (impl AsyncRead + Unpin + ?Sized),
    mut writer: &mut (impl AsyncWrite + Unpin + ?Sized),
    mux: Arc<Mux>,
    token: Token,
) -> Result<(), Error> {
    accept(&mut reader, &mut writer, async |host, port| {
        let open = messages::Request::Forwarded {
            listen: token,
            to: Some((host.to_owned(), port).into()),
        };
        forward::LocalForwarder::new(mux, open)
            .open_channel()
            .await
            .map(|(_, r, s)| (r, s))
            .map_err(io::Error::other)
    })
    .await
}
