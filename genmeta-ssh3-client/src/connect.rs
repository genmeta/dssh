use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use futures::StreamExt;
use genmeta_common::{
    connect::{DnsErrors, lookup},
    h3_stream::H3Stream,
    *,
};
use gm_quic::{BindInterfaceError, ParameterId, ToCertificate, handy::client_parameters};
use http::Uri;
use qdns::{HttpResolver, MdnsResolver, Resolvers, UdpResolver};
use qtraversal::iface::traversal_factory;
use snafu::prelude::*;
use ssh_config::genmeta::Profile;
use ssh3_proto::v0::mux;
use tokio::{io, time};
use tokio_util::{codec, io::StreamReader};

use crate::config::Config;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Failed to create DNS resolver"))]
    CreateDnsResolver {
        schema: &'static str,
        source: io::Error,
    },
    #[snafu(display("Missing host in URI {uri}"))]
    MissingServerName { uri: Uri },
    #[snafu(display("Dns lookup failed for `{server}`"))]
    DnsLookup { server: String, source: DnsErrors },
    #[snafu(transparent)]
    BindInterface { source: BindInterfaceError },
    #[snafu(display("Connection timed out after {}ms for server `{server}`", connect_timeout.as_millis()))]
    Timedout {
        server: String,
        connect_timeout: Duration,
    },
    #[snafu(transparent)]
    Quic { source: gm_quic::Error },
    #[snafu(display("Failed to initialize H3 connection"))]
    InitialH3 { source: h3::error::ConnectionError },

    #[snafu(display("H3 request failed"))]
    Request { source: h3::error::StreamError },

    #[snafu(display("H3 response failed"))]
    Response { source: h3::error::StreamError },

    #[snafu(display("Server returned error status: {status}"))]
    ResponseStatus { status: http::StatusCode },
}

pub type QuicConnection = Arc<gm_quic::Connection>;
pub type H3Connection = h3::client::Connection<h3_shim::QuicConnection, Bytes>;
pub type H3Client = h3::client::SendRequest<h3_shim::OpenStreams, Bytes>;

pub async fn connect(
    config: &Config,
) -> Result<
    (
        QuicConnection,
        H3Connection,
        H3Client,
        Arc<mux::Mux>,
        mux::Incomings,
    ),
    Error,
> {
    let resolvers = Resolvers::new()
        .with(Arc::new(
            HttpResolver::new(qdns::HTTP_DNS_SERVER)
                .context(CreateDnsResolverSnafu { schema: "http" })?,
        ))
        .with(Arc::new(
            MdnsResolver::new(qdns::MDNS_SERVICE)
                .context(CreateDnsResolverSnafu { schema: "mdns" })?,
        ))
        .with(Arc::new(UdpResolver::new(qdns::UDP_DNS_SERVER)));

    let server_name = config.uri.host().context(MissingServerNameSnafu {
        uri: config.uri.clone(),
    })?;

    let mut dns_lookup = lookup(&resolvers, server_name)
        .await
        .context(DnsLookupSnafu {
            server: server_name,
        })?;

    let (_, server_eps) = dns_lookup.next().await.unwrap();

    let quic_client = {
        let mut roots = rustls::RootCertStore::empty();
        roots.add_parsable_certificates(ROOT_CERT.to_certificate());

        let factory = traversal_factory(&AGENTS);
        let mut parameters = client_parameters();

        match &config.profile {
            Some(Profile { id, key, cert }) => {
                parameters
                    .set(ParameterId::ClientName, id.to_owned())
                    .unwrap();
                gm_quic::QuicClient::builder()
                    .with_root_certificates(roots)
                    .with_cert(cert.as_slice(), key.as_slice())
            }
            None => gm_quic::QuicClient::builder()
                .with_root_certificates(roots)
                .without_cert(),
        }
        .with_parameters(parameters)
        .with_iface_factory(factory.as_ref().clone())
        .bind(factory.devices().keys().map(|ip| SocketAddr::new(*ip, 0)))
        .enable_sslkeylog()
        .build()
    };

    let (quic_conn, h3_conn, mut h3_client) = {
        tracing::debug!(target: "connect", server_name, ?server_eps, "Attempt connect to server");
        let quic_connection = quic_client.connect(server_name, server_eps)?;
        tokio::spawn({
            let conn = quic_connection.clone();
            async move {
                while let Some((_, server_eps)) = dns_lookup.next().await {
                    for server_ep in server_eps {
                        if conn.add_peer_endpoint(server_ep.into()).is_err() {
                            return;
                        }
                    }
                }
            }
        });
        let connect = h3::client::new(h3_shim::QuicConnection::new(quic_connection.clone()));
        let (h3_conn, h3_client) = time::timeout(config.connect_timeout, connect)
            .await
            .map_err(|_| {
                if let Err(quic_error) = quic_connection.validate() {
                    return Error::from(quic_error);
                }
                _ = quic_connection.close("connect timeout", 0);
                TimedoutSnafu::build(TimedoutSnafu {
                    connect_timeout: config.connect_timeout,
                    server: server_name.to_string(),
                })
            })?
            .context(InitialH3Snafu)?;
        (quic_connection, h3_conn, h3_client)
    };

    let request = http::Request::builder()
        .method(ssh3_proto::v0::METHOD.clone())
        .uri(config.uri.clone())
        .body(())
        .unwrap();
    tracing::debug!(target: "connect", ?request);

    // sending request results in a bidirectional stream,
    // which is also used for receiving response
    let mut stream = h3_client
        .send_request(request)
        .await
        .context(RequestSnafu)?;
    let response = stream.recv_response().await.context(ResponseSnafu)?;
    tracing::debug!(target: "connect", ?response);
    ensure!(
        response.status() == 200,
        ResponseStatusSnafu {
            status: response.status()
        }
    );

    let (sender, recver) = stream.split();
    let (mux, incomings) = mux::Mux::new(
        mux::Role::Client,
        codec::FramedRead::new(
            StreamReader::new(H3Stream::new(recver)),
            cbor_codec::CborDecoder::default(),
        ),
        codec::FramedWrite::new(
            h3_stream::H3Sink::new(sender),
            cbor_codec::CborEncoder::default(),
        ),
    );

    Ok((quic_conn, h3_conn, h3_client, mux, incomings))
}
