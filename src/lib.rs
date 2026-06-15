//! DShell protocol types and codec

pub mod auth;
pub mod byte_channel;
pub mod channel;
#[cfg(feature = "client")]
pub mod client;
pub mod codec;
#[cfg(feature = "config")]
pub mod config;
pub mod constants;
pub mod conversation;
pub mod error;
pub mod forward;
pub mod message;
pub mod session;
pub mod version;
pub mod webtransport;

#[cfg(test)]
mod test_support;

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_raw_dshell_protocol_module_is_not_exported() {
        let lib = include_str!("lib.rs");
        let legacy_protocol_export = concat!("pub mod ", "protocol;");

        assert!(
            !lib.contains(legacy_protocol_export),
            "dshell transport must stay WebTransport-only"
        );
    }
}
