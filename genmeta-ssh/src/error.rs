use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub), module)]
pub enum Ssh3Error {
    #[snafu(display("missing ssh-version header"))]
    MissingSshVersionHeader,

    #[snafu(display("invalid ssh-version header value"))]
    InvalidSshVersionHeaderValue { source: http::header::ToStrError },

    #[snafu(display("empty ssh-version header"))]
    EmptySshVersionHeader,

    #[snafu(display("no supported ssh-version found in client offer: {offered:?}"))]
    UnsupportedSshVersion { offered: String },

    #[snafu(display("unknown channel type"))]
    UnknownChannelType,

    #[snafu(display("missing scheme/credentials separator"))]
    MissingSchemeSeparator,

    #[snafu(display("unsupported auth scheme: {scheme}"))]
    UnsupportedAuthScheme { scheme: String },

    #[snafu(display("empty credentials"))]
    EmptyCredentials,

    #[snafu(display("invalid base64 credentials"))]
    InvalidBase64Credentials { source: base64::DecodeError },

    #[snafu(display("credentials are not valid UTF-8"))]
    CredentialsNotUtf8 { source: std::string::FromUtf8Error },

    #[snafu(display("missing ':' separator in decoded credentials"))]
    MissingCredentialSeparator,

    #[snafu(display("invalid credentials"))]
    InvalidCredentials,

    #[snafu(display("channel closed"))]
    ChannelClosed,

    #[snafu(display("exec failed"))]
    ExecFailed,
}
