use std::{borrow::Cow, io, path::PathBuf};

use peg::{error::ParseError, str::LineCol};

#[derive(snafu::Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum ParseConfigError {
    #[snafu(transparent)]
    LexConfig { source: ParseError<LineCol> },
    #[snafu(display("Too many values at {location}"))]
    TooManyArguments { location: LineCol },
    #[snafu(display("Failed to expand path at {location}"))]
    ExpandAssetPath {
        location: LineCol,
        source: ExpandError,
    },
    #[snafu(display("Cannot read file `{}` which specified at {location}", path.display()))]
    ReadAssetFile {
        location: LineCol,
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(feature = "openssh")]
    #[snafu(display("Cannot parse URI at {location}"))]
    ParseUri {
        location: LineCol,
        source: <http::Uri as std::str::FromStr>::Err,
    },
    #[snafu(display("Cannot parse Integer at {location}"))]
    ParseInteger {
        location: LineCol,
        source: std::num::ParseIntError,
    },
    #[snafu(display("Missing parameter `{keyword}` for `{pattern}`"))]
    MissingParameter {
        pattern: String,
        keyword: Cow<'static, str>,
    },
}

#[derive(snafu::Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum ReadConfigError {
    #[snafu(display("Cannot locate config file: {message}"))]
    LocateConfigFile { message: String },
    #[snafu(display("Cannot read config file at `{}`", path.display()))]
    ReadConfigFile { path: PathBuf, source: io::Error },
    #[snafu(display("Cannot parse config file `{}`", path.display()))]
    ParseConfigFile {
        path: PathBuf,
        source: ParseConfigError,
    },
    #[snafu(display("Cannot parse config content `{content}`"))]
    ParseConfigContent {
        content: String,
        source: ParseConfigError,
    },
}

#[derive(snafu::Snafu, Debug)]
#[snafu(visibility(pub))]
pub enum CheckConfigError {
    #[snafu(display("Find unknown keyword `{keyword}` at {}:{location}", path.display()))]
    UnknownKeyword {
        keyword: String,
        path: PathBuf,
        location: LineCol,
    },
    #[snafu(transparent)]
    ReadConfig { source: ReadConfigError },
}

#[derive(snafu::Snafu, Debug)]
#[snafu(display("Failed to expand `{chars}`"))]
#[snafu(visibility(pub))]
pub struct ExpandError {
    chars: String,
}
