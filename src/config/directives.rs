//! Typed secondary parsing of directive arguments.
//!
//! Each struct here represents the parsed arguments of a specific SSH config
//! keyword.  Callers first match on `directive.keyword`, then call
//! `directive.parse_args::<T>()` to obtain a typed result whose [`Location`]s
//! remain valid references into the original source text.
//!
//! # Error types
//!
//! Error types are split by failure domain:
//!
//! - [`ArgumentCountError`] — for types whose only failure mode is wrong
//!   argument count (HostName, User, IdentityFile, Host, Include, …).
//! - [`ParseIntegerArgError`] — for types that also parse an integer
//!   (Port, ServerAliveInterval, ConnectTimeout, …).
//! - [`ParseRemoteForwardArgsError`] — RemoteForward's unique 1-or-2 count.

use std::num::ParseIntError;

use snafu::Snafu;

use super::{Located, ParseArguments};

// ---------------------------------------------------------------------------
// Error types — split by failure domain (no location info; wrapped by Located)
// ---------------------------------------------------------------------------

/// Argument count mismatch.
///
/// Used by types whose only failure mode is having the wrong number of
/// arguments (e.g., HostName expects exactly 1, Host expects at least 1).
#[derive(Debug, Snafu)]
#[snafu(display("expected {expected} argument(s), got {actual}"))]
pub struct ArgumentCountError {
    pub expected: &'static str,
    pub actual: usize,
}

/// Error when parsing an integer argument.
///
/// Used by types that expect exactly one argument and parse it as an integer
/// (Port, ServerAliveInterval, ConnectTimeout, ConnectionAttempts, etc.).
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseIntegerArgError {
    #[snafu(display("expected exactly 1 argument, got {actual}"))]
    WrongArgumentCount { actual: usize },

    #[snafu(display("invalid integer value"))]
    InvalidValue { source: ParseIntError },
}

/// Error specific to RemoteForward argument parsing (1 or 2 arguments).
#[derive(Debug, Snafu)]
#[snafu(display("expected 1 or 2 arguments, got {actual}"))]
pub struct ParseRemoteForwardArgsError {
    pub actual: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn tokenize_single<'a>(
    args: &Located<&'a str>,
) -> Result<Located<&'a str>, Located<ArgumentCountError>> {
    let tokens = args.tokenize();
    if tokens.len() != 1 {
        return Err(args.with_value(ArgumentCountError {
            expected: "exactly 1",
            actual: tokens.len(),
        }));
    }
    Ok(tokens.into_iter().next().unwrap())
}

fn tokenize_pair<'a>(
    args: &Located<&'a str>,
) -> Result<(Located<&'a str>, Located<&'a str>), Located<ArgumentCountError>> {
    let tokens = args.tokenize();
    if tokens.len() != 2 {
        return Err(args.with_value(ArgumentCountError {
            expected: "exactly 2",
            actual: tokens.len(),
        }));
    }
    let mut iter = tokens.into_iter();
    let first = iter.next().unwrap();
    let second = iter.next().unwrap();
    Ok((first, second))
}

fn tokenize_at_least_one<'a>(
    args: &Located<&'a str>,
) -> Result<Vec<Located<&'a str>>, Located<ArgumentCountError>> {
    let tokens = args.tokenize();
    if tokens.is_empty() {
        return Err(args.with_value(ArgumentCountError {
            expected: "at least 1",
            actual: 0,
        }));
    }
    Ok(tokens)
}

fn parse_single_integer<T: std::str::FromStr<Err = ParseIntError>>(
    args: &Located<&str>,
) -> Result<Located<T>, Located<ParseIntegerArgError>> {
    let tokens = args.tokenize();
    if tokens.len() != 1 {
        return Err(args.with_value(ParseIntegerArgError::WrongArgumentCount {
            actual: tokens.len(),
        }));
    }
    let token = &tokens[0];
    let value = token
        .value
        .parse::<T>()
        .map_err(|source| token.with_value(ParseIntegerArgError::InvalidValue { source }))?;
    Ok(token.with_value(value))
}

// ---------------------------------------------------------------------------
// Argument types — "at least 1" arguments (Error = ArgumentCountError)
// ---------------------------------------------------------------------------

/// `Host pattern1 pattern2 ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostArgs<'a> {
    pub patterns: Vec<Located<&'a str>>,
}

impl<'a> ParseArguments<'a> for HostArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let tokens = tokenize_at_least_one(args)?;
        Ok(args.with_value(Self { patterns: tokens }))
    }
}

/// `Match criteria ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchArgs<'a> {
    pub criteria: Vec<Located<&'a str>>,
}

impl<'a> ParseArguments<'a> for MatchArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let tokens = tokenize_at_least_one(args)?;
        Ok(args.with_value(Self { criteria: tokens }))
    }
}

/// `Include path1 path2 ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeArgs<'a> {
    pub paths: Vec<Located<&'a str>>,
}

impl<'a> ParseArguments<'a> for IncludeArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let tokens = tokenize_at_least_one(args)?;
        Ok(args.with_value(Self { paths: tokens }))
    }
}

/// Generic multi-string argument (usable for any keyword that takes one or more
/// opaque string values, e.g., `SendEnv`, `SetEnv`, `GlobalKnownHostsFile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiArg<'a> {
    pub values: Vec<Located<&'a str>>,
}

impl<'a> ParseArguments<'a> for MultiArg<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let tokens = tokenize_at_least_one(args)?;
        Ok(args.with_value(Self { values: tokens }))
    }
}

// ---------------------------------------------------------------------------
// Argument types — "exactly 1" string argument (Error = ArgumentCountError)
// ---------------------------------------------------------------------------

/// `HostName hostname`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNameArgs<'a> {
    pub hostname: Located<&'a str>,
}

impl<'a> ParseArguments<'a> for HostNameArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let hostname = tokenize_single(args)?;
        Ok(args.with_value(Self { hostname }))
    }
}

/// `User username`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserArgs<'a> {
    pub username: Located<&'a str>,
}

impl<'a> ParseArguments<'a> for UserArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let username = tokenize_single(args)?;
        Ok(args.with_value(Self { username }))
    }
}

/// `IdentityFile path`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFileArgs<'a> {
    pub path: Located<&'a str>,
}

impl<'a> ParseArguments<'a> for IdentityFileArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let path = tokenize_single(args)?;
        Ok(args.with_value(Self { path }))
    }
}

/// `CertificateFile path`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateFileArgs<'a> {
    pub path: Located<&'a str>,
}

impl<'a> ParseArguments<'a> for CertificateFileArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let path = tokenize_single(args)?;
        Ok(args.with_value(Self { path }))
    }
}

/// `DynamicForward [bind_address:]port`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicForwardArgs<'a> {
    pub bind: Located<&'a str>,
}

impl<'a> ParseArguments<'a> for DynamicForwardArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let bind = tokenize_single(args)?;
        Ok(args.with_value(Self { bind }))
    }
}

/// `ProxyJump destination1,destination2,...`
///
/// The first-layer parser captures the comma-separated list as a single token;
/// this secondary parser splits by comma and computes sub-locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyJumpArgs<'a> {
    pub jumps: Vec<Located<&'a str>>,
}

impl<'a> ParseArguments<'a> for ProxyJumpArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let token = tokenize_single(args)?;
        Ok(args.with_value(Self {
            jumps: token.split_comma(),
        }))
    }
}

/// Generic single-string argument (usable for any keyword that takes exactly
/// one opaque string value, e.g., `LogLevel`, `AddressFamily`, `Compression`,
/// `RequestTTY`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleArg<'a> {
    pub value: Located<&'a str>,
}

impl<'a> ParseArguments<'a> for SingleArg<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let value = tokenize_single(args)?;
        Ok(args.with_value(Self { value }))
    }
}

// ---------------------------------------------------------------------------
// Argument types — "exactly 2" arguments (Error = ArgumentCountError)
// ---------------------------------------------------------------------------

/// `LocalForward [bind_address:]port host:hostport` or Unix socket variants
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalForwardArgs<'a> {
    pub bind: Located<&'a str>,
    pub destination: Located<&'a str>,
}

impl<'a> ParseArguments<'a> for LocalForwardArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let (bind, destination) = tokenize_pair(args)?;
        Ok(args.with_value(Self { bind, destination }))
    }
}

// ---------------------------------------------------------------------------
// Argument types — integer parsing (Error = ParseIntegerArgError)
// ---------------------------------------------------------------------------

/// `Port number`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortArgs {
    pub port: Located<u16>,
}

impl ParseArguments<'_> for PortArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &Located<&str>) -> Result<Located<Self>, Located<Self::Error>> {
        let port = parse_single_integer(args)?;
        Ok(args.with_value(Self { port }))
    }
}

/// `ServerAliveInterval seconds`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAliveIntervalArgs {
    pub seconds: Located<u32>,
}

impl ParseArguments<'_> for ServerAliveIntervalArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &Located<&str>) -> Result<Located<Self>, Located<Self::Error>> {
        let seconds = parse_single_integer(args)?;
        Ok(args.with_value(Self { seconds }))
    }
}

/// `ServerAliveCountMax count`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAliveCountMaxArgs {
    pub count: Located<u32>,
}

impl ParseArguments<'_> for ServerAliveCountMaxArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &Located<&str>) -> Result<Located<Self>, Located<Self::Error>> {
        let count = parse_single_integer(args)?;
        Ok(args.with_value(Self { count }))
    }
}

/// `ConnectTimeout seconds`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTimeoutArgs {
    pub seconds: Located<u32>,
}

impl ParseArguments<'_> for ConnectTimeoutArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &Located<&str>) -> Result<Located<Self>, Located<Self::Error>> {
        let seconds = parse_single_integer(args)?;
        Ok(args.with_value(Self { seconds }))
    }
}

/// `ConnectionAttempts count`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAttemptsArgs {
    pub count: Located<u32>,
}

impl ParseArguments<'_> for ConnectionAttemptsArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &Located<&str>) -> Result<Located<Self>, Located<Self::Error>> {
        let count = parse_single_integer(args)?;
        Ok(args.with_value(Self { count }))
    }
}

// ---------------------------------------------------------------------------
// Argument types — unique count logic (Error = ParseRemoteForwardArgsError)
// ---------------------------------------------------------------------------

/// `RemoteForward [bind_address:]port [host:hostport]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForwardArgs<'a> {
    pub bind: Located<&'a str>,
    pub destination: Option<Located<&'a str>>,
}

impl<'a> ParseArguments<'a> for RemoteForwardArgs<'a> {
    type Error = ParseRemoteForwardArgsError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let tokens = args.tokenize();
        if tokens.is_empty() || tokens.len() > 2 {
            return Err(args.with_value(ParseRemoteForwardArgsError {
                actual: tokens.len(),
            }));
        }
        let mut iter = tokens.into_iter();
        let bind = iter.next().unwrap();
        let destination = iter.next();
        Ok(args.with_value(Self { bind, destination }))
    }
}
