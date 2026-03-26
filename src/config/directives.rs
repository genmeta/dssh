//! Typed secondary parsing of directive arguments.
//!
//! Each struct here represents the parsed arguments of a specific SSH config
//! keyword.  Callers first match on `directive.keyword`, then call
//! `directive.parse_args::<T>()` to obtain a typed result whose [`Span`]s
//! remain valid offsets into the original source text.
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

use super::{ParseArguments, Span, Spanned};

// ---------------------------------------------------------------------------
// Error types — split by failure domain
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
    pub span: Span,
}

/// Error when parsing an integer argument.
///
/// Used by types that expect exactly one argument and parse it as an integer
/// (Port, ServerAliveInterval, ConnectTimeout, ConnectionAttempts, etc.).
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseIntegerArgError {
    #[snafu(display("expected exactly 1 argument, got {actual}"))]
    WrongArgumentCount { actual: usize, span: Span },

    #[snafu(display("invalid integer value"))]
    InvalidValue {
        span: Span,
        source: ParseIntError,
    },
}

/// Error specific to RemoteForward argument parsing (1 or 2 arguments).
#[derive(Debug, Snafu)]
#[snafu(display("expected 1 or 2 arguments, got {actual}"))]
pub struct ParseRemoteForwardArgsError {
    pub actual: usize,
    pub span: Span,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn args_span(args: &[Spanned<&str>]) -> Span {
    match (args.first(), args.last()) {
        (Some(first), Some(last)) => Span {
            start: first.span.start,
            end: last.span.end,
        },
        _ => Span { start: 0, end: 0 },
    }
}

fn expect_exactly(args: &[Spanned<&str>], n: usize) -> Result<(), ArgumentCountError> {
    if args.len() != n {
        return Err(ArgumentCountError {
            expected: match n {
                1 => "exactly 1",
                2 => "exactly 2",
                _ => "the correct number of",
            },
            actual: args.len(),
            span: args_span(args),
        });
    }
    Ok(())
}

fn expect_at_least_one(args: &[Spanned<&str>]) -> Result<(), ArgumentCountError> {
    if args.is_empty() {
        return Err(ArgumentCountError {
            expected: "at least 1",
            actual: 0,
            span: Span { start: 0, end: 0 },
        });
    }
    Ok(())
}

fn parse_single_integer<T: std::str::FromStr<Err = ParseIntError>>(
    args: &[Spanned<&str>],
) -> Result<Spanned<T>, ParseIntegerArgError> {
    if args.len() != 1 {
        return Err(ParseIntegerArgError::WrongArgumentCount {
            actual: args.len(),
            span: args_span(args),
        });
    }
    let value = args[0]
        .value
        .parse::<T>()
        .map_err(|source| ParseIntegerArgError::InvalidValue {
            span: args[0].span,
            source,
        })?;
    Ok(Spanned {
        value,
        span: args[0].span,
    })
}

/// Split a single comma-separated `Spanned<&str>` into sub-spans.
fn split_comma_spanned<'a>(raw: &Spanned<&'a str>) -> Vec<Spanned<&'a str>> {
    let mut result = Vec::new();
    let base = raw.span.start;
    let mut offset = 0;

    for part in raw.value.split(',') {
        let start = base + offset;
        let end = start + part.len();
        result.push(Spanned {
            value: part,
            span: Span { start, end },
        });
        offset += part.len() + 1; // +1 for the comma
    }

    result
}

// ---------------------------------------------------------------------------
// Argument types — "at least 1" arguments (Error = ArgumentCountError)
// ---------------------------------------------------------------------------

/// `Host pattern1 pattern2 ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostArgs<'a> {
    pub patterns: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for HostArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_at_least_one(args)?;
        Ok(Self { patterns: args.to_vec() })
    }
}

/// `Match criteria ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchArgs<'a> {
    pub criteria: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for MatchArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_at_least_one(args)?;
        Ok(Self { criteria: args.to_vec() })
    }
}

/// `Include path1 path2 ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeArgs<'a> {
    pub paths: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for IncludeArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_at_least_one(args)?;
        Ok(Self { paths: args.to_vec() })
    }
}

/// Generic multi-string argument (usable for any keyword that takes one or more
/// opaque string values, e.g., `SendEnv`, `SetEnv`, `GlobalKnownHostsFile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiArg<'a> {
    pub values: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for MultiArg<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_at_least_one(args)?;
        Ok(Self { values: args.to_vec() })
    }
}

// ---------------------------------------------------------------------------
// Argument types — "exactly 1" string argument (Error = ArgumentCountError)
// ---------------------------------------------------------------------------

/// `HostName hostname`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNameArgs<'a> {
    pub hostname: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for HostNameArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self { hostname: args[0].clone() })
    }
}

/// `User username`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserArgs<'a> {
    pub username: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for UserArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self { username: args[0].clone() })
    }
}

/// `IdentityFile path`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFileArgs<'a> {
    pub path: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for IdentityFileArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self { path: args[0].clone() })
    }
}

/// `CertificateFile path`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateFileArgs<'a> {
    pub path: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for CertificateFileArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self { path: args[0].clone() })
    }
}

/// `DynamicForward [bind_address:]port`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicForwardArgs<'a> {
    pub bind: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for DynamicForwardArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self { bind: args[0].clone() })
    }
}

/// `ProxyJump destination1,destination2,...`
///
/// The first-layer parser treats the comma-separated list as a single token;
/// this secondary parser splits by comma and computes sub-spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyJumpArgs<'a> {
    pub jumps: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for ProxyJumpArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self { jumps: split_comma_spanned(&args[0]) })
    }
}

/// Generic single-string argument (usable for any keyword that takes exactly
/// one opaque string value, e.g., `LogLevel`, `AddressFamily`, `Compression`,
/// `RequestTTY`, etc.).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SingleArg<'a> {
    pub value: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for SingleArg<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self { value: args[0].clone() })
    }
}

// ---------------------------------------------------------------------------
// Argument types — "exactly 2" arguments (Error = ArgumentCountError)
// ---------------------------------------------------------------------------

/// `LocalForward [bind_address:]port host:hostport` or Unix socket variants
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalForwardArgs<'a> {
    pub bind: Spanned<&'a str>,
    pub destination: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for LocalForwardArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 2)?;
        Ok(Self {
            bind: args[0].clone(),
            destination: args[1].clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Argument types — integer parsing (Error = ParseIntegerArgError)
// ---------------------------------------------------------------------------

/// `Port number`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortArgs {
    pub port: Spanned<u16>,
}

impl ParseArguments<'_> for PortArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        Ok(Self { port: parse_single_integer(args)? })
    }
}

/// `ServerAliveInterval seconds`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAliveIntervalArgs {
    pub seconds: Spanned<u32>,
}

impl ParseArguments<'_> for ServerAliveIntervalArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        Ok(Self { seconds: parse_single_integer(args)? })
    }
}

/// `ServerAliveCountMax count`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAliveCountMaxArgs {
    pub count: Spanned<u32>,
}

impl ParseArguments<'_> for ServerAliveCountMaxArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        Ok(Self { count: parse_single_integer(args)? })
    }
}

/// `ConnectTimeout seconds`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTimeoutArgs {
    pub seconds: Spanned<u32>,
}

impl ParseArguments<'_> for ConnectTimeoutArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        Ok(Self { seconds: parse_single_integer(args)? })
    }
}

/// `ConnectionAttempts count`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAttemptsArgs {
    pub count: Spanned<u32>,
}

impl ParseArguments<'_> for ConnectionAttemptsArgs {
    type Error = ParseIntegerArgError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        Ok(Self { count: parse_single_integer(args)? })
    }
}

// ---------------------------------------------------------------------------
// Argument types — unique count logic (Error = ParseRemoteForwardArgsError)
// ---------------------------------------------------------------------------

/// `RemoteForward [bind_address:]port [host:hostport]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForwardArgs<'a> {
    pub bind: Spanned<&'a str>,
    pub destination: Option<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for RemoteForwardArgs<'a> {
    type Error = ParseRemoteForwardArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        if args.is_empty() || args.len() > 2 {
            return Err(ParseRemoteForwardArgsError {
                actual: args.len(),
                span: args_span(args),
            });
        }
        Ok(Self {
            bind: args[0].clone(),
            destination: args.get(1).cloned(),
        })
    }
}
