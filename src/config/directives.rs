//! Typed secondary parsing of directive arguments.
//!
//! Each struct here represents the parsed arguments of a specific SSH config
//! keyword.  Callers first match on `directive.keyword`, then call
//! `directive.parse_args::<T>()` to obtain a typed result whose [`Span`]s
//! remain valid offsets into the original source text.

use std::num::ParseIntError;

use snafu::Snafu;

use super::{ParseArguments, Span, Spanned};

// ---------------------------------------------------------------------------
// Error type for argument parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseArgsError {
    #[snafu(display("expected at least {expected} argument(s), got {actual}"))]
    TooFewArguments {
        expected: usize,
        actual: usize,
        span: Span,
    },

    #[snafu(display("expected at most {expected} argument(s), got {actual}"))]
    TooManyArguments {
        expected: usize,
        actual: usize,
        span: Span,
    },

    #[snafu(display("invalid integer value"))]
    InvalidInteger {
        span: Span,
        source: ParseIntError,
    },
}

// ---------------------------------------------------------------------------
// Helper: compute directive span from an argument slice
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

// ---------------------------------------------------------------------------
// Argument types for common SSH config keywords
// ---------------------------------------------------------------------------

/// `Host pattern1 pattern2 ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostArgs<'a> {
    pub patterns: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for HostArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        if args.is_empty() {
            return Err(ParseArgsError::TooFewArguments {
                expected: 1,
                actual: 0,
                span: Span { start: 0, end: 0 },
            });
        }
        Ok(Self {
            patterns: args.to_vec(),
        })
    }
}

/// `Match criteria ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchArgs<'a> {
    pub criteria: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for MatchArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        if args.is_empty() {
            return Err(ParseArgsError::TooFewArguments {
                expected: 1,
                actual: 0,
                span: Span { start: 0, end: 0 },
            });
        }
        Ok(Self {
            criteria: args.to_vec(),
        })
    }
}

/// `HostName hostname`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostNameArgs<'a> {
    pub hostname: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for HostNameArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self {
            hostname: args[0].clone(),
        })
    }
}

/// `Port number`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortArgs {
    pub port: Spanned<u16>,
}

impl ParseArguments<'_> for PortArgs {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        let port = args[0]
            .value
            .parse::<u16>()
            .map_err(|source| ParseArgsError::InvalidInteger {
                span: args[0].span,
                source,
            })?;
        Ok(Self {
            port: Spanned {
                value: port,
                span: args[0].span,
            },
        })
    }
}

/// `User username`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserArgs<'a> {
    pub username: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for UserArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self {
            username: args[0].clone(),
        })
    }
}

/// `IdentityFile path`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityFileArgs<'a> {
    pub path: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for IdentityFileArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self {
            path: args[0].clone(),
        })
    }
}

/// `CertificateFile path`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateFileArgs<'a> {
    pub path: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for CertificateFileArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self {
            path: args[0].clone(),
        })
    }
}

/// `ProxyJump destination1,destination2,...`
///
/// Each jump is a comma-separated `[user@]host[:port]` entry.  The first-layer
/// parser treats the entire comma-separated list as a single token, so this
/// secondary parser splits by comma and computes sub-spans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyJumpArgs<'a> {
    pub jumps: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for ProxyJumpArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        let raw = &args[0];
        let jumps = split_comma_spanned(raw);
        Ok(Self { jumps })
    }
}

/// `Include path1 path2 ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeArgs<'a> {
    pub paths: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for IncludeArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        if args.is_empty() {
            return Err(ParseArgsError::TooFewArguments {
                expected: 1,
                actual: 0,
                span: Span { start: 0, end: 0 },
            });
        }
        Ok(Self {
            paths: args.to_vec(),
        })
    }
}

/// `LocalForward [bind_address:]port host:hostport` or Unix socket variants
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalForwardArgs<'a> {
    pub bind: Spanned<&'a str>,
    pub destination: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for LocalForwardArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 2)?;
        Ok(Self {
            bind: args[0].clone(),
            destination: args[1].clone(),
        })
    }
}

/// `RemoteForward [bind_address:]port [host:hostport]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteForwardArgs<'a> {
    pub bind: Spanned<&'a str>,
    pub destination: Option<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for RemoteForwardArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        if args.is_empty() || args.len() > 2 {
            return Err(if args.is_empty() {
                ParseArgsError::TooFewArguments {
                    expected: 1,
                    actual: 0,
                    span: Span { start: 0, end: 0 },
                }
            } else {
                ParseArgsError::TooManyArguments {
                    expected: 2,
                    actual: args.len(),
                    span: args_span(args),
                }
            });
        }
        Ok(Self {
            bind: args[0].clone(),
            destination: args.get(1).cloned(),
        })
    }
}

/// `DynamicForward [bind_address:]port`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicForwardArgs<'a> {
    pub bind: Spanned<&'a str>,
}

impl<'a> ParseArguments<'a> for DynamicForwardArgs<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self {
            bind: args[0].clone(),
        })
    }
}

/// `ServerAliveInterval seconds`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAliveIntervalArgs {
    pub seconds: Spanned<u32>,
}

impl ParseArguments<'_> for ServerAliveIntervalArgs {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        let seconds =
            args[0]
                .value
                .parse::<u32>()
                .map_err(|source| ParseArgsError::InvalidInteger {
                    span: args[0].span,
                    source,
                })?;
        Ok(Self {
            seconds: Spanned {
                value: seconds,
                span: args[0].span,
            },
        })
    }
}

/// `ServerAliveCountMax count`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerAliveCountMaxArgs {
    pub count: Spanned<u32>,
}

impl ParseArguments<'_> for ServerAliveCountMaxArgs {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        let count =
            args[0]
                .value
                .parse::<u32>()
                .map_err(|source| ParseArgsError::InvalidInteger {
                    span: args[0].span,
                    source,
                })?;
        Ok(Self {
            count: Spanned {
                value: count,
                span: args[0].span,
            },
        })
    }
}

/// `ConnectTimeout seconds`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectTimeoutArgs {
    pub seconds: Spanned<u32>,
}

impl ParseArguments<'_> for ConnectTimeoutArgs {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        let seconds =
            args[0]
                .value
                .parse::<u32>()
                .map_err(|source| ParseArgsError::InvalidInteger {
                    span: args[0].span,
                    source,
                })?;
        Ok(Self {
            seconds: Spanned {
                value: seconds,
                span: args[0].span,
            },
        })
    }
}

/// `ConnectionAttempts count`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionAttemptsArgs {
    pub count: Spanned<u32>,
}

impl ParseArguments<'_> for ConnectionAttemptsArgs {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        let count =
            args[0]
                .value
                .parse::<u32>()
                .map_err(|source| ParseArgsError::InvalidInteger {
                    span: args[0].span,
                    source,
                })?;
        Ok(Self {
            count: Spanned {
                value: count,
                span: args[0].span,
            },
        })
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
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        expect_exactly(args, 1)?;
        Ok(Self {
            value: args[0].clone(),
        })
    }
}

/// Generic multi-string argument (usable for any keyword that takes one or more
/// opaque string values, e.g., `SendEnv`, `SetEnv`, `GlobalKnownHostsFile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiArg<'a> {
    pub values: Vec<Spanned<&'a str>>,
}

impl<'a> ParseArguments<'a> for MultiArg<'a> {
    type Error = ParseArgsError;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error> {
        if args.is_empty() {
            return Err(ParseArgsError::TooFewArguments {
                expected: 1,
                actual: 0,
                span: Span { start: 0, end: 0 },
            });
        }
        Ok(Self {
            values: args.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn expect_exactly(args: &[Spanned<&str>], expected: usize) -> Result<(), ParseArgsError> {
    if args.len() < expected {
        return Err(ParseArgsError::TooFewArguments {
            expected,
            actual: args.len(),
            span: args_span(args),
        });
    }
    if args.len() > expected {
        return Err(ParseArgsError::TooManyArguments {
            expected,
            actual: args.len(),
            span: args_span(args),
        });
    }
    Ok(())
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
        // +1 for the comma
        offset += part.len() + 1;
    }

    result
}
