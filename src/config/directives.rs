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
//!   argument count (HostName, User, IdentityFile, Include, …).
//! - [`ParseIntegerArgError`] — for types that also parse an integer
//!   (Port, ServerAliveInterval, ConnectTimeout, …).
//! - [`ParseRemoteForwardArgsError`] — RemoteForward's unique 1-or-2 count.
//! - [`ParseMatchArgsError`] — Match criteria parsing failures.

use std::num::ParseIntError;

use snafu::Snafu;

use super::{Located, ParseArguments};

// ---------------------------------------------------------------------------
// Common types
// ---------------------------------------------------------------------------

/// A possibly-negated glob pattern.
///
/// Used in `Host` patterns (space-separated) and `Match` criterion
/// pattern-lists (comma-separated).  The `!` prefix is parsed out and
/// stored in [`negated`](Self::negated); [`value`](Self::value) contains
/// the pattern text without the leading `!`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pattern<'a> {
    pub negated: bool,
    pub value: &'a str,
}

fn parse_pattern<'a>(token: Located<&'a str>) -> Located<Pattern<'a>> {
    let (negated, value) = match token.value.strip_prefix('!') {
        Some(rest) => (true, rest),
        None => (false, token.value),
    };
    token.with_value(Pattern { negated, value })
}

fn parse_pattern_list<'a>(token: &Located<&'a str>) -> Vec<Located<Pattern<'a>>> {
    token.split_comma().into_iter().map(parse_pattern).collect()
}

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

/// Error when parsing `Match` criteria arguments.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ParseMatchArgsError {
    #[snafu(display("empty match criteria"))]
    Empty,

    #[snafu(display("unknown match criterion `{keyword}`"))]
    UnknownCriterion { keyword: String },

    #[snafu(display("criterion `{keyword}` requires an argument"))]
    MissingArgument { keyword: String },

    #[snafu(display("`all` must appear alone or immediately after `canonical`/`final`"))]
    InvalidAllPlacement,
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
// Host — space-separated, possibly-negated glob patterns
// ---------------------------------------------------------------------------

/// `Host pattern1 pattern2 ...`
///
/// Each pattern may be negated with a `!` prefix.  See the `PATTERNS`
/// section of `ssh_config(5)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostArgs<'a> {
    pub patterns: Vec<Located<Pattern<'a>>>,
}

impl<'a> ParseArguments<'a> for HostArgs<'a> {
    type Error = ArgumentCountError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let tokens = tokenize_at_least_one(args)?;
        let patterns = tokens.into_iter().map(parse_pattern).collect();
        Ok(args.with_value(Self { patterns }))
    }
}

// ---------------------------------------------------------------------------
// Match — structured criteria parsing
// ---------------------------------------------------------------------------

/// A single `Match` criterion.
///
/// Criteria that take arguments carry comma-separated pattern-lists
/// (each element is a possibly-negated glob pattern).  `exec` takes
/// a single command string instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchCriterion<'a> {
    /// Always matches.  Must appear alone or immediately after
    /// `Canonical`/`Final`.
    All,
    /// Matches only during hostname canonicalization re-parse.
    Canonical,
    /// Matches only during the final configuration re-parse.
    Final,
    /// Matches if the command exits with status 0.
    Exec { command: Located<&'a str> },
    /// Matches against the target hostname (after canonicalization).
    Host { patterns: Vec<Located<Pattern<'a>>> },
    /// Matches against the original hostname from the command line.
    OriginalHost { patterns: Vec<Located<Pattern<'a>>> },
    /// Matches against the target remote username.
    User { patterns: Vec<Located<Pattern<'a>>> },
    /// Matches against the local username running ssh.
    LocalUser { patterns: Vec<Located<Pattern<'a>>> },
    /// Matches against local network interfaces (CIDR notation).
    LocalNetwork { networks: Vec<Located<&'a str>> },
    /// Matches against a tag set by a prior `Tag` directive.
    Tagged { patterns: Vec<Located<Pattern<'a>>> },
    /// Matches against the remote command or subsystem name.
    Command { patterns: Vec<Located<Pattern<'a>>> },
    /// Matches against the SSH version string.
    Version { patterns: Vec<Located<Pattern<'a>>> },
    /// Matches against the session type (shell, exec, subsystem, none).
    SessionType { patterns: Vec<Located<Pattern<'a>>> },
}

/// A possibly-negated match criterion.
///
/// The `!` prefix on the criterion keyword negates the entire criterion.
/// This is distinct from `!` on individual patterns within a pattern-list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchEntry<'a> {
    pub negated: bool,
    pub criterion: MatchCriterion<'a>,
}

/// `Match criteria ...`
///
/// Parsed into structured [`MatchEntry`] values.  See `ssh_config(5)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchArgs<'a> {
    pub entries: Vec<Located<MatchEntry<'a>>>,
}

impl<'a> ParseArguments<'a> for MatchArgs<'a> {
    type Error = ParseMatchArgsError;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>> {
        let tokens = args.tokenize();
        if tokens.is_empty() {
            return Err(args.with_value(ParseMatchArgsError::Empty));
        }

        let mut entries: Vec<Located<MatchEntry<'a>>> = Vec::new();
        let mut i = 0;

        while i < tokens.len() {
            let kw_token = &tokens[i];
            let (negated, keyword) = match kw_token.value.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, kw_token.value),
            };

            let kw_lower = keyword.to_ascii_lowercase();
            let (criterion, advance) = match kw_lower.as_str() {
                "all" => (MatchCriterion::All, 1),
                "canonical" => (MatchCriterion::Canonical, 1),
                "final" => (MatchCriterion::Final, 1),
                kw @ ("exec" | "host" | "originalhost" | "user" | "localuser" | "localnetwork"
                | "tagged" | "command" | "version" | "sessiontype") => {
                    let arg = tokens.get(i + 1).ok_or_else(|| {
                        kw_token.with_value(ParseMatchArgsError::MissingArgument {
                            keyword: kw.to_string(),
                        })
                    })?;
                    let criterion = match kw {
                        "exec" => MatchCriterion::Exec {
                            command: arg.clone(),
                        },
                        "localnetwork" => MatchCriterion::LocalNetwork {
                            networks: arg.split_comma(),
                        },
                        "host" => MatchCriterion::Host {
                            patterns: parse_pattern_list(arg),
                        },
                        "originalhost" => MatchCriterion::OriginalHost {
                            patterns: parse_pattern_list(arg),
                        },
                        "user" => MatchCriterion::User {
                            patterns: parse_pattern_list(arg),
                        },
                        "localuser" => MatchCriterion::LocalUser {
                            patterns: parse_pattern_list(arg),
                        },
                        "tagged" => MatchCriterion::Tagged {
                            patterns: parse_pattern_list(arg),
                        },
                        "command" => MatchCriterion::Command {
                            patterns: parse_pattern_list(arg),
                        },
                        "version" => MatchCriterion::Version {
                            patterns: parse_pattern_list(arg),
                        },
                        "sessiontype" => MatchCriterion::SessionType {
                            patterns: parse_pattern_list(arg),
                        },
                        _ => unreachable!(),
                    };
                    (criterion, 2)
                }
                _ => {
                    return Err(kw_token.with_value(ParseMatchArgsError::UnknownCriterion {
                        keyword: keyword.to_string(),
                    }));
                }
            };

            entries.push(kw_token.with_value(MatchEntry { negated, criterion }));
            i += advance;
        }

        // Validate `all` placement: must be last, preceded only by canonical/final.
        if let Some(all_idx) = entries
            .iter()
            .position(|e| matches!(e.value.criterion, MatchCriterion::All))
        {
            for entry in &entries[..all_idx] {
                if !matches!(
                    entry.value.criterion,
                    MatchCriterion::Canonical | MatchCriterion::Final
                ) {
                    return Err(
                        entries[all_idx].with_value(ParseMatchArgsError::InvalidAllPlacement)
                    );
                }
            }
        }

        Ok(args.with_value(Self { entries }))
    }
}

// ---------------------------------------------------------------------------
// Other argument types — "at least 1" (Error = ArgumentCountError)
// ---------------------------------------------------------------------------

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
