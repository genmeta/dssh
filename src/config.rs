//! SSH configuration file parser with precise source location tracking.
//!
//! Provides a two-layer parsing architecture:
//! 1. **Syntax layer** ([`parse`]): PEG-based lexical parsing that produces a flat
//!    `Vec<Entry>` with byte-accurate [`Span`]s on every element.
//! 2. **Semantic layer** ([`ParseArguments`]): Trait-based typed secondary parsing of
//!    directive arguments (e.g., `directive.parse_args::<PortArgs>()`).

mod directives;
mod parser;
#[cfg(test)]
mod tests;

pub use directives::*;

use std::path::{Path, PathBuf};

/// Byte offset range in source text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

/// A value annotated with its source location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spanned<T> {
    pub value: T,
    pub span: Span,
}

/// A single entry in an SSH config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry<'a> {
    /// An empty or whitespace-only line.
    Empty(Span),
    /// A comment line (value is the text after `#`, trimmed).
    Comment(Spanned<&'a str>),
    /// A keyword-arguments directive.
    Directive(Directive<'a>),
    /// A line that could not be parsed (error recovery).
    Unknown(Spanned<&'a str>),
}

/// A single directive: `keyword [=] arg1 arg2 ...`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive<'a> {
    /// The keyword, preserving original case.
    pub keyword: Spanned<&'a str>,
    /// Arguments split by whitespace, respecting double quotes.
    ///
    /// Each argument carries an independent span.
    /// - Unquoted arguments: span covers the value text directly.
    /// - Quoted arguments: span covers the content inside quotes (not the quotes).
    ///
    /// Invariant: `source[span.start..span.end] == value` always holds.
    pub arguments: Vec<Spanned<&'a str>>,
    /// Span of the entire directive line.
    pub span: Span,
}

impl<'a> Directive<'a> {
    /// Perform typed secondary parsing of this directive's arguments.
    ///
    /// Keyword matching is the caller's responsibility; this method only
    /// parses the arguments slice.
    pub fn parse_args<T: ParseArguments<'a>>(&self) -> Result<T, T::Error> {
        T::parse_arguments(&self.arguments)
    }
}

/// Trait for types that can be parsed from a directive's argument list.
///
/// Implementations reuse the first-layer `Spanned<&str>` arguments, so all
/// produced `Span`s remain valid offsets into the original source text.
pub trait ParseArguments<'a>: Sized {
    type Error;

    fn parse_arguments(args: &[Spanned<&'a str>]) -> Result<Self, Self::Error>;
}

// ---------------------------------------------------------------------------
// SourceFile: byte offset → line/column mapping
// ---------------------------------------------------------------------------

/// A source file with precomputed line-start indices for O(1) line/column lookup.
pub struct SourceFile {
    path: Option<PathBuf>,
    content: String,
    /// Byte offsets of each line start (index 0 = line 1).
    line_starts: Vec<usize>,
}

impl SourceFile {
    /// Create a `SourceFile` from a path and content string.
    pub fn new(path: Option<PathBuf>, content: String) -> Self {
        let line_starts = Self::compute_line_starts(&content);
        Self {
            path,
            content,
            line_starts,
        }
    }

    /// Read a file from disk into a `SourceFile`.
    pub fn read(path: impl AsRef<Path>) -> std::io::Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        Ok(Self::new(Some(path.to_owned()), content))
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    /// Parse the content into a list of config entries.
    pub fn parse(&self) -> Vec<Entry<'_>> {
        parser::parse(&self.content)
    }

    /// Convert a byte offset to a 1-based (line, column) pair.
    ///
    /// Column is measured in bytes from the start of the line.
    pub fn line_col(&self, offset: usize) -> (usize, usize) {
        let line_idx = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let col = offset - self.line_starts[line_idx] + 1;
        (line_idx + 1, col)
    }

    fn compute_line_starts(content: &str) -> Vec<usize> {
        let mut starts = vec![0];
        for (i, b) in content.bytes().enumerate() {
            if b == b'\n' {
                starts.push(i + 1);
            }
        }
        starts
    }
}

/// Parse an SSH config string into entries without a `SourceFile` wrapper.
pub fn parse(input: &str) -> Vec<Entry<'_>> {
    parser::parse(input)
}
