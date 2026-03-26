//! SSH configuration file parser with precise source location tracking.
//!
//! Provides a two-layer parsing architecture:
//! 1. **Syntax layer** ([`SourceFile::parse`]): PEG-based lexical parsing that produces a flat
//!    `Vec<Entry>` with [`Location`]-annotated elements.
//! 2. **Semantic layer** ([`ParseArguments`]): Trait-based typed secondary parsing of
//!    directive arguments (e.g., `directive.parse_args::<PortArgs>()`).

mod directives;
mod parser;
#[cfg(test)]
mod tests;

pub use directives::*;

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A resolved source location: file path + 1-based line and column.
///
/// [`Display`](fmt::Display) produces `path:line:col` (e.g.,
/// `~/.ssh/config:5:12`) which most terminals recognise as a clickable
/// file link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    pub path: Arc<PathBuf>,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.path.display(), self.line, self.column)
    }
}

/// A value annotated with its source location.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located<T> {
    pub value: T,
    pub location: Location,
}

impl<T> Located<T> {
    /// Create a new `Located` with the same location but a different value.
    pub fn with_value<U>(&self, value: U) -> Located<U> {
        Located {
            value,
            location: self.location.clone(),
        }
    }

    /// Transform the inner value, preserving location.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Located<U> {
        Located {
            value: f(self.value),
            location: self.location,
        }
    }
}

impl<T: fmt::Display> fmt::Display for Located<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at {}", self.value, self.location)
    }
}

impl<E: Error> Error for Located<E> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.value.source()
    }
}

impl<'a> Located<&'a str> {
    /// Tokenize by whitespace, respecting double quotes.
    ///
    /// For quoted arguments, the returned token covers the content inside
    /// quotes (not the quotes themselves). All tokens share the same line;
    /// columns are adjusted by byte offset within the string.
    pub fn tokenize(&self) -> Vec<Located<&'a str>> {
        let mut result = Vec::new();
        let s = self.value;
        let mut i = 0;

        while i < s.len() {
            // Skip horizontal whitespace
            while i < s.len() && matches!(s.as_bytes()[i], b' ' | b'\t') {
                i += 1;
            }
            if i >= s.len() {
                break;
            }

            if s.as_bytes()[i] == b'"' {
                // Quoted: span covers content inside quotes
                let content_start = i + 1;
                let content_end = s[content_start..]
                    .find('"')
                    .map(|j| content_start + j)
                    .unwrap_or(s.len());
                result.push(Located {
                    value: &s[content_start..content_end],
                    location: Location {
                        path: self.location.path.clone(),
                        line: self.location.line,
                        column: self.location.column + content_start,
                    },
                });
                i = if content_end < s.len() {
                    content_end + 1
                } else {
                    content_end
                };
            } else {
                // Unquoted: scan until whitespace or quote
                let start = i;
                while i < s.len() && !matches!(s.as_bytes()[i], b' ' | b'\t' | b'"') {
                    i += 1;
                }
                result.push(Located {
                    value: &s[start..i],
                    location: Location {
                        path: self.location.path.clone(),
                        line: self.location.line,
                        column: self.location.column + start,
                    },
                });
            }
        }

        result
    }

    /// Split by commas, preserving sub-locations.
    pub fn split_comma(&self) -> Vec<Located<&'a str>> {
        let mut result = Vec::new();
        let mut offset = 0;
        for part in self.value.split(',') {
            result.push(Located {
                value: part,
                location: Location {
                    path: self.location.path.clone(),
                    line: self.location.line,
                    column: self.location.column + offset,
                },
            });
            offset += part.len() + 1; // +1 for comma
        }
        result
    }
}

/// A single entry in an SSH config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry<'a> {
    /// An empty or whitespace-only line.
    Empty(Location),
    /// A comment line (value is the text after `#`, trimmed).
    Comment(Located<&'a str>),
    /// A keyword-arguments directive.
    Directive(Directive<'a>),
    /// A line that could not be parsed (error recovery).
    Unknown(Located<&'a str>),
}

/// A single directive: `keyword [=] arguments`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directive<'a> {
    /// The keyword, preserving original case.
    pub keyword: Located<&'a str>,
    /// Raw arguments string (not yet tokenized).
    ///
    /// Call [`Located::tokenize`] to split into individual tokens
    /// respecting double-quote grouping. Each token carries its own
    /// [`Location`].
    pub arguments: Located<&'a str>,
}

impl<'a> Directive<'a> {
    /// Perform typed secondary parsing of this directive's arguments.
    ///
    /// Keyword matching is the caller's responsibility; this method only
    /// parses the arguments string.
    pub fn parse_args<T: ParseArguments<'a>>(&self) -> Result<Located<T>, Located<T::Error>> {
        T::parse_arguments(&self.arguments)
    }
}

/// Trait for types that can be parsed from a directive's argument string.
///
/// Implementations receive the raw [`Located<&str>`] arguments and may call
/// [`Located::tokenize`] to split into tokens. All produced [`Location`]s
/// are derived from the input and remain valid references into the original
/// source text.
pub trait ParseArguments<'a>: Sized {
    type Error: Error;

    fn parse_arguments(args: &Located<&'a str>) -> Result<Located<Self>, Located<Self::Error>>;
}

// ---------------------------------------------------------------------------
// SourceFile: byte offset → Location mapping
// ---------------------------------------------------------------------------

/// A source file with precomputed line-start indices for O(1) line/column lookup.
pub struct SourceFile {
    path: Arc<PathBuf>,
    content: String,
    /// Byte offsets of each line start (index 0 = line 1).
    line_starts: Vec<usize>,
}

impl SourceFile {
    /// Create a `SourceFile` from a path and content string.
    pub fn new(path: impl Into<PathBuf>, content: String) -> Self {
        let path = Arc::new(path.into());
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
        Ok(Self::new(path.to_owned(), content))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn content(&self) -> &str {
        &self.content
    }

    /// Parse the content into a list of config entries.
    pub fn parse(&self) -> Vec<Entry<'_>> {
        let raw_entries = parser::parse(&self.content);
        raw_entries
            .into_iter()
            .map(|e| self.locate_entry(e))
            .collect()
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

    /// Resolve a byte offset to a [`Location`].
    pub fn location(&self, offset: usize) -> Location {
        let (line, column) = self.line_col(offset);
        Location {
            path: self.path.clone(),
            line,
            column,
        }
    }

    fn locate_entry<'a>(&self, raw: parser::RawEntry<'a>) -> Entry<'a> {
        match raw {
            parser::RawEntry::Empty(span) => Entry::Empty(self.location(span.start)),
            parser::RawEntry::Comment(s) => Entry::Comment(self.locate(s)),
            parser::RawEntry::Directive(d) => Entry::Directive(Directive {
                keyword: self.locate(d.keyword),
                arguments: self.locate(d.arguments),
            }),
            parser::RawEntry::Unknown(s) => Entry::Unknown(self.locate(s)),
        }
    }

    fn locate<T>(&self, spanned: parser::Spanned<T>) -> Located<T> {
        Located {
            location: self.location(spanned.span.start),
            value: spanned.value,
        }
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
