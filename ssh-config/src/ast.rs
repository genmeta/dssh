use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet, btree_map},
    fmt::Display,
    ops::Deref,
};

use derive_more::{Deref, DerefMut, From};
use peg::{Parse, str::LineCol};

use crate::pattern::SinglePattern;

#[derive(Debug, Clone, Copy, From)]
pub struct IStr<S>(S);

impl<S: AsRef<str>> IStr<S> {
    pub const fn new(s: S) -> Self {
        Self(s)
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.0.as_ref().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.0.as_ref().is_empty()
    }

    pub fn into_inner(self) -> S {
        self.0
    }
}

impl<S: AsRef<str>> Display for IStr<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write;
        self.0
            .as_ref()
            .chars()
            .flat_map(|c| c.to_lowercase())
            .try_for_each(|c| f.write_char(c))
    }
}

impl<S1: AsRef<str>, S2: AsRef<str>> PartialEq<IStr<S2>> for IStr<S1> {
    fn eq(&self, other: &IStr<S2>) -> bool {
        self.0.as_ref().eq_ignore_ascii_case(other.0.as_ref())
    }
}

impl<S: AsRef<str>> Eq for IStr<S> where Self: PartialEq<Self> {}

impl<S1: AsRef<str>, S2: AsRef<str>> PartialOrd<IStr<S2>> for IStr<S1> {
    fn partial_cmp(&self, other: &IStr<S2>) -> Option<std::cmp::Ordering> {
        let chars1 = self.0.as_ref().chars().flat_map(|c| c.to_lowercase());
        let chars2 = other.0.as_ref().chars().flat_map(|c| c.to_lowercase());
        Some(chars1.cmp(chars2))
        // Some(self.cmp(other))
    }
}

impl<S: AsRef<str>> Ord for IStr<S>
where
    Self: Eq + PartialOrd<Self>,
{
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let chars1 = self.0.as_ref().chars().flat_map(|c| c.to_lowercase());
        let chars2 = other.0.as_ref().chars().flat_map(|c| c.to_lowercase());
        chars1.cmp(chars2)
    }
}

impl<S: AsRef<str>> PartialEq<str> for IStr<S> {
    fn eq(&self, other: &str) -> bool {
        self.0.as_ref().eq_ignore_ascii_case(other)
    }
}

impl<S: AsRef<str>> PartialEq<&str> for IStr<S> {
    fn eq(&self, other: &&str) -> bool {
        self.0.as_ref().eq_ignore_ascii_case(other)
    }
}

impl From<IStr<&'static str>> for Cow<'static, str> {
    fn from(value: IStr<&'static str>) -> Self {
        if value.0.chars().all(|c| c.is_lowercase()) {
            Cow::Borrowed(value.into_inner())
        } else {
            Cow::Owned(value.to_string())
        }
    }
}

#[derive(Debug, Clone, Deref, DerefMut)]
pub struct PositionedToken<T> {
    #[deref]
    #[deref_mut]
    token: T,
    position: usize,
}

impl<T> PositionedToken<T> {
    pub fn token(&self) -> &T {
        &self.token
    }

    pub fn position(&self) -> usize {
        self.position
    }
}

pub struct Pair<'t> {
    pub keyword: PositionedToken<IStr<&'t str>>,
    pub arguments: Vec<PositionedToken<&'t str>>,
}

pub struct ConfigFile<'t> {
    source: &'t str,
    pairs: Vec<Pair<'t>>,
}

impl<'t> ConfigFile<'t> {
    pub fn new(source: &'t str) -> Result<Self, peg::error::ParseError<peg::str::LineCol>> {
        let tokens = lexer::tokens(source)?;
        Ok(ConfigFile {
            source,
            pairs: tokens,
        })
    }

    pub fn pairs(&self) -> &[Pair<'t>] {
        &self.pairs
    }
}

impl<'t> Extend<Pair<'t>> for ConfigFile<'t> {
    fn extend<T: IntoIterator<Item = Pair<'t>>>(&mut self, iter: T) {
        self.pairs.extend(iter);
    }
}

peg::parser! {
    grammar lexer() for str {
        rule whitespace() = quiet!{ [' ' | '\t'] } / expected!("whitespace")
        rule _ = whitespace()*
        rule __ = whitespace()+
        rule newline() = quiet!{ "\r\n" / "\n" / "\r" } / expected!("new line")
        /// Keyword is case-insensitive and arguments are case-sensitive.
        rule keyword() -> IStr<&'input str>
            = s:$( (!whitespace() !newline() !"=" [_])+ ) { IStr(s) }
        rule unquoted_argument() -> &'input str
            = s:$( (!whitespace() !newline() !"\"" [_])+ ) { s }
        rule quote() = quiet!{ "\"" } / expected!("\"")
        /// Arguments may optionally be enclosed in double quotes (") in order to represent arguments containing spaces.
        ///
        /// SSH似乎没有转义"，所以不处理
        rule quoted_argument() -> &'input str
            = quote() s:$( (quiet!{!"\"" !newline() [_]} / expected!("quoted argument ending with \"") )* ) quote() { s }
        rule argument() -> &'input str
            = quoted_argument() / unquoted_argument()
        rule positioned<T>(r: rule<T>) -> PositionedToken<T>
            = position:position!() token:r() { PositionedToken { token, position } }
        /// Configuration options may be separated by whitespace or optional whitespace and exactly one ‘=’;
        rule separator() = (quiet!{ _ "=" _ } / expected!("=")) / __
        rule pair() -> Pair<'input>
            = keyword:positioned(<keyword()>) separator() arguments:positioned(<argument()>) ++ __ _ {
                Pair { keyword, arguments }
            }
        /// Lines starting with ‘#’ and empty lines are interpreted as comments.
        ///
        /// OpenSSH似乎允许#前有空白
        rule sharp_comment() = _ "#" (!newline() [_])*
        rule eoi() = ![_]
        rule comment() = quiet!{ sharp_comment() / __ / &newline() / eoi() } / expected!("comment")
        rule line() -> Option<Pair<'input>>
            = (_ comment() { None }) / (_ p:pair() { Some(p) })
        pub rule tokens() -> Vec<Pair<'input>>
            = lines:line() ** newline() { lines.into_iter().flatten().collect() }
    }
}

pub type ConfigMap<'k, 'a> = BTreeMap<IStr<&'k str>, (LineCol, Vec<PositionedToken<&'a str>>)>;

impl<'s> ConfigFile<'s> {
    fn query_to(
        &self,
        map: &mut ConfigMap<'s, 's>,
        matchers: &[IStr<&str>],
        pattern: &str,
        mut make_matcher: impl FnMut(&str) -> SinglePattern,
    ) {
        let matchers = matchers.iter().collect::<BTreeSet<_>>();
        let mut macthed = true;

        for Pair { keyword, arguments } in self.pairs() {
            if matchers.contains(keyword.deref()) {
                macthed = arguments.iter().any(|pat| {
                    pat.split(',')
                        .any(|pat| make_matcher(pat).is_match(pattern))
                });
            }

            if !macthed {
                continue;
            }

            if let btree_map::Entry::Vacant(vacant_entry) = map.entry(*keyword.deref()) {
                vacant_entry.insert((
                    str::position_repr(self.source, keyword.position),
                    arguments.clone(),
                ));
            }
        }
    }

    pub fn query(
        &self,
        matchers: &[IStr<&str>],
        pattern: &str,
        mut make_matcher: impl FnMut(&str) -> SinglePattern,
    ) -> ConfigMap<'s, 's> {
        let mut map = BTreeMap::new();
        self.query_to(&mut map, matchers, pattern, &mut make_matcher);
        map
    }

    pub fn locate<T>(&self, token: &PositionedToken<T>) -> LineCol {
        str::position_repr(self.source, token.position())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_config() {
        let input = "Host example.com\n    Port 2222\n    User testuser";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 3);

        // First pair: Host example.com
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"example.com");

        // Second pair: Port 2222
        assert_eq!(pairs[1].keyword.token(), &IStr("Port"));
        assert_eq!(pairs[1].arguments.len(), 1);
        assert_eq!(pairs[1].arguments[0].token(), &"2222");

        // Third pair: User testuser
        assert_eq!(pairs[2].keyword.token(), &IStr("User"));
        assert_eq!(pairs[2].arguments.len(), 1);
        assert_eq!(pairs[2].arguments[0].token(), &"testuser");
    }

    #[test]
    fn test_quoted_arguments() {
        let input = r#"Host "example with spaces""#;
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"example with spaces");
    }

    #[test]
    fn test_comments() {
        let input = "# This is a comment\nHost example.com\n    # Another comment\n    Port 2222";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        // Comments should be ignored
        assert_eq!(pairs.len(), 2);

        // First pair: Host example.com
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"example.com");

        // Second pair: Port 2222
        assert_eq!(pairs[1].keyword.token(), &IStr("Port"));
        assert_eq!(pairs[1].arguments.len(), 1);
        assert_eq!(pairs[1].arguments[0].token(), &"2222");
    }

    #[test]
    fn test_equals_separator() {
        let input = "Host=example.com\nPort = 2222";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 2);

        // First pair: Host=example.com
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"example.com");

        // Second pair: Port = 2222
        assert_eq!(pairs[1].keyword.token(), &IStr("Port"));
        assert_eq!(pairs[1].arguments.len(), 1);
        assert_eq!(pairs[1].arguments[0].token(), &"2222");
    }

    #[test]
    fn test_case_insensitive_keywords() {
        let keyword = IStr("HOST");
        assert_eq!(keyword, "host");
        assert_eq!(keyword, "Host");
        assert_eq!(keyword, "HOST");

        let argument = "ExAmPlE.com";
        assert_eq!(argument, "ExAmPlE.com");
        assert_ne!(argument, "example.com"); // Arguments are case-sensitive
    }

    #[test]
    fn test_empty_lines() {
        let input = "Host example.com\n\n\n    Port 2222\n\n";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 2);

        // First pair: Host example.com
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"example.com");

        // Second pair: Port 2222
        assert_eq!(pairs[1].keyword.token(), &IStr("Port"));
        assert_eq!(pairs[1].arguments.len(), 1);
        assert_eq!(pairs[1].arguments[0].token(), &"2222");
    }

    #[test]
    fn test_multiple_arguments() {
        let input = "ProxyCommand ssh gateway.example.com nc %h %p";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].keyword.token(), &IStr("ProxyCommand"));
        assert_eq!(pairs[0].arguments.len(), 5);
        assert_eq!(pairs[0].arguments[0].token(), &"ssh");
        assert_eq!(pairs[0].arguments[1].token(), &"gateway.example.com");
        assert_eq!(pairs[0].arguments[2].token(), &"nc");
        assert_eq!(pairs[0].arguments[3].token(), &"%h");
        assert_eq!(pairs[0].arguments[4].token(), &"%p");
    }

    #[test]
    fn test_mixed_separators() {
        let input = "Host=example.com\nPort 2222\nUser = testuser";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 3);

        // First pair: Host=example.com
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"example.com");

        // Second pair: Port 2222
        assert_eq!(pairs[1].keyword.token(), &IStr("Port"));
        assert_eq!(pairs[1].arguments.len(), 1);
        assert_eq!(pairs[1].arguments[0].token(), &"2222");

        // Third pair: User = testuser
        assert_eq!(pairs[2].keyword.token(), &IStr("User"));
        assert_eq!(pairs[2].arguments.len(), 1);
        assert_eq!(pairs[2].arguments[0].token(), &"testuser");
    }

    #[test]
    fn test_whitespace_handling() {
        let input = "  Host    example.com  \n\t Port\t2222 \t";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 2);

        // First pair: Host example.com
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"example.com");

        // Second pair: Port 2222
        assert_eq!(pairs[1].keyword.token(), &IStr("Port"));
        assert_eq!(pairs[1].arguments.len(), 1);
        assert_eq!(pairs[1].arguments[0].token(), &"2222");
    }

    #[test]
    fn test_quoted_with_spaces() {
        let input = r#"LocalCommand "echo 'connecting to %h'""#;
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].keyword.token(), &IStr("LocalCommand"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"echo 'connecting to %h'");
    }

    #[test]
    fn test_special_characters_in_arguments() {
        let input = "HostKeyAlgorithms ssh-rsa,ssh-dss\nCiphers aes128-ctr,aes192-ctr";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 2);

        // First pair: HostKeyAlgorithms ssh-rsa,ssh-dss
        assert_eq!(pairs[0].keyword.token(), &IStr("HostKeyAlgorithms"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"ssh-rsa,ssh-dss");

        // Second pair: Ciphers aes128-ctr,aes192-ctr
        assert_eq!(pairs[1].keyword.token(), &IStr("Ciphers"));
        assert_eq!(pairs[1].arguments.len(), 1);
        assert_eq!(pairs[1].arguments[0].token(), &"aes128-ctr,aes192-ctr");
    }

    #[test]
    fn test_comment_variations() {
        let input = "#Full line comment\n   # Indented comment\nHost example.com # Inline comment not supported";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        // The line "Host example.com # Inline comment not supported" is parsed as one pair
        // with keyword "Host" and multiple arguments
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 6);
        assert_eq!(pairs[0].arguments[0].token(), &"example.com");
        assert_eq!(pairs[0].arguments[1].token(), &"#");
        assert_eq!(pairs[0].arguments[2].token(), &"Inline");
        assert_eq!(pairs[0].arguments[3].token(), &"comment");
        assert_eq!(pairs[0].arguments[4].token(), &"not");
        assert_eq!(pairs[0].arguments[5].token(), &"supported");
    }

    #[test]
    fn test_empty_quoted_string() {
        let input = r#"LocalCommand """#;
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].keyword.token(), &IStr("LocalCommand"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"");
    }

    #[test]
    fn test_token_positions() {
        let input = "Host example.com\nPort 2222";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 2);

        // Check keyword positions
        assert_eq!(pairs[0].keyword.position(), 0); // "Host"
        assert_eq!(pairs[0].arguments[0].position(), 5); // "example.com"
        assert_eq!(pairs[1].keyword.position(), 17); // "Port" (after newline)
        assert_eq!(pairs[1].arguments[0].position(), 22); // "2222"
    }

    #[test]
    fn test_invalid_syntax() {
        // Test missing arguments
        let input = "Host";
        let result = ConfigFile::new(input);
        assert!(result.is_err());

        // Test equals without spaces or arguments
        let input = "Host=";
        let result = ConfigFile::new(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_windows_line_endings() {
        let input = "Host example.com\r\nPort 2222\r\n";
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        assert_eq!(pairs.len(), 2);

        // First pair: Host example.com
        assert_eq!(pairs[0].keyword.token(), &IStr("Host"));
        assert_eq!(pairs[0].arguments.len(), 1);
        assert_eq!(pairs[0].arguments[0].token(), &"example.com");

        // Second pair: Port 2222
        assert_eq!(pairs[1].keyword.token(), &IStr("Port"));
        assert_eq!(pairs[1].arguments.len(), 1);
        assert_eq!(pairs[1].arguments[0].token(), &"2222");
    }

    #[test]
    fn test_complex_config() {
        let input = r#"# SSH Config for development
Host dev-server
    HostName 192.168.1.100
    Port 22
    User developer
    IdentityFile "~/.ssh/dev_rsa"
    
# Production server
Host prod
    HostName prod.example.com
    Port = 2222
    User admin
    ProxyCommand ssh gateway nc %h %p
"#;
        let stream = ConfigFile::new(input).unwrap();
        let pairs = stream.pairs();

        // Should parse all non-comment lines
        let expected_pairs = vec![
            ("Host", vec!["dev-server"]),
            ("HostName", vec!["192.168.1.100"]),
            ("Port", vec!["22"]),
            ("User", vec!["developer"]),
            ("IdentityFile", vec!["~/.ssh/dev_rsa"]),
            ("Host", vec!["prod"]),
            ("HostName", vec!["prod.example.com"]),
            ("Port", vec!["2222"]),
            ("User", vec!["admin"]),
            ("ProxyCommand", vec!["ssh", "gateway", "nc", "%h", "%p"]),
        ];

        assert_eq!(pairs.len(), expected_pairs.len());

        for (i, (expected_keyword, expected_args)) in expected_pairs.iter().enumerate() {
            assert_eq!(pairs[i].keyword.token(), &IStr(*expected_keyword));
            assert_eq!(pairs[i].arguments.len(), expected_args.len());
            for (j, expected_arg) in expected_args.iter().enumerate() {
                assert_eq!(pairs[i].arguments[j].token(), expected_arg);
            }
        }
    }
}
