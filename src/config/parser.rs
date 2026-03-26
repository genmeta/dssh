// Internal span types used only by the PEG parser.
// The public API uses `Located<T>` from the parent module.

#[derive(Debug, Clone, Copy)]
pub(super) struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub(super) struct Spanned<T> {
    pub value: T,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub(super) struct RawDirective<'a> {
    pub keyword: Spanned<&'a str>,
    pub arguments: Spanned<&'a str>,
}

#[derive(Debug, Clone)]
pub(super) enum RawEntry<'a> {
    Empty(Span),
    Comment(Spanned<&'a str>),
    Directive(RawDirective<'a>),
    Unknown(Spanned<&'a str>),
}

peg::parser! {
    grammar ssh_config() for str {
        // Horizontal whitespace (no newlines).
        rule _() = quiet!{[' ' | '\t']*}
        rule __() = quiet!{[' ' | '\t']+}

        // Line terminators.
        rule newline() = "\r\n" / "\n" / "\r"

        // A keyword: starts with a letter, followed by letters or digits.
        rule keyword() -> Spanned<&'input str>
            = s:position!() k:$(['a'..='z' | 'A'..='Z'] ['a'..='z' | 'A'..='Z' | '0'..='9']*) e:position!()
            { Spanned { value: k, span: Span { start: s, end: e } } }

        // Raw arguments: everything after separator until end of line,
        // trailing whitespace trimmed. Not tokenized.
        rule raw_arguments() -> Spanned<&'input str>
            = arg_s:position!() v:$([^ '\n' | '\r']*) {
                let trimmed = v.trim_end();
                let arg_e = arg_s + trimmed.len();
                Spanned { value: trimmed, span: Span { start: arg_s, end: arg_e } }
            }

        // Separator between keyword and arguments: `=` (with optional surrounding
        // whitespace) or plain whitespace.
        rule separator() = _ "=" _ / __()

        // A directive line: keyword separator arguments
        rule directive() -> RawEntry<'input>
            = _ kw:keyword() separator() args:raw_arguments() {
                RawEntry::Directive(RawDirective { keyword: kw, arguments: args })
            }
            / _ kw:keyword() _ e:position!() {
                RawEntry::Directive(RawDirective {
                    keyword: kw,
                    arguments: Spanned { value: "", span: Span { start: e, end: e } },
                })
            }

        // A comment line: optional leading whitespace, then `#`.
        rule comment() -> RawEntry<'input>
            = s:position!() _ "#" v:$([^ '\n' | '\r']*) e:position!()
            { RawEntry::Comment(Spanned { value: v.trim(), span: Span { start: s, end: e } }) }

        // An empty (or whitespace-only) line.
        rule empty_line() -> RawEntry<'input>
            = s:position!() &(newline() / ![_]) e:position!()
            { RawEntry::Empty(Span { start: s, end: e }) }
            / s:position!() [' ' | '\t']+ &(newline() / ![_]) e:position!()
            { RawEntry::Empty(Span { start: s, end: e }) }

        // Catch-all for lines that don't match any known pattern.
        rule unknown_line() -> RawEntry<'input>
            = s:position!() v:$([^ '\n' | '\r']+) e:position!()
            { RawEntry::Unknown(Spanned { value: v, span: Span { start: s, end: e } }) }

        // A single line (tried in order: empty, comment, directive, unknown).
        rule line() -> RawEntry<'input>
            = empty_line() / comment() / directive() / unknown_line()

        // A complete config file.
        pub rule config() -> Vec<RawEntry<'input>>
            = first:line() rest:(newline() l:line() { l })* newline()? {
                let mut v = vec![first];
                v.extend(rest);
                v
            }
    }
}

/// Parse an SSH config string into a list of raw entries.
///
/// This function never fails; unparseable lines are captured as
/// [`RawEntry::Unknown`].
pub(super) fn parse(input: &str) -> Vec<RawEntry<'_>> {
    ssh_config::config(input).unwrap_or_else(|_| {
        vec![RawEntry::Unknown(Spanned {
            value: input,
            span: Span {
                start: 0,
                end: input.len(),
            },
        })]
    })
}
