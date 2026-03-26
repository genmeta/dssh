use super::{Directive, Entry, Span, Spanned};

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

        // A double-quoted argument. Span covers the content (inside quotes).
        rule quoted_argument() -> Spanned<&'input str>
            = "\"" s:position!() v:$([^ '"']*) e:position!() "\""
            { Spanned { value: v, span: Span { start: s, end: e } } }

        // An unquoted argument: non-whitespace, non-quote, non-comment characters.
        rule unquoted_argument() -> Spanned<&'input str>
            = s:position!() v:$([^ ' ' | '\t' | '\n' | '\r' | '"']+) e:position!()
            { Spanned { value: v, span: Span { start: s, end: e } } }

        // A single argument (quoted or unquoted).
        rule argument() -> Spanned<&'input str>
            = quoted_argument() / unquoted_argument()

        // One or more arguments separated by horizontal whitespace.
        rule arguments() -> Vec<Spanned<&'input str>>
            = first:argument() rest:(__() a:argument() { a })* {
                let mut v = vec![first];
                v.extend(rest);
                v
            }

        // Separator between keyword and arguments: `=` (with optional surrounding
        // whitespace) or plain whitespace.
        rule separator() = _ "=" _ / __()

        // A directive line: keyword separator arguments
        rule directive() -> Entry<'input>
            = s:position!() _ kw:keyword() separator() args:arguments() _ e:position!()
            { Entry::Directive(Directive { keyword: kw, arguments: args, span: Span { start: s, end: e } }) }
            / s:position!() _ kw:keyword() _ e:position!()
            { Entry::Directive(Directive { keyword: kw, arguments: vec![], span: Span { start: s, end: e } }) }

        // A comment line: optional leading whitespace, then `#`.
        rule comment() -> Entry<'input>
            = s:position!() _ "#" v:$([^ '\n' | '\r']*) e:position!()
            { Entry::Comment(Spanned { value: v.trim(), span: Span { start: s, end: e } }) }

        // An empty (or whitespace-only) line.
        rule empty_line() -> Entry<'input>
            = s:position!() &(newline() / ![_]) e:position!()
            { Entry::Empty(Span { start: s, end: e }) }
            / s:position!() [' ' | '\t']+ &(newline() / ![_]) e:position!()
            { Entry::Empty(Span { start: s, end: e }) }

        // Catch-all for lines that don't match any known pattern.
        rule unknown_line() -> Entry<'input>
            = s:position!() v:$([^ '\n' | '\r']+) e:position!()
            { Entry::Unknown(Spanned { value: v, span: Span { start: s, end: e } }) }

        // A single line (tried in order: empty, comment, directive, unknown).
        rule line() -> Entry<'input>
            = empty_line() / comment() / directive() / unknown_line()

        // A complete config file.
        pub rule config() -> Vec<Entry<'input>>
            = first:line() rest:(newline() l:line() { l })* newline()? {
                let mut v = vec![first];
                v.extend(rest);
                v
            }
    }
}

/// Parse an SSH config string into a list of entries.
///
/// This function never fails; unparseable lines are captured as
/// [`Entry::Unknown`].
pub(super) fn parse(input: &str) -> Vec<Entry<'_>> {
    // The grammar is designed to always succeed (unknown_line is a catch-all),
    // but if somehow it doesn't, fall back to a single Unknown entry.
    ssh_config::config(input).unwrap_or_else(|_| {
        vec![Entry::Unknown(Spanned {
            value: input,
            span: Span {
                start: 0,
                end: input.len(),
            },
        })]
    })
}
