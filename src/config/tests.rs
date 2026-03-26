use super::*;
use std::sync::Arc;

fn source(input: &str) -> SourceFile {
    SourceFile::new("<test>", input.to_string())
}

fn directives<'a>(entries: &'a [Entry<'a>]) -> Vec<&'a Directive<'a>> {
    entries
        .iter()
        .filter_map(|e| match e {
            Entry::Directive(d) => Some(d),
            _ => None,
        })
        .collect()
}

// ===========================================================================
// First-layer parsing tests
// ===========================================================================

#[test]
fn empty_input() {
    let sf = source("");
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    assert!(matches!(entries[0], Entry::Empty(_)));
}

#[test]
fn blank_lines() {
    let sf = source("\n\n\n");
    let entries = sf.parse();
    assert!(entries.iter().all(|e| matches!(e, Entry::Empty(_))));
}

#[test]
fn comment_line() {
    let sf = source("# this is a comment");
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    match &entries[0] {
        Entry::Comment(c) => {
            assert_eq!(c.value, "this is a comment");
        }
        other => panic!("expected Comment, got {other:?}"),
    }
}

#[test]
fn comment_with_leading_whitespace() {
    let sf = source("   # indented comment");
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    match &entries[0] {
        Entry::Comment(c) => {
            assert_eq!(c.value, "indented comment");
        }
        other => panic!("expected Comment, got {other:?}"),
    }
}

#[test]
fn simple_directive_whitespace_separator() {
    let sf = source("HostName example.com");
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "HostName");
    assert_eq!(d.arguments.value, "example.com");
}

#[test]
fn simple_directive_equals_separator() {
    let sf = source("HostName=example.com");
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "HostName");
    assert_eq!(d.arguments.value, "example.com");
}

#[test]
fn directive_equals_with_spaces() {
    let sf = source("HostName = example.com");
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "HostName");
    assert_eq!(d.arguments.value, "example.com");
}

#[test]
fn multiple_arguments_raw() {
    let sf = source("Host server1 server2 *.example.com");
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "Host");
    assert_eq!(d.arguments.value, "server1 server2 *.example.com");
}

#[test]
fn multiple_arguments_tokenized() {
    let sf = source("Host server1 server2 *.example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let tokens = d.arguments.tokenize();
    assert_eq!(tokens.len(), 3);
    assert_eq!(tokens[0].value, "server1");
    assert_eq!(tokens[1].value, "server2");
    assert_eq!(tokens[2].value, "*.example.com");
}

#[test]
fn quoted_argument() {
    let sf = source(r#"ProxyCommand "ssh -W %h:%p bastion""#);
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "ProxyCommand");
    let tokens = d.arguments.tokenize();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].value, "ssh -W %h:%p bastion");
}

#[test]
fn mixed_quoted_and_unquoted() {
    let sf = source(r#"Host "my server" otherhost"#);
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let tokens = d.arguments.tokenize();
    assert_eq!(tokens.len(), 2);
    assert_eq!(tokens[0].value, "my server");
    assert_eq!(tokens[1].value, "otherhost");
}

#[test]
fn keyword_case_preserved() {
    let sf = source("HostName example.com\nhostname other.com\nHOSTNAME third.com");
    let entries = sf.parse();
    let ds = directives(&entries);
    assert_eq!(ds[0].keyword.value, "HostName");
    assert_eq!(ds[1].keyword.value, "hostname");
    assert_eq!(ds[2].keyword.value, "HOSTNAME");
}

#[test]
fn multiline_config() {
    let sf = source(
        "\
Host myserver
    HostName 192.168.1.1
    User admin
    Port 2222
",
    );
    let entries = sf.parse();
    let ds = directives(&entries);
    assert_eq!(ds.len(), 4);
    assert_eq!(ds[0].keyword.value, "Host");
    assert_eq!(ds[0].arguments.value, "myserver");
    assert_eq!(ds[1].keyword.value, "HostName");
    assert_eq!(ds[1].arguments.value, "192.168.1.1");
    assert_eq!(ds[2].keyword.value, "User");
    assert_eq!(ds[2].arguments.value, "admin");
    assert_eq!(ds[3].keyword.value, "Port");
    assert_eq!(ds[3].arguments.value, "2222");
}

#[test]
fn comments_and_blanks_interleaved() {
    let sf = source(
        "\
# Global settings
ServerAliveInterval 60

# My server
Host myserver
    HostName 10.0.0.1
",
    );
    let entries = sf.parse();

    let mut comments = 0;
    let mut empties = 0;
    let mut directive_count = 0;
    for e in &entries {
        match e {
            Entry::Comment(_) => comments += 1,
            Entry::Empty(_) => empties += 1,
            Entry::Directive(_) => directive_count += 1,
            Entry::Unknown(_) => panic!("unexpected Unknown entry"),
        }
    }
    assert_eq!(comments, 2);
    assert!(empties >= 1);
    assert_eq!(directive_count, 3);
}

#[test]
fn no_trailing_newline() {
    let sf = source("Port 22");
    let entries = sf.parse();
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "Port");
    assert_eq!(d.arguments.value, "22");
}

#[test]
fn crlf_line_endings() {
    let sf = source("Host a\r\nPort 22\r\n");
    let entries = sf.parse();
    let ds = directives(&entries);
    assert_eq!(ds.len(), 2);
    assert_eq!(ds[0].keyword.value, "Host");
    assert_eq!(ds[1].keyword.value, "Port");
}

#[test]
fn leading_whitespace_on_directive() {
    let sf = source("    HostName example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "HostName");
    assert_eq!(d.arguments.value, "example.com");
}

// ===========================================================================
// Location accuracy tests
// ===========================================================================

#[test]
fn keyword_location_accuracy() {
    let sf = source("HostName example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.location.line, 1);
    assert_eq!(d.keyword.location.column, 1);
}

#[test]
fn argument_location_accuracy() {
    let sf = source("HostName example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    // "example.com" starts at byte 9, column 10
    assert_eq!(d.arguments.location.line, 1);
    assert_eq!(d.arguments.location.column, 10);
}

#[test]
fn tokenized_location_accuracy() {
    let sf = source("Host alpha beta gamma");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let tokens = d.arguments.tokenize();
    // "alpha" at col 6, "beta" at col 12, "gamma" at col 17
    assert_eq!(tokens[0].location.column, 6);
    assert_eq!(tokens[0].value, "alpha");
    assert_eq!(tokens[1].location.column, 12);
    assert_eq!(tokens[1].value, "beta");
    assert_eq!(tokens[2].location.column, 17);
    assert_eq!(tokens[2].value, "gamma");
}

#[test]
fn quoted_argument_location() {
    let sf = source(r#"Host "my server" otherhost"#);
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let tokens = d.arguments.tokenize();
    // "my server" content starts at column 7 (inside opening quote)
    assert_eq!(tokens[0].value, "my server");
    assert_eq!(tokens[0].location.column, 7);
    // "otherhost" starts at column 18
    assert_eq!(tokens[1].value, "otherhost");
    assert_eq!(tokens[1].location.column, 18);
}

#[test]
fn location_on_second_line() {
    let sf = source("Host a\nPort 443");
    let entries = sf.parse();
    let ds = directives(&entries);
    let port_kw = &ds[1].keyword;
    assert_eq!(port_kw.value, "Port");
    assert_eq!(port_kw.location.line, 2);
    assert_eq!(port_kw.location.column, 1);
    let port_arg = &ds[1].arguments;
    assert_eq!(port_arg.value, "443");
    assert_eq!(port_arg.location.line, 2);
    assert_eq!(port_arg.location.column, 6);
}

#[test]
fn span_slices_source_text() {
    let input = "Host alpha beta gamma";
    let sf = source(input);
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };

    // Keyword span
    let kw_span = d.keyword.location.span;
    assert_eq!(&input[kw_span.start..kw_span.end], "Host");

    // Arguments span
    let args_span = d.arguments.location.span;
    assert_eq!(&input[args_span.start..args_span.end], "alpha beta gamma");

    // Tokenized spans
    let tokens = d.arguments.tokenize();
    for token in &tokens {
        let s = token.location.span;
        assert_eq!(&input[s.start..s.end], token.value);
    }
}

#[test]
fn span_slices_quoted() {
    let input = r#"Host "my server" otherhost"#;
    let sf = source(input);
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let tokens = d.arguments.tokenize();
    assert_eq!(
        &input[tokens[0].location.span.start..tokens[0].location.span.end],
        "my server"
    );
    assert_eq!(
        &input[tokens[1].location.span.start..tokens[1].location.span.end],
        "otherhost"
    );
}

#[test]
fn span_slices_comma_split() {
    let input = "ProxyJump hop1,hop2,hop3";
    let sf = source(input);
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<ProxyJumpArgs>().unwrap();
    for jump in &args.value.jumps {
        let s = jump.location.span;
        assert_eq!(&input[s.start..s.end], jump.value);
    }
}

// ===========================================================================
// SourceFile line/column tests
// ===========================================================================

#[test]
fn source_file_line_col_basic() {
    let sf = SourceFile::new("<test>", "line1\nline2\nline3".to_string());

    assert_eq!(sf.line_col(0), (1, 1)); // 'l' of line1
    assert_eq!(sf.line_col(4), (1, 5)); // '1' of line1
    assert_eq!(sf.line_col(6), (2, 1)); // 'l' of line2
    assert_eq!(sf.line_col(12), (3, 1)); // 'l' of line3
}

#[test]
fn source_file_line_col_with_config() {
    let sf = SourceFile::new(
        "<test>",
        "Host myserver\n    HostName 192.168.1.1\n    Port 2222\n".to_string(),
    );

    let entries = sf.parse();
    let ds = directives(&entries);

    // HostName keyword on line 2, after 4 spaces
    let hostname_kw = &ds[1].keyword;
    assert_eq!(hostname_kw.location.line, 2);
    assert_eq!(hostname_kw.location.column, 5);

    // Port argument "2222" on line 3
    let port_arg = &ds[2].arguments;
    assert_eq!(port_arg.location.line, 3);
}

// ===========================================================================
// Pattern matching tests
// ===========================================================================

#[test]
fn pattern_star_matches() {
    let p = Pattern {
        negated: false,
        value: "*",
    };
    assert!(p.matches("anything"));
    assert!(p.matches(""));
}

#[test]
fn pattern_star_suffix() {
    let p = Pattern {
        negated: false,
        value: "*.example.com",
    };
    assert!(p.matches("www.example.com"));
    assert!(!p.matches("example.com"));
}

#[test]
fn pattern_question_mark() {
    let p = Pattern {
        negated: false,
        value: "host?",
    };
    assert!(p.matches("host1"));
    assert!(!p.matches("host12"));
    assert!(!p.matches("host"));
}

#[test]
fn pattern_case_insensitive() {
    let p = Pattern {
        negated: false,
        value: "Host",
    };
    assert!(p.matches("host"));
    assert!(p.matches("HOST"));
    assert!(p.matches("Host"));
}

#[test]
fn pattern_negated() {
    let p = Pattern {
        negated: true,
        value: "*.internal",
    };
    assert!(!p.matches("srv.internal"));
    assert!(p.matches("srv.public"));
}

#[test]
fn pattern_ip_wildcard() {
    let p = Pattern {
        negated: false,
        value: "192.168.0.?",
    };
    assert!(p.matches("192.168.0.1"));
    assert!(p.matches("192.168.0.9"));
    assert!(!p.matches("192.168.0.10"));
}

// ===========================================================================
// Secondary parsing (ParseArguments) tests
// ===========================================================================

#[test]
fn parse_args_host() {
    let sf = source("Host server1 server2 *.example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let host = d.parse_args::<HostArgs>().unwrap();
    assert_eq!(host.value.patterns.len(), 3);
    assert_eq!(host.value.patterns[0].value.value, "server1");
    assert!(!host.value.patterns[0].value.negated);
    assert_eq!(host.value.patterns[1].value.value, "server2");
    assert_eq!(host.value.patterns[2].value.value, "*.example.com");
}

#[test]
fn parse_args_host_negated() {
    let sf = source("Host *.example.com !*.internal.example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let host = d.parse_args::<HostArgs>().unwrap();
    assert_eq!(host.value.patterns.len(), 2);
    assert!(!host.value.patterns[0].value.negated);
    assert_eq!(host.value.patterns[0].value.value, "*.example.com");
    assert!(host.value.patterns[1].value.negated);
    assert_eq!(host.value.patterns[1].value.value, "*.internal.example.com");
}

#[test]
fn parse_args_hostname() {
    let sf = source("HostName example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<HostNameArgs>().unwrap();
    assert_eq!(args.value.hostname.value, "example.com");
}

#[test]
fn parse_args_port() {
    let sf = source("Port 2222");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<PortArgs>().unwrap();
    assert_eq!(args.value.port.value, 2222u16);
}

#[test]
fn parse_args_port_invalid() {
    let sf = source("Port notanumber");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<PortArgs>().unwrap_err();
    match &err.value {
        ParseIntegerArgError::InvalidValue { .. } => {
            // Error location points to the bad token
            assert_eq!(err.location.line, 1);
            assert_eq!(err.location.column, 6);
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

#[test]
fn parse_args_port_too_many() {
    let sf = source("Port 22 80");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<PortArgs>().unwrap_err();
    assert!(matches!(
        err.value,
        ParseIntegerArgError::WrongArgumentCount { .. }
    ));
}

#[test]
fn parse_args_user() {
    let sf = source("User admin");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<UserArgs>().unwrap();
    assert_eq!(args.value.username.value, "admin");
}

#[test]
fn parse_args_identity_file() {
    let sf = source("IdentityFile ~/.ssh/id_ed25519");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<IdentityFileArgs>().unwrap();
    assert_eq!(args.value.path.value, "~/.ssh/id_ed25519");
}

#[test]
fn parse_args_proxy_jump_single() {
    let sf = source("ProxyJump bastion.example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<ProxyJumpArgs>().unwrap();
    assert_eq!(args.value.jumps.len(), 1);
    assert_eq!(args.value.jumps[0].value, "bastion.example.com");
}

#[test]
fn parse_args_proxy_jump_multiple() {
    let sf = source("ProxyJump hop1,hop2,hop3");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<ProxyJumpArgs>().unwrap();
    assert_eq!(args.value.jumps.len(), 3);
    assert_eq!(args.value.jumps[0].value, "hop1");
    assert_eq!(args.value.jumps[1].value, "hop2");
    assert_eq!(args.value.jumps[2].value, "hop3");
}

#[test]
fn parse_args_include() {
    let sf = source("Include ~/.ssh/config.d/*");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<IncludeArgs>().unwrap();
    assert_eq!(args.value.paths.len(), 1);
    assert_eq!(args.value.paths[0].value, "~/.ssh/config.d/*");
}

#[test]
fn parse_args_local_forward() {
    let sf = source("LocalForward 8080 remote:80");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<LocalForwardArgs>().unwrap();
    assert_eq!(args.value.bind.value, "8080");
    assert_eq!(args.value.destination.value, "remote:80");
}

#[test]
fn parse_args_remote_forward_with_destination() {
    let sf = source("RemoteForward 9090 localhost:3000");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<RemoteForwardArgs>().unwrap();
    assert_eq!(args.value.bind.value, "9090");
    assert_eq!(
        args.value.destination.as_ref().unwrap().value,
        "localhost:3000"
    );
}

#[test]
fn parse_args_remote_forward_socks() {
    let sf = source("RemoteForward 1080");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<RemoteForwardArgs>().unwrap();
    assert_eq!(args.value.bind.value, "1080");
    assert!(args.value.destination.is_none());
}

#[test]
fn parse_args_single_arg() {
    let sf = source("Compression yes");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<SingleArg>().unwrap();
    assert_eq!(args.value.value.value, "yes");
}

// ===========================================================================
// Secondary parsing location correctness
// ===========================================================================

#[test]
fn secondary_parse_location_correctness() {
    let sf = SourceFile::new(
        "/etc/ssh/config",
        "Host myserver\n    Port 2222\n    HostName 10.0.0.1".to_string(),
    );
    let entries = sf.parse();

    let port_d = entries
        .iter()
        .find_map(|e| match e {
            Entry::Directive(d) if d.keyword.value.eq_ignore_ascii_case("port") => Some(d),
            _ => None,
        })
        .unwrap();

    let port_args = port_d.parse_args::<PortArgs>().unwrap();
    // The port value location should point to "2222" on line 2
    assert_eq!(port_args.value.port.location.line, 2);
    assert_eq!(port_args.value.port.location.column, 10);
}

#[test]
fn proxy_jump_sub_locations() {
    let sf = source("ProxyJump hop1,hop2,hop3");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<ProxyJumpArgs>().unwrap();

    // hop1 at col 11, hop2 at col 16, hop3 at col 21
    assert_eq!(args.value.jumps[0].location.column, 11);
    assert_eq!(args.value.jumps[1].location.column, 16);
    assert_eq!(args.value.jumps[2].location.column, 21);
}

// ===========================================================================
// Location display tests
// ===========================================================================

#[test]
fn location_display_with_path() {
    let sf = SourceFile::new(
        "/home/user/.ssh/config",
        "Host myserver\nPort 2222\n".to_string(),
    );
    let entries = sf.parse();
    let ds = directives(&entries);
    // Port keyword on line 2
    assert_eq!(
        ds[1].keyword.location.to_string(),
        "/home/user/.ssh/config:2:1"
    );
}

#[test]
fn located_error_display() {
    let sf = SourceFile::new("/etc/ssh/ssh_config", "Port notanumber".to_string());
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<PortArgs>().unwrap_err();
    let display = err.to_string();
    assert!(display.contains("invalid integer value"));
    assert!(display.contains("/etc/ssh/ssh_config:1:6"));
}

#[test]
fn located_error_source_chain() {
    let sf = source("Port notanumber");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<PortArgs>().unwrap_err();
    // Located<E>::source() delegates to E::source()
    // For InvalidValue, source is ParseIntError
    use std::error::Error;
    let source = err.source().expect("should have source");
    let source_display = source.to_string();
    assert!(source_display.contains("invalid digit"));
}

#[test]
fn location_from_source_file() {
    let sf = SourceFile::new("config", "Host a\n    HostName b\n".to_string());
    let loc = sf.location(Span { start: 11, end: 19 }); // 'HostName'
    assert_eq!(loc.to_string(), "config:2:5");
    assert_eq!(loc.line, 2);
    assert_eq!(loc.column, 5);
}

// ===========================================================================
// Match criteria parsing tests
// ===========================================================================

#[test]
fn parse_match_all() {
    let sf = source("Match all");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<MatchArgs>().unwrap();
    assert_eq!(args.value.entries.len(), 1);
    assert!(matches!(
        args.value.entries[0].value.criterion,
        MatchCriterion::All
    ));
    assert!(!args.value.entries[0].value.negated);
}

#[test]
fn parse_match_canonical_all() {
    let sf = source("Match canonical final all");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<MatchArgs>().unwrap();
    assert_eq!(args.value.entries.len(), 3);
    assert!(matches!(
        args.value.entries[0].value.criterion,
        MatchCriterion::Canonical
    ));
    assert!(matches!(
        args.value.entries[1].value.criterion,
        MatchCriterion::Final
    ));
    assert!(matches!(
        args.value.entries[2].value.criterion,
        MatchCriterion::All
    ));
}

#[test]
fn parse_match_host_pattern() {
    let sf = source("Match host *.example.com,!*.internal");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<MatchArgs>().unwrap();
    assert_eq!(args.value.entries.len(), 1);
    let entry = &args.value.entries[0].value;
    assert!(!entry.negated);
    let MatchCriterion::Host { patterns } = &entry.criterion else {
        panic!("expected Host criterion");
    };
    assert_eq!(patterns.len(), 2);
    assert!(!patterns[0].value.negated);
    assert_eq!(patterns[0].value.value, "*.example.com");
    assert!(patterns[1].value.negated);
    assert_eq!(patterns[1].value.value, "*.internal");
}

#[test]
fn parse_match_negated_criterion() {
    let sf = source("Match !host *.bad");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<MatchArgs>().unwrap();
    assert!(args.value.entries[0].value.negated);
    assert!(matches!(
        args.value.entries[0].value.criterion,
        MatchCriterion::Host { .. }
    ));
}

#[test]
fn parse_match_exec() {
    let sf = source(r#"Match exec "test -f /etc/myconfig""#);
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<MatchArgs>().unwrap();
    let MatchCriterion::Exec { command } = &args.value.entries[0].value.criterion else {
        panic!("expected Exec criterion");
    };
    assert_eq!(command.value, "test -f /etc/myconfig");
}

#[test]
fn parse_match_multi_criteria() {
    let sf = source("Match host *.example.com user alice,bob");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<MatchArgs>().unwrap();
    assert_eq!(args.value.entries.len(), 2);
    assert!(matches!(
        args.value.entries[0].value.criterion,
        MatchCriterion::Host { .. }
    ));
    let MatchCriterion::User { patterns } = &args.value.entries[1].value.criterion else {
        panic!("expected User criterion");
    };
    assert_eq!(patterns.len(), 2);
    assert_eq!(patterns[0].value.value, "alice");
    assert_eq!(patterns[1].value.value, "bob");
}

#[test]
fn parse_match_localnetwork() {
    let sf = source("Match localnetwork 192.168.0.0/16,10.0.0.0/8");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<MatchArgs>().unwrap();
    let MatchCriterion::LocalNetwork { networks } = &args.value.entries[0].value.criterion else {
        panic!("expected LocalNetwork criterion");
    };
    assert_eq!(networks.len(), 2);
    assert_eq!(networks[0].value, "192.168.0.0/16");
    assert_eq!(networks[1].value, "10.0.0.0/8");
}

#[test]
fn parse_match_invalid_all_placement() {
    let sf = source("Match host *.example.com all");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<MatchArgs>().unwrap_err();
    assert!(matches!(
        err.value,
        ParseMatchArgsError::InvalidAllPlacement
    ));
}

#[test]
fn parse_match_unknown_criterion() {
    let sf = source("Match bogus *.example.com");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<MatchArgs>().unwrap_err();
    assert!(matches!(
        err.value,
        ParseMatchArgsError::UnknownCriterion { .. }
    ));
}

#[test]
fn parse_match_missing_argument() {
    let sf = source("Match host");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<MatchArgs>().unwrap_err();
    assert!(matches!(
        err.value,
        ParseMatchArgsError::MissingArgument { .. }
    ));
}

#[test]
fn parse_match_sessiontype() {
    let sf = source("Match sessiontype shell,exec");
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<MatchArgs>().unwrap();
    let MatchCriterion::SessionType { patterns } = &args.value.entries[0].value.criterion else {
        panic!("expected SessionType criterion");
    };
    assert_eq!(patterns.len(), 2);
    assert_eq!(patterns[0].value.value, "shell");
    assert_eq!(patterns[1].value.value, "exec");
}

// ===========================================================================
// Realistic config integration test
// ===========================================================================

#[test]
fn realistic_config() {
    let input = "\
# SSH client configuration

Host bastion
    HostName bastion.example.com
    User ops
    Port 2222
    IdentityFile ~/.ssh/bastion_key
    ForwardAgent yes

Host production
    HostName = prod.internal.example.com
    User deploy
    ProxyJump bastion
    IdentityFile ~/.ssh/deploy_key

Host *
    ServerAliveInterval 60
    ServerAliveCountMax 3
    Compression yes
    AddKeysToAgent yes
";
    let sf = SourceFile::new("/home/user/.ssh/config", input.to_string());
    let entries = sf.parse();

    let ds = directives(&entries);

    // Count directives
    assert_eq!(ds.len(), 16);

    // Verify no Unknown entries
    assert!(!entries.iter().any(|e| matches!(e, Entry::Unknown(_))));

    // Verify equals separator works
    let hostname_eq = ds
        .iter()
        .find(|d| d.keyword.value == "HostName" && d.arguments.value == "prod.internal.example.com")
        .expect("should find HostName with = separator");
    assert_eq!(hostname_eq.arguments.value, "prod.internal.example.com");

    // Verify secondary parsing on a few
    let port_d = ds
        .iter()
        .find(|d| d.keyword.value.eq_ignore_ascii_case("port"))
        .unwrap();
    let port = port_d.parse_args::<PortArgs>().unwrap();
    assert_eq!(port.value.port.value, 2222);

    let host_star = ds
        .iter()
        .find(|d| d.keyword.value.eq_ignore_ascii_case("host") && d.arguments.value == "*")
        .unwrap();
    let host_args = host_star.parse_args::<HostArgs>().unwrap();
    assert_eq!(host_args.value.patterns[0].value.value, "*");

    // Verify all paths share the same Arc
    let path1 = &ds[0].keyword.location.path;
    let path2 = &ds[5].keyword.location.path;
    assert!(
        Arc::ptr_eq(path1, path2),
        "locations should share Arc<PathBuf>"
    );
}
