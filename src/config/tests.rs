use super::*;
use std::path::PathBuf;

// ===========================================================================
// First-layer parsing tests
// ===========================================================================

#[test]
fn empty_input() {
    let entries = parse("");
    assert_eq!(entries.len(), 1);
    assert!(matches!(entries[0], Entry::Empty(_)));
}

#[test]
fn blank_lines() {
    let entries = parse("\n\n\n");
    assert!(entries.iter().all(|e| matches!(e, Entry::Empty(_))));
}

#[test]
fn comment_line() {
    let entries = parse("# this is a comment");
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
    let entries = parse("   # indented comment");
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
    let input = "HostName example.com";
    let entries = parse(input);
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "HostName");
    assert_eq!(d.arguments.len(), 1);
    assert_eq!(d.arguments[0].value, "example.com");
}

#[test]
fn simple_directive_equals_separator() {
    let input = "HostName=example.com";
    let entries = parse(input);
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "HostName");
    assert_eq!(d.arguments[0].value, "example.com");
}

#[test]
fn directive_equals_with_spaces() {
    let input = "HostName = example.com";
    let entries = parse(input);
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "HostName");
    assert_eq!(d.arguments[0].value, "example.com");
}

#[test]
fn multiple_arguments() {
    let input = "Host server1 server2 *.example.com";
    let entries = parse(input);
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "Host");
    assert_eq!(d.arguments.len(), 3);
    assert_eq!(d.arguments[0].value, "server1");
    assert_eq!(d.arguments[1].value, "server2");
    assert_eq!(d.arguments[2].value, "*.example.com");
}

#[test]
fn quoted_argument() {
    let input = r#"ProxyCommand "ssh -W %h:%p bastion""#;
    let entries = parse(input);
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "ProxyCommand");
    assert_eq!(d.arguments.len(), 1);
    assert_eq!(d.arguments[0].value, "ssh -W %h:%p bastion");
}

#[test]
fn mixed_quoted_and_unquoted() {
    let input = r#"Host "my server" otherhost"#;
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.arguments.len(), 2);
    assert_eq!(d.arguments[0].value, "my server");
    assert_eq!(d.arguments[1].value, "otherhost");
}

#[test]
fn keyword_case_preserved() {
    let input = "HostName example.com\nhostname other.com\nHOSTNAME third.com";
    let entries = parse(input);
    let directives: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Directive(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(directives[0].keyword.value, "HostName");
    assert_eq!(directives[1].keyword.value, "hostname");
    assert_eq!(directives[2].keyword.value, "HOSTNAME");
}

#[test]
fn multiline_config() {
    let input = "\
Host myserver
    HostName 192.168.1.1
    User admin
    Port 2222
";
    let entries = parse(input);
    let directives: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Directive(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(directives.len(), 4);
    assert_eq!(directives[0].keyword.value, "Host");
    assert_eq!(directives[0].arguments[0].value, "myserver");
    assert_eq!(directives[1].keyword.value, "HostName");
    assert_eq!(directives[1].arguments[0].value, "192.168.1.1");
    assert_eq!(directives[2].keyword.value, "User");
    assert_eq!(directives[2].arguments[0].value, "admin");
    assert_eq!(directives[3].keyword.value, "Port");
    assert_eq!(directives[3].arguments[0].value, "2222");
}

#[test]
fn comments_and_blanks_interleaved() {
    let input = "\
# Global settings
ServerAliveInterval 60

# My server
Host myserver
    HostName 10.0.0.1
";
    let entries = parse(input);

    let mut comments = 0;
    let mut empties = 0;
    let mut directives = 0;
    for e in &entries {
        match e {
            Entry::Comment(_) => comments += 1,
            Entry::Empty(_) => empties += 1,
            Entry::Directive(_) => directives += 1,
            Entry::Unknown(_) => panic!("unexpected Unknown entry"),
        }
    }
    assert_eq!(comments, 2);
    assert!(empties >= 1);
    assert_eq!(directives, 3);
}

#[test]
fn no_trailing_newline() {
    let input = "Port 22";
    let entries = parse(input);
    assert_eq!(entries.len(), 1);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "Port");
    assert_eq!(d.arguments[0].value, "22");
}

#[test]
fn crlf_line_endings() {
    let input = "Host a\r\nPort 22\r\n";
    let entries = parse(input);
    let directives: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Directive(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(directives.len(), 2);
    assert_eq!(directives[0].keyword.value, "Host");
    assert_eq!(directives[1].keyword.value, "Port");
}

#[test]
fn leading_whitespace_on_directive() {
    let input = "    HostName example.com";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.value, "HostName");
    assert_eq!(d.arguments[0].value, "example.com");
}

// ===========================================================================
// Span accuracy tests
// ===========================================================================

#[test]
fn keyword_span_accuracy() {
    let input = "HostName example.com";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    assert_eq!(d.keyword.span, Span { start: 0, end: 8 });
    assert_eq!(&input[d.keyword.span.start..d.keyword.span.end], "HostName");
}

#[test]
fn argument_span_accuracy() {
    let input = "HostName example.com";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let arg = &d.arguments[0];
    assert_eq!(&input[arg.span.start..arg.span.end], "example.com");
    assert_eq!(arg.value, &input[arg.span.start..arg.span.end]);
}

#[test]
fn quoted_argument_span_excludes_quotes() {
    let input = r#"Host "my server""#;
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let arg = &d.arguments[0];
    assert_eq!(arg.value, "my server");
    // Span covers the content inside quotes
    assert_eq!(&input[arg.span.start..arg.span.end], "my server");
}

#[test]
fn multiple_arguments_span_accuracy() {
    let input = "Host alpha beta gamma";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    for arg in &d.arguments {
        assert_eq!(arg.value, &input[arg.span.start..arg.span.end]);
    }
}

#[test]
fn span_on_second_line() {
    let input = "Host a\nPort 443";
    let entries = parse(input);
    let directives: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Directive(d) => Some(d),
            _ => None,
        })
        .collect();
    let port_kw = &directives[1].keyword;
    assert_eq!(port_kw.value, "Port");
    assert_eq!(&input[port_kw.span.start..port_kw.span.end], "Port");
    let port_arg = &directives[1].arguments[0];
    assert_eq!(&input[port_arg.span.start..port_arg.span.end], "443");
}

// ===========================================================================
// SourceFile line/column tests
// ===========================================================================

#[test]
fn source_file_line_col_basic() {
    let content = "line1\nline2\nline3".to_string();
    let sf = SourceFile::new(None, content);

    assert_eq!(sf.line_col(0), (1, 1)); // 'l' of line1
    assert_eq!(sf.line_col(4), (1, 5)); // '1' of line1
    assert_eq!(sf.line_col(6), (2, 1)); // 'l' of line2
    assert_eq!(sf.line_col(12), (3, 1)); // 'l' of line3
}

#[test]
fn source_file_line_col_with_config() {
    let content = "Host myserver\n    HostName 192.168.1.1\n    Port 2222\n".to_string();
    let sf = SourceFile::new(None, content);

    let entries = sf.parse();
    let directives: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Directive(d) => Some(d),
            _ => None,
        })
        .collect();

    // HostName keyword on line 2
    let hostname_kw = &directives[1].keyword;
    let (line, col) = sf.line_col(hostname_kw.span.start);
    assert_eq!(line, 2);
    assert_eq!(col, 5); // after 4 spaces of indentation

    // Port argument "2222" on line 3
    let port_arg = &directives[2].arguments[0];
    let (line, col) = sf.line_col(port_arg.span.start);
    assert_eq!(line, 3);
}

// ===========================================================================
// Secondary parsing (ParseArguments) tests
// ===========================================================================

#[test]
fn parse_args_host() {
    let input = "Host server1 server2 *.example.com";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let host = d.parse_args::<HostArgs>().unwrap();
    assert_eq!(host.patterns.len(), 3);
    assert_eq!(host.patterns[0].value, "server1");
    assert_eq!(host.patterns[1].value, "server2");
    assert_eq!(host.patterns[2].value, "*.example.com");
}

#[test]
fn parse_args_hostname() {
    let input = "HostName example.com";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<HostNameArgs>().unwrap();
    assert_eq!(args.hostname.value, "example.com");
}

#[test]
fn parse_args_port() {
    let input = "Port 2222";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<PortArgs>().unwrap();
    assert_eq!(args.port.value, 2222u16);
}

#[test]
fn parse_args_port_invalid() {
    let input = "Port notanumber";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<PortArgs>().unwrap_err();
    match err {
        ParseIntegerArgError::InvalidValue { span, .. } => {
            assert_eq!(&input[span.start..span.end], "notanumber");
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }
}

#[test]
fn parse_args_port_too_many() {
    let input = "Port 22 80";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<PortArgs>().unwrap_err();
    assert!(matches!(
        err,
        ParseIntegerArgError::WrongArgumentCount { .. }
    ));
}

#[test]
fn parse_args_user() {
    let input = "User admin";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<UserArgs>().unwrap();
    assert_eq!(args.username.value, "admin");
}

#[test]
fn parse_args_identity_file() {
    let input = "IdentityFile ~/.ssh/id_ed25519";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<IdentityFileArgs>().unwrap();
    assert_eq!(args.path.value, "~/.ssh/id_ed25519");
}

#[test]
fn parse_args_proxy_jump_single() {
    let input = "ProxyJump bastion.example.com";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<ProxyJumpArgs>().unwrap();
    assert_eq!(args.jumps.len(), 1);
    assert_eq!(args.jumps[0].value, "bastion.example.com");
}

#[test]
fn parse_args_proxy_jump_multiple() {
    let input = "ProxyJump hop1,hop2,hop3";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<ProxyJumpArgs>().unwrap();
    assert_eq!(args.jumps.len(), 3);
    assert_eq!(args.jumps[0].value, "hop1");
    assert_eq!(args.jumps[1].value, "hop2");
    assert_eq!(args.jumps[2].value, "hop3");
}

#[test]
fn parse_args_include() {
    let input = "Include ~/.ssh/config.d/*";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<IncludeArgs>().unwrap();
    assert_eq!(args.paths.len(), 1);
    assert_eq!(args.paths[0].value, "~/.ssh/config.d/*");
}

#[test]
fn parse_args_local_forward() {
    let input = "LocalForward 8080 remote:80";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<LocalForwardArgs>().unwrap();
    assert_eq!(args.bind.value, "8080");
    assert_eq!(args.destination.value, "remote:80");
}

#[test]
fn parse_args_remote_forward_with_destination() {
    let input = "RemoteForward 9090 localhost:3000";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<RemoteForwardArgs>().unwrap();
    assert_eq!(args.bind.value, "9090");
    assert_eq!(args.destination.as_ref().unwrap().value, "localhost:3000");
}

#[test]
fn parse_args_remote_forward_socks() {
    let input = "RemoteForward 1080";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<RemoteForwardArgs>().unwrap();
    assert_eq!(args.bind.value, "1080");
    assert!(args.destination.is_none());
}

#[test]
fn parse_args_single_arg() {
    let input = "Compression yes";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<SingleArg>().unwrap();
    assert_eq!(args.value.value, "yes");
}

// ===========================================================================
// Secondary parsing span correctness
// ===========================================================================

#[test]
fn secondary_parse_span_correctness() {
    let input = "Host myserver\n    Port 2222\n    HostName 10.0.0.1";
    let sf = SourceFile::new(None, input.to_string());
    let entries = sf.parse();

    // Find Port directive
    let port_d = entries
        .iter()
        .find_map(|e| match e {
            Entry::Directive(d) if d.keyword.value.eq_ignore_ascii_case("port") => Some(d),
            _ => None,
        })
        .unwrap();

    let port_args = port_d.parse_args::<PortArgs>().unwrap();
    // The span should point to "2222" in the original source
    assert_eq!(
        &input[port_args.port.span.start..port_args.port.span.end],
        "2222"
    );
    let (line, col) = sf.line_col(port_args.port.span.start);
    assert_eq!(line, 2);
}

#[test]
fn proxy_jump_sub_spans() {
    let input = "ProxyJump hop1,hop2,hop3";
    let entries = parse(input);
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let args = d.parse_args::<ProxyJumpArgs>().unwrap();

    // Each jump's span should point to the correct substring
    assert_eq!(
        &input[args.jumps[0].span.start..args.jumps[0].span.end],
        "hop1"
    );
    assert_eq!(
        &input[args.jumps[1].span.start..args.jumps[1].span.end],
        "hop2"
    );
    assert_eq!(
        &input[args.jumps[2].span.start..args.jumps[2].span.end],
        "hop3"
    );
}

// ===========================================================================
// Location and SpanDisplay tests
// ===========================================================================

#[test]
fn location_display_with_path() {
    let sf = SourceFile::new(
        Some(PathBuf::from("/home/user/.ssh/config")),
        "Host myserver\nPort 2222\n".to_string(),
    );
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[1] else {
        panic!("expected Directive");
    };
    let display = d.keyword.span.display_in(&sf);
    assert_eq!(display.to_string(), "/home/user/.ssh/config:2:1");
}

#[test]
fn location_display_without_path() {
    let sf = SourceFile::new(None, "Port 2222\n".to_string());
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let display = d.arguments[0].span.display_in(&sf);
    assert_eq!(display.to_string(), "<input>:1:6");
}

#[test]
fn location_from_source_file() {
    let sf = SourceFile::new(
        Some(PathBuf::from("config")),
        "Host a\n    HostName b\n".to_string(),
    );
    let loc = sf.location(11); // 'H' of HostName
    assert_eq!(loc.to_string(), "config:2:5");
    assert_eq!(loc.line, 2);
    assert_eq!(loc.column, 5);
}

#[test]
fn span_location_on_error() {
    let input = "Port notanumber";
    let sf = SourceFile::new(
        Some(PathBuf::from("/etc/ssh/ssh_config")),
        input.to_string(),
    );
    let entries = sf.parse();
    let Entry::Directive(d) = &entries[0] else {
        panic!("expected Directive");
    };
    let err = d.parse_args::<PortArgs>().unwrap_err();
    match &err {
        ParseIntegerArgError::InvalidValue { span, .. } => {
            let loc = sf.span_location(*span);
            assert_eq!(loc.to_string(), "/etc/ssh/ssh_config:1:6");
        }
        other => panic!("expected InvalidValue, got {other:?}"),
    }
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
    let sf = SourceFile::new(None, input.to_string());
    let entries = sf.parse();

    let directives: Vec<_> = entries
        .iter()
        .filter_map(|e| match e {
            Entry::Directive(d) => Some(d),
            _ => None,
        })
        .collect();

    // Count directives
    assert_eq!(directives.len(), 16);

    // Verify no Unknown entries
    assert!(!entries.iter().any(|e| matches!(e, Entry::Unknown(_))));

    // Verify equals separator works
    let hostname_eq = directives
        .iter()
        .find(|d| {
            d.keyword.value == "HostName" && d.arguments[0].value == "prod.internal.example.com"
        })
        .expect("should find HostName with = separator");
    assert_eq!(
        &input[hostname_eq.arguments[0].span.start..hostname_eq.arguments[0].span.end],
        "prod.internal.example.com"
    );

    // Verify secondary parsing on a few
    let port_d = directives
        .iter()
        .find(|d| d.keyword.value.eq_ignore_ascii_case("port"))
        .unwrap();
    let port = port_d.parse_args::<PortArgs>().unwrap();
    assert_eq!(port.port.value, 2222);

    let host_star = directives
        .iter()
        .find(|d| {
            d.keyword.value.eq_ignore_ascii_case("host")
                && d.arguments.first().is_some_and(|a| a.value == "*")
        })
        .unwrap();
    let host_args = host_star.parse_args::<HostArgs>().unwrap();
    assert_eq!(host_args.patterns[0].value, "*");
}
