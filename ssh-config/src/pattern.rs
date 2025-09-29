use std::{convert::Infallible, fmt::Display, str::FromStr};

use regex::Regex;

#[derive(Debug, Clone)]
pub struct SinglePattern {
    original: String,
    regex: Regex,
    negative: bool,
}

impl SinglePattern {
    #[inline]
    pub fn new(original: String) -> Self {
        let mut input = original.as_str();
        let mut negative = false;
        if input.starts_with('!') {
            negative = true;
            input = &input[1..];
        }
        let mut re = String::with_capacity((input.len() * 2).next_power_of_two());
        re.push('^');
        for char in input.chars() {
            match char {
                '*' => re.push_str(".*"),
                '?' => re.push('.'),
                c if regex_syntax::is_meta_character(c) => {
                    re.push('\\');
                    re.push(c);
                }
                c => re.push(c),
            }
        }
        re.push('$');
        let regex = Regex::new(&re).expect("Valid regex");
        Self {
            original,
            regex,
            negative,
        }
    }

    #[inline]
    pub fn is_match(&self, text: &str) -> bool {
        self.regex.is_match(text) ^ self.negative
    }
}

impl FromStr for SinglePattern {
    type Err = Infallible;

    fn from_str(original: &str) -> Result<Self, Self::Err> {
        Ok(Self::new(original.to_string()))
    }
}

impl Display for SinglePattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.original.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let pattern = SinglePattern::new("example".to_string());
        assert!(pattern.is_match("example"));
        assert!(!pattern.is_match("Example"));
        assert!(!pattern.is_match("example.com"));
        assert!(!pattern.is_match("test-example"));
    }

    #[test]
    fn test_wildcard_asterisk() {
        let pattern = SinglePattern::new("*.example.com".to_string());
        assert!(pattern.is_match("www.example.com"));
        assert!(pattern.is_match("mail.example.com"));
        assert!(pattern.is_match("subdomain.example.com"));
        assert!(pattern.is_match(".example.com"));
        assert!(!pattern.is_match("example.com"));
        assert!(!pattern.is_match("example.org"));
    }

    #[test]
    fn test_wildcard_question_mark() {
        let pattern = SinglePattern::new("host?.example.com".to_string());
        assert!(pattern.is_match("host1.example.com"));
        assert!(pattern.is_match("hosta.example.com"));
        assert!(pattern.is_match("host-.example.com"));
        assert!(!pattern.is_match("host.example.com"));
        assert!(!pattern.is_match("host12.example.com"));
        assert!(!pattern.is_match("hostab.example.com"));
    }

    #[test]
    fn test_mixed_wildcards() {
        let pattern = SinglePattern::new("*-?.example.com".to_string());
        assert!(pattern.is_match("web-1.example.com"));
        assert!(pattern.is_match("api-a.example.com"));
        assert!(pattern.is_match("staging-test-x.example.com"));
        assert!(!pattern.is_match("web-.example.com"));
        assert!(!pattern.is_match("web-12.example.com"));
    }

    #[test]
    fn test_negative_pattern() {
        let pattern = SinglePattern::new("!*.test.com".to_string());
        assert!(!pattern.is_match("www.test.com"));
        assert!(!pattern.is_match("api.test.com"));
        assert!(pattern.is_match("www.example.com"));
        assert!(pattern.is_match("test.com"));
    }

    #[test]
    fn test_negative_exact_pattern() {
        let pattern = SinglePattern::new("!localhost".to_string());
        assert!(!pattern.is_match("localhost"));
        assert!(pattern.is_match("localhost.local"));
        assert!(pattern.is_match("my-localhost"));
        assert!(pattern.is_match("example.com"));
    }

    #[test]
    fn test_regex_meta_characters_escaped() {
        let pattern = SinglePattern::new("host[1-9].example.com".to_string());
        // Square brackets should be escaped, so this matches literally
        assert!(pattern.is_match("host[1-9].example.com"));
        assert!(!pattern.is_match("host1.example.com"));
        assert!(!pattern.is_match("host9.example.com"));
    }

    #[test]
    fn test_other_regex_meta_characters() {
        let pattern = SinglePattern::new("host.example.com".to_string());
        // Dot should be escaped, so this matches literally
        assert!(pattern.is_match("host.example.com"));
        assert!(!pattern.is_match("hostXexample.com"));
    }

    #[test]
    fn test_from_str() {
        let pattern: SinglePattern = "*.example.com".parse().unwrap();
        assert!(pattern.is_match("www.example.com"));
        assert!(!pattern.is_match("example.com"));
    }

    #[test]
    fn test_display() {
        let pattern = SinglePattern::new("*.example.com".to_string());
        assert_eq!(pattern.to_string(), "*.example.com");

        let negative_pattern = SinglePattern::new("!localhost".to_string());
        assert_eq!(negative_pattern.to_string(), "!localhost");
    }

    #[test]
    fn test_empty_pattern() {
        let pattern = SinglePattern::new("".to_string());
        assert!(pattern.is_match(""));
        assert!(!pattern.is_match("anything"));
    }

    #[test]
    fn test_only_wildcards() {
        let asterisk_pattern = SinglePattern::new("*".to_string());
        assert!(asterisk_pattern.is_match("anything"));
        assert!(asterisk_pattern.is_match(""));
        assert!(asterisk_pattern.is_match("multiple words"));

        let question_pattern = SinglePattern::new("?".to_string());
        assert!(question_pattern.is_match("a"));
        assert!(question_pattern.is_match("1"));
        assert!(!question_pattern.is_match(""));
    }

    #[test]
    fn test_complex_patterns() {
        let pattern = SinglePattern::new("web-*-?.prod.*.com".to_string());
        assert!(pattern.is_match("web-frontend-1.prod.example.com"));
        assert!(pattern.is_match("web-api-a.prod.test.com"));
        assert!(!pattern.is_match("web-frontend-.prod.example.com"));
        assert!(!pattern.is_match("web-frontend-12.prod.example.com"));
    }

    #[test]
    fn test_negative_with_wildcards() {
        let pattern = SinglePattern::new("!test-*.local".to_string());
        assert!(!pattern.is_match("test-1.local"));
        assert!(!pattern.is_match("test-server.local"));
        assert!(pattern.is_match("prod-1.local"));
        assert!(pattern.is_match("test.local"));
    }

    #[test]
    fn test_special_characters() {
        // Test various special regex characters are properly escaped
        let pattern = SinglePattern::new("host+name^server$end.com".to_string());
        assert!(pattern.is_match("host+name^server$end.com"));
        assert!(!pattern.is_match("hostnameserverend.com"));
    }

    #[test]
    fn test_unicode_characters() {
        let pattern = SinglePattern::new("服务器-*.测试.com".to_string());
        assert!(pattern.is_match("服务器-1.测试.com"));
        assert!(pattern.is_match("服务器-production.测试.com"));
        assert!(!pattern.is_match("服务器.测试.com"));
    }
}
