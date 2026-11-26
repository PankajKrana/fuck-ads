//! Procedural cosmetic filters: selectors that need more than CSS, such as
//! `example.com##.card:has-text(Sponsored)` or
//! `example.com##.row:xpath(..):upward(2)`.
//!
//! The extension evaluates them in the page after the filter engine has
//! parsed and *validated* them here. Like every other filter, they cannot
//! carry code: the operators are a fixed set, each argument is parsed into a
//! typed value (plain text, a bounded regular expression, an XPath
//! expression, a number or a native CSS selector), and anything outside that
//! is rejected. Regular expressions are checked for constructs that make
//! JavaScript regex engines backtrack catastrophically.
//!
//! Supported operators (uBlock Origin spellings, with the common aliases):
//!
//! | Operator | Meaning |
//! |---|---|
//! | `:has-text(text)` `:contains()` `:-abp-contains()` | element text contains `text` (or matches `/regex/flags`) |
//! | `:matches-css(prop: value)` `-before` `-after` | computed style (of the element or its pseudo-element) matches |
//! | `:xpath(expr)` | elements selected by an XPath expression |
//! | `:upward(n)` `:upward(selector)` `:nth-ancestor(n)` | move to an ancestor |
//! | `:remove()` | remove the element instead of hiding it (must be last) |
//!
//! Native CSS may precede, follow, and sit between operators
//! (`.feed > div:has-text(Ad) > span.label`). Other procedural operators
//! (`:style()`, `:matches-attr()`, `:if()`, …) stay unsupported.

use crate::ParseError;
use crate::cosmetic::validate_selector;
use serde::{Deserialize, Serialize};

/// At most this many operators/segments in one filter.
const MAX_STEPS: usize = 8;
const MAX_TEXT_ARG: usize = 256;
const MAX_REGEX: usize = 256;
const MAX_XPATH: usize = 512;
const MAX_PROPERTY: usize = 64;

/// A text or regular-expression condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Matcher {
    /// `false`: `pattern` is a plain substring (exact value for CSS).
    pub regex: bool,
    pub pattern: String,
    /// Regular-expression flags (`i`, `m`, `s`, `u`); empty for plain text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flags: String,
}

/// One evaluation step, applied to the set of elements found so far.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum Step {
    /// Keep elements whose text matches.
    HasText { text: Matcher },
    /// Keep elements whose computed style matches. `pseudo` is `before` or
    /// `after` for the pseudo-elements.
    MatchesCss {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pseudo: Option<String>,
        property: String,
        value: Matcher,
    },
    /// Replace the set with the elements an XPath expression selects, with
    /// each current element as the context (the document if there is no base).
    Xpath { expr: String },
    /// Replace each element with an ancestor: `levels` parents up, or the
    /// closest ancestor matching `selector`.
    Upward {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        levels: Option<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        selector: Option<String>,
    },
    /// Native CSS evaluated inside each element (`:scope <selector>`), for
    /// example `> span.label` or ` .badge`.
    Scope { selector: String },
}

/// A parsed procedural filter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Procedural {
    /// Native CSS selecting the starting elements; empty starts from the
    /// whole document (used with `:xpath`).
    pub base: String,
    pub steps: Vec<Step>,
    /// Remove matching elements instead of hiding them.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub remove: bool,
    /// The filter body as written, to match `#@#` exceptions.
    #[serde(skip)]
    pub source: String,
}

/// Operators implemented by the extension.
const SUPPORTED: &[&str] = &[
    "has-text",
    "contains",
    "-abp-contains",
    "matches-css",
    "matches-css-before",
    "matches-css-after",
    "xpath",
    "upward",
    "nth-ancestor",
    "remove",
];

struct Op {
    name: String,
    arg: String,
}

/// The native-CSS segments around the operators, and the operators.
type Split = (Vec<String>, Vec<Op>);

/// Splits `body` into native-CSS segments and supported operators. Returns
/// `None` if there are no supported operators at the top level.
fn split(body: &str) -> Result<Option<Split>, ParseError> {
    let chars: Vec<char> = body.chars().collect();
    let mut segments = vec![String::new()];
    let mut ops: Vec<Op> = Vec::new();
    let mut quote: Option<char> = None;
    let (mut paren, mut bracket) = (0i32, 0i32);
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            if c == '\\' {
                segments.last_mut().unwrap().push(c);
                if let Some(&n) = chars.get(i + 1) {
                    segments.last_mut().unwrap().push(n);
                }
                i += 2;
                continue;
            }
            if c == q {
                quote = None;
            }
            segments.last_mut().unwrap().push(c);
            i += 1;
            continue;
        }
        match c {
            '\\' => {
                segments.last_mut().unwrap().push(c);
                if let Some(&n) = chars.get(i + 1) {
                    segments.last_mut().unwrap().push(n);
                }
                i += 2;
                continue;
            }
            '"' | '\'' => quote = Some(c),
            '(' => paren += 1,
            ')' => paren -= 1,
            '[' => bracket += 1,
            ']' => bracket -= 1,
            ':' if paren == 0
                && bracket == 0
                && chars.get(i + 1) != Some(&':')
                && (i == 0 || chars[i - 1] != ':') =>
            {
                // `:name(` at the top level?
                let mut j = i + 1;
                while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '-') {
                    j += 1;
                }
                let name: String = chars[i + 1..j]
                    .iter()
                    .collect::<String>()
                    .to_ascii_lowercase();
                if j < chars.len() && chars[j] == '(' && SUPPORTED.contains(&name.as_str()) {
                    // Find the matching `)`, honouring quotes and nesting.
                    let mut depth = 0i32;
                    let mut q: Option<char> = None;
                    let mut k = j;
                    let mut end = None;
                    while k < chars.len() {
                        let d = chars[k];
                        if let Some(qq) = q {
                            if d == '\\' {
                                k += 2;
                                continue;
                            }
                            if d == qq {
                                q = None;
                            }
                        } else {
                            match d {
                                '\\' => {
                                    k += 2;
                                    continue;
                                }
                                '"' | '\'' => q = Some(d),
                                '(' => depth += 1,
                                ')' => {
                                    depth -= 1;
                                    if depth == 0 {
                                        end = Some(k);
                                        break;
                                    }
                                }
                                _ => {}
                            }
                        }
                        k += 1;
                    }
                    let end = end.ok_or(ParseError::Invalid("unterminated procedural operator"))?;
                    ops.push(Op {
                        name,
                        arg: chars[j + 1..end].iter().collect(),
                    });
                    segments.push(String::new());
                    i = end + 1;
                    continue;
                }
            }
            _ => {}
        }
        segments.last_mut().unwrap().push(c);
        i += 1;
    }
    if ops.is_empty() {
        return Ok(None);
    }
    Ok(Some((segments, ops)))
}

/// Parses a text/regex argument: `/pattern/flags` or plain text.
fn parse_matcher(arg: &str, allow_regex: bool) -> Result<Matcher, ParseError> {
    let arg = arg.trim();
    if arg.is_empty() {
        return Err(ParseError::Invalid("empty procedural argument"));
    }
    if allow_regex
        && arg.starts_with('/')
        && let Some(close) = arg.rfind('/')
        && close > 1
    {
        let pattern = &arg[1..close];
        let flags = &arg[close + 1..];
        validate_regex(pattern, flags)?;
        return Ok(Matcher {
            regex: true,
            pattern: pattern.to_string(),
            flags: flags.to_string(),
        });
    }
    if arg.len() > MAX_TEXT_ARG || arg.chars().any(char::is_control) {
        return Err(ParseError::Invalid("procedural text argument not allowed"));
    }
    Ok(Matcher {
        regex: false,
        pattern: arg.to_string(),
        flags: String::new(),
    })
}

/// Rejects regular expressions that are invalid, too large, use features
/// JavaScript engines evaluate by backtracking dangerously (backreferences,
/// lookaround), or nest quantifiers.
pub fn validate_regex(pattern: &str, flags: &str) -> Result<(), ParseError> {
    if pattern.is_empty() || pattern.len() > MAX_REGEX || pattern.chars().any(char::is_control) {
        return Err(ParseError::Invalid("regular expression not allowed"));
    }
    let mut seen = String::new();
    for f in flags.chars() {
        if !matches!(f, 'i' | 'm' | 's' | 'u') || seen.contains(f) {
            return Err(ParseError::Invalid("unsupported regular expression flag"));
        }
        seen.push(f);
    }
    if regex::Regex::new(pattern).is_err() {
        return Err(ParseError::Invalid(
            "invalid or unsupported regular expression",
        ));
    }
    if risky_regex(pattern) {
        return Err(ParseError::Unsupported(
            "regular expression may backtrack heavily",
        ));
    }
    Ok(())
}

/// Conservative scan for patterns a backtracking engine can blow up on:
/// backreferences, lookaround, named/non-trivial `(?` groups, a quantified
/// group that itself contains a quantifier or alternation, such as `(a+)+`
/// or `(a|b)*`, and more than one unbounded repeat (`*`, `+`, `{n,}`), such
/// as `a*a*b` or `.*.*=x`, whose backtracking grows with each extra repeat.
fn risky_regex(p: &str) -> bool {
    let b = p.as_bytes();
    let mut stack: Vec<bool> = Vec::new(); // does this group contain a quantifier/alternation?
    let mut unbounded = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'\\' => {
                if matches!(b.get(i + 1), Some(b'1'..=b'9' | b'k')) {
                    return true; // backreference
                }
                i += 2;
                continue;
            }
            b'[' => {
                // Skip the character class.
                i += 1;
                if b.get(i) == Some(&b'^') {
                    i += 1;
                }
                if b.get(i) == Some(&b']') {
                    i += 1;
                }
                while i < b.len() && b[i] != b']' {
                    if b[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'(' => {
                if b.get(i + 1) == Some(&b'?') {
                    // Only plain non-capturing groups.
                    if b.get(i + 2) != Some(&b':') {
                        return true;
                    }
                    i += 2;
                }
                stack.push(false);
            }
            b')' => {
                let inner = stack.pop().unwrap_or(false);
                if inner && matches!(b.get(i + 1), Some(b'*' | b'+' | b'{')) {
                    return true;
                }
                if let Some(top) = stack.last_mut() {
                    *top |= inner;
                }
            }
            b'*' | b'+' | b'?' | b'{' | b'|' => {
                let open_ended = match b[i] {
                    b'*' | b'+' => true,
                    // `{n,}` has no upper bound; `{n}` and `{n,m}` do.
                    b'{' => p[i..]
                        .find('}')
                        .is_some_and(|end| p[i..i + end].ends_with(',')),
                    _ => false,
                };
                if open_ended {
                    unbounded += 1;
                    if unbounded > 1 {
                        return true;
                    }
                }
                if let Some(top) = stack.last_mut() {
                    *top = true;
                }
            }
            _ => {}
        }
        i += 1;
    }
    false
}

fn parse_css_value(arg: &str) -> Result<(String, Matcher), ParseError> {
    let (prop, value) = arg
        .split_once(':')
        .ok_or(ParseError::Invalid("matches-css needs `property: value`"))?;
    let prop = prop.trim().to_ascii_lowercase();
    if prop.is_empty()
        || prop.len() > MAX_PROPERTY
        || !prop.bytes().all(|c| c.is_ascii_lowercase() || c == b'-')
    {
        return Err(ParseError::Invalid("invalid CSS property name"));
    }
    Ok((prop, parse_matcher(value, true)?))
}

fn check_scope(segment: &str) -> Result<Option<String>, ParseError> {
    let trimmed = segment.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    // The text must continue the selector with a combinator or a space.
    let first = segment.chars().next().unwrap_or(' ');
    if !(first.is_whitespace() || matches!(first, '>' | '+' | '~')) {
        return Err(ParseError::Unsupported(
            "compound selector after procedural operator",
        ));
    }
    validate_selector(trimmed)?;
    Ok(Some(trimmed.to_string()))
}

/// Parses a cosmetic-filter body. Returns `Ok(None)` if it has no supported
/// procedural operator (it is plain CSS, or uses only unsupported ones, which
/// [`validate_selector`] then rejects).
pub fn parse(body: &str) -> Result<Option<Procedural>, ParseError> {
    let Some((segments, ops)) = split(body)? else {
        return Ok(None);
    };
    if ops.len() > MAX_STEPS {
        return Err(ParseError::Invalid("too many procedural operators"));
    }
    let base = segments[0].trim();
    if !base.is_empty() {
        validate_selector(base)?;
    }

    let mut steps = Vec::new();
    let mut remove = false;
    for (n, op) in ops.iter().enumerate() {
        if remove {
            return Err(ParseError::Invalid(":remove() must be the last operator"));
        }
        match op.name.as_str() {
            "has-text" | "contains" | "-abp-contains" => steps.push(Step::HasText {
                text: parse_matcher(&op.arg, true)?,
            }),
            "matches-css" | "matches-css-before" | "matches-css-after" => {
                let pseudo = match op.name.as_str() {
                    "matches-css-before" => Some("before".to_string()),
                    "matches-css-after" => Some("after".to_string()),
                    _ => None,
                };
                let (property, value) = parse_css_value(&op.arg)?;
                steps.push(Step::MatchesCss {
                    pseudo,
                    property,
                    value,
                });
            }
            "xpath" => {
                let expr = op.arg.trim();
                if expr.is_empty() || expr.len() > MAX_XPATH || expr.chars().any(char::is_control) {
                    return Err(ParseError::Invalid("XPath expression not allowed"));
                }
                steps.push(Step::Xpath {
                    expr: expr.to_string(),
                });
            }
            "upward" | "nth-ancestor" => {
                let arg = op.arg.trim();
                if !arg.is_empty() && arg.bytes().all(|c| c.is_ascii_digit()) {
                    let levels: u8 = arg
                        .parse()
                        .ok()
                        .filter(|n| *n >= 1)
                        .ok_or(ParseError::Invalid(":upward() takes 1 to 255"))?;
                    steps.push(Step::Upward {
                        levels: Some(levels),
                        selector: None,
                    });
                } else if op.name == "upward" {
                    validate_selector(arg)?;
                    steps.push(Step::Upward {
                        levels: None,
                        selector: Some(arg.to_string()),
                    });
                } else {
                    return Err(ParseError::Invalid(":nth-ancestor() takes a number"));
                }
            }
            "remove" => {
                if !op.arg.trim().is_empty() {
                    return Err(ParseError::Invalid(":remove() takes no argument"));
                }
                remove = true;
            }
            _ => return Err(ParseError::Unsupported("procedural cosmetic filter")),
        }
        // Native CSS that follows this operator.
        if let Some(sel) = check_scope(&segments[n + 1])? {
            if remove {
                return Err(ParseError::Invalid(":remove() must be last"));
            }
            steps.push(Step::Scope { selector: sel });
        }
    }
    if base.is_empty() && !matches!(steps.first(), Some(Step::Xpath { .. })) {
        return Err(ParseError::Invalid(
            "a procedural filter needs a selector before its first operator (except :xpath)",
        ));
    }
    if steps.len() > MAX_STEPS {
        return Err(ParseError::Invalid("too many procedural steps"));
    }
    Ok(Some(Procedural {
        base: base.to_string(),
        steps,
        remove,
        source: body.trim().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(body: &str) -> Procedural {
        parse(body)
            .unwrap()
            .unwrap_or_else(|| panic!("{body}: not procedural"))
    }

    fn text(s: &str) -> Matcher {
        Matcher {
            regex: false,
            pattern: s.into(),
            flags: String::new(),
        }
    }

    #[test]
    fn plain_css_is_not_procedural() {
        assert_eq!(parse(".ad").unwrap(), None);
        assert_eq!(parse("div:not(.x) > a:hover").unwrap(), None);
        assert_eq!(parse("a::before").unwrap(), None);
        assert_eq!(parse("div:has(> .sponsored)").unwrap(), None);
    }

    #[test]
    fn has_text_plain_and_regex() {
        let p = ok(".card:has-text(Sponsored)");
        assert_eq!(p.base, ".card");
        assert_eq!(
            p.steps,
            vec![Step::HasText {
                text: text("Sponsored")
            }]
        );
        assert!(!p.remove);
        assert_eq!(p.source, ".card:has-text(Sponsored)");

        let p = ok("div.post:has-text(/promoted|ad/i)");
        assert_eq!(
            p.steps,
            vec![Step::HasText {
                text: Matcher {
                    regex: true,
                    pattern: "promoted|ad".into(),
                    flags: "i".into()
                }
            }]
        );
        // Aliases.
        assert_eq!(ok("p:contains(x)").steps, ok("p:has-text(x)").steps);
        assert_eq!(ok("p:-abp-contains(x)").steps, ok("p:has-text(x)").steps);
    }

    #[test]
    fn matches_css_variants() {
        let p = ok("div:matches-css(display: block)");
        assert_eq!(
            p.steps,
            vec![Step::MatchesCss {
                pseudo: None,
                property: "display".into(),
                value: text("block")
            }]
        );
        let p = ok("span:matches-css-before(content: /^Ad/)");
        assert!(
            matches!(&p.steps[0], Step::MatchesCss { pseudo: Some(s), value, .. }
            if s == "before" && value.regex)
        );
        let p = ok("span:matches-css-after(content: \"x\")");
        assert!(matches!(&p.steps[0], Step::MatchesCss { pseudo: Some(s), .. } if s == "after"));
    }

    #[test]
    fn xpath_upward_remove_and_chains() {
        let p = ok(":xpath(//div[@class=\"ad\"])");
        assert_eq!(p.base, "");
        assert!(matches!(&p.steps[0], Step::Xpath { expr } if expr == "//div[@class=\"ad\"]"));

        let p = ok(".feed div:has-text(Ad) > span.label:upward(2)");
        assert_eq!(p.base, ".feed div");
        assert_eq!(
            p.steps,
            vec![
                Step::HasText { text: text("Ad") },
                Step::Scope {
                    selector: "> span.label".into()
                },
                Step::Upward {
                    levels: Some(2),
                    selector: None
                },
            ]
        );
        let p = ok("span.badge:upward(article)");
        assert_eq!(
            p.steps,
            vec![Step::Upward {
                levels: None,
                selector: Some("article".into())
            }]
        );
        assert_eq!(ok("span:nth-ancestor(3)").steps, ok("span:upward(3)").steps);
        assert!(ok("div:has-text(Ad):remove()").remove);
    }

    #[test]
    fn parentheses_quotes_and_pseudo_elements_inside_arguments() {
        // A `)` inside quotes or a nested group does not end the argument.
        let p = ok("div:has-text(/(foo|bar)/)");
        assert!(matches!(&p.steps[0], Step::HasText { text } if text.pattern == "(foo|bar)"));
        let p = ok("div:matches-css(background-image: /url\\(.*\\)/)");
        assert!(matches!(&p.steps[0], Step::MatchesCss { value, .. } if value.regex));
        // Native :not(...) with nested parens survives.
        let p = ok("div:not(.a):has-text(x)");
        assert_eq!(p.base, "div:not(.a)");
    }

    #[test]
    fn rejects_malformed_and_unsupported() {
        for bad in [
            "div:has-text()",
            "div:has-text(   )",
            "div:has-text(x",
            "div:matches-css(nocolon)",
            "div:matches-css(Bad Prop: x)",
            "div:upward(0)",
            "div:upward(256)",
            "div:nth-ancestor(div)",
            "div:remove(x)",
            "div:remove():has-text(x)",
            "div:remove() > a",
            ":has-text(x)", // nothing to start from
            "div:xpath()",
            "div:has-text(a):has-text(b):has-text(c):has-text(d):has-text(e):has-text(f):has-text(g):has-text(h):has-text(i)",
        ] {
            assert!(parse(bad).is_err(), "{bad} should be rejected");
        }
        // Compound CSS glued to an operator is not supported.
        assert!(matches!(
            parse("div:upward(2).x"),
            Err(ParseError::Unsupported(_))
        ));
        // Unsupported operators are not claimed by this module: they are not
        // recognised here, and the selector validator rejects them.
        assert_eq!(parse("div:style(color: red)").unwrap(), None);
        assert!(validate_selector("div:style(color: red)").is_err());
        assert_eq!(parse("div:matches-attr(x)").unwrap(), None);
    }

    #[test]
    fn regex_safety() {
        for bad in [
            "(a+)+",
            "(a*)*",
            "(a|b)*",
            "(a|aa)+$",
            "(\\d+)+",
            "(a?)+",
            "(a)\\1",
            "(?=a)b",
            "(?<!a)b",
            "(?<name>a)",
            "(?i)a",
            "a*a*a*a*a*b",
            ".*.*.*=x",
            "a+.*b",
            "a{2,}b*",
            &"a".repeat(MAX_REGEX + 1),
            "[",
            "",
        ] {
            assert!(
                validate_regex(bad, "").is_err(),
                "{bad:?} should be rejected"
            );
        }
        for good in [
            "Sponsored",
            "^Ad[sv]?$",
            "promoted|sponsored",
            "(?:foo|bar)",
            "(foo|bar)",
            "\\d{3}-\\d{4}",
            "[a-z]+ [0-9]{1,4}",
            "[*+]+x",
            "a.*b",
        ] {
            assert!(
                validate_regex(good, "i").is_ok(),
                "{good:?} should be accepted"
            );
        }
        assert!(validate_regex("a", "g").is_err()); // `g` is not allowed
        assert!(validate_regex("a", "ii").is_err());
        assert!(validate_regex("a", "ims").is_ok());
        // Through the parser too.
        assert!(parse("div:has-text(/(a+)+/)").is_err());
    }

    #[test]
    fn hostile_text_is_data_not_code() {
        // Selector-looking text in arguments stays an argument.
        let p = ok("div:has-text(}body{display:none)");
        assert!(
            matches!(&p.steps[0], Step::HasText { text } if text.pattern == "}body{display:none")
        );
        // Control characters are rejected.
        assert!(parse("div:has-text(a\u{7}b)").is_err());
        // Base and scope selectors are validated like any other selector.
        assert!(parse("div{x:y}:has-text(a)").is_err());
        assert!(parse("div:has-text(a) > a;color:red").is_err());
    }

    #[test]
    fn json_shape_is_stable() {
        let p = ok(".card:has-text(/ad/i):upward(2)");
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["base"], ".card");
        assert_eq!(json["steps"][0]["op"], "has-text");
        assert_eq!(json["steps"][0]["text"]["regex"], true);
        assert_eq!(json["steps"][0]["text"]["flags"], "i");
        assert_eq!(json["steps"][1]["op"], "upward");
        assert_eq!(json["steps"][1]["levels"], 2);
        assert!(json.get("remove").is_none());
        assert!(json.get("source").is_none());
        let back: Procedural = serde_json::from_value(json).unwrap();
        assert_eq!(back.steps, p.steps);
    }
}
