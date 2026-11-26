//! Cosmetic filters (`example.com##.ad`) and scriptlet filters
//! (`example.com##+js(json-prune, adPlacements)`).
//!
//! Security model: selectors are only ever inserted into a stylesheet as
//! `selector { display: none !important; }`, so they are validated to make
//! sure they cannot escape that rule. Scriptlets are referenced *by name*:
//! the implementations ship with the browser extension and filter lists can
//! only supply string arguments. No code from a filter list is executed.

use crate::ParseError;
use crate::domain::DomainConstraint;
use crate::procedural::{self, Procedural};

/// The scriptlets implemented by the browser extension. Filter lists may only
/// reference these names (or their aliases).
pub const SCRIPTLETS: &[(&str, &[&str])] = &[
    ("set-constant", &["set"]),
    ("json-prune", &[]),
    ("json-prune-fetch-response", &["jpfr"]),
    ("json-prune-xhr-response", &["jpxr"]),
    ("abort-on-property-read", &["aopr"]),
    ("abort-on-property-write", &["aopw"]),
    (
        "abort-current-script",
        &["acs", "abort-current-inline-script", "acis"],
    ),
    ("remove-attr", &["ra"]),
    ("remove-class", &["rc"]),
    ("no-setTimeout-if", &["nostif", "prevent-setTimeout"]),
    ("no-setInterval-if", &["nosiif", "prevent-setInterval"]),
    ("no-fetch-if", &["prevent-fetch"]),
];

const MAX_SELECTOR_LEN: usize = 4096;
const MAX_SCRIPTLET_ARGS: usize = 12;
const MAX_SCRIPTLET_ARG_LEN: usize = 2048;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CosmeticAction {
    /// Hide elements matching a CSS selector.
    Hide(String),
    /// Run a named, built-in scriptlet with string arguments. An exception
    /// with an empty name disables all scriptlets for the matching sites.
    Scriptlet { name: String, args: Vec<String> },
    /// A selector that needs the extension to evaluate it in the page
    /// (`:has-text()` and friends). Always site-specific.
    Procedural(Procedural),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CosmeticFilter {
    pub raw: Box<str>,
    pub exception: bool,
    pub domains: DomainConstraint,
    pub action: CosmeticAction,
}

/// Returns the separator if the line is a cosmetic/HTML/scriptlet filter.
pub fn find_cosmetic_separator(line: &str) -> Option<(usize, &'static str)> {
    const SEPARATORS: &[&str] = &[
        "#@?#", "#@$#", "#@%#", "#@#", "#?#", "#$#", "#%#", "##", "$@$", "$$",
    ];
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'#' && b != b'$' {
            continue;
        }
        for sep in SEPARATORS {
            if line[i..].starts_with(sep) {
                // `$$`/`$@$` (AdGuard HTML filtering) only counts when the
                // prefix is a hostname list; otherwise it's a network filter
                // option separator.
                if sep.starts_with('$') && line[..i].contains(['/', '|', '^', '*']) {
                    continue;
                }
                return Some((i, sep));
            }
        }
    }
    None
}

impl CosmeticFilter {
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let raw = line.trim();
        let (idx, sep) =
            find_cosmetic_separator(raw).ok_or(ParseError::Invalid("not a cosmetic filter"))?;
        let domains_part = &raw[..idx];
        let body = raw[idx + sep.len()..].trim();

        let exception = sep.contains('@');
        match sep {
            "##" | "#@#" | "#?#" | "#@?#" => {}
            // `#%#` is AdGuard's arbitrary-JavaScript syntax: never supported.
            "#%#" | "#@%#" => return Err(ParseError::Unsupported("arbitrary JavaScript filter")),
            // `#$#` injects arbitrary CSS declarations; `$$` is HTML filtering.
            _ => return Err(ParseError::Unsupported("CSS injection / HTML filtering")),
        }

        let domains = DomainConstraint::parse(domains_part, ',')
            .ok_or(ParseError::Invalid("invalid hostname in cosmetic filter"))?;

        if body.starts_with('^') {
            return Err(ParseError::Unsupported("HTML filtering"));
        }

        let action = if let Some(inner) = body.strip_prefix("+js(") {
            let inner = inner
                .strip_suffix(')')
                .ok_or(ParseError::Invalid("unterminated +js("))?;
            parse_scriptlet(inner, exception)?
        } else if let Some(rule) = procedural::parse(body)? {
            if domains.include.is_empty() && !exception {
                // Evaluating a procedural selector means walking the page, so
                // it is only run on the sites it is scoped to.
                return Err(ParseError::Unsupported(
                    "generic procedural cosmetic filter",
                ));
            }
            CosmeticAction::Procedural(rule)
        } else {
            validate_selector(body)?;
            CosmeticAction::Hide(body.to_string())
        };

        if let CosmeticAction::Scriptlet { .. } = action
            && domains.include.is_empty()
            && !exception
        {
            // uBlock Origin only runs scriptlets on sites they are scoped to;
            // generic scriptlets would run in every page.
            return Err(ParseError::Unsupported("generic scriptlet"));
        }

        Ok(CosmeticFilter {
            raw: raw.into(),
            exception,
            domains,
            action,
        })
    }
}

/// Splits scriptlet arguments on unescaped commas.
fn split_args(input: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' if chars.peek() == Some(&',') => {
                current.push(',');
                chars.next();
            }
            ',' => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(c),
        }
    }
    args.push(current.trim().to_string());
    // Strip matching quotes around arguments, as uBO allows.
    args.into_iter()
        .map(|a| {
            for q in ['"', '\''] {
                if a.len() >= 2 && a.starts_with(q) && a.ends_with(q) {
                    return a[1..a.len() - 1].to_string();
                }
            }
            a
        })
        .collect()
}

/// Resolves a scriptlet name or alias (with or without `.js`) to its
/// canonical name.
pub fn canonical_scriptlet(name: &str) -> Option<&'static str> {
    let name = name.trim();
    let name = name.strip_prefix("ubo-").unwrap_or(name);
    let name = name.strip_suffix(".js").unwrap_or(name);
    SCRIPTLETS
        .iter()
        .find(|(canonical, aliases)| *canonical == name || aliases.contains(&name))
        .map(|(canonical, _)| *canonical)
}

fn parse_scriptlet(inner: &str, exception: bool) -> Result<CosmeticAction, ParseError> {
    if inner.trim().is_empty() {
        return if exception {
            Ok(CosmeticAction::Scriptlet {
                name: String::new(),
                args: Vec::new(),
            })
        } else {
            Err(ParseError::Invalid("empty scriptlet"))
        };
    }
    let mut args = split_args(inner);
    let name = args.remove(0);
    let name = canonical_scriptlet(&name).ok_or(ParseError::Unsupported("unknown scriptlet"))?;
    if args.len() > MAX_SCRIPTLET_ARGS || args.iter().any(|a| a.len() > MAX_SCRIPTLET_ARG_LEN) {
        return Err(ParseError::Invalid("scriptlet arguments too large"));
    }
    if args.iter().any(|a| a.chars().any(|c| c.is_control())) {
        return Err(ParseError::Invalid(
            "control characters in scriptlet argument",
        ));
    }
    // Drop trailing empty arguments so equivalent filters compare equal.
    while args.last().is_some_and(String::is_empty) {
        args.pop();
    }
    Ok(CosmeticAction::Scriptlet {
        name: name.to_string(),
        args,
    })
}

/// Pseudo-classes that are uBlock/AdGuard extensions rather than CSS. They
/// would need a JavaScript engine to evaluate ("procedural" filters).
const PROCEDURAL: &[&str] = &[
    ":has-text(",
    ":-abp-",
    ":contains(",
    ":xpath(",
    ":upward(",
    ":remove(",
    ":style(",
    ":matches-css",
    ":min-text-length(",
    ":watch-attr(",
    ":matches-path(",
    ":matches-attr(",
    ":matches-prop(",
    ":others(",
    ":if(",
    ":if-not(",
    ":nth-ancestor(",
    ":matches-media(",
    ":remove-attr(",
    ":remove-class(",
    ":shadow-dom",
    ":spath(",
];

/// Validates that a selector is safe to place into
/// `selector { display: none !important; }`.
pub fn validate_selector(selector: &str) -> Result<(), ParseError> {
    if selector.is_empty() {
        return Err(ParseError::Invalid("empty selector"));
    }
    if selector.len() > MAX_SELECTOR_LEN {
        return Err(ParseError::Invalid("selector too long"));
    }
    if selector.starts_with('@') || selector.contains("/*") || selector.contains("*/") {
        return Err(ParseError::Invalid("selector contains CSS syntax"));
    }
    if selector.chars().any(|c| c.is_control()) {
        return Err(ParseError::Invalid("control characters in selector"));
    }
    let lower = selector.to_ascii_lowercase();
    if PROCEDURAL.iter().any(|p| lower.contains(p)) {
        return Err(ParseError::Unsupported("procedural cosmetic filter"));
    }

    // Structural scan: braces and semicolons are only acceptable inside
    // quoted strings; brackets and parentheses must balance.
    let mut quote: Option<char> = None;
    let mut depth_paren = 0i32;
    let mut depth_bracket = 0i32;
    let mut chars = selector.chars();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            match c {
                '\\' => {
                    chars.next();
                }
                c if c == q => quote = None,
                // Even quoted, a brace could close the rule in lenient parsers.
                '{' | '}' => return Err(ParseError::Invalid("brace in selector")),
                _ => {}
            }
            continue;
        }
        match c {
            '\\' => {
                chars.next();
            }
            '"' | '\'' => quote = Some(c),
            '(' => depth_paren += 1,
            ')' => depth_paren -= 1,
            '[' => depth_bracket += 1,
            ']' => depth_bracket -= 1,
            '{' | '}' | ';' => return Err(ParseError::Invalid("CSS syntax in selector")),
            _ => {}
        }
        if depth_paren < 0 || depth_bracket < 0 {
            return Err(ParseError::Invalid("unbalanced selector"));
        }
    }
    if quote.is_some() || depth_paren != 0 || depth_bracket != 0 {
        return Err(ParseError::Invalid("unbalanced selector"));
    }
    Ok(())
}

/// For generic selectors, returns the class or id that must be present in
/// the page for the selector to possibly match: `.ad-box > img` → class
/// `ad-box`. Used to index generic filters so pages only receive relevant
/// selectors.
pub fn selector_key(selector: &str) -> Option<SelectorKey<'_>> {
    let (kind, rest) = match selector.as_bytes().first()? {
        b'.' => (SelectorKind::Class, &selector[1..]),
        b'#' => (SelectorKind::Id, &selector[1..]),
        _ => return None,
    };
    if selector.contains(',') {
        return None;
    }
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
        .unwrap_or(rest.len());
    if end == 0 {
        return None;
    }
    // An escape sequence means the identifier continues in a form we would
    // have to decode; treat as complex instead.
    if rest[end..].starts_with('\\') {
        return None;
    }
    Some(SelectorKey {
        kind,
        name: &rest[..end],
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SelectorKind {
    Class,
    Id,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectorKey<'a> {
    pub kind: SelectorKind,
    pub name: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hide_filters() {
        let f = CosmeticFilter::parse("example.com,~sub.example.com##.ad-banner").unwrap();
        assert!(!f.exception);
        assert_eq!(f.action, CosmeticAction::Hide(".ad-banner".into()));
        assert!(f.domains.matches(Some("example.com")));
        assert!(!f.domains.matches(Some("sub.example.com")));

        let f = CosmeticFilter::parse("##div[id^=\"ad-\"]").unwrap();
        assert!(f.domains.include.is_empty());

        let f = CosmeticFilter::parse("example.com#@#.ad").unwrap();
        assert!(f.exception);

        // Standard CSS in #?# is accepted.
        let f = CosmeticFilter::parse("example.com#?#div:has(> .sponsored)").unwrap();
        assert_eq!(
            f.action,
            CosmeticAction::Hide("div:has(> .sponsored)".into())
        );
    }

    #[test]
    fn rejects_unsafe_selectors() {
        for bad in [
            "##div{background:url(//evil)}",
            "##a}body{display:none",
            "##div;color:red",
            "##@import url(x)",
            "##div[a=\"}\"]",
            "##div(",
            "##/* x */",
            "##",
        ] {
            assert!(CosmeticFilter::parse(bad).is_err(), "{bad}");
        }
        // Operators that stay unsupported.
        for unsupported in [
            "example.com##div:style(color: red)",
            "example.com##div:matches-attr(x)",
            "example.com##div:if(.a)",
            "example.com##div:min-text-length(10)",
            "example.com##div:has(:has-text(x))",
        ] {
            assert!(
                matches!(
                    CosmeticFilter::parse(unsupported),
                    Err(ParseError::Unsupported(_))
                ),
                "{unsupported}"
            );
        }
        // Procedural filters are site-specific only.
        assert!(matches!(
            CosmeticFilter::parse("##div:has-text(Sponsored)"),
            Err(ParseError::Unsupported(_))
        ));
        assert!(matches!(
            CosmeticFilter::parse("example.com#%#alert(1)"),
            Err(ParseError::Unsupported(_))
        ));
        assert!(matches!(
            CosmeticFilter::parse("example.com#$#body{x:y}"),
            Err(ParseError::Unsupported(_))
        ));
        assert!(matches!(
            CosmeticFilter::parse("example.com##^script"),
            Err(ParseError::Unsupported(_))
        ));
    }

    #[test]
    fn procedural_filters() {
        let f = CosmeticFilter::parse("example.com##.card:has-text(Sponsored)").unwrap();
        assert!(
            matches!(&f.action, CosmeticAction::Procedural(p) if p.base == ".card" && !p.remove)
        );
        assert!(!f.exception);
        let f = CosmeticFilter::parse("example.com#?#.row:has-text(/ad/i):upward(2)").unwrap();
        assert!(matches!(f.action, CosmeticAction::Procedural(_)));
        // Exceptions for procedural filters parse, even without a domain.
        let f = CosmeticFilter::parse("#@#.card:has-text(Sponsored)").unwrap();
        assert!(f.exception && matches!(f.action, CosmeticAction::Procedural(_)));
        // Unsafe arguments and selectors are still refused.
        assert!(CosmeticFilter::parse("example.com##.a:has-text(/(x+)+/)").is_err());
        assert!(CosmeticFilter::parse("example.com##.a{b}:has-text(x)").is_err());
    }

    #[test]
    fn scriptlets() {
        let f = CosmeticFilter::parse(
            "youtube.com##+js(json-prune, playerResponse.adPlacements adSlots)",
        )
        .unwrap();
        assert_eq!(
            f.action,
            CosmeticAction::Scriptlet {
                name: "json-prune".into(),
                args: vec!["playerResponse.adPlacements adSlots".into()]
            }
        );
        let f = CosmeticFilter::parse("x.com##+js(set.js, a.b, true)").unwrap();
        assert!(
            matches!(f.action, CosmeticAction::Scriptlet { ref name, .. } if name == "set-constant")
        );
        let f = CosmeticFilter::parse(r"x.com##+js(nostif, a\,b, 100)").unwrap();
        assert!(matches!(f.action, CosmeticAction::Scriptlet { ref args, .. } if args[0] == "a,b"));
        assert!(matches!(
            CosmeticFilter::parse("x.com##+js(evil-unknown)"),
            Err(ParseError::Unsupported(_))
        ));
        assert!(matches!(
            CosmeticFilter::parse("##+js(set, a, 1)"),
            Err(ParseError::Unsupported(_))
        ));
        let f = CosmeticFilter::parse("x.com#@#+js()").unwrap();
        assert!(f.exception);
    }

    #[test]
    fn keys() {
        assert_eq!(selector_key(".ad-box > img").unwrap().name, "ad-box");
        assert_eq!(selector_key("#banner").unwrap().kind, SelectorKind::Id);
        assert!(selector_key("div.ad").is_none());
        assert!(selector_key(".a, .b").is_none());
        assert!(selector_key("[id^=ad]").is_none());
    }

    #[test]
    fn separators() {
        assert_eq!(find_cosmetic_separator("a.com##.x").unwrap().1, "##");
        assert_eq!(find_cosmetic_separator("a.com#@#.x").unwrap().1, "#@#");
        assert!(find_cosmetic_separator("||a.com^$domain=b.com").is_none());
        assert!(find_cosmetic_separator("||a.com/$$x").is_none());
    }
}
