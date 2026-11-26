//! Network (URL) filters: `||ads.example.com^$third-party,script`.

use crate::ParseError;
use crate::domain::{DomainConstraint, normalize_hostname};
use crate::request::{Request, ResourceType, ResourceTypes};
use regex::{Regex, RegexBuilder};

/// Where the pattern is anchored at its start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// Pattern may match anywhere in the URL.
    None,
    /// `|pattern` — must match at the start of the URL.
    Left,
    /// `||pattern` — must match at the start of the hostname or of one of its
    /// labels.
    Hostname,
}

/// Party restriction (`$third-party` / `$first-party`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    First,
    Third,
}

/// Cosmetic-filtering exceptions expressed as network exception filters
/// (`@@||example.com^$elemhide`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CosmeticExceptions {
    pub elemhide: bool,
    pub generichide: bool,
    pub specifichide: bool,
}

impl CosmeticExceptions {
    pub fn any(&self) -> bool {
        self.elemhide || self.generichide || self.specifichide
    }
}

/// A parsed network filter.
#[derive(Debug, Clone)]
pub struct NetworkFilter {
    /// The original rule text (trimmed).
    pub raw: Box<str>,
    pub exception: bool,
    pub important: bool,
    pub anchor: Anchor,
    pub end_anchor: bool,
    /// Pattern without anchors. Lowercase unless `match_case`. May contain
    /// the `*` wildcard and the `^` separator placeholder.
    pub pattern: Box<str>,
    pub regex: Option<Regex>,
    pub match_case: bool,
    pub types: ResourceTypes,
    /// Whether the filter listed resource types explicitly.
    pub explicit_types: bool,
    pub party: Option<Party>,
    pub domains: Option<Box<DomainConstraint>>,
    pub cosmetic: CosmeticExceptions,
    pub badfilter: bool,
    /// `$removeparam=name`: instead of blocking, strip this query parameter
    /// from matching requests.
    pub removeparam: Option<Box<str>>,
    /// `$redirect=name`: block the request and serve this packaged resource
    /// (file name under `resources/`) instead.
    pub redirect: Option<&'static str>,
}

/// Size limit for compiled regex filters; keeps hostile lists from consuming
/// unbounded memory. The `regex` crate guarantees linear-time matching, so
/// there is no catastrophic backtracking risk.
const REGEX_SIZE_LIMIT: usize = 256 * 1024;

impl NetworkFilter {
    /// Parses a network filter line. The caller has already excluded
    /// comments and cosmetic filters.
    pub fn parse(line: &str) -> Result<Self, ParseError> {
        let raw = line.trim();
        let (exception, body) = match raw.strip_prefix("@@") {
            Some(rest) => (true, rest),
            None => (false, raw),
        };

        let (pattern_part, options_part) = split_options(body);

        let mut filter = NetworkFilter {
            raw: raw.into(),
            exception,
            important: false,
            anchor: Anchor::None,
            end_anchor: false,
            pattern: "".into(),
            regex: None,
            match_case: false,
            types: ResourceTypes::DEFAULT,
            explicit_types: false,
            party: None,
            domains: None,
            cosmetic: CosmeticExceptions::default(),
            badfilter: false,
            removeparam: None,
            redirect: None,
        };

        if let Some(options) = options_part {
            filter.parse_options(options)?;
        }

        // Regular expression filters: /.../
        if pattern_part.len() > 2 && pattern_part.starts_with('/') && pattern_part.ends_with('/') {
            let source = &pattern_part[1..pattern_part.len() - 1];
            let regex = RegexBuilder::new(source)
                .case_insensitive(!filter.match_case)
                .size_limit(REGEX_SIZE_LIMIT)
                .build()
                .map_err(|_| ParseError::Invalid("invalid regular expression"))?;
            filter.regex = Some(regex);
            filter.pattern = pattern_part.into();
            return filter.finish();
        }

        let mut pattern = pattern_part;
        if let Some(rest) = pattern.strip_prefix("||") {
            filter.anchor = Anchor::Hostname;
            pattern = rest;
        } else if let Some(rest) = pattern.strip_prefix('|') {
            filter.anchor = Anchor::Left;
            pattern = rest;
        }
        if let Some(rest) = pattern.strip_suffix('|') {
            filter.end_anchor = true;
            pattern = rest;
        }
        // Leading/trailing wildcards are redundant unless anchored.
        if filter.anchor == Anchor::None {
            pattern = pattern.trim_start_matches('*');
        }
        if !filter.end_anchor {
            pattern = pattern.trim_end_matches('*');
        }
        // `||*.example.com^` is a common way of writing `||example.com^`.
        if filter.anchor == Anchor::Hostname
            && let Some(rest) = pattern.strip_prefix("*.")
        {
            pattern = rest;
        }
        if pattern.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ParseError::Invalid("whitespace in pattern"));
        }
        filter.pattern = if filter.match_case {
            pattern.into()
        } else {
            pattern.to_ascii_lowercase().into()
        };
        filter.finish()
    }

    fn finish(self) -> Result<Self, ParseError> {
        let matches_everything = self.regex.is_none() && self.pattern.is_empty();
        if matches_everything
            && !self.exception
            && self.domains.is_none()
            && !self.badfilter
            && self.removeparam.is_none()
        {
            // A bare `*` (optionally with type/party options) would block
            // broad swaths of the web; refuse it rather than trust the list.
            return Err(ParseError::Invalid("filter matches every URL"));
        }
        if self.types == ResourceTypes::NONE && !self.cosmetic.any() {
            return Err(ParseError::Invalid("filter matches no resource type"));
        }
        Ok(self)
    }

    fn parse_options(&mut self, options: &str) -> Result<(), ParseError> {
        let mut include_types = ResourceTypes::NONE;
        let mut exclude_types = ResourceTypes::NONE;
        let mut cosmetic_only = true;

        for option in options.split(',') {
            let option = option.trim();
            if option.is_empty() {
                continue;
            }
            let (negated, name) = match option.strip_prefix('~') {
                Some(n) => (true, n),
                None => (false, option),
            };
            let (key, value) = match name.split_once('=') {
                Some((k, v)) => (k, Some(v)),
                None => (name, None),
            };
            let key_lower = key.to_ascii_lowercase();

            if let Some(t) = ResourceType::from_option(&key_lower) {
                if value.is_some() {
                    return Err(ParseError::Unsupported("resource type with value"));
                }
                if negated {
                    exclude_types.0 |= t.bit();
                } else {
                    include_types.0 |= t.bit();
                }
                cosmetic_only = false;
                continue;
            }

            match (key_lower.as_str(), value, negated) {
                ("third-party" | "3p", None, false) | ("first-party" | "1p", None, true) => {
                    self.party = Some(Party::Third);
                    cosmetic_only = false;
                }
                ("first-party" | "1p", None, false) | ("third-party" | "3p", None, true) => {
                    self.party = Some(Party::First);
                    cosmetic_only = false;
                }
                ("domain" | "from", Some(v), false) => {
                    if v.starts_with('/') {
                        return Err(ParseError::Unsupported("regex domain option"));
                    }
                    let constraint = DomainConstraint::parse(v, '|')
                        .ok_or(ParseError::Invalid("invalid domain option"))?;
                    if !constraint.is_empty() {
                        self.domains = Some(Box::new(constraint));
                    }
                    cosmetic_only = false;
                }
                ("removeparam" | "queryprune", Some(v), false)
                    if !self.exception && valid_param_name(v) =>
                {
                    self.removeparam = Some(v.into());
                    cosmetic_only = false;
                }
                ("redirect", Some(v), false) if !self.exception => {
                    self.redirect = Some(
                        crate::resources::lookup(v)
                            .ok_or(ParseError::Unsupported("unknown redirect resource"))?,
                    );
                    cosmetic_only = false;
                }
                ("match-case", None, false) => self.match_case = true,
                ("important", None, false) => self.important = true,
                ("badfilter", None, false) => self.badfilter = true,
                ("all", None, false) => {
                    include_types = ResourceTypes::ALL;
                    cosmetic_only = false;
                }
                ("elemhide" | "ehide", None, false) if self.exception => {
                    self.cosmetic.elemhide = true
                }
                ("generichide" | "ghide", None, false) if self.exception => {
                    self.cosmetic.generichide = true
                }
                ("specifichide" | "shide", None, false) if self.exception => {
                    self.cosmetic.specifichide = true
                }
                // Options that would require rewriting responses, redirecting
                // to local resources, header access or popup handling. Rather
                // than approximating them (and risking site breakage), the
                // whole filter is skipped.
                _ => return Err(ParseError::Unsupported("unsupported filter option")),
            }
        }

        if self.removeparam.is_some() && include_types == ResourceTypes::NONE {
            // Tracking parameters mostly ride on navigations, so unlike
            // blocking filters the default includes `document`.
            include_types = ResourceTypes(ResourceTypes::ALL.0 & !ResourceType::Websocket.bit());
        }
        if self.redirect.is_some() {
            // Replacing a page with a stub would break navigation.
            include_types = ResourceTypes(include_types.0 & !ResourceType::Document.bit());
        }
        if include_types != ResourceTypes::NONE {
            self.types = include_types;
            self.explicit_types = true;
        } else if self.cosmetic.any() && cosmetic_only {
            // `@@||example.com^$elemhide` only affects cosmetic filtering.
            self.types = ResourceTypes::NONE;
            self.explicit_types = true;
        }
        if exclude_types != ResourceTypes::NONE {
            if include_types == ResourceTypes::NONE {
                self.types = ResourceTypes::DEFAULT;
            }
            self.types = ResourceTypes(self.types.0 & !exclude_types.0);
            self.explicit_types = true;
        }
        Ok(())
    }

    /// If this filter blocks (or allows) an entire hostname and nothing more,
    /// returns that hostname. Such filters can be enforced at the DNS level.
    pub fn whole_hostname(&self) -> Option<&str> {
        if self.anchor != Anchor::Hostname
            || self.regex.is_some()
            || self.badfilter
            || self.removeparam.is_some()
            || self.redirect.is_some()
        {
            return None;
        }
        if self.party.is_some() || self.domains.is_some() || self.cosmetic.any() {
            return None;
        }
        // `@@…$document` only stops filtering on that site's pages; it must
        // not unblock the host (and its subdomains) everywhere.
        if self.exception && self.types == ResourceTypes(ResourceType::Document.bit()) {
            return None;
        }
        // Type-restricted filters do not apply to whole hosts, except the
        // "everything" forms (`$all`, `$document`, or the default set).
        if self.explicit_types
            && self.types != ResourceTypes::ALL
            && self.types != ResourceTypes(ResourceType::Document.bit())
        {
            return None;
        }
        let host = if let Some(h) = self.pattern.strip_suffix('^') {
            h
        } else if self.end_anchor {
            &self.pattern
        } else {
            return None;
        };
        // Must be a complete, valid hostname without wildcards.
        if host.contains(['*', '^', '/']) {
            return None;
        }
        normalize_hostname(host).filter(|n| n == host).map(|_| host)
    }

    /// Hostname-anchored filters whose host part contains a wildcard
    /// (`||ad*.example.com^`). Returned so the DNS layer can evaluate them.
    pub fn wildcard_hostname(&self) -> Option<&str> {
        if self.anchor != Anchor::Hostname
            || self.regex.is_some()
            || self.badfilter
            || self.removeparam.is_some()
            || self.redirect.is_some()
        {
            return None;
        }
        if self.party.is_some()
            || self.domains.is_some()
            || self.explicit_types
            || self.cosmetic.any()
        {
            return None;
        }
        let host = self.pattern.strip_suffix('^')?;
        if host.contains('*') && !host.contains(['/', '^']) && host.contains('.') && host.len() > 3
        {
            Some(host)
        } else {
            None
        }
    }

    /// Checks the URL pattern only (no options).
    pub fn matches_pattern(&self, req: &Request) -> bool {
        let url = if self.match_case {
            &req.url
        } else {
            &req.url_lower
        };
        if let Some(re) = &self.regex {
            return re.is_match(url);
        }
        glob_match(
            self.pattern.as_bytes(),
            url.as_bytes(),
            self.anchor,
            self.end_anchor,
            req.host_range,
        )
    }

    /// Checks resource type, party and domain options.
    pub fn matches_options(&self, req: &Request) -> bool {
        if !self.types.contains(req.resource_type) {
            return false;
        }
        match self.party {
            Some(Party::Third) if !req.third_party => return false,
            Some(Party::First) if req.third_party => return false,
            _ => {}
        }
        if let Some(domains) = &self.domains {
            // For top-level documents, `domain=` refers to the document itself.
            let context = if req.resource_type == ResourceType::Document {
                Some(req.hostname.as_str())
            } else {
                req.source_hostname.as_deref()
            };
            if !domains.matches(context) {
                return false;
            }
        }
        true
    }

    pub fn matches(&self, req: &Request) -> bool {
        self.matches_options(req) && self.matches_pattern(req)
    }

    /// The rule text with any `badfilter` option removed, used to pair
    /// `$badfilter` rules with the rules they disable.
    pub fn badfilter_key(&self) -> String {
        let raw: &str = &self.raw;
        let Some((pattern, options)) = split_raw_options(raw) else {
            return raw.to_string();
        };
        let kept: Vec<&str> = options
            .split(',')
            .map(str::trim)
            .filter(|o| !o.eq_ignore_ascii_case("badfilter") && !o.is_empty())
            .collect();
        if kept.is_empty() {
            pattern.to_string()
        } else {
            format!("{pattern}${}", kept.join(","))
        }
    }
}

/// Literal query-parameter names only; regex forms (`/re/`) are skipped
/// rather than approximated.
fn valid_param_name(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b'[' | b']')
        })
}

fn split_raw_options(raw: &str) -> Option<(&str, &str)> {
    let (prefix, body) = match raw.strip_prefix("@@") {
        Some(b) => ("@@", b),
        None => ("", raw),
    };
    let (pattern, options) = split_options(body);
    let options = options?;
    Some((&raw[..prefix.len() + pattern.len()], options))
}

/// Splits `pattern$options`. A `$` inside a regex filter (`/a$/`) is not an
/// option separator.
fn split_options(body: &str) -> (&str, Option<&str>) {
    if body.len() > 2 && body.starts_with('/') {
        if body.ends_with('/') {
            return (body, None); // regex filter without options
        }
        if let Some(idx) = body.rfind("/$")
            && idx > 0
            && looks_like_options(&body[idx + 2..])
        {
            return (&body[..idx + 1], Some(&body[idx + 2..]));
        }
    }
    match body.rfind('$') {
        Some(idx) if looks_like_options(&body[idx + 1..]) => (&body[..idx], Some(&body[idx + 1..])),
        _ => (body, None),
    }
}

/// An options block is a comma-separated list whose keys look like option
/// names (`~third-party`, `domain=...`, `3p`).
fn looks_like_options(s: &str) -> bool {
    !s.is_empty()
        && s.split(',').all(|opt| {
            let key = opt.split_once('=').map_or(opt, |(k, _)| k);
            let key = key.strip_prefix('~').unwrap_or(key);
            !key.is_empty()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

#[inline]
fn is_separator(c: u8) -> bool {
    !(c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b'%'))
}

/// Matches one `*`-free segment at `pos`; returns the end position.
#[inline]
fn match_segment_at(seg: &[u8], url: &[u8], pos: usize) -> Option<usize> {
    let mut i = pos;
    for &c in seg {
        if c == b'^' {
            if i == url.len() {
                continue; // `^` also matches the end of the URL
            }
            if is_separator(url[i]) {
                i += 1;
            } else {
                return None;
            }
        } else if i < url.len() && url[i] == c {
            i += 1;
        } else {
            return None;
        }
    }
    Some(i)
}

/// Finds the leftmost match of `seg` starting at or after `from`.
fn find_segment(seg: &[u8], url: &[u8], from: usize) -> Option<usize> {
    if seg.is_empty() {
        return Some(from);
    }
    let first = seg[0];
    let mut start = from;
    while start <= url.len() {
        if first != b'^' {
            // Fast skip to the next occurrence of the first literal byte.
            {
                let off = url[start..].iter().position(|&c| c == first)?;
                start += off
            }
        }
        if let Some(end) = match_segment_at(seg, url, start) {
            return Some(end);
        }
        start += 1;
    }
    None
}

fn match_rest(segs: &[&[u8]], url: &[u8], mut pos: usize, end_anchor: bool) -> bool {
    let Some((last, middle)) = segs.split_last() else {
        return !end_anchor || pos == url.len();
    };
    for seg in middle {
        match find_segment(seg, url, pos) {
            Some(end) => pos = end,
            None => return false,
        }
    }
    if end_anchor {
        (pos..=url.len())
            .rev()
            .any(|s| match_segment_at(last, url, s) == Some(url.len()))
    } else {
        find_segment(last, url, pos).is_some()
    }
}

/// Matches an Adblock-style pattern (`*` wildcard, `^` separator) against a
/// URL. All inputs are bytes; filter patterns and URLs are ASCII in practice
/// and non-ASCII bytes simply compare literally.
pub(crate) fn glob_match(
    pattern: &[u8],
    url: &[u8],
    anchor: Anchor,
    end_anchor: bool,
    host_range: (usize, usize),
) -> bool {
    let segs: Vec<&[u8]> = pattern.split(|&b| b == b'*').collect();
    let (first, rest) = segs
        .split_first()
        .expect("split yields at least one segment");

    let try_start = |start: usize| -> bool {
        match match_segment_at(first, url, start) {
            Some(end) => match_rest(rest, url, end, end_anchor),
            None => false,
        }
    };

    match anchor {
        Anchor::Left => try_start(0),
        Anchor::Hostname => {
            let (hs, he) = host_range;
            if try_start(hs) {
                return true;
            }
            (hs + 1..he).any(|i| url[i - 1] == b'.' && try_start(i))
        }
        Anchor::None => {
            if rest.is_empty() && !end_anchor {
                return find_segment(first, url, 0).is_some();
            }
            (0..=url.len()).any(try_start)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(url: &str) -> Request {
        Request::new(url, Some("https://site.example/"), ResourceType::Script).unwrap()
    }

    fn m(filter: &str, url: &str) -> bool {
        NetworkFilter::parse(filter).unwrap().matches(&req(url))
    }

    #[test]
    fn hostname_anchor() {
        assert!(m("||ads.com^", "https://ads.com/x.js"));
        assert!(m("||ads.com^", "https://sub.ads.com/x.js"));
        assert!(m("||ads.com^", "https://ads.com"));
        assert!(!m("||ads.com^", "https://badads.com/x.js"));
        assert!(!m("||ads.com^", "https://ads.com.evil/x.js"));
        assert!(m("||ads.com/banner", "https://ads.com/banner.png"));
    }

    #[test]
    fn wildcards_and_separators() {
        assert!(m("/banner/*/img^", "http://x.com/banner/foo/img?a"));
        assert!(m("/banner/*/img^", "http://x.com/banner/foo/img"));
        assert!(!m("/banner/*/img^", "http://x.com/banner/foo/imgs"));
        assert!(m("|https://ads.", "https://ads.foo.com/"));
        assert!(!m("|https://ads.", "http://x.com/?https://ads."));
        assert!(m(".swf|", "http://x.com/a.swf"));
        assert!(!m(".swf|", "http://x.com/a.swf?x"));
        assert!(m("ad*.js|", "http://x.com/adfoo.js"));
    }

    #[test]
    fn regex_filters() {
        assert!(m(r"/\/ad[0-9]+\.js/", "http://x.com/ad12.js"));
        assert!(!m(r"/\/ad[0-9]+\.js/", "http://x.com/add.js"));
        let f = NetworkFilter::parse(r"/^https?:\/\/x\.com\/a$/$script").unwrap();
        assert!(f.matches(&req("https://x.com/a")));
    }

    #[test]
    fn options() {
        let f = NetworkFilter::parse("||t.com^$third-party,image").unwrap();
        let img = Request::new(
            "https://t.com/p.gif",
            Some("https://news.com/"),
            ResourceType::Image,
        )
        .unwrap();
        let img_1p = Request::new(
            "https://t.com/p.gif",
            Some("https://www.t.com/"),
            ResourceType::Image,
        )
        .unwrap();
        let script = Request::new(
            "https://t.com/p.js",
            Some("https://news.com/"),
            ResourceType::Script,
        )
        .unwrap();
        assert!(f.matches(&img));
        assert!(!f.matches(&img_1p));
        assert!(!f.matches(&script));

        let f = NetworkFilter::parse("/ads.js$domain=a.com|~b.a.com").unwrap();
        let on_a = Request::new(
            "https://cdn.x/ads.js",
            Some("https://www.a.com/"),
            ResourceType::Script,
        )
        .unwrap();
        let on_b = Request::new(
            "https://cdn.x/ads.js",
            Some("https://b.a.com/"),
            ResourceType::Script,
        )
        .unwrap();
        assert!(f.matches(&on_a));
        assert!(!f.matches(&on_b));

        let f = NetworkFilter::parse("||x.com^$~script").unwrap();
        assert!(!f.matches(&req("https://x.com/a.js")));
    }

    #[test]
    fn whole_hostname_detection() {
        let host = |f: &str| {
            NetworkFilter::parse(f)
                .unwrap()
                .whole_hostname()
                .map(String::from)
        };
        assert_eq!(
            host("||ads.example.com^").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            host("||ads.example.com^$important").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            host("||ads.example.com^$all").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            host("||*.ads.example.com^").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(host("||ads.example.com^$third-party"), None);
        assert_eq!(host("||ads.example.com^$script"), None);
        assert_eq!(host("||ads.example.com/path"), None);
        assert_eq!(host("ads.example.com"), None);
    }

    #[test]
    fn rejects_dangerous_or_unsupported() {
        assert!(matches!(
            NetworkFilter::parse("*"),
            Err(ParseError::Invalid(_))
        ));
        assert!(matches!(
            NetworkFilter::parse("*$third-party"),
            Err(ParseError::Invalid(_))
        ));
        assert!(matches!(
            NetworkFilter::parse("||x.com^$redirect=google-analytics.js"),
            Err(ParseError::Unsupported(_))
        ));
        assert!(matches!(
            NetworkFilter::parse("||x.com^$redirect-rule=noop.js"),
            Err(ParseError::Unsupported(_))
        ));
        assert!(matches!(
            NetworkFilter::parse("@@||x.com^$redirect=noop.js"),
            Err(ParseError::Unsupported(_))
        ));
        assert!(NetworkFilter::parse("||x.com^$csp=script-src 'none'").is_err());
        assert!(NetworkFilter::parse("/[/").is_err());
    }

    #[test]
    fn parses_redirect() {
        let f = NetworkFilter::parse("||x.com/ads.js^$script,redirect=noopjs").unwrap();
        assert_eq!(f.redirect, Some("noop.js"));
        assert!(!f.exception);
        // Not a DNS-level rule: the page needs the stub, not a dead host.
        assert!(f.whole_hostname().is_none());
        let f = NetworkFilter::parse("||x.com^$redirect=1x1.gif").unwrap();
        assert!(f.whole_hostname().is_none());
        assert!(f.wildcard_hostname().is_none());
        assert!(!f.types.contains(ResourceType::Document));
        let f = NetworkFilter::parse("||x.com^$all,redirect=noop.html").unwrap();
        assert!(!f.types.contains(ResourceType::Document));
    }

    #[test]
    fn parses_removeparam() {
        let f = NetworkFilter::parse("$removeparam=utm_source").unwrap();
        assert_eq!(f.removeparam.as_deref(), Some("utm_source"));
        assert!(f.types.contains(ResourceType::Document));
        assert!(f.whole_hostname().is_none());
        let f = NetworkFilter::parse("||x.com^$removeparam=fbclid,image").unwrap();
        assert_eq!(f.removeparam.as_deref(), Some("fbclid"));
        for bad in [
            "$removeparam",
            "$removeparam=/^utm_/",
            "@@||x.com^$removeparam=a",
        ] {
            assert!(
                matches!(NetworkFilter::parse(bad), Err(ParseError::Unsupported(_))),
                "{bad}"
            );
        }
    }

    #[test]
    fn badfilter_key() {
        let f = NetworkFilter::parse("||x.com^$script,badfilter").unwrap();
        assert!(f.badfilter);
        assert_eq!(f.badfilter_key(), "||x.com^$script");
        let f = NetworkFilter::parse("||x.com^$badfilter").unwrap();
        assert_eq!(f.badfilter_key(), "||x.com^");
    }
}
