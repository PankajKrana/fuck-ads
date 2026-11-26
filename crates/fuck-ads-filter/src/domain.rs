//! Hostname helpers shared by the parser and the engine.
//!
//! Everything here operates on ASCII (punycode) hostnames; filter lists and
//! DNS both use the ASCII-compatible encoding, so no IDNA processing is needed.

/// Maximum length of a DNS name in presentation format (RFC 1035).
pub const MAX_HOSTNAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Normalizes a hostname: lowercases it, strips a single trailing dot and
/// validates the character set and label lengths.
///
/// Returns `None` for anything that is not a plausible hostname. Underscores
/// are accepted because they appear in real tracker hostnames.
pub fn normalize_hostname(input: &str) -> Option<String> {
    let host = input.trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > MAX_HOSTNAME_LEN {
        return None;
    }
    let mut out = String::with_capacity(host.len());
    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        for c in label.chars() {
            match c {
                'a'..='z' | '0'..='9' | '-' | '_' => out.push(c),
                'A'..='Z' => out.push(c.to_ascii_lowercase()),
                _ => return None,
            }
        }
    }
    Some(out)
}

/// Returns true if `host` equals `domain` or is a subdomain of it.
pub fn is_same_or_subdomain(host: &str, domain: &str) -> bool {
    if host.len() == domain.len() {
        return host == domain;
    }
    host.len() > domain.len()
        && host.ends_with(domain)
        && host.as_bytes()[host.len() - domain.len() - 1] == b'.'
}

/// Iterates over `host` and each parent domain: `a.b.c` → `a.b.c`, `b.c`, `c`.
pub fn suffixes(host: &str) -> impl Iterator<Item = &str> {
    let mut next = Some(host);
    std::iter::from_fn(move || {
        let current = next?;
        next = current.find('.').map(|i| &current[i + 1..]);
        Some(current)
    })
}

/// Public suffixes made of two labels that are common enough to matter for
/// third-party detection. This is deliberately a heuristic: the browser
/// extensions delegate third-party checks to the browser itself (which uses
/// the full Public Suffix List), so this is only used by the Rust URL matcher.
const MULTI_LABEL_SUFFIXES: &[&str] = &[
    "ac.uk",
    "co.uk",
    "gov.uk",
    "ltd.uk",
    "me.uk",
    "net.uk",
    "org.uk",
    "plc.uk",
    "sch.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "asn.au",
    "id.au",
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.nz",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "go.jp",
    "gr.jp",
    "co.kr",
    "or.kr",
    "ne.kr",
    "go.kr",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "com.hk",
    "net.hk",
    "org.hk",
    "com.tw",
    "net.tw",
    "org.tw",
    "co.in",
    "net.in",
    "org.in",
    "firm.in",
    "gen.in",
    "ind.in",
    "gov.in",
    "com.mx",
    "org.mx",
    "gob.mx",
    "com.ar",
    "com.co",
    "com.pe",
    "com.ve",
    "co.za",
    "org.za",
    "gov.za",
    "com.tr",
    "org.tr",
    "gov.tr",
    "com.sg",
    "edu.sg",
    "gov.sg",
    "com.my",
    "com.ph",
    "com.vn",
    "co.id",
    "or.id",
    "co.th",
    "com.ua",
    "co.il",
    "org.il",
    "com.eg",
    "com.sa",
    "com.pk",
    "com.ng",
    "github.io",
    "gitlab.io",
    "pages.dev",
    "netlify.app",
    "vercel.app",
    "herokuapp.com",
    "blogspot.com",
    "appspot.com",
    "cloudfront.net",
    "azurewebsites.net",
    "workers.dev",
];

/// Approximates the registrable domain ("eTLD+1") of a hostname.
pub fn registrable_domain(host: &str) -> &str {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    let labels: Vec<usize> = host.match_indices('.').map(|(i, _)| i).collect();
    if labels.is_empty() {
        return host;
    }
    // Candidate suffix made of the last two labels.
    let last_two = if labels.len() >= 2 {
        &host[labels[labels.len() - 2] + 1..]
    } else {
        host
    };
    let suffix_labels = if MULTI_LABEL_SUFFIXES.contains(&last_two) {
        2
    } else {
        1
    };
    if labels.len() < suffix_labels {
        return host;
    }
    if labels.len() == suffix_labels {
        return host;
    }
    &host[labels[labels.len() - suffix_labels - 1] + 1..]
}

/// Matches an "entity" hostname pattern such as `google.*`, which uBlock
/// Origin defines as "google followed by any public suffix". We accept the
/// pattern when some suffix of `host` starts with `entity.` and the remainder
/// is a plausible public suffix (one label, or a known two-label suffix).
pub fn matches_entity(host: &str, entity: &str) -> bool {
    for suffix in suffixes(host) {
        if let Some(rest) = suffix.strip_prefix(entity)
            && let Some(tld) = rest.strip_prefix('.')
        {
            return !tld.is_empty() && (!tld.contains('.') || MULTI_LABEL_SUFFIXES.contains(&tld));
        }
    }
    false
}

/// Hostname patterns as they appear in `domain=` options and cosmetic filters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum HostPattern {
    /// `example.com` — matches the domain and its subdomains.
    Domain(String),
    /// `example.*` — matches the entity under any public suffix.
    Entity(String),
}

impl HostPattern {
    /// Parses a single hostname pattern (without a leading `~`).
    pub fn parse(input: &str) -> Option<Self> {
        if let Some(entity) = input.strip_suffix(".*") {
            return normalize_hostname(entity).map(HostPattern::Entity);
        }
        normalize_hostname(input).map(HostPattern::Domain)
    }

    pub fn matches(&self, host: &str) -> bool {
        match self {
            HostPattern::Domain(d) => is_same_or_subdomain(host, d),
            HostPattern::Entity(e) => matches_entity(host, e),
        }
    }
}

/// A list of included/excluded hostname patterns (`a.com|~b.a.com`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct DomainConstraint {
    pub include: Vec<HostPattern>,
    pub exclude: Vec<HostPattern>,
}

impl DomainConstraint {
    /// Parses a separator-delimited list (`|` for `domain=`, `,` for cosmetic
    /// filters). Returns `None` if any entry is invalid.
    pub fn parse(input: &str, separator: char) -> Option<Self> {
        let mut constraint = DomainConstraint::default();
        for raw in input.split(separator) {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            if let Some(negated) = raw.strip_prefix('~') {
                constraint.exclude.push(HostPattern::parse(negated)?);
            } else {
                constraint.include.push(HostPattern::parse(raw)?);
            }
        }
        Some(constraint)
    }

    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }

    /// Evaluates the constraint against a hostname. An empty include list
    /// means "everywhere"; exclusions always win.
    pub fn matches(&self, host: Option<&str>) -> bool {
        let Some(host) = host else {
            return self.include.is_empty();
        };
        if self.exclude.iter().any(|p| p.matches(host)) {
            return false;
        }
        self.include.is_empty() || self.include.iter().any(|p| p.matches(host))
    }
}

/// Extracts the hostname from an absolute URL (`scheme://[user@]host[:port]/...`).
/// Returns the byte range of the host inside `url`.
pub fn url_host_range(url: &str) -> Option<(usize, usize)> {
    let scheme_end = url.find("://")?;
    let start = scheme_end + 3;
    let rest = &url[start..];
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_len];
    let host_start = authority.rfind('@').map(|i| i + 1).unwrap_or(0);
    let host_part = &authority[host_start..];
    let host_len = if host_part.starts_with('[') {
        host_part
            .find(']')
            .map(|i| i + 1)
            .unwrap_or(host_part.len())
    } else {
        host_part.find(':').unwrap_or(host_part.len())
    };
    Some((start + host_start, start + host_start + host_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes() {
        assert_eq!(
            normalize_hostname("Ads.Example.COM.").as_deref(),
            Some("ads.example.com")
        );
        assert_eq!(
            normalize_hostname("a_b.example.com").as_deref(),
            Some("a_b.example.com")
        );
        assert!(normalize_hostname("").is_none());
        assert!(normalize_hostname("a..b").is_none());
        assert!(normalize_hostname("-a.com").is_none());
        assert!(normalize_hostname("exa mple.com").is_none());
        assert!(normalize_hostname(&"a".repeat(64)).is_none());
    }

    #[test]
    fn subdomains() {
        assert!(is_same_or_subdomain("a.example.com", "example.com"));
        assert!(is_same_or_subdomain("example.com", "example.com"));
        assert!(!is_same_or_subdomain("badexample.com", "example.com"));
        assert_eq!(
            suffixes("a.b.c").collect::<Vec<_>>(),
            vec!["a.b.c", "b.c", "c"]
        );
    }

    #[test]
    fn registrable() {
        assert_eq!(registrable_domain("www.example.com"), "example.com");
        assert_eq!(registrable_domain("a.b.example.co.uk"), "example.co.uk");
        assert_eq!(registrable_domain("example.com"), "example.com");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("co.uk"), "co.uk");
        assert_eq!(registrable_domain("10.0.0.1"), "10.0.0.1");
    }

    #[test]
    fn entities() {
        assert!(matches_entity("www.google.com", "google"));
        assert!(matches_entity("google.co.uk", "google"));
        assert!(!matches_entity("google.evil.example", "google"));
        assert!(!matches_entity("notgoogle.com", "google"));
    }

    #[test]
    fn hosts_from_urls() {
        let url = "https://user@Sub.Example.com:8443/path?q";
        let (s, e) = url_host_range(url).unwrap();
        assert_eq!(&url[s..e], "Sub.Example.com");
        let url = "http://[::1]:80/";
        let (s, e) = url_host_range(url).unwrap();
        assert_eq!(&url[s..e], "[::1]");
    }
}
