//! The compiled filtering engine.
//!
//! Build an [`Engine`] with [`EngineBuilder`], then share it immutably
//! (`Arc<Engine>`) between the DNS server and the browser API. Updating rules
//! means building a new engine and swapping the `Arc`.

use crate::ParseError;
use crate::cosmetic::{CosmeticAction, CosmeticFilter, SelectorKind, selector_key};
use crate::domain::{DomainConstraint, HostPattern, suffixes};
use crate::network::{Anchor, NetworkFilter, glob_match};
use crate::parser::{ListFormat, Rule, parse_line};
use crate::procedural::Procedural;
use crate::request::{Request, ResourceType};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// What kind of content a list targets; used to classify statistics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    #[default]
    Ads,
    Trackers,
    Malware,
    Annoyances,
    Custom,
}

/// Index of a list inside an engine.
pub type ListIndex = u16;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListStats {
    pub lines: usize,
    pub network: usize,
    pub cosmetic: usize,
    pub hosts: usize,
    pub unsupported: usize,
    pub invalid: usize,
}

impl ListStats {
    pub fn rules(&self) -> usize {
        self.network + self.cosmetic + self.hosts
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListInfo {
    pub name: String,
    pub category: Category,
    pub stats: ListStats,
}

/// Result of a DNS-level hostname check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostVerdict {
    /// Blocked by a rule for `domain` (the matching suffix) from `list`.
    Blocked {
        domain: String,
        list: ListIndex,
    },
    /// A matching exception rule exists for `domain`.
    Allowed {
        domain: String,
    },
    NoMatch,
}

/// Result of a URL-level check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlVerdict {
    Blocked { rule: String, list: ListIndex },
    Allowed { rule: String },
    NoMatch,
}

impl UrlVerdict {
    pub fn is_blocked(&self) -> bool {
        matches!(self, UrlVerdict::Blocked { .. })
    }
}

/// Cosmetic filters applicable to a page.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CosmeticResult {
    pub selectors: Vec<String>,
    /// Procedural filters for the page (`:has-text()` and friends), which the
    /// extension evaluates in the DOM. Only sent with the once-per-frame
    /// request (`include_complex`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub procedural: Vec<Procedural>,
    /// The page disabled generic cosmetic filtering (`$generichide`), so the
    /// client need not send class/id tokens.
    pub generichide: bool,
}

/// A scriptlet invocation, scoped to hostnames, exported for the browser
/// extension.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScriptletRule {
    pub include: Vec<HostPattern>,
    pub exclude: Vec<HostPattern>,
    pub name: String,
    pub args: Vec<String>,
    /// Exceptions disable matching scriptlets; an empty name disables all.
    pub exception: bool,
}

#[derive(Debug, Default)]
struct HostGlob {
    pattern: Box<str>,
    exception: bool,
    important: bool,
    list: ListIndex,
}

/// Token-indexed set of URL filters.
#[derive(Debug, Default)]
struct UrlIndex {
    filters: Vec<(NetworkFilter, ListIndex)>,
    buckets: HashMap<u64, Vec<u32>>,
    fallback: Vec<u32>,
}

const BAD_TOKENS: &[&str] = &[
    "com", "http", "https", "www", "net", "org", "js", "img", "images", "html",
];

#[inline]
fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'%'
}

#[inline]
fn hash_token(tok: &[u8]) -> u64 {
    // FNV-1a: fast, adequate distribution for short ASCII tokens.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in tok {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// All usable tokens of a filter pattern: complete alphanumeric runs that
/// are not adjacent to a wildcard or an unanchored edge (a partial run could
/// be part of a longer token in the URL and would never be looked up).
fn candidate_tokens(filter: &NetworkFilter) -> Vec<u64> {
    if filter.regex.is_some() {
        return Vec::new();
    }
    let lower = filter.pattern.to_ascii_lowercase();
    let p = lower.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < p.len() {
        if !is_token_char(p[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < p.len() && is_token_char(p[i]) {
            i += 1;
        }
        let end = i;
        let left_ok = if start == 0 {
            filter.anchor != Anchor::None
        } else {
            p[start - 1] != b'*'
        };
        let right_ok = if end == p.len() {
            filter.end_anchor
        } else {
            p[end] != b'*'
        };
        let tok = &p[start..end];
        if left_ok
            && right_ok
            && tok.len() >= 2
            && !BAD_TOKENS.contains(&std::str::from_utf8(tok).unwrap_or(""))
        {
            out.push(hash_token(tok));
        }
    }
    out
}

fn url_tokens(url: &[u8], out: &mut Vec<u64>) {
    out.clear();
    let mut i = 0;
    while i < url.len() {
        if !is_token_char(url[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < url.len() && is_token_char(url[i]) {
            i += 1;
        }
        if i - start >= 2 {
            let h = hash_token(&url[start..i]);
            if !out.contains(&h) {
                out.push(h);
            }
        }
    }
}

impl UrlIndex {
    fn add(&mut self, filter: NetworkFilter, list: ListIndex) {
        self.filters.push((filter, list));
    }

    /// Assigns every filter to the bucket of its *rarest* token across the
    /// whole index, so that common tokens (`ads`, `cdn`, a shared domain)
    /// do not produce huge buckets that every matching URL must scan.
    fn finalize(&mut self) {
        let candidates: Vec<Vec<u64>> = self
            .filters
            .iter()
            .map(|(f, _)| candidate_tokens(f))
            .collect();
        let mut freq: HashMap<u64, u32> = HashMap::new();
        for c in &candidates {
            for t in c {
                *freq.entry(*t).or_default() += 1;
            }
        }
        self.buckets.clear();
        self.fallback.clear();
        for (idx, c) in candidates.iter().enumerate() {
            match c.iter().min_by_key(|t| freq[*t]) {
                Some(tok) => self.buckets.entry(*tok).or_default().push(idx as u32),
                None => self.fallback.push(idx as u32),
            }
        }
        self.buckets.shrink_to_fit();
    }

    fn find(&self, req: &Request, tokens: &[u64]) -> Option<&(NetworkFilter, ListIndex)> {
        let check = |idx: &u32| {
            let entry = &self.filters[*idx as usize];
            entry.0.matches(req).then_some(entry)
        };
        for tok in tokens {
            if let Some(bucket) = self.buckets.get(tok)
                && let Some(hit) = bucket.iter().find_map(check)
            {
                return Some(hit);
            }
        }
        self.fallback.iter().find_map(check)
    }

    fn len(&self) -> usize {
        self.filters.len()
    }
}

#[derive(Debug, Clone)]
struct CosmeticEntry {
    selector: Box<str>,
    domains: DomainConstraint,
}

#[derive(Debug, Clone)]
struct ProceduralEntry {
    rule: Procedural,
    domains: DomainConstraint,
}

/// Most procedural filters sent to one page.
const MAX_PROCEDURAL_PER_PAGE: usize = 500;

/// Accumulates parsed rules before compiling them into an [`Engine`].
#[derive(Debug, Default)]
pub struct EngineBuilder {
    lists: Vec<ListInfo>,
    hosts: Vec<(String, ListIndex)>,
    network: Vec<(NetworkFilter, ListIndex)>,
    cosmetic: Vec<CosmeticFilter>,
}

impl EngineBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses and adds a list. Malformed and unsupported lines are counted
    /// and skipped; they never abort the whole list.
    pub fn add_list(
        &mut self,
        name: &str,
        category: Category,
        text: &str,
        format: ListFormat,
    ) -> ListStats {
        let index = self.lists.len() as ListIndex;
        let mut stats = ListStats::default();
        for line in text.lines() {
            stats.lines += 1;
            match parse_line(line, format) {
                Ok(None) => {}
                Ok(Some(Rule::Hosts(hosts))) => {
                    stats.hosts += hosts.len();
                    self.hosts.extend(hosts.into_iter().map(|h| (h, index)));
                }
                Ok(Some(Rule::Network(f))) => {
                    stats.network += 1;
                    self.network.push((f, index));
                }
                Ok(Some(Rule::Cosmetic(f))) => {
                    stats.cosmetic += 1;
                    self.cosmetic.push(f);
                }
                Err(ParseError::Unsupported(_)) => stats.unsupported += 1,
                Err(ParseError::Invalid(_)) => stats.invalid += 1,
            }
        }
        self.lists.push(ListInfo {
            name: name.to_string(),
            category,
            stats: stats.clone(),
        });
        stats
    }

    pub fn build(self) -> Engine {
        let mut engine = Engine {
            lists: self.lists,
            ..Engine::default()
        };

        // `$badfilter` rules cancel the identical rule without the option.
        let badfilters: HashSet<String> = self
            .network
            .iter()
            .filter(|(f, _)| f.badfilter)
            .map(|(f, _)| f.badfilter_key())
            .collect();

        for (host, list) in self.hosts {
            if badfilters.is_empty() || !badfilters.contains(&format!("||{host}^")) {
                engine.blocked_hosts.entry(host.into()).or_insert(list);
            }
        }

        for (filter, list) in self.network {
            if filter.badfilter || badfilters.contains(&*filter.raw) {
                continue;
            }
            if filter.cosmetic.any() {
                engine.cosmetic_exceptions.push(filter);
                continue;
            }
            if filter.removeparam.is_some() {
                // Rewrites URLs instead of blocking them; never enters the
                // blocking indexes or the DNS layer.
                engine.param_filters.push((filter, list));
                continue;
            }
            if let Some(host) = filter.whole_hostname() {
                let host: Box<str> = host.into();
                // Filters naming `$document`/`$all` also carry URL-level
                // meaning (block navigation / allowlist a page), so they are
                // indexed both ways.
                let url_level =
                    filter.explicit_types && filter.types.contains(ResourceType::Document);
                match (filter.exception, filter.important) {
                    (false, false) => {
                        engine.blocked_hosts.entry(host).or_insert(list);
                    }
                    (false, true) => {
                        engine.important_hosts.entry(host).or_insert(list);
                    }
                    (true, false) => {
                        engine.allowed_hosts.insert(host);
                    }
                    (true, true) => {
                        engine.important_allowed_hosts.insert(host);
                    }
                }
                if !url_level {
                    continue;
                }
            } else if let Some(glob) = filter.wildcard_hostname() {
                engine.host_globs.push(HostGlob {
                    pattern: glob.into(),
                    exception: filter.exception,
                    important: filter.important,
                    list,
                });
            }
            match (filter.exception, filter.important) {
                (false, false) => engine.block.add(filter, list),
                (false, true) => engine.important.add(filter, list),
                (true, _) => {
                    if filter.types.contains(ResourceType::Document) {
                        engine.document_exceptions.add(filter.clone(), list);
                    }
                    if filter.important {
                        engine.important_exceptions.add(filter, list);
                    } else {
                        engine.exceptions.add(filter, list);
                    }
                }
            }
        }

        for index in [
            &mut engine.block,
            &mut engine.important,
            &mut engine.exceptions,
            &mut engine.important_exceptions,
            &mut engine.document_exceptions,
        ] {
            index.finalize();
        }

        for filter in self.cosmetic {
            engine.add_cosmetic(filter);
        }
        engine
    }
}

/// An immutable, compiled set of filters.
#[derive(Debug, Default)]
pub struct Engine {
    lists: Vec<ListInfo>,
    blocked_hosts: HashMap<Box<str>, ListIndex>,
    important_hosts: HashMap<Box<str>, ListIndex>,
    allowed_hosts: HashSet<Box<str>>,
    important_allowed_hosts: HashSet<Box<str>>,
    host_globs: Vec<HostGlob>,
    param_filters: Vec<(NetworkFilter, ListIndex)>,

    block: UrlIndex,
    important: UrlIndex,
    exceptions: UrlIndex,
    important_exceptions: UrlIndex,
    document_exceptions: UrlIndex,
    cosmetic_exceptions: Vec<NetworkFilter>,

    specific_hide: HashMap<Box<str>, Vec<CosmeticEntry>>,
    entity_hide: Vec<(Box<str>, CosmeticEntry)>,
    generic_class: HashMap<Box<str>, Vec<CosmeticEntry>>,
    generic_id: HashMap<Box<str>, Vec<CosmeticEntry>>,
    generic_complex: Vec<CosmeticEntry>,
    hide_exceptions: Vec<CosmeticEntry>,
    specific_procedural: HashMap<Box<str>, Vec<ProceduralEntry>>,
    entity_procedural: Vec<ProceduralEntry>,
    procedural_exceptions: Vec<(Box<str>, DomainConstraint)>,
    generic_hide_exceptions: HashSet<Box<str>>,
    scriptlets: Vec<ScriptletRule>,
}

impl Engine {
    /// Convenience constructor for a single list in auto-detected format.
    pub fn from_rules(text: &str) -> Engine {
        let mut b = EngineBuilder::new();
        b.add_list("rules", Category::Ads, text, ListFormat::Auto);
        b.build()
    }

    fn add_cosmetic(&mut self, filter: CosmeticFilter) {
        match filter.action {
            CosmeticAction::Scriptlet { name, args } => self.scriptlets.push(ScriptletRule {
                include: filter.domains.include,
                exclude: filter.domains.exclude,
                name,
                args,
                exception: filter.exception,
            }),
            CosmeticAction::Procedural(rule) => {
                if filter.exception {
                    self.procedural_exceptions
                        .push((rule.source.as_str().into(), filter.domains));
                    return;
                }
                let entry = ProceduralEntry {
                    rule,
                    domains: filter.domains.clone(),
                };
                for pattern in &filter.domains.include {
                    match pattern {
                        HostPattern::Domain(d) => self
                            .specific_procedural
                            .entry(d.as_str().into())
                            .or_default()
                            .push(entry.clone()),
                        HostPattern::Entity(_) => self.entity_procedural.push(entry.clone()),
                    }
                }
            }
            CosmeticAction::Hide(selector) => {
                let generic = filter.domains.include.is_empty();
                if filter.exception {
                    if generic && filter.domains.exclude.is_empty() {
                        self.generic_hide_exceptions.insert(selector.into());
                    } else {
                        self.hide_exceptions.push(CosmeticEntry {
                            selector: selector.into(),
                            domains: filter.domains,
                        });
                    }
                    return;
                }
                if !generic {
                    let entry = CosmeticEntry {
                        selector: selector.into(),
                        domains: filter.domains.clone(),
                    };
                    for pattern in &filter.domains.include {
                        match pattern {
                            HostPattern::Domain(d) => self
                                .specific_hide
                                .entry(d.as_str().into())
                                .or_default()
                                .push(entry.clone()),
                            HostPattern::Entity(e) => {
                                self.entity_hide.push((e.as_str().into(), entry.clone()))
                            }
                        }
                    }
                    return;
                }
                let key = selector_key(&selector).map(|k| (k.kind, Box::<str>::from(k.name)));
                let entry = CosmeticEntry {
                    selector: selector.into(),
                    domains: filter.domains,
                };
                match key {
                    Some((SelectorKind::Class, name)) => {
                        self.generic_class.entry(name).or_default().push(entry)
                    }
                    Some((SelectorKind::Id, name)) => {
                        self.generic_id.entry(name).or_default().push(entry)
                    }
                    None => self.generic_complex.push(entry),
                }
            }
        }
    }

    pub fn lists(&self) -> &[ListInfo] {
        &self.lists
    }

    /// Total number of active rules.
    pub fn rule_count(&self) -> usize {
        self.blocked_hosts.len()
            + self.important_hosts.len()
            + self.allowed_hosts.len()
            + self.important_allowed_hosts.len()
            + self.block.len()
            + self.important.len()
            + self.exceptions.len()
            + self.important_exceptions.len()
            + self.cosmetic_exceptions.len()
            + self.specific_hide.values().map(Vec::len).sum::<usize>()
            + self.entity_hide.len()
            + self.generic_class.values().map(Vec::len).sum::<usize>()
            + self.generic_id.values().map(Vec::len).sum::<usize>()
            + self.generic_complex.len()
            + self.hide_exceptions.len()
            + self.generic_hide_exceptions.len()
            + self.scriptlets.len()
    }

    /// Number of hostnames enforceable at the DNS level.
    pub fn dns_rule_count(&self) -> usize {
        self.blocked_hosts.len() + self.important_hosts.len() + self.host_globs.len()
    }

    fn find_host<'a, V>(map: &'a HashMap<Box<str>, V>, host: &'a str) -> Option<(&'a str, &'a V)> {
        if map.is_empty() {
            return None;
        }
        suffixes(host).find_map(|s| map.get(s).map(|v| (s, v)))
    }

    fn find_host_set<'a>(set: &HashSet<Box<str>>, host: &'a str) -> Option<&'a str> {
        if set.is_empty() {
            return None;
        }
        suffixes(host).find(|s| set.contains(*s))
    }

    fn glob_matches(glob: &HostGlob, host: &str) -> bool {
        let url = format!("http://{host}/");
        glob_match(
            glob.pattern.as_bytes(),
            url.as_bytes(),
            Anchor::Hostname,
            false,
            (7, 7 + host.len()),
        ) && {
            // The match must end at the host boundary (`^` before `/`).
            let p = format!("{}^", glob.pattern);
            glob_match(
                p.as_bytes(),
                url.as_bytes(),
                Anchor::Hostname,
                false,
                (7, 7 + host.len()),
            )
        }
    }

    /// Checks a hostname for DNS-level blocking. `host` must already be
    /// normalized (lowercase, no trailing dot).
    pub fn check_hostname(&self, host: &str) -> HostVerdict {
        if let Some((domain, list)) = Self::find_host(&self.important_hosts, host)
            && Self::find_host_set(&self.important_allowed_hosts, host).is_none()
        {
            return HostVerdict::Blocked {
                domain: domain.to_string(),
                list: *list,
            };
        }
        if let Some(domain) = Self::find_host_set(&self.important_allowed_hosts, host)
            .or_else(|| Self::find_host_set(&self.allowed_hosts, host))
        {
            return HostVerdict::Allowed {
                domain: domain.to_string(),
            };
        }
        if let Some((domain, list)) = Self::find_host(&self.blocked_hosts, host) {
            return HostVerdict::Blocked {
                domain: domain.to_string(),
                list: *list,
            };
        }
        if !self.host_globs.is_empty() {
            let mut blocked = None;
            for glob in &self.host_globs {
                if Self::glob_matches(glob, host) {
                    if glob.exception {
                        return HostVerdict::Allowed {
                            domain: host.to_string(),
                        };
                    }
                    if glob.important {
                        return HostVerdict::Blocked {
                            domain: host.to_string(),
                            list: glob.list,
                        };
                    }
                    blocked.get_or_insert(glob.list);
                }
            }
            if let Some(list) = blocked {
                return HostVerdict::Blocked {
                    domain: host.to_string(),
                    list,
                };
            }
        }
        HostVerdict::NoMatch
    }

    /// Checks a network request (browser-level filtering).
    pub fn check_request(&self, req: &Request) -> UrlVerdict {
        let mut tokens = Vec::with_capacity(16);
        url_tokens(req.url_lower.as_bytes(), &mut tokens);
        let host = req.hostname.as_str();

        // 1. `$important` blocks override normal exceptions.
        let important = Self::find_host(&self.important_hosts, host)
            .map(|(d, l)| (format!("||{d}^$important"), *l))
            .or_else(|| {
                self.important
                    .find(req, &tokens)
                    .map(|(f, l)| (f.raw.to_string(), *l))
            });
        if let Some((rule, list)) = important {
            if let Some(d) = Self::find_host_set(&self.important_allowed_hosts, host) {
                return UrlVerdict::Allowed {
                    rule: format!("@@||{d}^$important"),
                };
            }
            if let Some((f, _)) = self.important_exceptions.find(req, &tokens) {
                return UrlVerdict::Allowed {
                    rule: f.raw.to_string(),
                };
            }
            return UrlVerdict::Blocked { rule, list };
        }

        // 2. Page-level allowlisting (`@@||site^$document`).
        if let Some(source) = &req.source_hostname
            && self.document_exceptions.len() > 0
            && let Some(doc) =
                Request::new(&format!("https://{source}/"), None, ResourceType::Document)
        {
            let mut doc_tokens = Vec::new();
            url_tokens(doc.url_lower.as_bytes(), &mut doc_tokens);
            if let Some((f, _)) = self.document_exceptions.find(&doc, &doc_tokens) {
                return UrlVerdict::Allowed {
                    rule: f.raw.to_string(),
                };
            }
        }

        // 3. Regular blocks, then exceptions.
        let blocked = if req.resource_type == ResourceType::Document {
            None // whole-host rules do not block top-level navigation
        } else {
            Self::find_host(&self.blocked_hosts, host).map(|(d, l)| (format!("||{d}^"), *l))
        }
        .or_else(|| {
            self.block
                .find(req, &tokens)
                .map(|(f, l)| (f.raw.to_string(), *l))
        });

        let Some((rule, list)) = blocked else {
            return UrlVerdict::NoMatch;
        };
        if let Some(d) = Self::find_host_set(&self.allowed_hosts, host) {
            return UrlVerdict::Allowed {
                rule: format!("@@||{d}^"),
            };
        }
        if let Some((f, _)) = self.exceptions.find(req, &tokens) {
            return UrlVerdict::Allowed {
                rule: f.raw.to_string(),
            };
        }
        UrlVerdict::Blocked { rule, list }
    }

    /// Cosmetic exceptions declared with network syntax for a page.
    fn page_cosmetic_exceptions(&self, hostname: &str) -> (bool, bool) {
        let Some(doc) = Request::new(
            &format!("https://{hostname}/"),
            None,
            ResourceType::Document,
        ) else {
            return (false, false);
        };
        let (mut generic, mut specific) = (false, false);
        for f in &self.cosmetic_exceptions {
            // Only the pattern and domain options are relevant here.
            let domain_ok = f.domains.as_ref().is_none_or(|d| d.matches(Some(hostname)));
            if domain_ok && f.matches_pattern(&doc) {
                generic |= f.cosmetic.generichide || f.cosmetic.elemhide;
                specific |= f.cosmetic.specifichide || f.cosmetic.elemhide;
            }
        }
        (generic, specific)
    }

    /// Returns the selectors to hide on `hostname`.
    ///
    /// * `classes` / `ids` — tokens seen in the page; generic filters keyed by
    ///   a class or id are returned only if the token is present.
    /// * `include_complex` — include generic selectors that cannot be keyed
    ///   (sent once per frame).
    pub fn cosmetic_filters(
        &self,
        hostname: &str,
        classes: &[String],
        ids: &[String],
        include_complex: bool,
    ) -> CosmeticResult {
        let (generichide, specifichide) = self.page_cosmetic_exceptions(hostname);
        let mut out: Vec<&str> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        fn push<'a>(
            e: &'a CosmeticEntry,
            host: &str,
            seen: &mut HashSet<&'a str>,
            out: &mut Vec<&'a str>,
        ) {
            if e.domains.matches(Some(host)) && seen.insert(&e.selector) {
                out.push(&e.selector);
            }
        }

        if !specifichide {
            for suffix in suffixes(hostname) {
                if let Some(entries) = self.specific_hide.get(suffix) {
                    entries
                        .iter()
                        .for_each(|e| push(e, hostname, &mut seen, &mut out));
                }
            }
            for (_, entry) in &self.entity_hide {
                push(entry, hostname, &mut seen, &mut out);
            }
        }
        if !generichide {
            for c in classes {
                if let Some(entries) = self.generic_class.get(c.as_str()) {
                    entries
                        .iter()
                        .for_each(|e| push(e, hostname, &mut seen, &mut out));
                }
            }
            for id in ids {
                if let Some(entries) = self.generic_id.get(id.as_str()) {
                    entries
                        .iter()
                        .for_each(|e| push(e, hostname, &mut seen, &mut out));
                }
            }
            if include_complex {
                self.generic_complex
                    .iter()
                    .for_each(|e| push(e, hostname, &mut seen, &mut out));
            }
        }

        let excepted: HashSet<&str> = self
            .hide_exceptions
            .iter()
            .filter(|e| e.domains.matches(Some(hostname)))
            .map(|e| &*e.selector)
            .collect();
        let selectors = out
            .into_iter()
            .filter(|s| !excepted.contains(s) && !self.generic_hide_exceptions.contains(*s))
            .map(String::from)
            .collect();
        let procedural = if include_complex && !specifichide {
            self.procedural_for(hostname)
        } else {
            Vec::new()
        };
        CosmeticResult {
            selectors,
            procedural,
            generichide,
        }
    }

    /// Procedural filters for `hostname`, after exceptions.
    fn procedural_for(&self, hostname: &str) -> Vec<Procedural> {
        let mut candidates: Vec<&ProceduralEntry> = Vec::new();
        for suffix in suffixes(hostname) {
            if let Some(entries) = self.specific_procedural.get(suffix) {
                candidates.extend(entries);
            }
        }
        candidates.extend(&self.entity_procedural);

        let mut out: Vec<Procedural> = Vec::new();
        let mut seen: HashSet<&str> = HashSet::new();
        for e in candidates {
            if out.len() >= MAX_PROCEDURAL_PER_PAGE {
                break;
            }
            let excepted = self
                .procedural_exceptions
                .iter()
                .any(|(src, d)| **src == *e.rule.source && d.matches(Some(hostname)));
            if e.domains.matches(Some(hostname)) && !excepted && seen.insert(&e.rule.source) {
                out.push(e.rule.clone());
            }
        }
        out
    }

    /// Scriptlets to run on `hostname`, after applying exceptions.
    pub fn scriptlets_for(&self, hostname: &str) -> Vec<(String, Vec<String>)> {
        let applies = |r: &ScriptletRule| {
            (r.include.is_empty() || r.include.iter().any(|p| p.matches(hostname)))
                && !r.exclude.iter().any(|p| p.matches(hostname))
        };
        let exceptions: Vec<&ScriptletRule> = self
            .scriptlets
            .iter()
            .filter(|r| r.exception && applies(r))
            .collect();
        if exceptions.iter().any(|e| e.name.is_empty()) {
            return Vec::new();
        }
        let mut out: Vec<(String, Vec<String>)> = Vec::new();
        for r in self
            .scriptlets
            .iter()
            .filter(|r| !r.exception && applies(r))
        {
            let excepted = exceptions
                .iter()
                .any(|e| e.name == r.name && (e.args.is_empty() || e.args == r.args));
            let entry = (r.name.clone(), r.args.clone());
            if !excepted && !out.contains(&entry) {
                out.push(entry);
            }
        }
        out
    }

    /// All scriptlet rules, for bulk export to the browser extension.
    pub fn scriptlet_rules(&self) -> &[ScriptletRule] {
        &self.scriptlets
    }

    pub(crate) fn network_filters(&self) -> impl Iterator<Item = &(NetworkFilter, ListIndex)> {
        self.important
            .filters
            .iter()
            .chain(self.important_exceptions.filters.iter())
            .chain(self.exceptions.filters.iter())
            .chain(self.block.filters.iter())
    }

    pub(crate) fn blocked_host_list(&self) -> impl Iterator<Item = &str> {
        self.blocked_hosts.keys().map(|k| &**k)
    }

    pub(crate) fn param_filters(&self) -> impl Iterator<Item = &NetworkFilter> {
        self.param_filters.iter().map(|(f, _)| f)
    }

    pub(crate) fn important_host_list(&self) -> impl Iterator<Item = &str> {
        self.important_hosts.keys().map(|k| &**k)
    }

    pub(crate) fn allowed_host_list(&self) -> impl Iterator<Item = &str> {
        self.allowed_hosts
            .iter()
            .chain(self.important_allowed_hosts.iter())
            .map(|k| &**k)
    }

    pub(crate) fn site_cosmetics(&self) -> impl Iterator<Item = (&str, &str)> {
        self.specific_hide
            .iter()
            .flat_map(|(host, entries)| entries.iter().map(move |e| (&**host, &*e.selector)))
    }

    pub(crate) fn hide_exception_list(
        &self,
    ) -> impl Iterator<Item = (Option<&DomainConstraint>, &str)> {
        self.hide_exceptions
            .iter()
            .map(|e| (Some(&e.domains), &*e.selector))
            .chain(self.generic_hide_exceptions.iter().map(|s| (None, &**s)))
    }

    /// True if `host` (or a parent) is in the blocked hostname set. Used by
    /// self-tests to verify critical domains are not blocked.
    pub fn is_host_blocked(&self, host: &str) -> bool {
        matches!(self.check_hostname(host), HostVerdict::Blocked { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RULES: &str = r#"
! test list
||ads.example.com^
||tracker.example.net^$important
@@||good.ads.example.com^
0.0.0.0 hosts-blocked.example.org
||ad*.wild.example^
/banner/ad.
||cdn.example/ads/*.js$script,third-party
@@||cdn.example/ads/allowed.js
example.com##.ad-banner
example.com,~shop.example.com##.sidebar-ad
##.generic-ad
###top-ad
##div[data-ad-slot]
example.com#@#.generic-ad
@@||nohide.example^$generichide
youtube.com##+js(json-prune, adPlacements)
m.youtube.com#@#+js(json-prune, adPlacements)
"#;

    fn engine() -> Engine {
        Engine::from_rules(RULES)
    }

    #[test]
    fn hostnames() {
        let e = engine();
        assert!(matches!(
            e.check_hostname("ads.example.com"),
            HostVerdict::Blocked { .. }
        ));
        assert!(matches!(
            e.check_hostname("x.ads.example.com"),
            HostVerdict::Blocked { .. }
        ));
        assert!(matches!(
            e.check_hostname("good.ads.example.com"),
            HostVerdict::Allowed { .. }
        ));
        assert!(matches!(
            e.check_hostname("hosts-blocked.example.org"),
            HostVerdict::Blocked { .. }
        ));
        assert!(matches!(
            e.check_hostname("adserver.wild.example"),
            HostVerdict::Blocked { .. }
        ));
        assert!(matches!(
            e.check_hostname("adserver.wild.example.com"),
            HostVerdict::NoMatch
        ));
        assert_eq!(e.check_hostname("example.com"), HostVerdict::NoMatch);
    }

    #[test]
    fn urls() {
        let e = engine();
        let r = |url: &str, ty| Request::new(url, Some("https://news.site/"), ty).unwrap();
        assert!(
            e.check_request(&r("https://ads.example.com/x", ResourceType::Image))
                .is_blocked()
        );
        assert!(
            e.check_request(&r("https://news.site/banner/ad.png", ResourceType::Image))
                .is_blocked()
        );
        assert!(
            e.check_request(&r("https://cdn.example/ads/x.js", ResourceType::Script))
                .is_blocked()
        );
        assert!(
            !e.check_request(&r("https://cdn.example/ads/x.js", ResourceType::Image))
                .is_blocked()
        );
        assert!(matches!(
            e.check_request(&r(
                "https://cdn.example/ads/allowed.js",
                ResourceType::Script
            )),
            UrlVerdict::Allowed { .. }
        ));
        assert!(matches!(
            e.check_request(&r("https://good.ads.example.com/a", ResourceType::Script)),
            UrlVerdict::Allowed { .. }
        ));
        // Top-level navigation is not blocked by plain host rules.
        assert!(
            !e.check_request(&r("https://ads.example.com/", ResourceType::Document))
                .is_blocked()
        );
    }

    #[test]
    fn cosmetics() {
        let e = engine();
        let res = e.cosmetic_filters(
            "www.example.com",
            &["generic-ad".into()],
            &["top-ad".into()],
            true,
        );
        assert!(res.selectors.contains(&".ad-banner".to_string()));
        assert!(res.selectors.contains(&".sidebar-ad".to_string()));
        assert!(res.selectors.contains(&"#top-ad".to_string()));
        assert!(res.selectors.contains(&"div[data-ad-slot]".to_string()));
        assert!(
            !res.selectors.contains(&".generic-ad".to_string()),
            "exception applies"
        );

        let res = e.cosmetic_filters("shop.example.com", &[], &[], false);
        assert!(!res.selectors.contains(&".sidebar-ad".to_string()));

        let res = e.cosmetic_filters("other.site", &["generic-ad".into()], &[], false);
        assert_eq!(res.selectors, vec![".generic-ad".to_string()]);

        let res = e.cosmetic_filters("nohide.example", &["generic-ad".into()], &[], true);
        assert!(res.generichide);
        assert!(res.selectors.is_empty());
    }

    #[test]
    fn scriptlets() {
        let e = engine();
        assert_eq!(
            e.scriptlets_for("www.youtube.com"),
            vec![("json-prune".into(), vec!["adPlacements".into()])]
        );
        assert!(e.scriptlets_for("m.youtube.com").is_empty());
        assert!(e.scriptlets_for("example.com").is_empty());
    }

    #[test]
    fn removeparam_filters_never_block() {
        let mut b = EngineBuilder::new();
        b.add_list(
            "t",
            Category::Trackers,
            "$removeparam=utm_source\n||x.example^$removeparam=fbclid\n",
            ListFormat::Auto,
        );
        let e = b.build();
        let req =
            Request::new("https://x.example/p?fbclid=1", None, ResourceType::Document).unwrap();
        assert!(!e.check_request(&req).is_blocked());
    }

    #[test]
    fn procedural_filters_by_site() {
        let mut b = EngineBuilder::new();
        let stats = b.add_list(
            "t",
            Category::Ads,
            "shop.example##.card:has-text(Sponsored)\n\
             shop.example##.row:xpath(..)\n\
             news.*##.promo:has-text(/ad/i)\n\
             ##.generic:has-text(x)\n\
             shop.example##div:style(color: red)\n",
            ListFormat::Auto,
        );
        // The generic procedural filter and the unsupported operator are skipped.
        assert_eq!(stats.cosmetic, 3);
        assert_eq!(stats.unsupported, 2);
        let e = b.build();

        let sources = |host: &str, complex: bool| -> Vec<String> {
            e.cosmetic_filters(host, &[], &[], complex)
                .procedural
                .into_iter()
                .map(|p| p.source)
                .collect()
        };
        assert_eq!(
            sources("shop.example", true),
            vec![".card:has-text(Sponsored)", ".row:xpath(..)"]
        );
        // Subdomains inherit; other sites do not.
        assert_eq!(sources("www.shop.example", true).len(), 2);
        assert!(sources("other.example", true).is_empty());
        // Entity patterns (`news.*`).
        assert_eq!(sources("news.com", true), vec![".promo:has-text(/ad/i)"]);
        assert_eq!(sources("news.co.uk", true).len(), 1);
        // Sent only with the once-per-frame request.
        assert!(sources("shop.example", false).is_empty());
        // Procedural filters are not mixed into the plain CSS selectors.
        assert!(
            e.cosmetic_filters("shop.example", &[], &[], true)
                .selectors
                .is_empty()
        );
    }

    #[test]
    fn procedural_exceptions_and_specifichide() {
        let e = Engine::from_rules(
            "shop.example##.card:has-text(Sponsored)\n\
             shop.example##.row:xpath(..)\n\
             vip.shop.example#@#.card:has-text(Sponsored)\n",
        );
        let n = |host: &str| e.cosmetic_filters(host, &[], &[], true).procedural.len();
        assert_eq!(n("shop.example"), 2);
        // The exception applies to vip.shop.example only, and only to its filter.
        assert_eq!(n("vip.shop.example"), 1);

        let e = Engine::from_rules(
            "shop.example##.card:has-text(Sponsored)\n\
             @@||shop.example^$specifichide\n",
        );
        assert!(
            e.cosmetic_filters("shop.example", &[], &[], true)
                .procedural
                .is_empty()
        );
    }

    #[test]
    fn badfilter() {
        let e = Engine::from_rules(
            "||a.example^\n||a.example^$badfilter\n0.0.0.0 b.example\n||b.example^$badfilter",
        );
        assert_eq!(e.check_hostname("a.example"), HostVerdict::NoMatch);
        assert_eq!(e.check_hostname("b.example"), HostVerdict::NoMatch);
    }

    #[test]
    fn stats_count_bad_lines() {
        let mut b = EngineBuilder::new();
        let s = b.add_list(
            "x",
            Category::Ads,
            "||ok.example^\n*\n||x^$redirect-rule=noop.js\n! c\n",
            ListFormat::Auto,
        );
        assert_eq!(s.network, 1);
        assert_eq!(s.invalid, 1);
        assert_eq!(s.unsupported, 1);
        assert_eq!(s.lines, 4);
    }
}
