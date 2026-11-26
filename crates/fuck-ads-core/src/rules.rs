//! Rule sources, user allow/block lists, and the live filter used by DNS.

use fuck_ads_config::{Config, FilterList, Paths};
use fuck_ads_dns::{Decision, QueryFilter};
use fuck_ads_filter::domain::{normalize_hostname, suffixes};
use fuck_ads_filter::{Category, Engine, EngineBuilder, HostVerdict, ListFormat};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Maximum entries in each user list (protects the daemon from abuse).
pub const MAX_USER_ENTRIES: usize = 100_000;

/// Domains added with `fuck-ads allow` / `fuck-ads block`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRules {
    #[serde(default)]
    pub allow: BTreeSet<String>,
    #[serde(default)]
    pub block: BTreeSet<String>,
}

impl UserRules {
    /// Loads the rules. A file that does not parse is renamed to
    /// `<name>.bad` first, so the next save cannot overwrite the user's lists.
    pub fn load(path: &Path) -> std::io::Result<UserRules> {
        match std::fs::read(path) {
            Ok(bytes) => {
                let mut rules: UserRules = serde_json::from_slice(&bytes).map_err(|e| {
                    let bad = path.with_extension("json.bad");
                    let kept = match std::fs::rename(path, &bad) {
                        Ok(()) => format!("moved to {}", bad.display()),
                        Err(re) => format!("could not move it aside: {re}"),
                    };
                    std::io::Error::new(std::io::ErrorKind::InvalidData, format!("{e}; {kept}"))
                })?;
                // Re-validate on load: the file could have been edited.
                rules.allow = rules
                    .allow
                    .into_iter()
                    .filter_map(|d| normalize_hostname(&d))
                    .collect();
                rules.block = rules
                    .block
                    .into_iter()
                    .filter_map(|d| normalize_hostname(&d))
                    .collect();
                Ok(rules)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(UserRules::default()),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        fuck_ads_config::fs::write_atomic(path, &bytes, 0o640)
    }
}

/// Validates a domain supplied by a user.
pub fn parse_user_domain(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    // Accept URLs and wildcard forms people commonly paste.
    let without_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let host = without_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = host.split(':').next().unwrap_or(host);
    let host = host.strip_prefix("*.").unwrap_or(host);
    match normalize_hostname(host) {
        Some(h) if h.contains('.') || h == "localhost" => Ok(h),
        _ => Err(format!("{input:?} is not a valid domain name")),
    }
}

/// Effective user lists (user rules plus administrator `[custom]` entries).
#[derive(Debug, Default)]
struct Overrides {
    allow: HashSet<String>,
    block: HashSet<String>,
    /// Hosts FuckAds needs to function (DoH upstreams, list servers).
    critical: HashSet<String>,
}

fn find_suffix<'a>(set: &HashSet<String>, host: &'a str) -> Option<&'a str> {
    if set.is_empty() {
        return None;
    }
    suffixes(host).find(|s| set.contains(*s))
}

/// The live filter shared by the DNS resolver and the control API.
#[derive(Debug)]
pub struct LiveFilter {
    engine: RwLock<Arc<Engine>>,
    overrides: RwLock<Overrides>,
    enabled: AtomicBool,
    revision: AtomicU64,
}

impl LiveFilter {
    pub fn new(engine: Engine, user: &UserRules, config: &Config) -> Self {
        let f = LiveFilter {
            engine: RwLock::new(Arc::new(engine)),
            overrides: RwLock::new(Overrides::default()),
            enabled: AtomicBool::new(config.general.enabled && config.filters.enabled),
            revision: AtomicU64::new(1),
        };
        f.set_user_rules(user, config);
        f
    }

    pub fn engine(&self) -> Arc<Engine> {
        self.engine
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_engine(&self, engine: Engine) {
        *self.engine.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(engine);
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_user_rules(&self, user: &UserRules, config: &Config) {
        let allow = user
            .allow
            .iter()
            .chain(&config.custom.allow)
            .filter_map(|d| normalize_hostname(d))
            .collect();
        let block = user
            .block
            .iter()
            .chain(&config.custom.block)
            .filter_map(|d| normalize_hostname(d))
            .collect();
        let critical = critical_hosts(config).into_iter().collect();
        *self.overrides.write().unwrap_or_else(|e| e.into_inner()) = Overrides {
            allow,
            block,
            critical,
        };
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    pub fn user_lists(&self) -> (Vec<String>, Vec<String>) {
        let o = self.overrides.read().unwrap_or_else(|e| e.into_inner());
        let mut allow: Vec<String> = o.allow.iter().cloned().collect();
        let mut block: Vec<String> = o.block.iter().cloned().collect();
        allow.sort();
        block.sort();
        (allow, block)
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.revision.fetch_add(1, Ordering::Relaxed);
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }

    pub fn revision(&self) -> u64 {
        self.revision.load(Ordering::Relaxed)
    }

    /// Decisions that do not depend on the filter lists: paused filtering,
    /// hosts FuckAds itself needs, and the user's allow/block entries.
    fn overridden(&self, host: &str) -> Option<(Decision, String)> {
        if !self.is_enabled() {
            return Some((Decision::Allow, "filtering is paused".into()));
        }
        let o = self.overrides.read().unwrap_or_else(|e| e.into_inner());
        if o.critical.contains(host) {
            return Some((Decision::Allow, "required by FuckAds itself".into()));
        }
        if let Some(d) = find_suffix(&o.allow, host) {
            return Some((Decision::Allow, format!("allowlisted ({d})")));
        }
        if let Some(d) = find_suffix(&o.block, host) {
            return Some((
                Decision::Block {
                    domain: d.to_string(),
                    category: Category::Custom,
                },
                format!("blocklisted ({d})"),
            ));
        }
        None
    }

    /// Full decision with a human-readable explanation.
    pub fn explain(&self, host: &str) -> (Decision, String, Option<String>) {
        if let Some((decision, reason)) = self.overridden(host) {
            return (decision, reason, None);
        }
        let engine = self.engine();
        match engine.check_hostname(host) {
            HostVerdict::Blocked { domain, list } => {
                let info = engine.lists().get(usize::from(list));
                let category = info.map(|l| l.category).unwrap_or_default();
                let name = info.map(|l| l.name.clone());
                let reason = format!("rule ||{domain}^ from {}", name.as_deref().unwrap_or("?"));
                (Decision::Block { domain, category }, reason, name)
            }
            HostVerdict::Allowed { domain } => (
                Decision::Allow,
                format!("exception rule @@||{domain}^"),
                None,
            ),
            HostVerdict::NoMatch => (Decision::Allow, "no matching rule".into(), None),
        }
    }
}

impl fuck_ads_proxy::ProxyFilter for LiveFilter {
    fn check_host(&self, host: &str) -> fuck_ads_proxy::Verdict {
        match self.explain(host).0 {
            Decision::Allow => fuck_ads_proxy::Verdict::Allow,
            Decision::Block { domain, category } => {
                fuck_ads_proxy::Verdict::Block { domain, category }
            }
        }
    }

    fn check_url(&self, url: &str, referer: Option<&str>) -> fuck_ads_proxy::Verdict {
        let Some(req) =
            fuck_ads_filter::Request::new(url, referer, fuck_ads_filter::ResourceType::Other)
        else {
            return fuck_ads_proxy::Verdict::Allow;
        };
        // User entries, pause and "needed by FuckAds" win over list rules.
        if let Some((decision, _)) = self.overridden(&req.hostname) {
            return match decision {
                Decision::Allow => fuck_ads_proxy::Verdict::Allow,
                Decision::Block { domain, category } => {
                    fuck_ads_proxy::Verdict::Block { domain, category }
                }
            };
        }
        let engine = self.engine();
        match engine.check_request(&req) {
            fuck_ads_filter::UrlVerdict::Blocked { list, .. } => fuck_ads_proxy::Verdict::Block {
                category: engine
                    .lists()
                    .get(usize::from(list))
                    .map(|l| l.category)
                    .unwrap_or_default(),
                domain: req.hostname,
            },
            _ => fuck_ads_proxy::Verdict::Allow,
        }
    }
}

impl QueryFilter for LiveFilter {
    fn check(&self, host: &str) -> Decision {
        self.explain(host).0
    }
}

/// Where a list's current content comes from.
pub fn list_source_path(list: &FilterList, paths: &Paths) -> Option<PathBuf> {
    if let Some(p) = &list.path {
        return Some(p.clone());
    }
    let downloaded = paths.lists_dir().join(format!("{}.txt", list.name));
    if downloaded.is_file() {
        return Some(downloaded);
    }
    let previous = paths.lists_dir().join(format!("{}.txt.prev", list.name));
    if previous.is_file() {
        return Some(previous);
    }
    list.bundled
        .as_ref()
        .map(|b| paths.bundled_filters.join(b))
        .filter(|p| p.is_file())
}

/// Reads a list file, rejecting binary or oversized content.
pub fn read_list_file(path: &Path, max_bytes: u64) -> std::io::Result<String> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "list file too large",
        ));
    }
    let bytes = std::fs::read(path)?;
    decode_list(&bytes).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Decodes list bytes as UTF-8 text. Binary content is rejected.
pub fn decode_list(bytes: &[u8]) -> Result<String, &'static str> {
    if bytes.contains(&0) {
        return Err("list contains NUL bytes (binary data)");
    }
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    String::from_utf8(bytes.to_vec()).map_err(|_| "list is not valid UTF-8")
}

/// Builds the engine from every enabled list plus `[custom] rules`.
/// Unreadable lists are logged and skipped so one bad file never disables
/// protection entirely.
pub fn build_engine(config: &Config, paths: &Paths) -> Engine {
    let max = u64::from(config.filters.max_list_size_mb) * 1024 * 1024;
    let mut builder = EngineBuilder::new();
    if config.filters.enabled {
        for list in config.filters.lists.iter().filter(|l| l.enabled) {
            let Some(path) = list_source_path(list, paths) else {
                tracing::info!(list = %list.name, "list not downloaded yet");
                continue;
            };
            match read_list_file(&path, max) {
                Ok(text) => {
                    let stats = builder.add_list(&list.name, list.category, &text, list.format);
                    tracing::debug!(list = %list.name, rules = stats.rules(), "loaded list");
                }
                Err(e) => {
                    tracing::warn!(list = %list.name, path = %path.display(), error = %e, "cannot read list")
                }
            }
        }
    }
    if !config.custom.rules.is_empty() {
        builder.add_list(
            "custom",
            Category::Custom,
            &config.custom.rules.join("\n"),
            ListFormat::Adblock,
        );
    }
    builder.build()
}

/// Hostnames that must never be blocked, or FuckAds would break itself:
/// DoH upstreams and filter-list servers.
pub fn critical_hosts(config: &Config) -> Vec<String> {
    let mut hosts: Vec<String> = config
        .upstreams()
        .into_iter()
        .filter_map(|u| match u {
            fuck_ads_config::Upstream::Https { host, .. } => normalize_hostname(&host),
            fuck_ads_config::Upstream::Plain(_) => None,
        })
        .collect();
    for list in &config.filters.lists {
        if let Some(url) = &list.url
            && let Some(host) = url
                .strip_prefix("https://")
                .and_then(|r| r.split(['/', '?', ':']).next())
            && let Some(h) = normalize_hostname(host)
        {
            hosts.push(h);
        }
    }
    hosts.sort();
    hosts.dedup();
    hosts
}

/// Post-build sanity check run before activating new rules: a large drop in
/// the number of rules almost always means a truncated or broken download.
pub fn self_test(new: &Engine, old: &Engine) -> Result<(), String> {
    let (n, o) = (new.rule_count(), old.rule_count());
    if o >= 1_000 && n < o / 2 {
        return Err(format!(
            "rule count dropped from {o} to {n}; keeping previous rules"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corrupt_rules_file_is_kept_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("user-rules.json");
        std::fs::write(&path, br#"{"allow":["a.example",]}"#).unwrap();
        let err = UserRules::load(&path).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(!path.exists());
        let bad = std::fs::read(dir.path().join("user-rules.json.bad")).unwrap();
        assert_eq!(bad, br#"{"allow":["a.example",]}"#);
    }

    #[test]
    fn user_domain_parsing() {
        assert_eq!(parse_user_domain("Example.COM").unwrap(), "example.com");
        assert_eq!(
            parse_user_domain("https://www.example.com/path?q").unwrap(),
            "www.example.com"
        );
        assert_eq!(parse_user_domain("*.example.com").unwrap(), "example.com");
        assert_eq!(parse_user_domain("example.com:443").unwrap(), "example.com");
        assert!(parse_user_domain("not a domain").is_err());
        assert!(parse_user_domain("com").is_err());
        assert!(parse_user_domain("; rm -rf /").is_err());
    }

    #[test]
    fn overrides_take_precedence() {
        let engine = Engine::from_rules("||ads.example^\n");
        let mut user = UserRules::default();
        user.allow.insert("ads.example".into());
        user.block.insert("evil.example".into());
        let f = LiveFilter::new(engine, &user, &Config::default());
        assert_eq!(f.check("ads.example"), Decision::Allow);
        assert!(matches!(f.check("x.evil.example"), Decision::Block { .. }));
        f.set_user_rules(&UserRules::default(), &Config::default());
        assert!(matches!(f.check("ads.example"), Decision::Block { .. }));
        f.set_enabled(false);
        assert_eq!(f.check("ads.example"), Decision::Allow);
    }

    #[test]
    fn rejects_binary_lists() {
        assert!(decode_list(b"||a^\n\0\x01").is_err());
        assert!(decode_list(&[0xff, 0xfe, 0x41]).is_err());
        assert_eq!(decode_list(b"\xEF\xBB\xBF||a^").unwrap(), "||a^");
    }

    #[test]
    fn critical_hosts_are_never_blocked() {
        let config = Config::default();
        let f = LiveFilter::new(
            Engine::from_rules("||easylist.to^\n||dns.google^"),
            &UserRules::default(),
            &config,
        );
        assert_eq!(f.check("easylist.to"), Decision::Allow);
        assert_eq!(f.check("dns.google"), Decision::Allow);
    }

    #[test]
    fn self_test_detects_collapse() {
        let big: String = (0..2000).map(|i| format!("||a{i}.example^\n")).collect();
        let old = Engine::from_rules(&big);
        assert!(self_test(&Engine::from_rules("||x.example^"), &old).is_err());
        assert!(self_test(&old, &Engine::from_rules("")).is_ok());
    }
}
