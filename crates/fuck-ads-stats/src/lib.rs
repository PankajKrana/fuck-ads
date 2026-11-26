//! Local statistics.
//!
//! Privacy properties (also documented in `docs/security.md`):
//!
//! * Only aggregate counters are kept per local calendar day.
//! * For *blocked* queries the blocked hostname may be counted (configurable)
//!   so "top blocked domains" can be shown. Allowed hostnames — i.e. the
//!   sites a user actually visits — are never recorded.
//! * No timestamps of individual queries, no client addresses, no URLs.
//! * Data stays in a local file and is pruned after `retention_days`.

pub mod time;

use fuck_ads_filter::Category;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

/// Per-day cap on distinct blocked domains tracked for "top blocked".
const MAX_TOP_DOMAINS: usize = 2_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct DayStats {
    pub queries: u64,
    pub blocked: u64,
    pub ads: u64,
    pub trackers: u64,
    pub malware: u64,
    pub other_blocked: u64,
    pub cache_hits: u64,
    pub upstream_failures: u64,
    pub blocked_domains: HashMap<String, u64>,
}

impl DayStats {
    fn merge(&mut self, other: &DayStats) {
        self.queries += other.queries;
        self.blocked += other.blocked;
        self.ads += other.ads;
        self.trackers += other.trackers;
        self.malware += other.malware;
        self.other_blocked += other.other_blocked;
        self.cache_hits += other.cache_hits;
        self.upstream_failures += other.upstream_failures;
        for (d, c) in &other.blocked_domains {
            *self.blocked_domains.entry(d.clone()).or_default() += c;
        }
    }

    pub fn top_blocked(&self, n: usize) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .blocked_domains
            .iter()
            .map(|(d, c)| (d.clone(), *c))
            .collect();
        v.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v.truncate(n);
        v
    }

    fn cap_domains(&mut self) {
        if self.blocked_domains.len() <= MAX_TOP_DOMAINS {
            return;
        }
        // Keep the most frequently blocked half; rarely blocked domains add
        // little to "top blocked" and bound memory and file size.
        let keep = self.top_blocked(MAX_TOP_DOMAINS / 2);
        self.blocked_domains = keep.into_iter().collect();
    }
}

/// Outcome of a DNS query, as recorded in statistics.
#[derive(Debug, Clone, Copy)]
pub enum Outcome<'a> {
    Allowed { cached: bool },
    Blocked { domain: &'a str, category: Category },
    UpstreamFailure,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StatsFile {
    version: u32,
    days: BTreeMap<String, DayStats>,
}

/// Thread-safe statistics store with periodic persistence.
#[derive(Debug)]
pub struct StatsStore {
    path: Option<PathBuf>,
    days: Mutex<BTreeMap<String, DayStats>>,
    dirty: AtomicBool,
    enabled: AtomicBool,
    record_domains: AtomicBool,
}

impl StatsStore {
    /// Creates a store, loading existing data from `path` if present.
    /// A corrupt file is moved to `<name>.bad` and the store starts empty
    /// (statistics are not worth failing over, but not worth overwriting).
    pub fn open(path: Option<&Path>, enabled: bool, record_domains: bool) -> StatsStore {
        let days = path
            .and_then(|p| {
                let bytes = std::fs::read(p).ok()?;
                let parsed = serde_json::from_slice::<StatsFile>(&bytes).ok();
                if parsed.is_none() {
                    let _ = std::fs::rename(p, p.with_extension("json.bad"));
                }
                parsed
            })
            .map(|f| f.days)
            .unwrap_or_default();
        StatsStore {
            path: path.map(Path::to_path_buf),
            days: Mutex::new(days),
            dirty: AtomicBool::new(false),
            enabled: AtomicBool::new(enabled),
            record_domains: AtomicBool::new(record_domains),
        }
    }

    pub fn set_options(&self, enabled: bool, record_domains: bool) {
        self.enabled.store(enabled, Ordering::Relaxed);
        self.record_domains.store(record_domains, Ordering::Relaxed);
        if !record_domains {
            let mut days = self.lock();
            for d in days.values_mut() {
                d.blocked_domains.clear();
            }
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<String, DayStats>> {
        // A panic while holding the lock leaves counters consistent enough.
        self.days.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn record(&self, outcome: Outcome<'_>) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let today = time::local_date(time::now_unix());
        let record_domains = self.record_domains.load(Ordering::Relaxed);
        let mut days = self.lock();
        let day = days.entry(today).or_default();
        match outcome {
            Outcome::Allowed { cached } => {
                day.queries += 1;
                if cached {
                    day.cache_hits += 1;
                }
            }
            Outcome::Blocked { domain, category } => {
                day.queries += 1;
                day.blocked += 1;
                match category {
                    Category::Ads => day.ads += 1,
                    Category::Trackers => day.trackers += 1,
                    Category::Malware => day.malware += 1,
                    Category::Annoyances | Category::Custom => day.other_blocked += 1,
                }
                if record_domains {
                    if let Some(c) = day.blocked_domains.get_mut(domain) {
                        *c += 1;
                    } else {
                        day.blocked_domains.insert(domain.to_string(), 1);
                        day.cap_domains();
                    }
                }
            }
            Outcome::UpstreamFailure => {
                day.queries += 1;
                day.upstream_failures += 1;
            }
        }
        self.dirty.store(true, Ordering::Relaxed);
    }

    pub fn today(&self) -> DayStats {
        let today = time::local_date(time::now_unix());
        self.lock().get(&today).cloned().unwrap_or_default()
    }

    /// Aggregate over the most recent `days` calendar days that have data.
    pub fn last_days(&self, days: usize) -> DayStats {
        let mut total = DayStats::default();
        for d in self.lock().values().rev().take(days) {
            total.merge(d);
        }
        total
    }

    pub fn all_time(&self) -> DayStats {
        self.last_days(usize::MAX)
    }

    pub fn reset(&self) {
        self.lock().clear();
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Drops days older than `retention_days`.
    pub fn prune(&self, retention_days: u32) {
        let cutoff =
            time::local_date(time::now_unix().saturating_sub(u64::from(retention_days) * 86_400));
        let mut days = self.lock();
        let before = days.len();
        days.retain(|date, _| date.as_str() > cutoff.as_str());
        if days.len() != before {
            self.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Persists to disk if anything changed since the last save.
    pub fn save_if_dirty(&self) -> std::io::Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return Ok(());
        }
        let file = StatsFile {
            version: 1,
            days: self.lock().clone(),
        };
        let bytes = serde_json::to_vec(&file).map_err(std::io::Error::other)?;
        let result = fuck_ads_config::fs::write_atomic(path, &bytes, 0o640);
        if result.is_err() {
            self.dirty.store(true, Ordering::Relaxed);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_and_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        let s = StatsStore::open(Some(&path), true, true);
        s.record(Outcome::Allowed { cached: false });
        s.record(Outcome::Allowed { cached: true });
        s.record(Outcome::Blocked {
            domain: "ads.example",
            category: Category::Ads,
        });
        s.record(Outcome::Blocked {
            domain: "ads.example",
            category: Category::Ads,
        });
        s.record(Outcome::Blocked {
            domain: "t.example",
            category: Category::Trackers,
        });
        let t = s.today();
        assert_eq!(
            (t.queries, t.blocked, t.ads, t.trackers, t.cache_hits),
            (5, 3, 2, 1, 1)
        );
        assert_eq!(t.top_blocked(1), vec![("ads.example".to_string(), 2)]);
        s.save_if_dirty().unwrap();

        let again = StatsStore::open(Some(&path), true, true);
        assert_eq!(again.today(), t);
        again.reset();
        assert_eq!(again.today(), DayStats::default());
    }

    #[test]
    fn corrupt_file_is_kept_aside() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        std::fs::write(&path, b"{not json").unwrap();
        let s = StatsStore::open(Some(&path), true, true);
        assert_eq!(s.today(), DayStats::default());
        assert_eq!(
            std::fs::read(dir.path().join("stats.json.bad")).unwrap(),
            b"{not json"
        );
    }

    #[test]
    fn never_records_allowed_domains_and_respects_opt_out() {
        let s = StatsStore::open(None, true, false);
        s.record(Outcome::Blocked {
            domain: "ads.example",
            category: Category::Ads,
        });
        assert!(s.today().blocked_domains.is_empty());
        assert_eq!(s.today().blocked, 1);
        let off = StatsStore::open(None, false, true);
        off.record(Outcome::Allowed { cached: false });
        assert_eq!(off.today().queries, 0);
    }

    #[test]
    fn caps_domain_map() {
        let s = StatsStore::open(None, true, true);
        for i in 0..(MAX_TOP_DOMAINS + 10) {
            s.record(Outcome::Blocked {
                domain: &format!("d{i}.example"),
                category: Category::Ads,
            });
        }
        assert!(s.today().blocked_domains.len() <= MAX_TOP_DOMAINS);
    }

    #[test]
    fn corrupt_file_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stats.json");
        std::fs::write(&path, b"{not json").unwrap();
        let s = StatsStore::open(Some(&path), true, true);
        assert_eq!(s.today().queries, 0);
    }
}
