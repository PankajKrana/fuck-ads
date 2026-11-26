//! Filter-list updates.
//!
//! ```text
//! download (HTTPS, conditional) → validate (size, UTF-8, pinned SHA-256)
//!   → parse (minimum rule count, shrink guard) → stage (<name>.txt.new)
//!   → install (current → .prev, .new → current, atomic renames)
//!   → build engine → self-test → activate   |   on failure: roll back
//! ```
//!
//! A working rule set is never replaced by one that failed any step.

use crate::rules::{LiveFilter, build_engine, decode_list, self_test};
use fuck_ads_config::{Config, FilterList, Paths};
use fuck_ads_filter::EngineBuilder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

#[derive(Debug, Clone)]
pub struct FetchRequest<'a> {
    pub url: &'a str,
    pub etag: Option<&'a str>,
    pub last_modified: Option<&'a str>,
    pub max_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchResponse {
    NotModified,
    Body {
        bytes: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Downloads list content. Abstracted for testing.
pub trait Fetcher: Send + Sync {
    fn fetch<'a>(&'a self, req: FetchRequest<'a>) -> BoxFuture<'a, Result<FetchResponse, String>>;
}

/// HTTPS fetcher with conditional requests and a streaming size limit.
#[derive(Debug, Clone)]
pub struct HttpFetcher {
    client: reqwest::Client,
}

impl HttpFetcher {
    pub fn new() -> Result<Self, String> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(concat!("fuck-ads/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(HttpFetcher { client })
    }
}

impl Fetcher for HttpFetcher {
    fn fetch<'a>(&'a self, req: FetchRequest<'a>) -> BoxFuture<'a, Result<FetchResponse, String>> {
        Box::pin(async move {
            let mut builder = self.client.get(req.url);
            if let Some(etag) = req.etag {
                builder = builder.header("if-none-match", etag);
            }
            if let Some(lm) = req.last_modified {
                builder = builder.header("if-modified-since", lm);
            }
            let mut resp = builder
                .send()
                .await
                .map_err(|e| e.without_url().to_string())?;
            if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
                return Ok(FetchResponse::NotModified);
            }
            if !resp.status().is_success() {
                return Err(format!("HTTP status {}", resp.status()));
            }
            if resp.content_length().is_some_and(|l| l > req.max_bytes) {
                return Err("list exceeds the configured size limit".into());
            }
            let header = |name: &str| {
                resp.headers()
                    .get(name)
                    .and_then(|v| v.to_str().ok())
                    .map(String::from)
            };
            let etag = header("etag");
            let last_modified = header("last-modified");
            let mut bytes = Vec::new();
            while let Some(chunk) = resp
                .chunk()
                .await
                .map_err(|e| e.without_url().to_string())?
            {
                bytes.extend_from_slice(&chunk);
                if bytes.len() as u64 > req.max_bytes {
                    return Err("list exceeds the configured size limit".into());
                }
            }
            Ok(FetchResponse::Body {
                bytes,
                etag,
                last_modified,
            })
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ListState {
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub sha256: Option<String>,
    pub rules: usize,
    pub last_success: Option<u64>,
    pub last_attempt: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct UpdateState {
    pub last_success: Option<u64>,
    pub last_attempt: Option<u64>,
    pub last_error: Option<String>,
    pub consecutive_failures: u32,
    pub lists: BTreeMap<String, ListState>,
}

impl UpdateState {
    pub fn load(path: &Path) -> UpdateState {
        std::fs::read(path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        fuck_ads_config::fs::write_atomic(path, &bytes, 0o640)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateOutcome {
    pub changed: Vec<String>,
    pub unchanged: Vec<String>,
    pub failed: Vec<(String, String)>,
    /// New rules were built and activated.
    pub activated: bool,
    /// Installed lists were rolled back because the new rule set failed.
    pub rolled_back: bool,
    pub error: Option<String>,
}

impl UpdateOutcome {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if !self.changed.is_empty() {
            parts.push(format!("updated: {}", self.changed.join(", ")));
        }
        if !self.unchanged.is_empty() {
            parts.push(format!("unchanged: {}", self.unchanged.len()));
        }
        for (name, err) in &self.failed {
            parts.push(format!("{name} failed: {err}"));
        }
        if self.rolled_back {
            parts.push("rolled back to previous rules".into());
        }
        if let Some(e) = &self.error {
            parts.push(e.clone());
        }
        if parts.is_empty() {
            "no lists to update".into()
        } else {
            parts.join("; ")
        }
    }
}

pub struct Updater {
    paths: Paths,
    fetcher: Arc<dyn Fetcher>,
    state: Mutex<UpdateState>,
    running: tokio::sync::Mutex<()>,
    /// Delay between download attempts within one run.
    retry_base: Duration,
}

impl std::fmt::Debug for Updater {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Updater")
            .field("paths", &self.paths)
            .finish()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn now() -> u64 {
    fuck_ads_stats::time::now_unix()
}

impl Updater {
    pub fn new(paths: Paths, fetcher: Arc<dyn Fetcher>) -> Self {
        let state = UpdateState::load(&paths.update_state_file());
        Updater {
            paths,
            fetcher,
            state: Mutex::new(state),
            running: tokio::sync::Mutex::new(()),
            retry_base: Duration::from_secs(2),
        }
    }

    pub fn with_retry_base(mut self, d: Duration) -> Self {
        self.retry_base = d;
        self
    }

    pub fn state(&self) -> UpdateState {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn is_running(&self) -> bool {
        self.running.try_lock().is_err()
    }

    fn save_state(&self) {
        let state = self.state();
        if let Err(e) = state.save(&self.paths.update_state_file()) {
            tracing::warn!(error = %e, "cannot save update state");
        }
    }

    /// How long to wait before the next automatic update.
    pub fn next_delay(&self, config: &Config) -> Duration {
        let state = self.state();
        let interval = u64::from(config.filters.update_interval_hours) * 3_600;
        let now = now();
        if state.consecutive_failures > 0 {
            // Exponential backoff: 1, 2, 4, ... minutes, capped at an hour
            // and never longer than the regular interval.
            let backoff = (60u64 << state.consecutive_failures.min(6))
                .min(3_600)
                .min(interval);
            let since = now.saturating_sub(state.last_attempt.unwrap_or(0));
            return Duration::from_secs(backoff.saturating_sub(since));
        }
        match state.last_success {
            None => Duration::from_secs(5),
            Some(t) => Duration::from_secs(interval.saturating_sub(now.saturating_sub(t))),
        }
    }

    pub fn next_update_at(&self, config: &Config) -> u64 {
        now() + self.next_delay(config).as_secs()
    }

    fn list_path(&self, name: &str, suffix: &str) -> PathBuf {
        self.paths.lists_dir().join(format!("{name}.txt{suffix}"))
    }

    /// Downloads and validates one list, staging it as `<name>.txt.new`.
    /// Returns `Ok(true)` if new content was staged.
    async fn fetch_list(
        &self,
        list: &FilterList,
        config: &Config,
        force: bool,
    ) -> Result<bool, String> {
        let url = list.url.as_deref().expect("caller checks url");
        let current = self.list_path(&list.name, "");
        let prev_state = self
            .state()
            .lists
            .get(&list.name)
            .cloned()
            .unwrap_or_default();
        let conditional = !force && current.is_file();
        let max_bytes = u64::from(config.filters.max_list_size_mb) * 1024 * 1024;

        let mut attempt = 0;
        let response = loop {
            let req = FetchRequest {
                url,
                etag: prev_state.etag.as_deref().filter(|_| conditional),
                last_modified: prev_state.last_modified.as_deref().filter(|_| conditional),
                max_bytes,
            };
            match self.fetcher.fetch(req).await {
                Ok(r) => break r,
                Err(e) if attempt < 2 => {
                    attempt += 1;
                    tracing::debug!(list = %list.name, error = %e, attempt, "download failed; retrying");
                    tokio::time::sleep(self.retry_base * (1 << attempt)).await;
                }
                Err(e) => return Err(e),
            }
        };

        let (bytes, etag, last_modified) = match response {
            FetchResponse::NotModified => return Ok(false),
            FetchResponse::Body {
                bytes,
                etag,
                last_modified,
            } => (bytes, etag, last_modified),
        };
        let digest = sha256_hex(&bytes);
        if let Some(pinned) = &list.sha256
            && !pinned.eq_ignore_ascii_case(&digest)
        {
            return Err(format!(
                "SHA-256 mismatch (expected {pinned}, got {digest})"
            ));
        }
        if !force && prev_state.sha256.as_deref() == Some(digest.as_str()) && current.is_file() {
            self.record_list(&list.name, |s| {
                s.etag = etag.clone();
                s.last_modified = last_modified.clone();
            });
            return Ok(false);
        }
        let text = decode_list(&bytes).map_err(String::from)?;

        // Parse in isolation to validate before touching the installed copy.
        let stats = tokio::task::spawn_blocking({
            let (name, category, format) = (list.name.clone(), list.category, list.format);
            move || EngineBuilder::new().add_list(&name, category, &text, format)
        })
        .await
        .map_err(|e| format!("parser crashed: {e}"))?;
        let rules = stats.rules();
        if rules < list.min_rules {
            return Err(format!(
                "only {rules} valid rules (minimum {}); refusing update",
                list.min_rules
            ));
        }
        if !force && prev_state.rules >= 1_000 && rules < prev_state.rules / 2 {
            return Err(format!(
                "rule count dropped from {} to {rules}; looks truncated (use --force to accept)",
                prev_state.rules
            ));
        }

        fuck_ads_config::fs::write_atomic(&self.list_path(&list.name, ".new"), &bytes, 0o644)
            .map_err(|e| format!("cannot stage list: {e}"))?;
        self.record_list(&list.name, |s| {
            s.etag = etag.clone();
            s.last_modified = last_modified.clone();
            s.sha256 = Some(digest.clone());
            s.rules = rules;
        });
        Ok(true)
    }

    fn record_list(&self, name: &str, f: impl FnOnce(&mut ListState)) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        f(state.lists.entry(name.to_string()).or_default());
    }

    /// Moves staged files into place, keeping the previous version. On
    /// failure, also returns how many of `names` were touched and need a
    /// rollback; rolling back untouched lists would downgrade or delete them.
    fn install(&self, names: &[String]) -> Result<(), (usize, std::io::Error)> {
        for (i, name) in names.iter().enumerate() {
            let current = self.list_path(name, "");
            let prev = self.list_path(name, ".prev");
            let staged = self.list_path(name, ".new");
            if current.is_file() {
                std::fs::rename(&current, &prev).map_err(|e| (i, e))?;
            }
            std::fs::rename(&staged, &current).map_err(|e| (i + 1, e))?;
        }
        Ok(())
    }

    /// Restores `.prev` copies after a failed activation.
    fn rollback(&self, names: &[String]) {
        for name in names {
            let current = self.list_path(name, "");
            let prev = self.list_path(name, ".prev");
            let result = if prev.is_file() {
                std::fs::rename(&prev, &current)
            } else {
                std::fs::remove_file(&current)
            };
            if let Err(e) = result {
                tracing::error!(list = %name, error = %e, "rollback failed");
            }
            // The stored metadata described the rejected version.
            self.record_list(name, |s| {
                s.etag = None;
                s.last_modified = None;
                s.sha256 = None;
            });
        }
    }

    /// Runs an update of all enabled remote lists and activates the result.
    pub async fn run(&self, config: &Config, filter: &LiveFilter, force: bool) -> UpdateOutcome {
        let Ok(_guard) = self.running.try_lock() else {
            return UpdateOutcome {
                error: Some("an update is already in progress".into()),
                ..Default::default()
            };
        };
        let mut outcome = UpdateOutcome::default();
        if let Err(e) = fuck_ads_config::fs::ensure_dir(&self.paths.lists_dir(), 0o755) {
            outcome.error = Some(format!(
                "cannot create {}: {e}",
                self.paths.lists_dir().display()
            ));
            return outcome;
        }
        let started = now();
        {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            s.last_attempt = Some(started);
        }

        let remote: Vec<&FilterList> = config
            .filters
            .lists
            .iter()
            .filter(|l| l.enabled && l.url.is_some())
            .collect();
        for list in remote {
            self.record_list(&list.name, |s| s.last_attempt = Some(started));
            match self.fetch_list(list, config, force).await {
                Ok(true) => outcome.changed.push(list.name.clone()),
                Ok(false) => {
                    outcome.unchanged.push(list.name.clone());
                    self.record_list(&list.name, |s| {
                        s.last_success = Some(started);
                        s.last_error = None;
                    });
                }
                Err(e) => {
                    tracing::warn!(list = %list.name, error = %e, "filter update failed; retaining previous version");
                    self.record_list(&list.name, |s| s.last_error = Some(e.clone()));
                    let _ = std::fs::remove_file(self.list_path(&list.name, ".new"));
                    outcome.failed.push((list.name.clone(), e));
                }
            }
        }

        let has_local = config
            .filters
            .lists
            .iter()
            .any(|l| l.enabled && l.path.is_some());
        if !outcome.changed.is_empty() || has_local {
            if let Err((touched, e)) = self.install(&outcome.changed) {
                self.rollback(&outcome.changed[..touched]);
                outcome.rolled_back = true;
                outcome.error = Some(format!("install failed: {e}"));
            } else {
                let (cfg, paths) = (config.clone(), self.paths.clone());
                let built = tokio::task::spawn_blocking(move || build_engine(&cfg, &paths)).await;
                match built {
                    // `--force` explicitly accepts a large rule-count drop.
                    Ok(engine) => match if force {
                        Ok(())
                    } else {
                        self_test(&engine, &filter.engine())
                    } {
                        Ok(()) => {
                            tracing::info!(
                                rules = engine.rule_count(),
                                "filter update completed; new rules active"
                            );
                            filter.set_engine(engine);
                            outcome.activated = true;
                            for name in &outcome.changed {
                                self.record_list(name, |s| {
                                    s.last_success = Some(started);
                                    s.last_error = None;
                                });
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "new rules failed self-test; rolling back");
                            self.rollback(&outcome.changed);
                            outcome.rolled_back = true;
                            outcome.error = Some(e);
                        }
                    },
                    Err(e) => {
                        self.rollback(&outcome.changed);
                        outcome.rolled_back = true;
                        outcome.error = Some(format!("rule compilation failed: {e}"));
                    }
                }
            }
        }

        {
            let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if outcome.failed.is_empty() && outcome.error.is_none() {
                s.last_success = Some(started);
                s.last_error = None;
                s.consecutive_failures = 0;
            } else {
                s.last_error = Some(outcome.summary());
                s.consecutive_failures = s.consecutive_failures.saturating_add(1);
            }
        }
        self.save_state();
        outcome
    }
}
