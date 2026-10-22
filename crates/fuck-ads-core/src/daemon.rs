//! The long-running service.

use crate::control;
use crate::protocol::{CheckInfo, ListStatus, Request, Response, StatsInfo, StatusInfo};
use crate::rules::{
    LiveFilter, MAX_USER_ENTRIES, UserRules, build_engine, list_source_path, parse_user_domain,
};
use crate::update::{Fetcher, HttpFetcher, Updater};
use anyhow::{Context, Result};
use fuck_ads_config::{Config, Paths};
use fuck_ads_dns::{Decision, Resolver, ResolverConfig};
use fuck_ads_filter::export::{UserOverrides, dnr_rules, safari_content_blocker};
use fuck_ads_filter::{Request as FilterRequest, ResourceType, UrlVerdict};
use fuck_ads_stats::StatsStore;
use serde_json::Value;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, watch};

/// How often statistics are flushed to disk (bounded disk writes).
const STATS_FLUSH: Duration = Duration::from_secs(300);
/// Maximum DNR rules per response page.
const MAX_DNR_PAGE: usize = 5_000;
/// Byte budget per DNR page: browsers reject native messages over 1 MiB.
const MAX_DNR_PAGE_BYTES: usize = 600 * 1024;

pub fn platform_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        std::env::consts::OS
    }
}

/// How the daemon is started.
#[derive(Debug, Clone, Copy, Default)]
pub struct StartOptions {
    /// If the process is root, switch to this `(uid, gid)` right after the
    /// listening sockets are bound. macOS only lets root bind port 53 on a
    /// specific address (loopback), so the service starts as root, binds, and
    /// immediately gives root up, before reading any file or filter list.
    pub drop_privileges: Option<(u32, u32)>,
}

/// Gives up root: clears supplementary groups, switches gid then uid, and
/// verifies that root cannot be regained. Does nothing if not running as
/// root.
pub fn drop_privileges(uid: u32, gid: u32) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind};
    // SAFETY: these are plain credential syscalls; the only pointer passed
    // is the (unused) empty supplementary group list.
    unsafe {
        if libc::geteuid() != 0 {
            return Ok(());
        }
        if uid == 0 {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "refusing to drop privileges to uid 0",
            ));
        }
        if libc::setgroups(0, std::ptr::null()) != 0 {
            let g = gid as libc::gid_t;
            if libc::setgroups(1, &g) != 0 {
                return Err(Error::last_os_error());
            }
        }
        if libc::setgid(gid as libc::gid_t) != 0 || libc::setuid(uid as libc::uid_t) != 0 {
            return Err(Error::last_os_error());
        }
        if libc::getuid() != uid as libc::uid_t
            || libc::geteuid() != uid as libc::uid_t
            || libc::getgid() != gid as libc::gid_t
            || libc::getegid() != gid as libc::gid_t
        {
            return Err(Error::other("credentials did not change"));
        }
        if libc::setuid(0) == 0 {
            return Err(Error::other(
                "root could be regained after dropping privileges",
            ));
        }
    }
    Ok(())
}

/// Shared daemon state.
pub struct Daemon {
    config: Config,
    paths: Paths,
    pub filter: Arc<LiveFilter>,
    pub stats: Arc<StatsStore>,
    pub updater: Arc<Updater>,
    resolver: Option<Arc<Resolver>>,
    listen: Mutex<Vec<SocketAddr>>,
    proxy_listen: Vec<SocketAddr>,
    started: Instant,
    user_rules: Mutex<UserRules>,
    browser_seen: AtomicU64,
    browser_name: Mutex<Option<String>>,
    update_now: Notify,
    export_cache: Mutex<Option<(u64, Arc<Vec<Value>>)>>,
}

impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon")
            .field("paths", &self.paths)
            .finish()
    }
}

/// A running daemon; dropping the handle does not stop it, call
/// [`RunningDaemon::shutdown`].
pub struct RunningDaemon {
    pub daemon: Arc<Daemon>,
    pub dns_addrs: Vec<SocketAddr>,
    /// Where the local filtering proxy listens (empty when it is off).
    pub proxy_addrs: Vec<SocketAddr>,
    shutdown_tx: watch::Sender<bool>,
    tasks: tokio::task::JoinSet<()>,
}

impl RunningDaemon {
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(true);
        while self.tasks.join_next().await.is_some() {}
        self.daemon.finish();
    }

    /// Resolves when a shutdown is requested by a signal handler task.
    pub fn shutdown_sender(&self) -> watch::Sender<bool> {
        self.shutdown_tx.clone()
    }
}

fn now() -> u64 {
    fuck_ads_stats::time::now_unix()
}

impl Daemon {
    /// Starts all services. `fetcher` defaults to HTTPS downloads.
    pub async fn start(
        config: Config,
        paths: Paths,
        fetcher: Option<Arc<dyn Fetcher>>,
    ) -> Result<RunningDaemon> {
        Self::start_with(config, paths, fetcher, StartOptions::default()).await
    }

    pub async fn start_with(
        config: Config,
        paths: Paths,
        fetcher: Option<Arc<dyn Fetcher>>,
        options: StartOptions,
    ) -> Result<RunningDaemon> {
        // Bind the DNS sockets before anything else, then drop root (see
        // `StartOptions::drop_privileges`).
        let dns_listeners = if config.dns.enabled {
            Some(fuck_ads_dns::bind(&config.listen_addrs()).await.context(
                "cannot start the DNS listener (is another DNS server using port 53? see `fuck-ads doctor`)",
            )?)
        } else {
            None
        };
        if let Some((uid, gid)) = options.drop_privileges {
            drop_privileges(uid, gid).context("cannot drop root privileges after binding")?;
            // SAFETY: geteuid has no preconditions.
            if unsafe { libc::geteuid() } != 0 {
                tracing::info!(uid, "bound sockets as root, now running unprivileged");
            }
        }
        fuck_ads_config::fs::ensure_dir(&paths.data_dir, 0o755).with_context(|| {
            format!("cannot create data directory {}", paths.data_dir.display())
        })?;
        fuck_ads_config::fs::ensure_dir(&paths.lists_dir(), 0o755)?;
        if let Some(parent) = paths.socket.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }

        let stats = Arc::new(StatsStore::open(
            Some(&paths.stats_file()),
            config.stats.enabled,
            config.stats.record_blocked_domains,
        ));
        let user_rules = UserRules::load(&paths.user_rules_file()).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "user rules file unreadable; starting with empty allow/block lists");
            UserRules::default()
        });

        let engine = {
            let (c, p) = (config.clone(), paths.clone());
            tokio::task::spawn_blocking(move || build_engine(&c, &p)).await?
        };
        tracing::info!(
            rules = engine.rule_count(),
            dns_rules = engine.dns_rule_count(),
            "loaded rules"
        );
        let filter = Arc::new(LiveFilter::new(engine, &user_rules, &config));

        let fetcher = match fetcher {
            Some(f) => f,
            None => Arc::new(HttpFetcher::new().map_err(anyhow::Error::msg)?),
        };
        let updater = Arc::new(Updater::new(paths.clone(), fetcher));

        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut tasks = tokio::task::JoinSet::new();

        // DNS
        let mut dns_addrs = Vec::new();
        let resolver = if config.dns.enabled {
            let resolver = Arc::new(
                Resolver::new(
                    ResolverConfig::from_config(&config),
                    filter.clone(),
                    stats.clone(),
                )
                .map_err(|e| anyhow::anyhow!("cannot initialize upstream resolvers: {e}"))?,
            );
            let listeners = dns_listeners.context("DNS listeners were not bound")?;
            dns_addrs = listeners.bound.clone();
            tracing::info!(addrs = ?dns_addrs, upstreams = ?resolver.upstream_names(), "DNS server started");
            tasks.spawn(fuck_ads_dns::serve(
                listeners,
                resolver.clone(),
                config.dns.max_concurrent,
                shutdown_rx.clone(),
            ));
            Some(resolver)
        } else {
            tracing::info!("DNS filtering disabled in configuration");
            None
        };

        // Local filtering proxy (off by default)
        let mut proxy_listen = Vec::new();
        if config.proxy.enabled {
            let listeners = fuck_ads_proxy::bind(&config.proxy_listen_addrs())
                .await
                .context("cannot start the proxy listener (is the address already in use?)")?;
            proxy_listen = listeners.bound.clone();
            tracing::info!(addrs = ?proxy_listen, "proxy started");
            tasks.spawn(fuck_ads_proxy::serve(
                listeners,
                filter.clone(),
                stats.clone(),
                fuck_ads_proxy::ProxyConfig {
                    ports: config.proxy.ports.clone(),
                    max_connections: config.proxy.max_connections,
                    log_blocked: config.privacy.log_blocked,
                    allow_local_targets: false,
                },
                shutdown_rx.clone(),
            ));
        }

        let daemon = Arc::new(Daemon {
            config,
            paths,
            filter,
            stats,
            updater,
            resolver,
            listen: Mutex::new(dns_addrs.clone()),
            proxy_listen: proxy_listen.clone(),
            started: Instant::now(),
            user_rules: Mutex::new(user_rules),
            browser_seen: AtomicU64::new(0),
            browser_name: Mutex::new(None),
            update_now: Notify::new(),
            export_cache: Mutex::new(None),
        });

        // Control API
        let listener = control::bind(&daemon.paths.socket).await.with_context(|| {
            format!(
                "cannot create control socket {}",
                daemon.paths.socket.display()
            )
        })?;
        let handler_daemon = daemon.clone();
        let handler = Arc::new(move |req: Request, privileged: bool| {
            let d = handler_daemon.clone();
            async move { d.handle(req, privileged).await }
        });
        tasks.spawn(control::serve(listener, handler, shutdown_rx.clone()));

        // Background jobs
        tasks.spawn(daemon.clone().update_loop(shutdown_rx.clone()));
        tasks.spawn(daemon.clone().stats_loop(shutdown_rx.clone()));

        Ok(RunningDaemon {
            daemon,
            dns_addrs,
            proxy_addrs: proxy_listen,
            shutdown_tx,
            tasks,
        })
    }

    /// Final cleanup after all tasks stopped.
    fn finish(&self) {
        if let Err(e) = self.stats.save_if_dirty() {
            tracing::warn!(error = %e, "cannot save statistics");
        }
        let _ = std::fs::remove_file(&self.paths.socket);
        tracing::info!("stopped");
    }

    async fn update_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        loop {
            let delay = if self.config.filters.auto_update {
                self.updater.next_delay(&self.config)
            } else {
                Duration::from_secs(365 * 86_400)
            };
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = self.update_now.notified() => {}
                _ = shutdown.changed() => return,
            }
            let outcome = self.updater.run(&self.config, &self.filter, false).await;
            if let Some(r) = &self.resolver
                && outcome.activated
            {
                // Cached answers may reflect the old rules.
                r.cache().clear();
            }
            if !outcome.failed.is_empty() || outcome.error.is_some() {
                tracing::warn!(summary = %outcome.summary(), "filter update incomplete; retaining previous rules where needed");
            } else {
                tracing::info!(summary = %outcome.summary(), "filter update check finished");
            }
        }
    }

    async fn stats_loop(self: Arc<Self>, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(STATS_FLUSH);
        interval.tick().await;
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = shutdown.changed() => return,
            }
            self.stats.prune(self.config.stats.retention_days);
            let stats = self.stats.clone();
            let result = tokio::task::spawn_blocking(move || stats.save_if_dirty()).await;
            if let Ok(Err(e)) = result {
                tracing::warn!(error = %e, "cannot save statistics");
            }
        }
    }

    fn status(&self) -> StatusInfo {
        let today = self.stats.today();
        let engine = self.filter.engine();
        let update = self.updater.state();
        let seen = self.browser_seen.load(Ordering::Relaxed);
        StatusInfo {
            version: env!("CARGO_PKG_VERSION").into(),
            platform: platform_name().into(),
            pid: std::process::id(),
            uptime_secs: self.started.elapsed().as_secs(),
            filtering: self.filter.is_enabled(),
            dns_enabled: self.resolver.is_some(),
            dns_listen: self
                .listen
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|a| a.to_string())
                .collect(),
            dns_upstreams: self
                .resolver
                .as_ref()
                .map(|r| r.upstream_names())
                .unwrap_or_default(),
            last_upstream_success: self
                .resolver
                .as_ref()
                .map(|r| r.metrics.last_upstream_success.load(Ordering::Relaxed))
                .filter(|t| *t > 0),
            rule_count: engine.rule_count(),
            dns_rule_count: engine.dns_rule_count(),
            list_count: engine.lists().len(),
            queries_today: today.queries,
            blocked_today: today.blocked,
            ads_today: today.ads,
            trackers_today: today.trackers,
            last_update: update.last_success,
            last_update_error: update.last_error,
            next_update: self
                .config
                .filters
                .auto_update
                .then(|| self.updater.next_update_at(&self.config)),
            update_in_progress: self.updater.is_running(),
            proxy_listen: self.proxy_listen.iter().map(|a| a.to_string()).collect(),
            browser_enabled: self.config.browser.enabled,
            browser_last_seen: (seen > 0).then_some(seen),
            browser_name: self
                .browser_name
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone(),
            revision: self.filter.revision(),
            cache_entries: self.resolver.as_ref().map(|r| r.cache().len()).unwrap_or(0),
            now: now(),
        }
    }

    fn list_statuses(&self) -> Vec<ListStatus> {
        let engine = self.filter.engine();
        let state = self.updater.state();
        self.config
            .filters
            .lists
            .iter()
            .map(|l| {
                let loaded = engine.lists().iter().find(|i| i.name == l.name);
                let ls = state.lists.get(&l.name);
                let source = l
                    .url
                    .clone()
                    .or_else(|| l.path.as_ref().map(|p| p.display().to_string()))
                    .or_else(|| l.bundled.as_ref().map(|b| format!("bundled:{b}")))
                    .unwrap_or_default();
                let _ = list_source_path(l, &self.paths);
                ListStatus {
                    name: l.name.clone(),
                    enabled: l.enabled,
                    category: format!("{:?}", l.category).to_lowercase(),
                    source,
                    rules: loaded.map(|i| i.stats.rules()).unwrap_or(0),
                    unsupported: loaded.map(|i| i.stats.unsupported).unwrap_or(0),
                    invalid: loaded.map(|i| i.stats.invalid).unwrap_or(0),
                    last_success: ls.and_then(|s| s.last_success),
                    last_error: ls.and_then(|s| s.last_error.clone()),
                }
            })
            .collect()
    }

    fn modify_user_rules(
        &self,
        f: impl FnOnce(&mut UserRules) -> Result<String, String>,
    ) -> Response {
        let mut rules = self.user_rules.lock().unwrap_or_else(|e| e.into_inner());
        let mut updated = rules.clone();
        let message = match f(&mut updated) {
            Ok(m) => m,
            Err(e) => return Response::error(e),
        };
        if updated.allow.len() > MAX_USER_ENTRIES || updated.block.len() > MAX_USER_ENTRIES {
            return Response::error(format!(
                "user lists are limited to {MAX_USER_ENTRIES} entries"
            ));
        }
        if let Err(e) = updated.save(&self.paths.user_rules_file()) {
            return Response::error(format!("cannot save user rules: {e}"));
        }
        *rules = updated;
        self.filter.set_user_rules(&rules, &self.config);
        if let Some(r) = &self.resolver {
            // Cached answers may reflect the old decision.
            r.cache().clear();
        }
        Response::ok(message)
    }

    fn browser_export(&self) -> Arc<Vec<Value>> {
        let revision = self.filter.revision();
        let mut cache = self.export_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((rev, rules)) = cache.as_ref()
            && *rev == revision
        {
            return rules.clone();
        }
        let rules = if self.filter.is_enabled() {
            let (allow, block) = self.filter.user_lists();
            let engine = self.filter.engine();
            dnr_rules(
                &engine,
                &UserOverrides {
                    allow: &allow,
                    block: &block,
                },
                self.config.browser.max_dnr_rules,
            )
        } else {
            Vec::new()
        };
        let rules = Arc::new(rules);
        *cache = Some((revision, rules.clone()));
        rules
    }

    /// Handles one control request. `privileged` has already been enforced
    /// for state-changing requests by the transport.
    pub async fn handle(self: &Arc<Self>, req: Request, privileged: bool) -> Response {
        debug_assert!(!req.is_privileged() || privileged);
        match req {
            Request::Status => Response::Status(Box::new(self.status())),
            Request::Stats { days } => {
                let days = days.unwrap_or(1).clamp(1, 3650);
                let d = if days == 1 {
                    self.stats.today()
                } else {
                    self.stats.last_days(days as usize)
                };
                Response::Stats(StatsInfo {
                    days,
                    queries: d.queries,
                    blocked: d.blocked,
                    ads: d.ads,
                    trackers: d.trackers,
                    malware: d.malware,
                    other_blocked: d.other_blocked,
                    cache_hits: d.cache_hits,
                    upstream_failures: d.upstream_failures,
                    top_blocked: d.top_blocked(10),
                })
            }
            Request::StatsReset => {
                self.stats.reset();
                let _ = self.stats.save_if_dirty();
                Response::ok("statistics reset")
            }
            Request::ListAllow => Response::List(self.filter.user_lists().0),
            Request::ListBlock => Response::List(self.filter.user_lists().1),
            Request::Rules => Response::Rules(self.list_statuses()),
            Request::Check { domain } => match parse_user_domain(&domain) {
                Ok(host) => {
                    let (decision, reason, list) = self.filter.explain(&host);
                    Response::Check(CheckInfo {
                        input: host,
                        blocked: matches!(decision, Decision::Block { .. }),
                        reason,
                        list,
                    })
                }
                Err(e) => Response::error(e),
            },
            Request::CheckUrl {
                url,
                source,
                resource_type,
            } => {
                let ty = resource_type.unwrap_or(ResourceType::Other);
                let Some(fr) = FilterRequest::new(&url, source.as_deref(), ty) else {
                    return Response::error("invalid URL (expected scheme://host/...)");
                };
                let (dns_decision, dns_reason, _) = self.filter.explain(&fr.hostname);
                if let Decision::Block { .. } = dns_decision {
                    return Response::Check(CheckInfo {
                        input: url,
                        blocked: true,
                        reason: dns_reason,
                        list: None,
                    });
                }
                let engine = self.filter.engine();
                let verdict = if self.filter.is_enabled() {
                    engine.check_request(&fr)
                } else {
                    UrlVerdict::NoMatch
                };
                let (blocked, reason, list) = match verdict {
                    UrlVerdict::Blocked { rule, list } => {
                        let name = engine
                            .lists()
                            .get(usize::from(list))
                            .map(|l| l.name.clone());
                        (true, format!("rule {rule}"), name)
                    }
                    UrlVerdict::Allowed { rule } => (false, format!("exception {rule}"), None),
                    UrlVerdict::NoMatch => (false, dns_reason, None),
                };
                Response::Check(CheckInfo {
                    input: url,
                    blocked,
                    reason,
                    list,
                })
            }
            Request::BrowserHello {
                browser,
                version: _,
            } => {
                self.browser_seen.store(now(), Ordering::Relaxed);
                let name: String = browser
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
                    .take(32)
                    .collect();
                *self.browser_name.lock().unwrap_or_else(|e| e.into_inner()) = Some(name);
                Response::Status(Box::new(self.status()))
            }
            Request::Cosmetic {
                hostname,
                classes,
                ids,
                complex,
            } => {
                if !self.config.browser.enabled || !self.filter.is_enabled() {
                    return Response::Cosmetic(Default::default());
                }
                let Ok(host) = parse_user_domain(&hostname) else {
                    return Response::Cosmetic(Default::default());
                };
                if self
                    .filter
                    .user_lists()
                    .0
                    .iter()
                    .any(|a| fuck_ads_filter::domain::is_same_or_subdomain(&host, a))
                {
                    return Response::Cosmetic(Default::default());
                }
                // Bound the work a page can request.
                let classes: Vec<String> = classes
                    .into_iter()
                    .take(5_000)
                    .filter(|c| c.len() <= 128)
                    .collect();
                let ids: Vec<String> = ids
                    .into_iter()
                    .take(5_000)
                    .filter(|c| c.len() <= 128)
                    .collect();
                let engine = self.filter.engine();
                let result = tokio::task::spawn_blocking(move || {
                    engine.cosmetic_filters(&host, &classes, &ids, complex)
                })
                .await;
                Response::Cosmetic(result.unwrap_or_default())
            }
            Request::DnrRules { offset, limit } => {
                self.browser_seen.store(now(), Ordering::Relaxed);
                if !self.config.browser.enabled {
                    return Response::Dnr {
                        revision: self.filter.revision(),
                        total: 0,
                        rules: Vec::new(),
                    };
                }
                let revision = self.filter.revision();
                let this = self.clone();
                let rules = tokio::task::spawn_blocking(move || this.browser_export())
                    .await
                    .unwrap_or_default();
                let limit = limit.clamp(1, MAX_DNR_PAGE);
                let mut page = Vec::new();
                let mut bytes = 0;
                for rule in rules.iter().skip(offset).take(limit) {
                    let size = serde_json::to_string(rule).map(|s| s.len()).unwrap_or(0);
                    if !page.is_empty() && bytes + size > MAX_DNR_PAGE_BYTES {
                        break;
                    }
                    bytes += size;
                    page.push(rule.clone());
                }
                Response::Dnr {
                    revision,
                    total: rules.len(),
                    rules: page,
                }
            }
            Request::Scriptlets => {
                let revision = self.filter.revision();
                if !self.config.browser.enabled || !self.filter.is_enabled() {
                    return Response::Scriptlets {
                        revision,
                        rules: Vec::new(),
                    };
                }
                let mut rules = self.filter.engine().scriptlet_rules().to_vec();
                // User-allowlisted sites get no scriptlets.
                let (allow, _) = self.filter.user_lists();
                if !allow.is_empty() {
                    rules.push(fuck_ads_filter::ScriptletRule {
                        include: allow
                            .into_iter()
                            .map(fuck_ads_filter::domain::HostPattern::Domain)
                            .collect(),
                        exclude: Vec::new(),
                        name: String::new(),
                        args: Vec::new(),
                        exception: true,
                    });
                }
                Response::Scriptlets { revision, rules }
            }
            Request::SafariRules => {
                let revision = self.filter.revision();
                let (allow, block) = self.filter.user_lists();
                let engine = self.filter.engine();
                let rules = tokio::task::spawn_blocking(move || {
                    safari_content_blocker(
                        &engine,
                        &UserOverrides {
                            allow: &allow,
                            block: &block,
                        },
                        50_000,
                    )
                })
                .await
                .unwrap_or_default();
                Response::Safari { revision, rules }
            }
            Request::Reload => {
                let (c, p) = (self.config.clone(), self.paths.clone());
                let engine = match tokio::task::spawn_blocking(move || build_engine(&c, &p)).await {
                    Ok(e) => e,
                    Err(e) => return Response::error(format!("reload failed: {e}")),
                };
                let count = engine.rule_count();
                self.filter.set_engine(engine);
                match UserRules::load(&self.paths.user_rules_file()) {
                    Ok(rules) => {
                        self.filter.set_user_rules(&rules, &self.config);
                        *self.user_rules.lock().unwrap_or_else(|e| e.into_inner()) = rules;
                    }
                    Err(e) => tracing::warn!(error = %e, "cannot reload user rules"),
                }
                if let Some(r) = &self.resolver {
                    r.cache().clear();
                }
                tracing::info!(rules = count, "rules reloaded");
                Response::ok(format!("reloaded {count} rules"))
            }
            Request::Update { force } => {
                let outcome = self.updater.run(&self.config, &self.filter, force).await;
                if let Some(r) = &self.resolver
                    && outcome.activated
                {
                    r.cache().clear();
                }
                if outcome.failed.is_empty() && outcome.error.is_none() {
                    Response::ok(outcome.summary())
                } else {
                    Response::error(outcome.summary())
                }
            }
            Request::Allow { domain } => self.modify_user_rules(|r| {
                let d = parse_user_domain(&domain)?;
                r.block.remove(&d);
                Ok(if r.allow.insert(d.clone()) {
                    format!("{d} allowed")
                } else {
                    format!("{d} was already allowed")
                })
            }),
            Request::Block { domain } => self.modify_user_rules(|r| {
                let d = parse_user_domain(&domain)?;
                r.allow.remove(&d);
                Ok(if r.block.insert(d.clone()) {
                    format!("{d} blocked")
                } else {
                    format!("{d} was already blocked")
                })
            }),
            Request::RemoveAllow { domain } => self.modify_user_rules(|r| {
                let d = parse_user_domain(&domain)?;
                if r.allow.remove(&d) {
                    Ok(format!("{d} removed from allowlist"))
                } else {
                    Err(format!("{d} is not in the allowlist"))
                }
            }),
            Request::RemoveBlock { domain } => self.modify_user_rules(|r| {
                let d = parse_user_domain(&domain)?;
                if r.block.remove(&d) {
                    Ok(format!("{d} removed from blocklist"))
                } else {
                    Err(format!("{d} is not in the blocklist"))
                }
            }),
            Request::SetEnabled { enabled } => {
                self.filter.set_enabled(enabled);
                if let Some(r) = &self.resolver {
                    r.cache().clear();
                }
                tracing::info!(enabled, "filtering toggled");
                Response::ok(if enabled {
                    "filtering resumed"
                } else {
                    "filtering paused"
                })
            }
        }
    }

    /// Triggers the background updater immediately.
    pub fn request_update(&self) {
        self.update_now.notify_one();
    }

    pub fn socket_path(&self) -> PathBuf {
        self.paths.socket.clone()
    }
}

/// Tells systemd the service is ready (Type=notify). No-op elsewhere.
pub fn notify_ready() {
    #[cfg(target_os = "linux")]
    {
        use std::os::linux::net::SocketAddrExt;
        use std::os::unix::net::{SocketAddr as UnixAddr, UnixDatagram};
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return;
        };
        let path = path.to_string_lossy().into_owned();
        let addr = if let Some(abstract_name) = path.strip_prefix('@') {
            UnixAddr::from_abstract_name(abstract_name.as_bytes())
        } else {
            UnixAddr::from_pathname(&path)
        };
        if let (Ok(addr), Ok(sock)) = (addr, UnixDatagram::unbound()) {
            let _ = sock.send_to_addr(b"READY=1", &addr);
        }
    }
}

/// Runs the daemon until SIGTERM/SIGINT. SIGHUP reloads rules.
pub async fn run(config: Config, paths: Paths) -> Result<()> {
    run_with(config, paths, StartOptions::default()).await
}

/// Like [`run`], with startup options (privilege dropping).
pub async fn run_with(config: Config, paths: Paths, options: StartOptions) -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } == 0 && !paths.user_mode && options.drop_privileges.is_none() {
        tracing::warn!(
            "running as root; the installed service runs under a dedicated unprivileged account"
        );
    }
    let running = Daemon::start_with(config, paths, None, options).await?;
    notify_ready();
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut hup = signal(SignalKind::hangup())?;
    loop {
        tokio::select! {
            _ = term.recv() => break,
            _ = int.recv() => break,
            _ = hup.recv() => {
                let resp = running.daemon.handle(Request::Reload, true).await;
                tracing::info!(?resp, "SIGHUP");
            }
        }
    }
    tracing::info!("shutting down");
    running.shutdown().await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not root: nothing to drop, and the call must not touch credentials.
    /// (Skipped as root, where it would really drop this test process's
    /// privileges.)
    #[test]
    fn dropping_privileges_is_a_no_op_for_non_root() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let before = unsafe { (libc::getuid(), libc::getgid()) };
        assert!(drop_privileges(12345, 12345).is_ok());
        assert_eq!(before, unsafe { (libc::getuid(), libc::getgid()) });
    }
}
