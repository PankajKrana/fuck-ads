//! Privileged commands that change system configuration.
//!
//! Safety rules:
//! * The backup needed to undo a DNS change is saved *before* the change.
//! * After changing DNS, resolution is verified; if the system can no longer
//!   resolve names, the change is rolled back immediately.
//! * The system resolver is only pointed at FuckAds while the service is
//!   running (`stop` restores DNS; `start` re-applies it).

use crate::cli::{EnforceDnsAction, ProxyAction};
use crate::context::{Ctx, system_dns_routing, system_resolution_works};
use crate::output::DnsRouting;
use anyhow::{Context, Result, bail};
use fuck_ads_core::protocol::{Request, Response};
use fuck_ads_platform::{
    FirewallPlan, Platform, ProxyConfigState, ServiceStatus, SystemState, browser,
};
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, Instant};

fn require_root(command: &str) -> Result<()> {
    if !fuck_ads_platform::is_root() {
        bail!(
            "this changes system settings and requires administrator rights:\n\n    sudo fuck-ads {command}"
        );
    }
    Ok(())
}

fn step(ctx: &Ctx, msg: &str) {
    if !ctx.json {
        println!("{} {msg}", ctx.style.green("✓"));
    }
}

/// Addresses the system resolver may be pointed at: those configured in the
/// root-owned configuration that the daemon actually bound. The daemon runs
/// unprivileged, so its report alone is never trusted for what root writes
/// into system DNS settings.
fn trusted_listen(config: &fuck_ads_config::Config, reported: &[SocketAddr]) -> Vec<SocketAddr> {
    config
        .listen_addrs()
        .into_iter()
        .filter(|a| a.ip().is_loopback() && reported.contains(a))
        .collect()
}

/// Waits until the daemon answers on its control socket and (if DNS is
/// enabled) on its DNS listener. Returns the listener addresses.
async fn wait_healthy(ctx: &Ctx, timeout: Duration) -> Result<Vec<SocketAddr>> {
    let deadline = Instant::now() + timeout;
    let mut last_error = String::from("no response");
    while Instant::now() < deadline {
        match ctx.request(Request::Status).await {
            Ok(Response::Status(s)) => {
                if !s.dns_enabled {
                    return Ok(Vec::new());
                }
                let addrs: Vec<SocketAddr> =
                    s.dns_listen.iter().filter_map(|a| a.parse().ok()).collect();
                for addr in &addrs {
                    if fuck_ads_dns::probe(*addr, Duration::from_secs(2)).await {
                        return Ok(addrs);
                    }
                }
                last_error = format!(
                    "DNS listener on {} is not answering",
                    s.dns_listen.join(", ")
                );
            }
            Ok(other) => last_error = format!("{other:?}"),
            Err(e) => last_error = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    bail!(
        "the FuckAds service did not become ready: {last_error}\n\nSee `fuck-ads logs` for details."
    )
}

async fn verify_routing(platform: &dyn Platform) -> DnsRouting {
    for _ in 0..8 {
        platform.flush_dns_cache();
        if system_dns_routing().await == DnsRouting::Active {
            return DnsRouting::Active;
        }
        tokio::time::sleep(Duration::from_millis(750)).await;
    }
    system_dns_routing().await
}

/// Points system DNS at the daemon, verifying and rolling back on failure.
async fn apply_dns(
    ctx: &Ctx,
    platform: &dyn Platform,
    state: &mut SystemState,
    listen: &[SocketAddr],
) -> Result<()> {
    let state_file = ctx.paths.system_state_file();
    let plan = match &state.dns {
        Some(existing) => existing.clone(),
        None => {
            let plan = platform.plan_dns(listen)?;
            state.dns = Some(plan.clone());
            state.save(&state_file)?; // persist the backup first
            plan
        }
    };
    if let Err(e) = platform.apply_dns(&plan, listen) {
        let _ = platform.restore_dns(&plan);
        state.dns = None;
        state.save(&state_file)?;
        return Err(e.context("could not change system DNS settings; previous settings restored"));
    }

    match verify_routing(platform).await {
        DnsRouting::Active => step(ctx, "System DNS now uses FuckAds"),
        _ if system_resolution_works().await => {
            println!(
                "{} System DNS was configured, but lookups do not appear to pass through FuckAds.\n  \
                 A VPN or other DNS software may be overriding it. Run `fuck-ads doctor`.",
                ctx.style.yellow("!")
            );
        }
        _ => {
            platform
                .restore_dns(&plan)
                .context("DNS verification failed AND restoring previous settings failed")?;
            platform.flush_dns_cache();
            state.dns = None;
            state.save(&state_file)?;
            bail!(
                "name resolution stopped working after switching DNS to FuckAds, so the previous \
                 settings were restored. Check `fuck-ads logs` and `fuck-ads doctor`."
            );
        }
    }
    Ok(())
}

fn restore_dns(ctx: &Ctx, platform: &dyn Platform, state: &mut SystemState) -> Result<()> {
    if let Some(backup) = state.dns.clone() {
        platform.restore_dns(&backup)?;
        platform.flush_dns_cache();
        state.dns = None;
        state.save(&ctx.paths.system_state_file())?;
        step(ctx, "Previous DNS settings restored");
    }
    Ok(())
}

/// Removes the DNS bypass rules if they were loaded. Always done *before*
/// DNS settings are restored or the service stops, so the original resolvers
/// are never blocked by our own rules.
fn remove_firewall(ctx: &Ctx, platform: &dyn Platform, state: &mut SystemState) -> Result<()> {
    if let Some(fw) = state.firewall.clone() {
        platform.firewall_remove(&fw)?;
        state.firewall = None;
        state.save(&ctx.paths.system_state_file())?;
        step(ctx, "DNS bypass protection removed");
    }
    Ok(())
}

fn service_uid() -> Option<u32> {
    let name = if cfg!(target_os = "macos") {
        fuck_ads_platform::SERVICE_USER_MACOS
    } else {
        fuck_ads_platform::SERVICE_USER_LINUX
    };
    fuck_ads_platform::user_ids(name).map(|(uid, _)| uid)
}

/// Loads the bypass rules, verifying that name resolution still works and
/// rolling back otherwise.
async fn apply_firewall(
    ctx: &Ctx,
    platform: &dyn Platform,
    state: &mut SystemState,
    plan: &FirewallPlan,
) -> Result<()> {
    let state_file = ctx.paths.system_state_file();
    // Persist first: if anything below fails half-way, `off`, `stop` and
    // `uninstall` still know there may be rules to remove.
    state.firewall = Some(fuck_ads_platform::FirewallState::default());
    state.save(&state_file)?;
    let loaded = match platform.firewall_apply(plan) {
        Ok(loaded) => loaded,
        Err(e) => {
            let _ = platform.firewall_remove(&Default::default());
            state.firewall = None;
            state.save(&state_file)?;
            return Err(e.context("DNS bypass protection was not enabled"));
        }
    };
    state.firewall = Some(loaded.clone());
    state.save(&state_file)?;

    if !platform.firewall_active() || !system_resolution_works().await {
        let _ = platform.firewall_remove(&loaded);
        state.firewall = None;
        state.save(&state_file)?;
        bail!(
            "name resolution stopped working (or the rules did not load) after enabling DNS              bypass protection, so it was removed again. Run `fuck-ads doctor`."
        );
    }
    step(ctx, "DNS bypass protection is on");
    Ok(())
}

pub async fn enforce_dns(ctx: &Ctx, action: &EnforceDnsAction) -> Result<()> {
    let platform = fuck_ads_platform::current();
    match action {
        EnforceDnsAction::Show => {
            // A placeholder uid is fine here: nothing is loaded.
            let uid = service_uid().unwrap_or_else(|| {
                eprintln!("note: the FuckAds service account is not installed yet; showing uid 0");
                0
            });
            let rules = platform
                .firewall_rules(&FirewallPlan { daemon_uid: uid })
                .context("DNS bypass protection is not supported on this platform")?;
            print!("{rules}");
            Ok(())
        }
        EnforceDnsAction::Status => {
            require_root("enforce-dns status")?;
            let state = SystemState::load(&ctx.paths.system_state_file())?;
            let recorded = state.firewall.is_some();
            let active = platform.firewall_active();
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({ "recorded": recorded, "active": active })
                );
            } else if active {
                println!("DNS bypass protection: on");
            } else if recorded {
                println!(
                    "DNS bypass protection: recorded as on, but the rules are not loaded \
                     (they are lost at reboot). Re-apply with: sudo fuck-ads enforce-dns on"
                );
            } else {
                println!("DNS bypass protection: off");
            }
            Ok(())
        }
        EnforceDnsAction::Off => {
            require_root("enforce-dns off")?;
            let _lock = StateLock::acquire(ctx)?;
            let mut state = SystemState::load(&ctx.paths.system_state_file())?;
            if state.firewall.is_none() && !platform.firewall_active() {
                if state.enforce_dns {
                    state.enforce_dns = false;
                    state.save(&ctx.paths.system_state_file())?;
                }
                println!("DNS bypass protection is already off.");
                return Ok(());
            }
            let fw = state.firewall.clone().unwrap_or_default();
            platform.firewall_remove(&fw)?;
            state.firewall = None;
            state.enforce_dns = false;
            state.save(&ctx.paths.system_state_file())?;
            step(ctx, "DNS bypass protection removed");
            Ok(())
        }
        EnforceDnsAction::On => {
            require_root("enforce-dns on")?;
            let _lock = StateLock::acquire(ctx)?;
            let mut state = SystemState::load(&ctx.paths.system_state_file())?;
            let Some(uid) = service_uid() else {
                bail!(
                    "the FuckAds service account does not exist; run `sudo fuck-ads enable` first"
                );
            };
            // Refusing resolvers is only safe while the system resolver goes
            // through FuckAds; otherwise the machine would lose DNS.
            if !state.enabled || system_dns_routing().await != DnsRouting::Active {
                bail!(
                    "system DNS is not routed through FuckAds, so refusing other resolvers would \
                     break name resolution. Run `sudo fuck-ads enable` and check `fuck-ads doctor` first."
                );
            }
            apply_firewall(
                ctx,
                platform.as_ref(),
                &mut state,
                &FirewallPlan { daemon_uid: uid },
            )
            .await?;
            if !ctx.json {
                println!(
                    "\nApps can no longer reach public DNS servers directly; they fall back to the \
                     system resolver.\nThe rules do not survive a reboot. Re-run this command (or \
                     `sudo fuck-ads start`) afterwards.\nRemove them with: sudo fuck-ads enforce-dns off"
                );
            }
            Ok(())
        }
    }
}

/// Restores the system proxy settings if `fuck-ads proxy on` changed them.
/// Done before DNS is restored and before the service stops, so no client is
/// left pointing at a proxy that is about to disappear.
fn remove_proxy_setting(ctx: &Ctx, platform: &dyn Platform, state: &mut SystemState) -> Result<()> {
    if let Some(backup) = state.proxy.clone() {
        platform.proxy_restore(&backup)?;
        state.proxy = None;
        state.save(&ctx.paths.system_state_file())?;
        step(ctx, "Previous system proxy settings restored");
    }
    Ok(())
}

/// The PAC URL of the running proxy, or `None` if the daemon is not running
/// or the proxy is off.
async fn proxy_pac_url(ctx: &Ctx) -> Option<(SocketAddr, String)> {
    let Ok(Response::Status(s)) = ctx.request(Request::Status).await else {
        return None;
    };
    let addr: SocketAddr = s.proxy_listen.iter().find_map(|a| a.parse().ok())?;
    Some((addr, format!("http://{addr}/proxy.pac")))
}

/// Whether the proxy at `addr` really serves its PAC file.
async fn pac_served(addr: SocketAddr) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let attempt = async {
        let mut s = tokio::net::TcpStream::connect(addr).await.ok()?;
        s.write_all(b"GET /proxy.pac HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut out = Vec::new();
        s.take(16 * 1024).read_to_end(&mut out).await.ok()?;
        let text = String::from_utf8_lossy(&out);
        (text.starts_with("HTTP/1.1 200") && text.contains("FindProxyForURL")).then_some(())
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(3), attempt).await,
        Ok(Some(()))
    )
}

/// Sets the system proxy, verifying and rolling back on failure.
async fn apply_proxy(
    ctx: &Ctx,
    platform: &dyn Platform,
    state: &mut SystemState,
    addr: SocketAddr,
    pac_url: &str,
) -> Result<()> {
    let state_file = ctx.paths.system_state_file();
    // Persist the backup first, like the DNS settings.
    let plan = match &state.proxy {
        Some(existing) => existing.clone(),
        None => {
            let plan = platform.proxy_plan(pac_url)?;
            state.proxy = Some(plan.clone());
            state.save(&state_file)?;
            plan
        }
    };
    let rollback = |state: &mut SystemState| -> Result<()> {
        let result = platform.proxy_restore(&plan);
        state.proxy = None;
        state.save(&state_file)?;
        result
    };
    if let Err(e) = platform.proxy_apply(&plan, pac_url) {
        let _ = rollback(state);
        return Err(
            e.context("could not change the system proxy settings; previous settings restored")
        );
    }
    let active = platform.proxy_config_state(pac_url) == ProxyConfigState::Active;
    if !active || !pac_served(addr).await || !system_resolution_works().await {
        rollback(state)
            .context("verification failed AND restoring the previous proxy settings failed")?;
        bail!(
            "the system proxy could not be verified (settings applied: {active}), so the previous \
             settings were restored. Check `fuck-ads logs` and `fuck-ads doctor`."
        );
    }
    step(ctx, "System proxy now uses FuckAds");
    Ok(())
}

fn print_manual_instructions(pac_url: &str) {
    println!("To use the proxy, point an app or system at this PAC URL:\n\n    {pac_url}\n");
    if cfg!(target_os = "macos") {
        println!(
            "macOS: `sudo fuck-ads proxy on` sets it for every network service \
             (System Settings → Network → Proxies → Automatic Proxy Configuration)."
        );
    } else {
        println!(
            "Linux has no system-wide proxy setting that a service can change safely. Set it in \
             your desktop (GNOME: Settings → Network → Network Proxy → Automatic) or per app, or \
             use it directly: http_proxy=http://127.0.0.1:8118"
        );
    }
}

pub async fn proxy(ctx: &Ctx, action: &ProxyAction) -> Result<()> {
    let platform = fuck_ads_platform::current();
    match action {
        ProxyAction::Show => {
            let config = ctx.config()?;
            let pac_url = match proxy_pac_url(ctx).await {
                Some((_, url)) => url,
                None => {
                    let addr = config
                        .proxy_listen_addrs()
                        .into_iter()
                        .next()
                        .context("proxy.listen has no usable address")?;
                    println!(
                        "The proxy is not running{}.\n",
                        if config.proxy.enabled {
                            ""
                        } else {
                            " ([proxy] enabled = false in the configuration)"
                        }
                    );
                    format!("http://{addr}/proxy.pac")
                }
            };
            print_manual_instructions(&pac_url);
            Ok(())
        }
        ProxyAction::Status => {
            let running = proxy_pac_url(ctx).await;
            let (served, system) = match &running {
                Some((addr, url)) => (
                    pac_served(*addr).await,
                    Some(platform.proxy_config_state(url)),
                ),
                None => (false, None),
            };
            if ctx.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "running": running.is_some(),
                        "pac_served": served,
                        "system_configured": system == Some(ProxyConfigState::Active),
                        "supported": platform.proxy_supported(),
                    })
                );
                return Ok(());
            }
            match (&running, &system) {
                (None, _) => println!(
                    "Proxy: not running. Enable it with `[proxy] enabled = true` in the \
                     configuration, then `sudo fuck-ads restart`."
                ),
                (Some((addr, _)), Some(ProxyConfigState::Active)) => {
                    println!("Proxy: running on {addr}; the system uses it.");
                }
                (Some((addr, _)), Some(ProxyConfigState::Inactive(why))) => {
                    println!("Proxy: running on {addr}; not used by the system ({why}).");
                    if platform.proxy_supported() {
                        println!("Use it with: sudo fuck-ads proxy on");
                    }
                }
                _ => {}
            }
            if running.is_some() && !served {
                println!(
                    "{} the proxy is not answering PAC requests",
                    ctx.style.yellow("!")
                );
            }
            Ok(())
        }
        ProxyAction::Off => {
            require_root("proxy off")?;
            let _lock = StateLock::acquire(ctx)?;
            let mut state = SystemState::load(&ctx.paths.system_state_file())?;
            let had = state.proxy.is_some();
            remove_proxy_setting(ctx, platform.as_ref(), &mut state)?;
            if state.proxy_intent {
                state.proxy_intent = false;
                state.save(&ctx.paths.system_state_file())?;
            }
            if !had {
                println!("The system proxy was not changed by FuckAds; nothing to restore.");
            }
            Ok(())
        }
        ProxyAction::On => {
            require_root("proxy on")?;
            let _lock = StateLock::acquire(ctx)?;
            let config = ctx.config().context("the configuration file is invalid")?;
            if !config.proxy.enabled {
                bail!(
                    "the proxy is off. Set `enabled = true` under [proxy] in the configuration, \
                     then run `sudo fuck-ads restart`."
                );
            }
            let Some((addr, pac_url)) = proxy_pac_url(ctx).await else {
                bail!(
                    "the proxy is not running; run `sudo fuck-ads restart` and check `fuck-ads logs`"
                );
            };
            if !platform.proxy_supported() {
                print_manual_instructions(&pac_url);
                bail!(
                    "`fuck-ads proxy on` is not supported on this platform; see the instructions above"
                );
            }
            if !pac_served(addr).await {
                bail!(
                    "the proxy is listening on {addr} but does not serve its PAC file; see `fuck-ads logs`"
                );
            }
            let mut state = SystemState::load(&ctx.paths.system_state_file())?;
            apply_proxy(ctx, platform.as_ref(), &mut state, addr, &pac_url).await?;
            state.proxy_intent = true;
            state.save(&ctx.paths.system_state_file())?;
            if !ctx.json {
                println!(
                    "\nApps that follow the system proxy now send HTTP/HTTPS through FuckAds. Local \
                     addresses go direct, and the PAC file falls back to DIRECT if the proxy stops.\n\
                     Undo with: sudo fuck-ads proxy off"
                );
            }
            Ok(())
        }
    }
}

pub async fn enable(ctx: &Ctx) -> Result<()> {
    require_root("enable")?;
    let _lock = StateLock::acquire(ctx)?;
    let config = ctx
        .config()
        .context("the configuration file is invalid; fix it before enabling")?;
    let platform = fuck_ads_platform::current();
    let state_file = ctx.paths.system_state_file();
    let mut state = SystemState::load(&state_file)?;

    if platform.service_status() == ServiceStatus::NotInstalled {
        let exe = std::env::current_exe().context("cannot locate the fuck-ads executable")?;
        let exe = fuck_ads_platform::stable_exe_path(&exe);
        platform.install_service(&exe)?;
        step(
            ctx,
            &format!("Service installed ({})", platform.service_file().display()),
        );
        if let Ok(host) = ensure_native_host_link(&exe) {
            let _ = browser::install(&browser::system_locations(), &host, &[], false);
        }
    }
    platform.service_start()?;
    step(ctx, "Service started (and enabled at boot)");
    let listen = trusted_listen(&config, &wait_healthy(ctx, Duration::from_secs(30)).await?);

    if config.dns.enabled {
        apply_dns(ctx, platform.as_ref(), &mut state, &listen).await?;
    } else {
        println!(
            "  DNS filtering is disabled in the configuration; only browser filtering is active."
        );
    }
    state.enabled = true;
    state.save(&state_file)?;

    if !ctx.json {
        println!("\n{} FuckAds is active.", ctx.style.bold("Done."));
        if browser::installed(None).is_empty() {
            println!(
                "For in-page ad blocking (including YouTube), install the browser extension: fuck-ads browser install"
            );
        }
    }
    Ok(())
}

/// Ensures `fuck-ads-native-host` exists next to the binary.
fn ensure_native_host_link(exe: &Path) -> Result<std::path::PathBuf> {
    let host = exe.with_file_name("fuck-ads-native-host");
    if !host.exists() {
        std::os::unix::fs::symlink(exe, &host)?;
    }
    Ok(host)
}

pub async fn disable(ctx: &Ctx) -> Result<()> {
    require_root("disable")?;
    let _lock = StateLock::acquire(ctx)?;
    let platform = fuck_ads_platform::current();
    let state_file = ctx.paths.system_state_file();
    let mut state = SystemState::load(&state_file)?;
    remove_firewall(ctx, platform.as_ref(), &mut state)?;
    remove_proxy_setting(ctx, platform.as_ref(), &mut state)?;
    restore_dns(ctx, platform.as_ref(), &mut state)?;
    platform.service_stop()?;
    step(ctx, "Service stopped (and disabled at boot)");
    state.enabled = false;
    state.enforce_dns = false;
    state.proxy_intent = false;
    state.save(&state_file)?;
    if !ctx.json {
        println!("\nFuckAds is off. Turn it back on with: sudo fuck-ads enable");
    }
    Ok(())
}

pub async fn start(ctx: &Ctx) -> Result<()> {
    require_root("start")?;
    let _lock = StateLock::acquire(ctx)?;
    let platform = fuck_ads_platform::current();
    let state_file = ctx.paths.system_state_file();
    let mut state = SystemState::load(&state_file)?;
    let config = ctx.config().context("the configuration file is invalid")?;
    platform.service_start()?;
    let listen = trusted_listen(&config, &wait_healthy(ctx, Duration::from_secs(30)).await?);
    step(ctx, "Service started");
    if state.enabled && !listen.is_empty() {
        apply_dns(ctx, platform.as_ref(), &mut state, &listen).await?;
        // `stop` removed the bypass rules; bring them back if they were on.
        if state.enforce_dns
            && state.firewall.is_none()
            && let Some(uid) = service_uid()
            && let Err(e) = apply_firewall(
                ctx,
                platform.as_ref(),
                &mut state,
                &FirewallPlan { daemon_uid: uid },
            )
            .await
        {
            eprintln!(
                "{} DNS bypass protection could not be re-applied: {e:#}",
                ctx.style.yellow("!")
            );
        }
        // Likewise the system proxy setting, if the proxy is running again.
        if state.proxy_intent
            && state.proxy.is_none()
            && let Some((addr, pac_url)) = proxy_pac_url(ctx).await
            && let Err(e) = apply_proxy(ctx, platform.as_ref(), &mut state, addr, &pac_url).await
        {
            eprintln!(
                "{} the system proxy setting could not be re-applied: {e:#}",
                ctx.style.yellow("!")
            );
        }
    } else if !state.enabled && !ctx.json {
        println!(
            "  System DNS is unchanged. Run `sudo fuck-ads enable` to route it through FuckAds."
        );
    }
    Ok(())
}

pub async fn stop(ctx: &Ctx) -> Result<()> {
    require_root("stop")?;
    let _lock = StateLock::acquire(ctx)?;
    let platform = fuck_ads_platform::current();
    let mut state = SystemState::load(&ctx.paths.system_state_file())?;
    // Never leave the system pointing at a resolver that is not running, or
    // blocking the resolvers it is about to go back to.
    remove_firewall(ctx, platform.as_ref(), &mut state)?;
    remove_proxy_setting(ctx, platform.as_ref(), &mut state)?;
    restore_dns(ctx, platform.as_ref(), &mut state)?;
    platform.service_stop()?;
    step(ctx, "Service stopped");
    Ok(())
}

pub async fn restart(ctx: &Ctx) -> Result<()> {
    require_root("restart")?;
    let _lock = StateLock::acquire(ctx)?;
    let platform = fuck_ads_platform::current();
    if platform.service_status() == ServiceStatus::NotInstalled {
        bail!("the fuck-ads service is not installed");
    }
    // A daemon that refuses its configuration would leave system DNS
    // pointing at nothing, so check it before taking the running one down.
    let config = ctx
        .config()
        .context("the configuration file is invalid; the running service was left unchanged")?;
    let state_file = ctx.paths.system_state_file();
    let mut state = SystemState::load(&state_file)?;
    platform.service_restart()?;
    let reported = match wait_healthy(ctx, Duration::from_secs(30)).await {
        Ok(reported) => reported,
        Err(e) => {
            fail_open(ctx, platform.as_ref(), &mut state);
            return Err(e);
        }
    };
    step(ctx, "Service restarted");
    // The configuration may have turned DNS filtering off or moved the
    // listener, so make system DNS match what is running now.
    let listen = trusted_listen(&config, &reported);
    if state.enabled && !listen.is_empty() {
        apply_dns(ctx, platform.as_ref(), &mut state, &listen).await?;
    } else if state.dns.is_some() {
        remove_firewall(ctx, platform.as_ref(), &mut state)?;
        restore_dns(ctx, platform.as_ref(), &mut state)?;
    }
    Ok(())
}

/// Puts the system back on its own resolvers when the daemon is not
/// answering, so a broken service never takes name resolution down with it.
/// `state.enabled` is kept: the next successful start routes DNS again. The
/// system proxy setting is left alone because the PAC file already falls
/// back to DIRECT while the proxy is down.
fn fail_open(ctx: &Ctx, platform: &dyn Platform, state: &mut SystemState) {
    // The bypass rules must go first, or they would block the resolvers the
    // system is about to go back to.
    if let Err(e) = remove_firewall(ctx, platform, state) {
        eprintln!("{} {e:#}", ctx.style.red("✗"));
    }
    if let Err(e) = restore_dns(ctx, platform, state) {
        eprintln!("{} {e:#}", ctx.style.red("✗"));
    }
}

/// Run by the service manager whenever the daemon starts or stops
/// (`ExecStartPost`/`ExecStopPost`): routes system DNS through FuckAds while
/// the daemon answers and restores the previous settings while it does not.
/// It does nothing while another fuck-ads command is changing the settings.
pub async fn sync_dns(ctx: &Ctx) -> Result<()> {
    require_root("_sync-dns")?;
    let Some(_lock) = StateLock::try_acquire(ctx)? else {
        return Ok(());
    };
    // At shutdown the settings stay as they are: they are checked again when
    // the service starts at boot, and resolvers cannot be restarted reliably
    // while the system is going down.
    if system_shutting_down() {
        return Ok(());
    }
    let platform = fuck_ads_platform::current();
    let mut state = SystemState::load(&ctx.paths.system_state_file())?;
    if !state.enabled {
        return Ok(());
    }
    let reported = match ctx.request(Request::Status).await {
        Ok(Response::Status(s)) if s.dns_enabled => {
            let addrs: Vec<SocketAddr> =
                s.dns_listen.iter().filter_map(|a| a.parse().ok()).collect();
            let mut answering = Vec::new();
            for addr in addrs {
                if fuck_ads_dns::probe(addr, Duration::from_secs(2)).await {
                    answering.push(addr);
                }
            }
            answering
        }
        _ => Vec::new(),
    };
    let listen = match ctx.config() {
        Ok(config) => trusted_listen(&config, &reported),
        Err(_) => Vec::new(),
    };
    if listen.is_empty() {
        fail_open(ctx, platform.as_ref(), &mut state);
        return Ok(());
    }
    apply_dns(ctx, platform.as_ref(), &mut state, &listen).await?;
    if state.enforce_dns
        && state.firewall.is_none()
        && let Some(uid) = service_uid()
    {
        apply_firewall(
            ctx,
            platform.as_ref(),
            &mut state,
            &FirewallPlan { daemon_uid: uid },
        )
        .await?;
    }
    Ok(())
}

fn system_shutting_down() -> bool {
    cfg!(target_os = "linux")
        && std::process::Command::new("systemctl")
            .arg("is-system-running")
            .output()
            .is_ok_and(|o| o.stdout.starts_with(b"stopping"))
}

/// Serializes the commands that change system DNS settings, including the
/// service manager's `_sync-dns` hooks, through an advisory lock next to the
/// state file. Released when dropped.
struct StateLock(#[allow(dead_code)] std::fs::File);

impl StateLock {
    fn open(ctx: &Ctx) -> Result<std::fs::File> {
        let path = ctx.paths.system_state_file().with_extension("lock");
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("cannot create {}", dir.display()))?;
        }
        std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .with_context(|| format!("cannot open {}", path.display()))
    }

    fn lock(file: &std::fs::File, flags: libc::c_int) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        // SAFETY: flock on a descriptor we own; no memory is passed.
        if unsafe { libc::flock(file.as_raw_fd(), flags) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Waits for the lock.
    fn acquire(ctx: &Ctx) -> Result<StateLock> {
        let file = Self::open(ctx)?;
        Self::lock(&file, libc::LOCK_EX).context("cannot lock the system state")?;
        Ok(StateLock(file))
    }

    /// Takes the lock only if no other command holds it. Never waits: the
    /// service manager runs `_sync-dns` while `start`/`stop` hold the lock
    /// and wait for the service manager.
    fn try_acquire(ctx: &Ctx) -> Result<Option<StateLock>> {
        let file = Self::open(ctx)?;
        match Self::lock(&file, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(()) => Ok(Some(StateLock(file))),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context("cannot lock the system state")),
        }
    }
}

fn confirm(prompt: &str) -> bool {
    print!("{prompt} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).is_ok()
        && matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}

/// Removes a directory tree only if it is one of the expected locations.
fn remove_known_dir(path: &Path, allowed: &[&str]) {
    let s = path.to_string_lossy();
    if !allowed.iter().any(|a| s == *a) {
        return;
    }
    if path.exists() {
        match std::fs::remove_dir_all(path) {
            Ok(()) => println!("removed {}", path.display()),
            Err(e) => eprintln!("could not remove {}: {e}", path.display()),
        }
    }
}

pub async fn uninstall(ctx: &Ctx, yes: bool, purge: bool) -> Result<()> {
    require_root("uninstall")?;
    let _lock = StateLock::acquire(ctx)?;
    if !yes && !confirm("Remove FuckAds and restore the original DNS settings?") {
        println!("Cancelled.");
        return Ok(());
    }
    let platform = fuck_ads_platform::current();
    // Use the built-in system locations, never configurable overrides, for
    // anything that is deleted recursively.
    let system = fuck_ads_config::Paths::system();
    let mut state = SystemState::load(&system.system_state_file()).unwrap_or_default();
    if let Err(e) = remove_firewall(ctx, platform.as_ref(), &mut state) {
        eprintln!(
            "{} could not remove the DNS bypass rules automatically: {e:#}",
            ctx.style.red("✗")
        );
    }
    if let Err(e) = remove_proxy_setting(ctx, platform.as_ref(), &mut state) {
        eprintln!(
            "{} could not restore the system proxy settings automatically: {e:#}",
            ctx.style.red("✗")
        );
    }
    // The state file holds the only copy of the previous DNS settings; it
    // is kept if they could not be put back.
    let dns_restored = match restore_dns(ctx, platform.as_ref(), &mut state) {
        Ok(()) => true,
        Err(e) => {
            eprintln!(
                "{} could not restore DNS automatically: {e:#}\n  The backup of the previous \
                 settings is kept in {}",
                ctx.style.red("✗"),
                system.system_state_file().display()
            );
            false
        }
    };
    platform.remove_service()?;
    step(ctx, "Service removed");
    for p in browser::uninstall(&browser::system_locations()) {
        println!("removed {}", p.display());
    }

    if cfg!(target_os = "macos") {
        let base = "/Library/Application Support/FuckAds";
        remove_known_dir(
            Path::new(&format!("{base}/data")),
            &[&format!("{base}/data")],
        );
        if dns_restored {
            let _ = std::fs::remove_file(format!("{base}/system-state.json"));
        }
        if purge && dns_restored {
            remove_known_dir(Path::new(base), &[base]);
        }
        remove_known_dir(
            Path::new("/Library/Logs/FuckAds"),
            &["/Library/Logs/FuckAds"],
        );
        let _ = std::fs::remove_file("/etc/newsyslog.d/fuck-ads.conf");
    } else {
        if dns_restored {
            remove_known_dir(Path::new("/var/lib/fuck-ads"), &["/var/lib/fuck-ads"]);
        } else {
            remove_known_dir(
                Path::new("/var/lib/fuck-ads/data"),
                &["/var/lib/fuck-ads/data"],
            );
        }
        if purge {
            remove_known_dir(Path::new("/etc/fuck-ads"), &["/etc/fuck-ads"]);
        }
    }
    for share in [
        "/usr/local/share/fuck-ads",
        "/usr/share/fuck-ads",
        "/opt/homebrew/share/fuck-ads",
    ] {
        // Package-managed files are removed by the package manager.
        if share != "/usr/share/fuck-ads" {
            remove_known_dir(Path::new(share), &[share]);
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && exe.starts_with("/usr/local/bin")
    {
        let _ = std::fs::remove_file(exe.with_file_name("fuck-ads-native-host"));
        let _ = std::fs::remove_file(&exe);
        println!("removed {}", exe.display());
    }
    println!(
        "\nFuckAds has been removed.{}",
        if purge {
            ""
        } else {
            " The configuration file was kept (use --purge to delete it)."
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_in(dir: &Path) -> Ctx {
        let mut paths = fuck_ads_config::Paths::system();
        paths.system_dir = dir.to_path_buf();
        Ctx {
            paths,
            json: true,
            style: crate::output::Style { color: false },
            explicit_config: false,
        }
    }

    #[test]
    fn sync_hook_skips_while_another_command_holds_the_state_lock() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = ctx_in(dir.path());
        let held = StateLock::acquire(&ctx).unwrap();
        // flock locks belong to the open file description, so a second open
        // in the same process contends like another process would.
        assert!(StateLock::try_acquire(&ctx).unwrap().is_none());
        drop(held);
        assert!(StateLock::try_acquire(&ctx).unwrap().is_some());
    }

    #[test]
    fn only_configured_loopback_addresses_are_trusted() {
        let config = fuck_ads_config::Config::default();
        let reported: Vec<SocketAddr> = vec![
            "127.0.0.1:53".parse().unwrap(),
            "203.0.113.9:53".parse().unwrap(),
            "127.0.0.1:5353".parse().unwrap(),
        ];
        assert_eq!(
            trusted_listen(&config, &reported),
            vec!["127.0.0.1:53".parse::<SocketAddr>().unwrap()]
        );
    }
}
