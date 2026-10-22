//! macOS: launchd service management and DNS configuration via
//! `networksetup`.
//!
//! macOS resolver settings cannot specify a port, so the daemon listens on
//! port 53. macOS refuses to let an unprivileged user bind port 53 on a
//! specific address such as 127.0.0.1 (only the wildcard address is allowed),
//! so the LaunchDaemon starts as root; the daemon binds its sockets first and
//! then switches to the unprivileged `_fuck-ads` account before reading any
//! file or filter list.

use crate::cmd::{run, stdout, succeeds};
use crate::firewall::{FirewallPlan, FirewallState, PF_ANCHOR, render_pf};
use crate::{
    DnsBackup, DnsConfigState, LAUNCHD_LABEL, LogSource, Platform, ProxyBackup, ProxyConfigState,
    SERVICE_USER_MACOS, ServiceProxy, ServiceStatus, resolver_addresses,
};
use anyhow::{Context, Result, bail};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

const LAUNCHCTL: &str = "/bin/launchctl";
const NETWORKSETUP: &str = "/usr/sbin/networksetup";
const PLIST: &str = "/Library/LaunchDaemons/com.fuckads.daemon.plist";
const PFCTL: &str = "/sbin/pfctl";
const PF_RULES_FILE: &str = "/Library/Application Support/FuckAds/enforce-dns.pf";

#[derive(Debug, Default)]
pub struct MacOs;

fn target() -> String {
    format!("system/{LAUNCHD_LABEL}")
}

fn loaded() -> bool {
    succeeds(LAUNCHCTL, &["print", &target()])
}

/// All network services (including disabled ones, so that enabling one
/// later does not silently bypass filtering).
pub fn network_services() -> Result<Vec<String>> {
    let out = stdout(NETWORKSETUP, &["-listallnetworkservices"])?;
    Ok(parse_services(&out))
}

fn parse_services(out: &str) -> Vec<String> {
    out.lines()
        .skip_while(|l| l.starts_with("An asterisk"))
        .map(|l| l.trim_start_matches('*').trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

fn parse_dns_servers(out: &str) -> Vec<String> {
    if out.contains("aren't any DNS Servers") {
        return Vec::new();
    }
    out.lines()
        .map(str::trim)
        .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
        .map(String::from)
        .collect()
}

/// Parses `networksetup -getautoproxyurl` ("URL: ...\nEnabled: Yes").
fn parse_autoproxy(out: &str) -> (Option<String>, bool) {
    let mut url = None;
    let mut enabled = false;
    for line in out.lines() {
        if let Some(v) = line.trim().strip_prefix("URL:") {
            let v = v.trim();
            if !v.is_empty() && v != "(null)" {
                url = Some(v.to_string());
            }
        } else if let Some(v) = line.trim().strip_prefix("Enabled:") {
            enabled = v.trim().eq_ignore_ascii_case("yes");
        }
    }
    (url, enabled)
}

fn get_autoproxy(service: &str) -> Result<ServiceProxy> {
    let out = stdout(NETWORKSETUP, &["-getautoproxyurl", service])?;
    let (url, enabled) = parse_autoproxy(&out);
    Ok(ServiceProxy {
        service: service.to_string(),
        url,
        enabled,
    })
}

/// Only http://loopback PAC URLs are ever written by FuckAds; refuse
/// anything that could smuggle extra arguments or a remote script.
fn valid_pac_url(url: &str) -> bool {
    (url.starts_with("http://127.0.0.1:") || url.starts_with("http://[::1]:"))
        && url.ends_with("/proxy.pac")
        && url
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'/' | b'.' | b'[' | b']'))
}

fn set_autoproxy(service: &str, url: Option<&str>, enabled: bool) -> Result<()> {
    match url {
        Some(u) => {
            run(NETWORKSETUP, &["-setautoproxyurl", service, u])?;
        }
        // Best effort: clear a URL that we set. Older macOS versions reject
        // an empty value, in which case the URL is left stored but disabled.
        None => {
            let _ = run(NETWORKSETUP, &["-setautoproxyurl", service, ""]);
        }
    }
    run(
        NETWORKSETUP,
        &[
            "-setautoproxystate",
            service,
            if enabled { "on" } else { "off" },
        ],
    )?;
    Ok(())
}

fn set_dns(service: &str, servers: &[String]) -> Result<()> {
    let mut args: Vec<&str> = vec!["-setdnsservers", service];
    if servers.is_empty() {
        args.push("Empty"); // revert to DHCP-provided servers
    } else {
        args.extend(servers.iter().map(String::as_str));
    }
    run(NETWORKSETUP, &args)?;
    Ok(())
}

/// Extracts the reference token from `pfctl -E` output ("Token : 123").
fn parse_pf_token(out: &str) -> Option<String> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("Token :"))
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()))
}

impl Platform for MacOs {
    fn name(&self) -> &'static str {
        "macOS"
    }

    fn service_file(&self) -> PathBuf {
        PathBuf::from(PLIST)
    }

    fn service_status(&self) -> ServiceStatus {
        if !Path::new(PLIST).exists() {
            return ServiceStatus::NotInstalled;
        }
        match stdout(LAUNCHCTL, &["print", &target()]) {
            Ok(out) if out.lines().any(|l| l.trim() == "state = running") => ServiceStatus::Running,
            _ => ServiceStatus::Stopped,
        }
    }

    fn service_start(&self) -> Result<()> {
        if !Path::new(PLIST).exists() {
            bail!("the fuck-ads service is not installed; run the installer first");
        }
        run(LAUNCHCTL, &["enable", &target()])?;
        if loaded() {
            run(LAUNCHCTL, &["kickstart", &target()])?;
        } else {
            run(LAUNCHCTL, &["bootstrap", "system", PLIST])
                .context("launchctl could not load the FuckAds daemon")?;
        }
        Ok(())
    }

    fn service_stop(&self) -> Result<()> {
        if loaded() {
            run(LAUNCHCTL, &["bootout", &target()])?;
        }
        // Prevent launchd from starting it at boot.
        let _ = run(LAUNCHCTL, &["disable", &target()]);
        Ok(())
    }

    fn service_restart(&self) -> Result<()> {
        if loaded() {
            run(LAUNCHCTL, &["kickstart", "-k", &target()])?;
            Ok(())
        } else {
            self.service_start()
        }
    }

    fn plan_dns(&self, listen: &[SocketAddr]) -> Result<DnsBackup> {
        let addrs = resolver_addresses(listen);
        if addrs.is_empty() {
            bail!("dns.listen has no loopback address the system resolver could use");
        }
        if addrs.iter().any(|a| a.port() != 53) {
            bail!("macOS resolver settings cannot use a custom port; dns.listen must use port 53");
        }
        let mut services = Vec::new();
        for service in network_services()? {
            let out = stdout(NETWORKSETUP, &["-getdnsservers", &service])?;
            let mut previous = parse_dns_servers(&out);
            // If a stale FuckAds configuration is present, treat it as DHCP.
            previous.retain(|s| !addrs.iter().any(|a| a.ip().to_string() == *s));
            services.push((service, previous));
        }
        if services.is_empty() {
            bail!("no network services found");
        }
        Ok(DnsBackup::MacOs { services })
    }

    fn apply_dns(&self, plan: &DnsBackup, listen: &[SocketAddr]) -> Result<()> {
        let DnsBackup::MacOs { services } = plan else {
            bail!("non-macOS DNS backup on macOS")
        };
        let servers: Vec<String> = resolver_addresses(listen)
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        for (service, _) in services {
            set_dns(service, &servers).with_context(|| format!("cannot set DNS for {service}"))?;
        }
        self.flush_dns_cache();
        Ok(())
    }

    fn restore_dns(&self, backup: &DnsBackup) -> Result<()> {
        let DnsBackup::MacOs { services } = backup else {
            bail!("non-macOS DNS backup on macOS")
        };
        let mut errors = Vec::new();
        // Without the list every service would be skipped and the restore
        // would wrongly report success, dropping the backup.
        let existing = network_services().context("cannot list network services")?;
        for (service, previous) in services {
            if !existing.contains(service) {
                continue; // service was removed meanwhile
            }
            if let Err(e) = set_dns(service, previous) {
                errors.push(format!("{service}: {e}"));
            }
        }
        self.flush_dns_cache();
        if !errors.is_empty() {
            bail!("could not restore DNS for: {}", errors.join("; "));
        }
        Ok(())
    }

    fn dns_config_state(&self, listen: &[SocketAddr]) -> DnsConfigState {
        let ours: Vec<String> = resolver_addresses(listen)
            .iter()
            .map(|a| a.ip().to_string())
            .collect();
        let Ok(services) = network_services() else {
            return DnsConfigState::Inactive("cannot list network services".into());
        };
        let mut missing = Vec::new();
        for service in services {
            let servers = stdout(NETWORKSETUP, &["-getdnsservers", &service])
                .map(|o| parse_dns_servers(&o))
                .unwrap_or_default();
            if !servers.iter().any(|s| ours.contains(s)) {
                missing.push(service);
            }
        }
        if missing.is_empty() {
            DnsConfigState::Active
        } else {
            DnsConfigState::Inactive(format!("not configured for: {}", missing.join(", ")))
        }
    }

    fn proxy_supported(&self) -> bool {
        true
    }

    fn proxy_plan(&self, pac_url: &str) -> Result<ProxyBackup> {
        if !valid_pac_url(pac_url) {
            bail!("refusing to configure an unexpected PAC URL");
        }
        let mut services = Vec::new();
        for service in network_services()? {
            let mut current = get_autoproxy(&service)?;
            // A stale FuckAds setting counts as "nothing was configured".
            if current.url.as_deref() == Some(pac_url) {
                current.url = None;
                current.enabled = false;
            }
            services.push(current);
        }
        if services.is_empty() {
            bail!("no network services found");
        }
        Ok(ProxyBackup { services })
    }

    fn proxy_apply(&self, plan: &ProxyBackup, pac_url: &str) -> Result<()> {
        if !valid_pac_url(pac_url) {
            bail!("refusing to configure an unexpected PAC URL");
        }
        for s in &plan.services {
            set_autoproxy(&s.service, Some(pac_url), true)
                .with_context(|| format!("cannot set the proxy for {}", s.service))?;
        }
        Ok(())
    }

    fn proxy_restore(&self, backup: &ProxyBackup) -> Result<()> {
        let existing = network_services().context("cannot list network services")?;
        let mut errors = Vec::new();
        for s in &backup.services {
            if !existing.contains(&s.service) {
                continue; // service was removed meanwhile
            }
            if let Err(e) = set_autoproxy(&s.service, s.url.as_deref(), s.enabled) {
                errors.push(format!("{}: {e}", s.service));
            }
        }
        if !errors.is_empty() {
            bail!(
                "could not restore the proxy setting for: {}",
                errors.join("; ")
            );
        }
        Ok(())
    }

    fn proxy_config_state(&self, pac_url: &str) -> ProxyConfigState {
        let Ok(services) = network_services() else {
            return ProxyConfigState::Inactive("cannot list network services".into());
        };
        let missing: Vec<String> = services
            .into_iter()
            .filter(|s| {
                !get_autoproxy(s)
                    .map(|p| p.enabled && p.url.as_deref() == Some(pac_url))
                    .unwrap_or(false)
            })
            .collect();
        if missing.is_empty() {
            ProxyConfigState::Active
        } else {
            ProxyConfigState::Inactive(format!("not configured for: {}", missing.join(", ")))
        }
    }

    fn firewall_rules(&self, plan: &FirewallPlan) -> Option<String> {
        Some(render_pf(plan))
    }

    fn firewall_apply(&self, plan: &FirewallPlan) -> Result<FirewallState> {
        let file = Path::new(PF_RULES_FILE);
        if let Some(dir) = file.parent() {
            fuck_ads_config::fs::ensure_dir(dir, 0o755)?;
        }
        fuck_ads_config::fs::write_atomic(file, render_pf(plan).as_bytes(), 0o644)
            .context("cannot write the pf rules file")?;
        // Parse-only check first: nothing is loaded unless the rules are valid.
        run(PFCTL, &["-n", "-a", PF_ANCHOR, "-f", PF_RULES_FILE])
            .context("pf rejected the generated rules")?;
        run(PFCTL, &["-a", PF_ANCHOR, "-f", PF_RULES_FILE])
            .context("could not load the FuckAds pf anchor")?;
        // Reference-counted enable: other tools that enabled pf keep it on.
        let out = run(PFCTL, &["-E"]).context("could not enable pf")?;
        let text = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(FirewallState {
            pf_token: parse_pf_token(&text),
        })
    }

    fn firewall_remove(&self, state: &FirewallState) -> Result<()> {
        // Flush only our anchor; never the main ruleset.
        let flushed = run(PFCTL, &["-a", PF_ANCHOR, "-F", "all"]);
        if let Some(token) = &state.pf_token {
            let _ = run(PFCTL, &["-X", token]);
        }
        let _ = std::fs::remove_file(PF_RULES_FILE);
        flushed.map(|_| ())
    }

    fn firewall_active(&self) -> bool {
        stdout(PFCTL, &["-a", PF_ANCHOR, "-sr"])
            .map(|o| o.contains("fuck_ads_doh4"))
            .unwrap_or(false)
    }

    fn flush_dns_cache(&self) {
        let _ = run("/usr/bin/dscacheutil", &["-flushcache"]);
        let _ = run("/usr/bin/killall", &["-HUP", "mDNSResponder"]);
    }

    fn log_source(
        &self,
        paths: &fuck_ads_config::Paths,
        _follow: bool,
        _lines: usize,
    ) -> LogSource {
        LogSource::File(
            paths
                .log_file
                .clone()
                .unwrap_or_else(|| PathBuf::from("/Library/Logs/FuckAds/fuck-ads.log")),
        )
    }

    fn install_service(&self, exe: &Path) -> Result<()> {
        const TEMPLATE: &str = include_str!("../../../platforms/macos/com.fuckads.daemon.plist");
        const NEWSYSLOG: &str = include_str!("../../../platforms/macos/newsyslog-fuck-ads.conf");
        if crate::user_ids(SERVICE_USER_MACOS).is_none() {
            create_service_account()?;
        }
        let (uid, gid) = crate::user_ids(SERVICE_USER_MACOS)
            .context("service account missing after creation")?;
        let base = Path::new("/Library/Application Support/FuckAds");
        fuck_ads_config::fs::ensure_dir(base, 0o755)?;
        for dir in [base.join("data"), PathBuf::from("/Library/Logs/FuckAds")] {
            fuck_ads_config::fs::ensure_dir(&dir, 0o755)?;
            crate::chown(&dir, uid, gid)?;
        }
        crate::ensure_default_config(&base.join("config.toml"))?;
        fuck_ads_config::fs::write_atomic(
            Path::new("/etc/newsyslog.d/fuck-ads.conf"),
            NEWSYSLOG.as_bytes(),
            0o644,
        )?;
        let plist = crate::render_service_template(TEMPLATE, exe)?;
        fuck_ads_config::fs::write_atomic(Path::new(PLIST), plist.as_bytes(), 0o644)?;
        crate::chown(Path::new(PLIST), 0, 0)?;
        Ok(())
    }

    fn remove_service(&self) -> Result<()> {
        if loaded() {
            let _ = run(LAUNCHCTL, &["bootout", &target()]);
        }
        let _ = run(LAUNCHCTL, &["enable", &target()]); // clear the disabled override
        if Path::new(PLIST).exists() {
            std::fs::remove_file(PLIST).context("cannot remove LaunchDaemon plist")?;
        }
        let user_path = format!("/Users/{SERVICE_USER_MACOS}");
        let group_path = format!("/Groups/{SERVICE_USER_MACOS}");
        if succeeds("/usr/bin/dscl", &[".", "-read", &user_path]) {
            let _ = run("/usr/bin/dscl", &[".", "-delete", &user_path]);
        }
        if succeeds("/usr/bin/dscl", &[".", "-read", &group_path]) {
            let _ = run("/usr/bin/dscl", &[".", "-delete", &group_path]);
        }
        Ok(())
    }
}

/// Creates the hidden `_fuck-ads` user and group with the first free ID in
/// the 400-499 system range.
fn create_service_account() -> Result<()> {
    let used = |kind: &str, attr: &str| -> Result<Vec<u32>> {
        let out = stdout("/usr/bin/dscl", &[".", "-list", kind, attr])?;
        Ok(out
            .lines()
            .filter_map(|l| l.split_whitespace().last()?.parse().ok())
            .collect())
    };
    let users = used("/Users", "UniqueID")?;
    let groups = used("/Groups", "PrimaryGroupID")?;
    let id = (400..500)
        .find(|id| !users.contains(id) && !groups.contains(id))
        .context("no free system user ID in 400-499")?
        .to_string();
    let group = format!("/Groups/{SERVICE_USER_MACOS}");
    let user = format!("/Users/{SERVICE_USER_MACOS}");
    let dscl =
        |args: &[&str]| run("/usr/bin/dscl", &[&[".", "-create"][..], args].concat()).map(|_| ());
    dscl(&[&group])?;
    dscl(&[&group, "PrimaryGroupID", &id])?;
    dscl(&[&group, "RealName", "FuckAds"])?;
    dscl(&[&group, "Password", "*"])?;
    dscl(&[&user])?;
    dscl(&[&user, "UniqueID", &id])?;
    dscl(&[&user, "PrimaryGroupID", &id])?;
    dscl(&[&user, "UserShell", "/usr/bin/false"])?;
    dscl(&[&user, "NFSHomeDirectory", "/var/empty"])?;
    dscl(&[&user, "RealName", "FuckAds"])?;
    dscl(&[&user, "Password", "*"])?;
    dscl(&[&user, "IsHidden", "1"])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autoproxy_parsing() {
        assert_eq!(
            parse_autoproxy("URL: http://127.0.0.1:8118/proxy.pac\nEnabled: Yes\n"),
            (Some("http://127.0.0.1:8118/proxy.pac".to_string()), true)
        );
        assert_eq!(parse_autoproxy("URL: (null)\nEnabled: No\n"), (None, false));
        assert_eq!(
            parse_autoproxy("URL: http://corp/proxy.pac\nEnabled: No\n"),
            (Some("http://corp/proxy.pac".to_string()), false)
        );
    }

    #[test]
    fn pac_urls_are_restricted_to_loopback() {
        assert!(valid_pac_url("http://127.0.0.1:8118/proxy.pac"));
        assert!(valid_pac_url("http://[::1]:8118/proxy.pac"));
        for bad in [
            "http://evil.example/proxy.pac",
            "https://127.0.0.1:8118/proxy.pac",
            "http://127.0.0.1:8118/other.pac",
            "http://127.0.0.1:8118/proxy.pac;rm",
            "http://127.0.0.1:8118/proxy.pac -x",
            "http://127.0.0.1.evil.example:8118/proxy.pac",
            "-setautoproxyurl",
        ] {
            assert!(!valid_pac_url(bad), "{bad}");
        }
    }

    #[test]
    fn pf_token_parsing() {
        assert_eq!(
            parse_pf_token("pf enabled\nToken : 14735192827\n").as_deref(),
            Some("14735192827")
        );
        assert_eq!(parse_pf_token("pf already enabled"), None);
        assert_eq!(parse_pf_token("Token : abc; rm -rf /"), None);
    }

    #[test]
    fn parsing() {
        let out = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN\n";
        assert_eq!(
            parse_services(out),
            vec!["Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN"]
        );
        assert!(parse_dns_servers("There aren't any DNS Servers set on Wi-Fi.").is_empty());
        assert_eq!(
            parse_dns_servers("1.1.1.1\n2606:4700::1111\n"),
            vec!["1.1.1.1", "2606:4700::1111"]
        );
    }
}
