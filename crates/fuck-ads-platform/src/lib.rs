//! Operating-system integration.
//!
//! Everything that differs between Linux and macOS lives behind the
//! [`Platform`] trait: the service manager (systemd / launchd), the system
//! DNS configuration, log access and browser native-messaging registration.
//! The core daemon never calls into this crate; only the CLI's privileged
//! commands (`enable`, `disable`, `start`, `stop`, `uninstall`) do.
//!
//! Adding Windows later means implementing [`Platform`] once more.

pub mod browser;
pub mod cmd;
pub mod firewall;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;

use anyhow::{Context, Result};
pub use firewall::{FirewallPlan, FirewallState};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Service identifiers, kept in one place.
pub const SYSTEMD_UNIT: &str = "fuck-ads.service";
pub const LAUNCHD_LABEL: &str = "com.fuckads.daemon";
pub const SERVICE_USER_LINUX: &str = "fuck-ads";
pub const SERVICE_USER_MACOS: &str = "_fuck-ads";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStatus {
    Running,
    Stopped,
    NotInstalled,
}

/// Saved copy of `/etc/resolv.conf`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResolvBackup {
    /// The file was a symlink to this target.
    pub symlink: Option<PathBuf>,
    /// Otherwise, its content (None if it did not exist).
    pub content: Option<String>,
}

/// How system DNS was changed by `enable`, so `disable` can undo exactly
/// that. Persisted in a root-only file before any change is made.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum DnsBackup {
    /// A systemd-resolved drop-in was created.
    Resolved { dropin: PathBuf },
    /// NetworkManager was told not to manage resolv.conf.
    NetworkManager {
        dropin: PathBuf,
        resolv: ResolvBackup,
    },
    /// `/etc/resolv.conf` was rewritten.
    ResolvConf { resolv: ResolvBackup },
    /// macOS: previous DNS servers per network service (empty = DHCP).
    MacOs {
        services: Vec<(String, Vec<String>)>,
    },
}

/// One network service's automatic-proxy (PAC) setting before FuckAds changed
/// it (macOS).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceProxy {
    pub service: String,
    pub url: Option<String>,
    pub enabled: bool,
}

/// The system proxy settings replaced by `fuck-ads proxy on`, so `off` can put
/// back exactly what was there.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyBackup {
    pub services: Vec<ServiceProxy>,
}

/// Whether the system is configured to use FuckAds's PAC file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyConfigState {
    Active,
    /// Not configured; the string describes what was found.
    Inactive(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemState {
    /// The user ran `enable` (and not `disable`).
    pub enabled: bool,
    pub dns: Option<DnsBackup>,
    /// The rules are currently loaded (`fuck-ads enforce-dns on`). Cleared
    /// while the service is stopped, so the rules never outlive the resolver
    /// they depend on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<FirewallState>,
    /// The user wants DNS bypass protection; `start` re-applies it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enforce_dns: bool,
    /// System proxy settings replaced by `fuck-ads proxy on` (to restore).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxyBackup>,
    /// The user wants the system to use the FuckAds proxy; `start` re-applies it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub proxy_intent: bool,
}

impl SystemState {
    pub fn load(path: &Path) -> Result<SystemState> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("corrupt state file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SystemState::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
        }
    }

    /// Saves with root-only permissions (the file drives privileged restores).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fuck_ads_config::fs::ensure_dir(dir, 0o755)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        fuck_ads_config::fs::write_atomic(path, &bytes, 0o600)
            .with_context(|| format!("cannot write {}", path.display()))
    }
}

/// Where logs can be read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogSource {
    /// Run this command (journalctl) and stream its output.
    Command(String, Vec<String>),
    File(PathBuf),
}

/// Result of inspecting the system DNS configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsConfigState {
    /// System resolver points at FuckAds.
    Active,
    /// Configured elsewhere; the string describes what was found.
    Inactive(String),
}

pub trait Platform {
    fn name(&self) -> &'static str;

    fn service_status(&self) -> ServiceStatus;
    /// Starts the service and enables it at boot.
    fn service_start(&self) -> Result<()>;
    /// Stops the service and disables it at boot.
    fn service_stop(&self) -> Result<()>;
    fn service_restart(&self) -> Result<()>;
    fn service_file(&self) -> PathBuf;

    /// Points the system resolver at `listen`. Returns the backup needed to
    /// undo the change; it is persisted by the caller *before* this runs via
    /// [`Platform::plan_dns`].
    fn plan_dns(&self, listen: &[SocketAddr]) -> Result<DnsBackup>;
    fn apply_dns(&self, plan: &DnsBackup, listen: &[SocketAddr]) -> Result<()>;
    fn restore_dns(&self, backup: &DnsBackup) -> Result<()>;
    /// Static inspection of the configuration (complements the live probe).
    fn dns_config_state(&self, listen: &[SocketAddr]) -> DnsConfigState;
    fn flush_dns_cache(&self) {}

    /// Whether the system proxy can be configured from here (macOS only;
    /// Linux has no universal system proxy setting).
    fn proxy_supported(&self) -> bool {
        false
    }
    /// Records the current proxy settings of every network service. Changes
    /// nothing.
    fn proxy_plan(&self, _pac_url: &str) -> Result<ProxyBackup> {
        anyhow::bail!("configuring the system proxy is not supported on this platform")
    }
    /// Points every network service at the PAC file.
    fn proxy_apply(&self, _plan: &ProxyBackup, _pac_url: &str) -> Result<()> {
        anyhow::bail!("configuring the system proxy is not supported on this platform")
    }
    fn proxy_restore(&self, _backup: &ProxyBackup) -> Result<()> {
        Ok(())
    }
    fn proxy_config_state(&self, _pac_url: &str) -> ProxyConfigState {
        ProxyConfigState::Inactive("not supported on this platform".into())
    }

    /// The firewall rules that would be loaded, for `enforce-dns show`.
    /// `None` where DNS bypass protection is unsupported.
    fn firewall_rules(&self, _plan: &FirewallPlan) -> Option<String> {
        None
    }
    /// Loads the DNS bypass rules (see [`firewall`]). Must not change
    /// anything unless the rules validate first.
    fn firewall_apply(&self, _plan: &FirewallPlan) -> Result<FirewallState> {
        anyhow::bail!("DNS bypass protection is not supported on this platform")
    }
    /// Removes exactly what [`Platform::firewall_apply`] loaded. Succeeds if
    /// nothing is loaded.
    fn firewall_remove(&self, _state: &FirewallState) -> Result<()> {
        Ok(())
    }
    /// Whether the rules are currently loaded (needs root).
    fn firewall_active(&self) -> bool {
        false
    }

    fn log_source(&self, paths: &fuck_ads_config::Paths, follow: bool, lines: usize) -> LogSource;

    /// Installs the service: service account, directories, default
    /// configuration and the unit/plist pointing at `exe`. Idempotent.
    fn install_service(&self, exe: &Path) -> Result<()>;

    /// Removes service files and the service account (used by uninstall).
    fn remove_service(&self) -> Result<()>;
}

/// The path the service definition should reference. Homebrew runs binaries
/// from a versioned Cellar directory; the service must use the stable
/// `<prefix>/bin/fuck-ads` symlink so upgrades keep working.
pub fn stable_exe_path(exe: &Path) -> PathBuf {
    let s = exe.to_string_lossy();
    if let Some(idx) = s.find("/Cellar/fuck-ads/") {
        let prefix = &s[..idx];
        let candidate = PathBuf::from(format!("{prefix}/bin/fuck-ads"));
        if candidate.exists() {
            return candidate;
        }
    }
    exe.to_path_buf()
}

/// Renders a service template, substituting the executable path.
pub fn render_service_template(template: &str, exe: &Path) -> Result<String> {
    let exe = exe.to_string_lossy();
    // The path ends up in a unit file / plist: refuse anything that could
    // break their syntax.
    if exe
        .chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | '&' | '"' | '\\' | '%' | '$'))
    {
        anyhow::bail!("unsupported characters in executable path {exe:?}");
    }
    Ok(template.replace("/usr/local/bin/fuck-ads", &exe))
}

/// Writes the default configuration if none exists yet.
pub fn ensure_default_config(path: &Path) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        fuck_ads_config::fs::ensure_dir(dir, 0o755)?;
    }
    fuck_ads_config::fs::write_atomic(path, fuck_ads_config::DEFAULT_CONFIG_TOML.as_bytes(), 0o644)
        .with_context(|| format!("cannot write {}", path.display()))
}

/// chown via libc (no shell).
pub fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: `c` is a valid NUL-terminated path.
    if unsafe { libc::chown(c.as_ptr(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot chown {}", path.display()));
    }
    Ok(())
}

/// Looks up a user's uid and primary gid.
pub fn user_ids(name: &str) -> Option<(u32, u32)> {
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer to static storage or NULL; we copy
    // the fields out immediately. Only called from single-threaded CLI code.
    unsafe {
        let pw = libc::getpwnam(c.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some(((*pw).pw_uid, (*pw).pw_gid))
        }
    }
}

/// The implementation for the running OS.
pub fn current() -> Box<dyn Platform> {
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::Linux)
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOs)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        compile_error!("FuckAds currently supports Linux and macOS");
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}

/// Loopback addresses that a system resolver configuration can point to.
pub fn resolver_addresses(listen: &[SocketAddr]) -> Vec<SocketAddr> {
    listen
        .iter()
        .copied()
        .filter(|a| a.ip().is_loopback())
        .collect()
}

/// Supported CPU architectures.
pub fn arch_supported() -> bool {
    matches!(std::env::consts::ARCH, "x86_64" | "aarch64")
}

/// Rendering helpers for resolv.conf.
pub fn render_resolv_conf(listen: &[SocketAddr]) -> String {
    let mut out = String::from(
        "# Generated by FuckAds (`fuck-ads enable`).\n\
         # The previous configuration is saved; `sudo fuck-ads disable` restores it.\n",
    );
    for addr in resolver_addresses(listen) {
        out.push_str(&format!("nameserver {}\n", addr.ip()));
    }
    out.push_str("options edns0 trust-ad\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sub/system-state.json");
        let state = SystemState {
            enabled: true,
            dns: Some(DnsBackup::MacOs {
                services: vec![
                    ("Wi-Fi".into(), vec![]),
                    ("Ethernet".into(), vec!["1.1.1.1".into()]),
                ],
            }),
            firewall: Some(FirewallState {
                pf_token: Some("42".into()),
            }),
            enforce_dns: true,
            proxy: Some(ProxyBackup {
                services: vec![ServiceProxy {
                    service: "Wi-Fi".into(),
                    url: Some("http://corp.example/proxy.pac".into()),
                    enabled: true,
                }],
            }),
            proxy_intent: true,
        };
        state.save(&path).unwrap();
        assert_eq!(SystemState::load(&path).unwrap(), state);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            SystemState::load(&dir.path().join("missing")).unwrap(),
            SystemState::default()
        );
    }

    #[test]
    fn old_state_files_without_firewall_still_load() {
        let state: SystemState = serde_json::from_str(r#"{"enabled": true, "dns": null}"#).unwrap();
        assert!(state.enabled);
        assert_eq!(state.firewall, None);
        assert!(!state.enforce_dns);
        assert_eq!(state.proxy, None);
        assert!(!state.proxy_intent);
    }

    #[test]
    fn unit_hooks_use_the_installed_binary() {
        let unit = render_service_template(
            include_str!("../../../platforms/linux/fuck-ads.service"),
            Path::new("/usr/bin/fuck-ads"),
        )
        .unwrap();
        assert!(!unit.contains("/usr/local/bin"));
        assert!(unit.contains("ExecStartPost=-+/usr/bin/fuck-ads _sync-dns\n"));
        assert!(unit.contains("ExecStopPost=-+/usr/bin/fuck-ads _sync-dns\n"));
    }

    #[test]
    fn templates() {
        let out = render_service_template(
            "ExecStart=/usr/local/bin/fuck-ads daemon",
            Path::new("/usr/bin/fuck-ads"),
        )
        .unwrap();
        assert_eq!(out, "ExecStart=/usr/bin/fuck-ads daemon");
        assert!(render_service_template("x", Path::new("/tmp/a$b")).is_err());
        assert!(render_service_template("x", Path::new("/tmp/a</string>")).is_err());
        assert_eq!(
            stable_exe_path(Path::new("/usr/local/bin/fuck-ads")),
            PathBuf::from("/usr/local/bin/fuck-ads")
        );
    }

    #[test]
    fn resolv_conf_rendering() {
        let text =
            render_resolv_conf(&["127.0.0.1:53".parse().unwrap(), "[::1]:53".parse().unwrap()]);
        assert!(text.contains("nameserver 127.0.0.1\n"));
        assert!(text.contains("nameserver ::1\n"));
    }
}
