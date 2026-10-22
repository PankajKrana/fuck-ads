//! Command-line definitions.

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "fuck-ads",
    version,
    about = "System-wide ad and tracker blocking for Linux and macOS",
    long_about = "FuckAds blocks ads and trackers for the whole system (DNS) and inside \
                  browsers (extension). Run `sudo fuck-ads enable` to turn it on.",
    after_help = "Common commands:\n  sudo fuck-ads enable     Turn protection on (survives reboots)\n  \
                  fuck-ads status          Show what is running\n  fuck-ads doctor          Diagnose problems\n  \
                  sudo fuck-ads allow X    Never block site X"
)]
pub struct Cli {
    /// Use this configuration file instead of the system one.
    #[arg(long, global = true, env = "FUCK_ADS_CONFIG", value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Use per-user paths (no root needed; for development or browser-only use).
    #[arg(long, global = true)]
    pub user: bool,

    /// Machine-readable JSON output.
    #[arg(long, global = true)]
    pub json: bool,

    /// Disable colored output (also honors NO_COLOR).
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Show protection status.
    Status,
    /// Turn protection on: start the service at boot and route system DNS through it.
    Enable,
    /// Turn protection off: restore the previous DNS settings and stop the service.
    Disable,
    /// Start the service (and re-apply DNS settings if protection is enabled).
    Start,
    /// Stop the service (system DNS settings are restored while stopped).
    Stop,
    /// Restart the service (applies configuration changes).
    Restart,
    /// Stop apps from bypassing system DNS (hardcoded resolvers, DNS-over-HTTPS).
    EnforceDns(EnforceDnsArgs),
    /// Use the local filtering proxy as the system proxy (macOS), or show how.
    Proxy(ProxyArgs),
    /// Temporarily stop filtering without changing system settings.
    Pause,
    /// Resume filtering after `pause`.
    Resume,
    /// Download filter-list updates now.
    Update(UpdateArgs),
    /// Show filter lists and rule counts.
    Rules,
    /// Explain whether a domain or URL is blocked, and why.
    Check(CheckArgs),
    /// Show blocking statistics.
    Stats(StatsArgs),
    /// Show service logs.
    Logs(LogsArgs),
    /// Show or validate the configuration.
    Config(ConfigArgs),
    /// Diagnose installation and configuration problems.
    Doctor,
    /// Never block a domain (and its subdomains).
    Allow(DomainArg),
    /// Always block a domain (and its subdomains).
    Block(DomainArg),
    /// Remove a domain from the allowlist.
    RemoveAllow(DomainArg),
    /// Remove a domain from the blocklist.
    RemoveBlock(DomainArg),
    /// List allowed domains.
    Allowlist,
    /// List blocked domains.
    Blocklist,
    /// Browser integration (native messaging host, Safari export).
    Browser(BrowserArgs),
    /// Remove FuckAds from this computer.
    Uninstall(UninstallArgs),
    /// Run the daemon in the foreground (used by systemd/launchd).
    #[command(hide = true)]
    Daemon,
    /// Route system DNS through the daemon if it answers, restore it if not
    /// (run by the service manager when the daemon starts or stops).
    #[command(name = "_sync-dns", hide = true)]
    SyncDns,
    /// Browser native-messaging host (started by the browser).
    #[command(hide = true)]
    NativeHost {
        /// Arguments passed by the browser (origin / manifest path).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[derive(Debug, Args)]
pub struct ProxyArgs {
    #[command(subcommand)]
    pub action: ProxyAction,
}

#[derive(Debug, Subcommand)]
pub enum ProxyAction {
    /// Point every network service at the proxy's PAC file (macOS). The
    /// previous settings are saved and restored by `off`.
    On,
    /// Restore the previous system proxy settings.
    Off,
    /// Show whether the proxy is running and whether the system uses it.
    Status,
    /// Print the PAC URL and what `on` would change, without changing anything.
    Show,
}

#[derive(Debug, Args)]
pub struct EnforceDnsArgs {
    #[command(subcommand)]
    pub action: EnforceDnsAction,
}

#[derive(Debug, Subcommand)]
pub enum EnforceDnsAction {
    /// Load firewall rules that refuse plain DNS, DNS-over-TLS and well-known
    /// DNS-over-HTTPS servers for every account except FuckAds's.
    On,
    /// Remove those rules.
    Off,
    /// Show whether the rules are loaded.
    Status,
    /// Print the rules that `on` would load, without loading anything.
    Show,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Re-download everything and accept large rule-count drops.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct CheckArgs {
    /// Domain (`ads.example.com`) or URL (`https://example.com/ad.js`).
    pub target: String,
    /// For URLs: the page that made the request.
    #[arg(long)]
    pub source: Option<String>,
    /// For URLs: resource type (script, image, stylesheet, xmlhttprequest, sub_frame, ...).
    #[arg(long, value_name = "TYPE")]
    pub r#type: Option<String>,
}

#[derive(Debug, Args)]
pub struct StatsArgs {
    #[command(subcommand)]
    pub action: Option<StatsAction>,
    /// Aggregate over the last N days (default: today).
    #[arg(long, default_value_t = 1)]
    pub days: u32,
}

#[derive(Debug, Subcommand)]
pub enum StatsAction {
    /// Delete all statistics.
    Reset,
}

#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Keep printing new log lines.
    #[arg(short, long)]
    pub follow: bool,
    /// Number of lines to show.
    #[arg(short = 'n', long, default_value_t = 100)]
    pub lines: usize,
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub action: Option<ConfigAction>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigAction {
    /// Print the effective configuration (default).
    Show,
    /// Print the configuration file path.
    Path,
    /// Check the configuration file for errors.
    Validate,
    /// Print the default configuration file.
    Default,
}

#[derive(Debug, Args)]
pub struct DomainArg {
    pub domain: String,
}

#[derive(Debug, Args)]
pub struct BrowserArgs {
    #[command(subcommand)]
    pub action: BrowserAction,
}

#[derive(Debug, Subcommand)]
pub enum BrowserAction {
    /// Register the native messaging host for installed browsers.
    Install {
        /// Register system-wide for all users (requires root).
        #[arg(long)]
        system: bool,
        /// Additional allowed extension IDs (e.g. store-assigned IDs).
        #[arg(long = "extension-id", value_name = "ID")]
        extension_ids: Vec<String>,
    },
    /// Remove native messaging host registrations.
    Uninstall {
        #[arg(long)]
        system: bool,
    },
    /// Show browser integration status.
    Status,
    /// Export Safari content-blocker rules (JSON) to a file.
    ExportSafari {
        /// Output file.
        output: PathBuf,
    },
}

#[derive(Debug, Args)]
pub struct UninstallArgs {
    /// Do not ask for confirmation.
    #[arg(short, long)]
    pub yes: bool,
    /// Also delete the configuration file.
    #[arg(long)]
    pub purge: bool,
}
