//! The `fuck-ads` executable: user-facing CLI, daemon entry point
//! (`fuck-ads daemon`) and browser native-messaging host
//! (`fuck-ads-native-host`, a symlink to the same binary).

pub mod cli;
pub mod commands;
pub mod context;
pub mod doctor;
pub mod logs;
pub mod native_host;
pub mod output;
pub mod system;

use clap::Parser;
use cli::{Cli, Command};
use context::Ctx;
use fuck_ads_config::{Config, Paths};
use std::ffi::OsString;
use std::path::Path;
use std::process::ExitCode;

/// sysexits.h EX_CONFIG: lets service managers distinguish bad configuration.
const EXIT_CONFIG: u8 = 78;

/// True if the browser started us as a native-messaging host.
fn invoked_as_native_host(args: &[OsString]) -> bool {
    let argv0 = args
        .first()
        .map(Path::new)
        .and_then(Path::file_name)
        .and_then(|n| n.to_str());
    if argv0 == Some("fuck-ads-native-host") {
        return true;
    }
    // Chromium passes the caller origin; Firefox passes the manifest path
    // and the extension ID.
    args.get(1).and_then(|a| a.to_str()).is_some_and(|a| {
        a.starts_with("chrome-extension://")
            || (a.ends_with(".json") && a.contains(fuck_ads_platform::browser::NATIVE_HOST_NAME))
    })
}

fn init_tracing(level: &str, log_file: Option<&Path>) {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt::writer::MakeWriterExt;
    let filter = EnvFilter::try_from_env("FUCK_ADS_LOG").unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "{level},hyper=warn,hyper_util=warn,reqwest=warn,rustls=warn,h2=warn"
        ))
    });
    // journald adds its own timestamps.
    let journald = std::env::var_os("JOURNAL_STREAM").is_some();
    // SAFETY: isatty has no preconditions.
    let tty = unsafe { libc::isatty(2) } == 1;
    let file = log_file.and_then(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .ok()
            .map(std::sync::Arc::new)
    });
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    match (file, journald) {
        (Some(f), _) => builder
            .with_ansi(false)
            .with_writer(std::io::stderr.and(f))
            .init(),
        (None, true) => builder
            .with_ansi(false)
            .without_time()
            .with_writer(std::io::stderr)
            .init(),
        (None, false) => builder.with_ansi(tty).with_writer(std::io::stderr).init(),
    }
}

fn run_daemon(cli: &Cli) -> ExitCode {
    let mut paths = if cli.user {
        match Paths::user() {
            Ok(p) => p,
            Err(e) => {
                eprintln!("fuck-ads: {e}");
                return ExitCode::from(EXIT_CONFIG);
            }
        }
    } else {
        Paths::system()
    };
    if let Some(c) = &cli.config {
        paths.config_file = c.clone();
    }
    let config = match Config::load(&paths.config_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fuck-ads: {e}");
            return ExitCode::from(EXIT_CONFIG);
        }
    };
    paths.apply_overrides(&config.paths);
    if paths.user_mode {
        let _ = fuck_ads_config::fs::ensure_dir(&paths.data_dir, 0o700);
    }
    init_tracing(
        &config.general.log_level,
        paths
            .user_mode
            .then_some(paths.log_file.as_deref())
            .flatten(),
    );
    tracing::info!(version = env!("CARGO_PKG_VERSION"), config = %paths.config_file.display(), "FuckAds starting");

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fuck-ads: cannot start runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    // The installed macOS service starts as root only so that it can bind
    // port 53 on loopback; the daemon gives root up right after binding.
    let service_user = if cfg!(target_os = "macos") {
        fuck_ads_platform::SERVICE_USER_MACOS
    } else {
        fuck_ads_platform::SERVICE_USER_LINUX
    };
    let drop_privileges = if fuck_ads_platform::is_root() && !paths.user_mode {
        let ids = fuck_ads_platform::user_ids(service_user);
        if ids.is_none() {
            tracing::warn!(service_user, "service account not found; staying root");
        }
        ids
    } else {
        None
    };
    let options = fuck_ads_core::StartOptions { drop_privileges };
    match rt.block_on(fuck_ads_core::run_with(config, paths, options)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn dispatch(cli: Cli, ctx: Ctx) -> anyhow::Result<ExitCode> {
    use fuck_ads_core::protocol::Request;
    let done = |r: anyhow::Result<()>| r.map(|()| ExitCode::SUCCESS);
    match &cli.command {
        Command::Status => commands::status(&ctx).await,
        Command::Enable => done(system::enable(&ctx).await),
        Command::Disable => done(system::disable(&ctx).await),
        Command::Start => done(system::start(&ctx).await),
        Command::Stop => done(system::stop(&ctx).await),
        Command::Restart => done(system::restart(&ctx).await),
        Command::SyncDns => done(system::sync_dns(&ctx).await),
        Command::Proxy(a) => done(system::proxy(&ctx, &a.action).await),
        Command::EnforceDns(a) => done(system::enforce_dns(&ctx, &a.action).await),
        Command::Pause => {
            done(commands::simple(&ctx, Request::SetEnabled { enabled: false }).await)
        }
        Command::Resume => {
            done(commands::simple(&ctx, Request::SetEnabled { enabled: true }).await)
        }
        Command::Update(a) => done(commands::update(&ctx, a.force).await),
        Command::Rules => done(commands::rules(&ctx).await),
        Command::Check(a) => done(commands::check(&ctx, a).await),
        Command::Stats(a) => done(commands::stats(&ctx, a).await),
        Command::Logs(a) => done(logs::logs(&ctx, a.follow, a.lines)),
        Command::Config(a) => done(commands::config(&ctx, a.action.as_ref())),
        Command::Doctor => doctor::doctor(&ctx).await,
        Command::Allow(d) => done(
            commands::simple(
                &ctx,
                Request::Allow {
                    domain: d.domain.clone(),
                },
            )
            .await,
        ),
        Command::Block(d) => done(
            commands::simple(
                &ctx,
                Request::Block {
                    domain: d.domain.clone(),
                },
            )
            .await,
        ),
        Command::RemoveAllow(d) => done(
            commands::simple(
                &ctx,
                Request::RemoveAllow {
                    domain: d.domain.clone(),
                },
            )
            .await,
        ),
        Command::RemoveBlock(d) => done(
            commands::simple(
                &ctx,
                Request::RemoveBlock {
                    domain: d.domain.clone(),
                },
            )
            .await,
        ),
        Command::Allowlist => done(commands::list(&ctx, Request::ListAllow, "Allowlist").await),
        Command::Blocklist => done(commands::list(&ctx, Request::ListBlock, "Blocklist").await),
        Command::Browser(a) => done(commands::browser(&ctx, &a.action).await),
        Command::Uninstall(a) => done(system::uninstall(&ctx, a.yes, a.purge).await),
        Command::Daemon | Command::NativeHost { .. } => unreachable!("handled before dispatch"),
    }
}

/// Entry point with explicit arguments (used by `main` and tests).
pub fn main_with_args(args: Vec<OsString>) -> ExitCode {
    if invoked_as_native_host(&args) {
        return match native_host::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::FAILURE,
        };
    }
    let cli = match Cli::try_parse_from(&args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return ExitCode::from(if e.use_stderr() { 2 } else { 0 });
        }
    };
    match cli.command {
        Command::Daemon => return run_daemon(&cli),
        Command::NativeHost { .. } => {
            return if native_host::run().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        _ => {}
    }
    let ctx = match Ctx::new(cli.config.clone(), cli.user, cli.json, cli.no_color) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("fuck-ads: {e:#}");
            return ExitCode::FAILURE;
        }
    };
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("fuck-ads: {e}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(dispatch(cli, ctx)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {e:#}", Style::detect(false).red("error:"));
            ExitCode::FAILURE
        }
    }
}

use output::Style;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_host_detection() {
        let a = |v: &[&str]| v.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(invoked_as_native_host(&a(&[
            "/usr/local/bin/fuck-ads-native-host"
        ])));
        assert!(invoked_as_native_host(&a(&[
            "fuck-ads",
            "chrome-extension://abc/"
        ])));
        assert!(invoked_as_native_host(&a(&[
            "fuck-ads",
            "/x/com.fuckads.native.json",
            "fuck-ads@fuck-ads.local"
        ])));
        assert!(!invoked_as_native_host(&a(&["fuck-ads", "status"])));
        assert!(!invoked_as_native_host(&a(&["fuck-ads", "config.json"])));
    }

    #[test]
    fn parses_all_commands() {
        for args in [
            &["fuck-ads", "status"][..],
            &["fuck-ads", "enable"],
            &["fuck-ads", "stats", "reset"],
            &["fuck-ads", "stats", "--days", "7"],
            &["fuck-ads", "logs", "--follow"],
            &["fuck-ads", "logs", "-n", "20"],
            &["fuck-ads", "allow", "example.com"],
            &["fuck-ads", "remove-block", "example.com"],
            &["fuck-ads", "config", "validate"],
            &[
                "fuck-ads",
                "check",
                "https://x.com/a.js",
                "--type",
                "script",
            ],
            &["fuck-ads", "browser", "install", "--extension-id", "abc"],
            &["fuck-ads", "--json", "doctor"],
            &["fuck-ads", "uninstall", "--yes", "--purge"],
        ] {
            Cli::try_parse_from(args).unwrap_or_else(|e| panic!("{args:?}: {e}"));
        }
        assert!(Cli::try_parse_from(["fuck-ads", "frobnicate"]).is_err());
        assert!(Cli::try_parse_from(["fuck-ads", "allow"]).is_err());
    }
}
