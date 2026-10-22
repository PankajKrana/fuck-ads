//! Shared state for command execution: resolved paths, configuration,
//! output style and control-API helpers.

use crate::output::{DnsRouting, Style};
use anyhow::{Result, anyhow, bail};
use fuck_ads_config::{Config, Paths};
use fuck_ads_core::control::{self, ControlError};
use fuck_ads_core::protocol::{Request, Response};
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::time::Duration;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15);
/// Updates download several lists; allow plenty of time.
pub const UPDATE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug, Clone)]
pub struct Ctx {
    pub paths: Paths,
    pub json: bool,
    pub style: Style,
    /// Configuration file was given explicitly (`--config` / env).
    pub explicit_config: bool,
}

impl Ctx {
    pub fn new(config: Option<PathBuf>, user: bool, json: bool, no_color: bool) -> Result<Ctx> {
        let explicit_config = config.is_some();
        let mut paths = if user {
            Paths::user()?
        } else {
            Paths::system()
        };
        // Developer convenience: with no system service, talk to a per-user
        // daemon if one is running. Never as root: privileged commands would
        // then keep the system DNS backup in a user's home directory.
        if !user
            && !explicit_config
            && !fuck_ads_platform::is_root()
            && !paths.socket.exists()
            && let Ok(user_paths) = Paths::user()
            && user_paths.socket.exists()
        {
            paths = user_paths;
        }
        if let Some(c) = config {
            paths.config_file = c;
        }
        let mut ctx = Ctx {
            paths,
            json,
            style: Style::detect(no_color || json),
            explicit_config,
        };
        // Apply [paths] overrides if the configuration is readable.
        if let Ok(cfg) = ctx.config() {
            ctx.paths.apply_overrides(&cfg.paths);
        }
        Ok(ctx)
    }

    /// Loads and validates the configuration file (defaults if missing).
    pub fn config(&self) -> Result<Config> {
        Ok(Config::load(&self.paths.config_file)?)
    }

    pub async fn request(&self, req: Request) -> Result<Response, ControlError> {
        let timeout = if matches!(req, Request::Update { .. }) {
            UPDATE_TIMEOUT
        } else {
            DEFAULT_TIMEOUT
        };
        control::request(&self.paths.socket, &req, timeout).await
    }

    /// Sends a request and converts `Response::Error` into an error.
    pub async fn call(&self, req: Request) -> Result<Response> {
        match self.request(req).await {
            Ok(Response::Error { message }) => Err(anyhow!(message)),
            Ok(r) => Ok(r),
            Err(ControlError::NotRunning(_)) => {
                bail!(
                    "the FuckAds service is not running. Start it with:\n\n    sudo fuck-ads start"
                )
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn print_json<T: serde::Serialize>(&self, value: &T) -> Result<()> {
        println!("{}", serde_json::to_string_pretty(value)?);
        Ok(())
    }
}

/// Determines whether the OS resolver routes through FuckAds by resolving
/// the probe name through the normal system path (getaddrinfo).
pub async fn system_dns_routing() -> DnsRouting {
    let lookup = tokio::task::spawn_blocking(|| {
        (fuck_ads_dns::PROBE_NAME, 0)
            .to_socket_addrs()
            .map(|addrs| {
                addrs
                    .into_iter()
                    .any(|a| a.ip() == std::net::IpAddr::V4(fuck_ads_dns::PROBE_ADDR))
            })
    });
    match tokio::time::timeout(Duration::from_secs(4), lookup).await {
        Ok(Ok(Ok(true))) => DnsRouting::Active,
        Ok(Ok(Ok(false))) | Ok(Ok(Err(_))) => DnsRouting::NotRouted,
        _ => DnsRouting::Unknown,
    }
}

/// Checks that general name resolution through the system works.
pub async fn system_resolution_works() -> bool {
    let lookup = tokio::task::spawn_blocking(|| {
        ["example.com:443", "cloudflare.com:443", "google.com:443"]
            .iter()
            .any(|h| {
                h.to_socket_addrs()
                    .map(|mut a| a.next().is_some())
                    .unwrap_or(false)
            })
    });
    matches!(
        tokio::time::timeout(Duration::from_secs(10), lookup).await,
        Ok(Ok(true))
    )
}
