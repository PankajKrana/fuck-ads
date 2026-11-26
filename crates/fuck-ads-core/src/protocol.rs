//! Control-API protocol: newline-delimited JSON over a Unix domain socket.
//!
//! The same protocol is used by the CLI, the browser native-messaging host
//! and (in future) a GUI. Each request is one JSON object on one line; each
//! response likewise.

use fuck_ads_filter::{CosmeticResult, ResourceType, ScriptletRule};
use serde::{Deserialize, Serialize};

/// Largest accepted request line.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    // --- read-only (any local user) ---
    Status,
    /// `top_blocked` is only filled in for privileged peers.
    Stats {
        #[serde(default)]
        days: Option<u32>,
    },
    Rules,
    Check {
        domain: String,
    },
    CheckUrl {
        url: String,
        #[serde(default)]
        source: Option<String>,
        #[serde(default)]
        resource_type: Option<ResourceType>,
    },
    // --- browser integration (read-only) ---
    BrowserHello {
        browser: String,
        #[serde(default)]
        version: String,
    },
    Cosmetic {
        hostname: String,
        #[serde(default)]
        classes: Vec<String>,
        #[serde(default)]
        ids: Vec<String>,
        #[serde(default)]
        complex: bool,
    },
    DnrRules {
        #[serde(default)]
        offset: usize,
        #[serde(default = "default_page")]
        limit: usize,
    },
    Scriptlets,
    SafariRules,
    // --- privileged (root or the service account) ---
    // The user lists and blocked domains reveal which sites people visit.
    ListAllow,
    ListBlock,
    StatsReset,
    Reload,
    Update {
        #[serde(default)]
        force: bool,
    },
    Allow {
        domain: String,
    },
    Block {
        domain: String,
    },
    RemoveAllow {
        domain: String,
    },
    RemoveBlock {
        domain: String,
    },
    SetEnabled {
        enabled: bool,
    },
}

fn default_page() -> usize {
    2_000
}

impl Request {
    /// Requests that change state and therefore require privileges.
    pub fn is_privileged(&self) -> bool {
        matches!(
            self,
            Request::ListAllow
                | Request::ListBlock
                | Request::StatsReset
                | Request::Reload
                | Request::Update { .. }
                | Request::Allow { .. }
                | Request::Block { .. }
                | Request::RemoveAllow { .. }
                | Request::RemoveBlock { .. }
                | Request::SetEnabled { .. }
        )
    }

    /// Requests the browser native-messaging host may forward.
    pub fn is_browser_safe(&self) -> bool {
        matches!(
            self,
            Request::Status
                | Request::BrowserHello { .. }
                | Request::Cosmetic { .. }
                | Request::DnrRules { .. }
                | Request::Scriptlets
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Response {
    Ok {
        message: String,
    },
    Error {
        message: String,
    },
    Status(Box<StatusInfo>),
    Stats(StatsInfo),
    List(Vec<String>),
    Rules(Vec<ListStatus>),
    Check(CheckInfo),
    Cosmetic(CosmeticResult),
    Dnr {
        revision: u64,
        total: usize,
        rules: Vec<serde_json::Value>,
    },
    Scriptlets {
        revision: u64,
        rules: Vec<ScriptletRule>,
    },
    Safari {
        revision: u64,
        rules: Vec<serde_json::Value>,
    },
}

impl Response {
    pub fn ok(message: impl Into<String>) -> Self {
        Response::Ok {
            message: message.into(),
        }
    }
    pub fn error(message: impl Into<String>) -> Self {
        Response::Error {
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct StatusInfo {
    pub version: String,
    pub platform: String,
    pub pid: u32,
    pub uptime_secs: u64,
    /// Filtering active (the protection toggle).
    pub filtering: bool,
    pub dns_enabled: bool,
    pub dns_listen: Vec<String>,
    pub dns_upstreams: Vec<String>,
    pub last_upstream_success: Option<u64>,
    pub rule_count: usize,
    pub dns_rule_count: usize,
    pub list_count: usize,
    pub queries_today: u64,
    pub blocked_today: u64,
    pub ads_today: u64,
    pub trackers_today: u64,
    pub last_update: Option<u64>,
    pub last_update_error: Option<String>,
    pub next_update: Option<u64>,
    pub update_in_progress: bool,
    /// Addresses the local filtering proxy listens on (empty when off).
    #[serde(default)]
    pub proxy_listen: Vec<String>,
    pub browser_enabled: bool,
    pub browser_last_seen: Option<u64>,
    pub browser_name: Option<String>,
    /// Increments whenever effective rules change; browser clients use it
    /// to know when to refetch.
    pub revision: u64,
    pub cache_entries: usize,
    pub now: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct StatsInfo {
    pub days: u32,
    pub queries: u64,
    pub blocked: u64,
    pub ads: u64,
    pub trackers: u64,
    pub malware: u64,
    pub other_blocked: u64,
    pub cache_hits: u64,
    pub upstream_failures: u64,
    pub top_blocked: Vec<(String, u64)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ListStatus {
    pub name: String,
    pub enabled: bool,
    pub category: String,
    pub source: String,
    pub rules: usize,
    pub unsupported: usize,
    pub invalid: usize,
    pub last_success: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CheckInfo {
    pub input: String,
    pub blocked: bool,
    /// Human-readable reason ("user allowlist", "rule ||x^ from easylist").
    pub reason: String,
    pub list: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_format() {
        let r: Request = serde_json::from_str(r#"{"cmd":"allow","domain":"example.com"}"#).unwrap();
        assert_eq!(
            r,
            Request::Allow {
                domain: "example.com".into()
            }
        );
        assert!(r.is_privileged());
        let r: Request = serde_json::from_str(r#"{"cmd":"dnr_rules"}"#).unwrap();
        assert_eq!(
            r,
            Request::DnrRules {
                offset: 0,
                limit: 2000
            }
        );
        assert!(r.is_browser_safe());
        let text = serde_json::to_string(&Response::List(vec!["a".into()])).unwrap();
        assert_eq!(text, r#"{"type":"list","data":["a"]}"#);
        assert!(serde_json::from_str::<Request>(r#"{"cmd":"rm_rf"}"#).is_err());
    }
}
