//! Query processing: local answers, filtering, cache, upstream forwarding.

use crate::cache::{CacheKey, DnsCache};
use crate::upstream::{BootstrapResolver, UpstreamClient, UpstreamError, plain_exchange, rand_id};
use fuck_ads_config::{BlockingMode, Config, Upstream};
use fuck_ads_filter::Category;
use fuck_ads_filter::domain::{is_same_or_subdomain, normalize_hostname};
use fuck_ads_stats::{Outcome, StatsStore};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, SOA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

/// EDNS payload size we advertise and accept (DNS Flag Day 2020).
pub const EDNS_PAYLOAD: u16 = 1232;

/// Filtering decision for a hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Block { domain: String, category: Category },
}

/// The policy consulted for each query. Implemented by the daemon on top of
/// the filter engine and user allow/block lists; kept as a trait so the DNS
/// layer has no knowledge of how rules are stored or updated.
pub trait QueryFilter: Send + Sync + 'static {
    fn check(&self, host: &str) -> Decision;

    /// Whether the user explicitly allowed `host`; such names skip CNAME
    /// uncloaking, or the user could never unblock a cloaked site.
    fn explicitly_allowed(&self, _host: &str) -> bool {
        false
    }
}

/// Settings derived from [`Config`].
#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub upstreams: Vec<Upstream>,
    pub bootstrap: Vec<SocketAddr>,
    pub blocking_mode: BlockingMode,
    pub blocked_ttl: u32,
    pub cache_size: usize,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub timeout: Duration,
    pub block_private_ptr: bool,
    pub forward_zones: Vec<(String, Vec<SocketAddr>)>,
    pub log_blocked: bool,
}

impl ResolverConfig {
    pub fn from_config(c: &Config) -> Self {
        ResolverConfig {
            upstreams: c.upstreams(),
            bootstrap: c.bootstrap_addrs(),
            blocking_mode: c.dns.blocking_mode,
            blocked_ttl: c.dns.blocked_ttl,
            cache_size: c.dns.cache_size,
            cache_min_ttl: c.dns.cache_min_ttl,
            cache_max_ttl: c.dns.cache_max_ttl,
            timeout: Duration::from_millis(c.dns.timeout_ms),
            block_private_ptr: c.dns.block_private_ptr,
            forward_zones: c.forward_zones(),
            log_blocked: c.privacy.log_blocked,
        }
    }
}

/// Health counters exposed through the control API.
#[derive(Debug, Default)]
pub struct Metrics {
    pub queries: AtomicU64,
    pub blocked: AtomicU64,
    pub upstream_errors: AtomicU64,
    /// Unix time of the last successful upstream exchange.
    pub last_upstream_success: AtomicU64,
}

/// Special-use names answered locally and never sent upstream (RFC 6761,
/// RFC 6762, RFC 8375) unless covered by a forward zone.
const LOCAL_ZONES: &[&str] = &[
    "local",
    "home.arpa",
    "lan",
    "internal",
    "localdomain",
    "invalid",
    "test",
];

/// Name answered with [`PROBE_ADDR`], letting tools verify that the system
/// resolver is actually routed through this server.
pub const PROBE_NAME: &str = "fuck-ads-probe.test";
pub const PROBE_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 209);

/// Firefox disables its built-in DoH when this name does not resolve, so
/// that network-level filtering (this resolver) keeps working.
const FIREFOX_DOH_CANARY: &str = "use-application-dns.net";

pub struct Resolver {
    cfg: ResolverConfig,
    upstreams: Vec<UpstreamClient>,
    preferred: AtomicUsize,
    cache: DnsCache,
    filter: Arc<dyn QueryFilter>,
    stats: Arc<StatsStore>,
    pub metrics: Metrics,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("upstreams", &self.upstreams.len())
            .finish()
    }
}

/// Protocol the query arrived on; determines the response size limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
}

impl Resolver {
    pub fn new(
        cfg: ResolverConfig,
        filter: Arc<dyn QueryFilter>,
        stats: Arc<StatsStore>,
    ) -> Result<Self, UpstreamError> {
        let bootstrap = BootstrapResolver::new(cfg.bootstrap.clone(), cfg.timeout);
        let upstreams = cfg
            .upstreams
            .iter()
            .map(|u| match u {
                Upstream::Https { url, .. } => {
                    UpstreamClient::https(url, bootstrap.clone(), cfg.timeout)
                }
                Upstream::Plain(addr) => Ok(UpstreamClient::Plain { addr: *addr }),
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Resolver {
            cache: DnsCache::new(cfg.cache_size, cfg.cache_min_ttl, cfg.cache_max_ttl),
            cfg,
            upstreams,
            preferred: AtomicUsize::new(0),
            filter,
            stats,
            metrics: Metrics::default(),
        })
    }

    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    pub fn upstream_names(&self) -> Vec<String> {
        self.upstreams
            .iter()
            .map(UpstreamClient::describe)
            .collect()
    }

    /// Processes one wire-format query and returns the wire-format response,
    /// or `None` if the packet should be dropped.
    pub async fn handle(&self, request: &[u8], transport: Transport) -> Option<Vec<u8>> {
        let req = match Message::from_vec(request) {
            Ok(m) => m,
            Err(_) if request.len() >= 12 => {
                // Echo the ID so the client fails fast instead of timing out.
                let id = u16::from_be_bytes([request[0], request[1]]);
                let resp = Message::error_msg(id, OpCode::Query, ResponseCode::FormErr);
                return resp.to_vec().ok();
            }
            Err(_) => return None,
        };
        if req.metadata.message_type != MessageType::Query {
            return None;
        }
        self.metrics.queries.fetch_add(1, Ordering::Relaxed);

        let max_len = match transport {
            Transport::Tcp => usize::from(u16::MAX),
            Transport::Udp => req.edns.as_ref().map_or(512, |e| {
                usize::from(e.max_payload().clamp(512, EDNS_PAYLOAD))
            }),
        };

        if req.metadata.op_code != OpCode::Query {
            return self.finalize(self.error(&req, ResponseCode::NotImp), &req, max_len);
        }
        if req.queries.len() != 1 {
            return self.finalize(self.error(&req, ResponseCode::FormErr), &req, max_len);
        }
        let query = req.queries[0].clone();
        let raw_name = query.name().to_ascii();
        let host = normalize_hostname(&raw_name);

        if let Some(host) = &host {
            if let Some(resp) = self.local_answer(&req, &query, host) {
                self.stats.record(Outcome::Allowed { cached: false });
                return self.finalize(resp, &req, max_len);
            }
            if query.query_class() == DNSClass::IN
                && let Decision::Block { domain, category } = self.filter.check(host)
            {
                return self.finalize(self.blocked(&req, &query, &domain, category), &req, max_len);
            }
        }

        let dnssec_ok = req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        let key = CacheKey {
            name: raw_name.to_ascii_lowercase(),
            qtype: u16::from(query.query_type()),
            qclass: u16::from(query.query_class()),
            dnssec_ok,
            checking_disabled: req.metadata.checking_disabled,
        };
        if let Some(cached) = self.cache.get(&key) {
            self.stats.record(Outcome::Allowed { cached: true });
            return self.finalize(cached, &req, max_len);
        }

        let zone_servers = host.as_deref().and_then(|h| self.forward_zone(h));
        let response = match zone_servers {
            Some(servers) => self.forward_plain(&req, &query, servers).await,
            None => self.forward(&req, &query).await,
        };
        let Some(response) = response else {
            self.metrics.upstream_errors.fetch_add(1, Ordering::Relaxed);
            self.stats.record(Outcome::UpstreamFailure);
            return self.finalize(self.error(&req, ResponseCode::ServFail), &req, max_len);
        };

        // CNAME uncloaking: trackers hide behind first-party CNAMEs
        // (metrics.site.example → site.tracker.example).
        let allowed = host
            .as_deref()
            .is_some_and(|h| self.filter.explicitly_allowed(h));
        for record in response.answers.iter().filter(|_| !allowed) {
            if let RData::CNAME(target) = &record.data
                && let Some(target) = normalize_hostname(&target.0.to_ascii())
                && let Decision::Block { domain, category } = self.filter.check(&target)
            {
                return self.finalize(self.blocked(&req, &query, &domain, category), &req, max_len);
            }
        }

        self.cache.insert(key, response.clone());
        self.stats.record(Outcome::Allowed { cached: false });
        self.finalize(response, &req, max_len)
    }

    fn forward_zone(&self, host: &str) -> Option<&[SocketAddr]> {
        self.cfg
            .forward_zones
            .iter()
            .filter(|(zone, _)| is_same_or_subdomain(host, zone))
            .max_by_key(|(zone, _)| zone.len())
            .map(|(_, servers)| servers.as_slice())
    }

    fn upstream_query(&self, req: &Message, query: &Query, id: u16) -> Option<Vec<u8>> {
        let mut up = Message::new(id, MessageType::Query, OpCode::Query);
        up.metadata.recursion_desired = true;
        up.metadata.checking_disabled = req.metadata.checking_disabled;
        up.add_query(query.clone());
        // Fresh EDNS: client options (e.g. Client Subnet) are not forwarded.
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        edns.set_dnssec_ok(req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok));
        up.set_edns(edns);
        up.to_vec().ok()
    }

    /// Validates that an upstream response answers our question.
    fn accept(bytes: &[u8], query: &Query, id: Option<u16>) -> Option<Message> {
        let msg = Message::from_vec(bytes).ok()?;
        if msg.metadata.message_type != MessageType::Response
            || id.is_some_and(|id| msg.metadata.id != id)
        {
            return None;
        }
        let q = msg.queries.first()?;
        let same = q.query_type() == query.query_type()
            && q.query_class() == query.query_class()
            && q.name()
                .to_ascii()
                .eq_ignore_ascii_case(&query.name().to_ascii());
        if !same || msg.metadata.response_code == ResponseCode::ServFail {
            return None;
        }
        Some(msg)
    }

    async fn forward(&self, req: &Message, query: &Query) -> Option<Message> {
        let n = self.upstreams.len();
        let start = self.preferred.load(Ordering::Relaxed) % n.max(1);
        for i in 0..n {
            let idx = (start + i) % n;
            let upstream = &self.upstreams[idx];
            // RFC 8484 recommends ID 0 for DoH (better HTTP cacheability).
            let id = match upstream {
                UpstreamClient::Https { .. } => 0,
                UpstreamClient::Plain { .. } => rand_id(),
            };
            let bytes = self.upstream_query(req, query, id)?;
            match upstream.exchange(&bytes, self.cfg.timeout).await {
                Ok(resp) => {
                    if let Some(msg) = Self::accept(&resp, query, Some(id)) {
                        self.preferred.store(idx, Ordering::Relaxed);
                        self.metrics
                            .last_upstream_success
                            .store(fuck_ads_stats::time::now_unix(), Ordering::Relaxed);
                        return Some(msg);
                    }
                    tracing::debug!(upstream = %upstream.describe(), "rejected invalid upstream response");
                }
                Err(e) => {
                    tracing::debug!(upstream = %upstream.describe(), error = %e, "upstream failed")
                }
            }
        }
        if n > 0 {
            tracing::warn!("all upstream resolvers failed");
        }
        None
    }

    async fn forward_plain(
        &self,
        req: &Message,
        query: &Query,
        servers: &[SocketAddr],
    ) -> Option<Message> {
        for server in servers {
            let id = rand_id();
            let bytes = self.upstream_query(req, query, id)?;
            if let Ok(resp) = plain_exchange(*server, &bytes, self.cfg.timeout).await
                && let Some(msg) = Self::accept(&resp, query, Some(id))
            {
                return Some(msg);
            }
        }
        None
    }

    fn base_response(&self, req: &Message, code: ResponseCode) -> Message {
        let mut resp = Message::response(req.metadata.id, req.metadata.op_code);
        resp.metadata.response_code = code;
        resp
    }

    fn error(&self, req: &Message, code: ResponseCode) -> Message {
        self.base_response(req, code)
    }

    fn synthetic_soa(&self, zone: &Name) -> Record {
        let mname = Name::from_ascii("fuck-ads.invalid.").expect("static name");
        let rname = Name::from_ascii("hostmaster.fuck-ads.invalid.").expect("static name");
        let ttl = self.cfg.blocked_ttl;
        Record::from_rdata(
            zone.clone(),
            ttl,
            RData::SOA(SOA::new(mname, rname, 1, 3600, 600, 86_400, ttl)),
        )
    }

    fn nxdomain(&self, req: &Message, query: &Query) -> Message {
        let mut resp = self.base_response(req, ResponseCode::NXDomain);
        resp.add_authority(self.synthetic_soa(query.name()));
        resp
    }

    /// Answers names that must never leave the machine.
    fn local_answer(&self, req: &Message, query: &Query, host: &str) -> Option<Message> {
        if host == "localhost" || host.ends_with(".localhost") {
            let mut resp = self.base_response(req, ResponseCode::NoError);
            let name = query.name().clone();
            match query.query_type() {
                RecordType::A => {
                    resp.add_answer(Record::from_rdata(
                        name,
                        3600,
                        RData::A(A(Ipv4Addr::LOCALHOST)),
                    ));
                }
                RecordType::AAAA => {
                    resp.add_answer(Record::from_rdata(
                        name,
                        3600,
                        RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
                    ));
                }
                _ => {}
            }
            return Some(resp);
        }
        if host == PROBE_NAME {
            let mut resp = self.base_response(req, ResponseCode::NoError);
            if query.query_type() == RecordType::A {
                resp.add_answer(Record::from_rdata(
                    query.name().clone(),
                    0,
                    RData::A(A(PROBE_ADDR)),
                ));
            }
            return Some(resp);
        }
        if self.forward_zone(host).is_some() {
            return None;
        }
        if host == FIREFOX_DOH_CANARY {
            return Some(self.nxdomain(req, query));
        }
        if LOCAL_ZONES.iter().any(|z| is_same_or_subdomain(host, z)) {
            return Some(self.nxdomain(req, query));
        }
        if self.cfg.block_private_ptr && is_private_reverse(host) {
            return Some(self.nxdomain(req, query));
        }
        None
    }

    fn blocked(&self, req: &Message, query: &Query, domain: &str, category: Category) -> Message {
        self.metrics.blocked.fetch_add(1, Ordering::Relaxed);
        self.stats.record(Outcome::Blocked { domain, category });
        if self.cfg.log_blocked {
            tracing::debug!(domain, "blocked");
        }
        let ttl = self.cfg.blocked_ttl;
        match self.cfg.blocking_mode {
            BlockingMode::Refused => self.base_response(req, ResponseCode::Refused),
            BlockingMode::Nxdomain => self.nxdomain(req, query),
            BlockingMode::Null => {
                let mut resp = self.base_response(req, ResponseCode::NoError);
                let name = query.name().clone();
                match query.query_type() {
                    RecordType::A => {
                        resp.add_answer(Record::from_rdata(
                            name,
                            ttl,
                            RData::A(A(Ipv4Addr::UNSPECIFIED)),
                        ));
                    }
                    RecordType::AAAA => {
                        resp.add_answer(Record::from_rdata(
                            name,
                            ttl,
                            RData::AAAA(AAAA(Ipv6Addr::UNSPECIFIED)),
                        ));
                    }
                    // NODATA for everything else (HTTPS/SVCB, MX, TXT, ...).
                    _ => {
                        resp.add_authority(self.synthetic_soa(query.name()));
                    }
                }
                resp
            }
        }
    }

    /// Fixes up header fields and EDNS, then serializes, truncating for UDP
    /// when the response exceeds the client's limit.
    fn finalize(&self, mut resp: Message, req: &Message, max_len: usize) -> Option<Vec<u8>> {
        resp.metadata.id = req.metadata.id;
        resp.metadata.message_type = MessageType::Response;
        resp.metadata.op_code = req.metadata.op_code;
        resp.metadata.recursion_desired = req.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.metadata.authoritative = false;
        resp.metadata.truncation = false;
        // Echo the question exactly as asked (preserves 0x20 case).
        resp.queries = req.queries.clone();
        let dnssec_ok = req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok);
        resp.edns = req.edns.as_ref().map(|_| {
            let mut e = Edns::new();
            e.set_max_payload(EDNS_PAYLOAD);
            e.set_dnssec_ok(dnssec_ok);
            e
        });
        let resp = resp.maybe_strip_dnssec_records(dnssec_ok);
        let bytes = resp.to_vec().ok()?;
        if bytes.len() <= max_len {
            return Some(bytes);
        }
        resp.truncate().to_vec().ok()
    }
}

/// True for reverse-lookup names of private, loopback and link-local
/// addresses (RFC 1918, RFC 6598, RFC 3927, RFC 4193, RFC 4291).
pub fn is_private_reverse(host: &str) -> bool {
    if let Some(rest) = host.strip_suffix(".in-addr.arpa") {
        let octets: Vec<u8> = rest.rsplit('.').filter_map(|o| o.parse().ok()).collect();
        return match octets.as_slice() {
            [10, ..] | [127, ..] => true,
            [192, 168, ..] => true,
            [172, b, ..] => (16..=31).contains(b),
            [169, 254, ..] => true,
            [100, b, ..] => (64..=127).contains(b),
            _ => false,
        };
    }
    if let Some(rest) = host.strip_suffix(".ip6.arpa") {
        let nibbles: String = rest.rsplit('.').collect();
        return nibbles.starts_with("fc")
            || nibbles.starts_with("fd")
            || nibbles.starts_with("fe8")
            || nibbles.starts_with("fe9")
            || nibbles.starts_with("fea")
            || nibbles.starts_with("feb")
            || nibbles == "00000000000000000000000000000001";
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_reverse() {
        assert!(is_private_reverse("1.0.168.192.in-addr.arpa"));
        assert!(is_private_reverse("5.20.172.in-addr.arpa"));
        assert!(!is_private_reverse("5.15.172.in-addr.arpa"));
        assert!(is_private_reverse("4.3.2.10.in-addr.arpa"));
        assert!(!is_private_reverse("8.8.8.8.in-addr.arpa"));
        assert!(is_private_reverse(
            "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa"
        ));
        assert!(is_private_reverse(
            "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.d.f.ip6.arpa"
        ));
    }
}
