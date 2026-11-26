//! End-to-end DNS behaviour against an in-process daemon and a mock upstream.

use fuck_ads_config::BlockingMode;
use fuck_ads_tests::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, RecordType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

fn v4(addrs: &[SocketAddr]) -> SocketAddr {
    *addrs.iter().find(|a| a.is_ipv4()).unwrap()
}

#[tokio::test]
async fn blocks_and_forwards_ipv4_and_ipv6() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);

    let r = query(dns, "ads.example.", RecordType::A).await.unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert_eq!(first_ip(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));

    let r = query(dns, "sub.ads.example.", RecordType::AAAA)
        .await
        .unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

    let r = query(dns, "hosts.example.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));

    // Exception rule: forwarded.
    let r = query(dns, "good.ads.example.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(UPSTREAM_V4)));

    let r = query(dns, "www.allowed.example.", RecordType::AAAA)
        .await
        .unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V6(UPSTREAM_V6)));

    // IPv6 listener, if the host has IPv6 loopback.
    if let Some(v6) = d.dns_addrs.iter().find(|a| a.is_ipv6()) {
        let r = query(*v6, "ads.example.", RecordType::A).await.unwrap();
        assert_eq!(first_ip(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        let r = query(*v6, "ok.example.", RecordType::A).await.unwrap();
        assert_eq!(first_ip(&r), Some(IpAddr::V4(UPSTREAM_V4)));
    }

    // TCP transport.
    let r = query_tcp(dns, "ads.example.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    let r = query_tcp(dns, "ok.example.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(UPSTREAM_V4)));
    d.shutdown().await;
}

#[tokio::test]
async fn blocked_non_address_types_get_nodata() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let r = query(v4(&d.dns_addrs), "ads.example.", RecordType::HTTPS)
        .await
        .unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NoError);
    assert!(r.answers.is_empty());
    assert!(
        r.authorities
            .iter()
            .any(|a| matches!(a.data, RData::SOA(_)))
    );
    d.shutdown().await;
}

#[tokio::test]
async fn nxdomain_blocking_mode() {
    let mut env = TestEnv::new().await;
    env.config.dns.blocking_mode = BlockingMode::Nxdomain;
    let d = env.start().await;
    let r = query(v4(&d.dns_addrs), "ads.example.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    d.shutdown().await;
}

#[tokio::test]
async fn caches_responses() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);
    query(dns, "cache.example.", RecordType::A).await.unwrap();
    let after_first = env.upstream.count();
    let r = query(dns, "CACHE.example.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(UPSTREAM_V4)));
    assert_eq!(
        env.upstream.count(),
        after_first,
        "second query must be served from cache"
    );
    // Negative answers are cached too.
    let r = query(dns, "nx.example.", RecordType::A).await.unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    d.shutdown().await;
}

#[tokio::test]
async fn upstream_failure_returns_servfail() {
    let env = TestEnv::new().await;
    env.upstream
        .silent
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let d = env.start().await;
    let r = query(v4(&d.dns_addrs), "down.example.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::ServFail);
    // Blocking still works while upstreams are down.
    let r = query(v4(&d.dns_addrs), "ads.example.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    d.shutdown().await;
}

#[tokio::test]
async fn fails_over_to_next_upstream() {
    let mut env = TestEnv::new().await;
    let dead = MockUpstream::start().await;
    dead.silent.store(true, std::sync::atomic::Ordering::SeqCst);
    env.config.dns.upstreams = vec![dead.addr.to_string(), env.upstream.addr.to_string()];
    let d = env.start().await;
    let r = query(v4(&d.dns_addrs), "failover.example.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(UPSTREAM_V4)));
    assert!(dead.count() >= 1);
    d.shutdown().await;
}

#[tokio::test]
async fn concurrent_queries() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);
    let mut tasks = Vec::new();
    for i in 0..300 {
        tasks.push(tokio::spawn(async move {
            let (name, blocked) = if i % 2 == 0 {
                (format!("x{i}.ads.example."), true)
            } else {
                (format!("h{i}.ok.example."), false)
            };
            // The kernel may drop part of a 300-packet UDP burst on a busy
            // runner; real resolvers retry, so the test does too.
            let mut r = None;
            for _ in 0..3 {
                r = query(dns, &name, RecordType::A).await;
                if r.is_some() {
                    break;
                }
            }
            let r = r.expect("answer");
            let ip = first_ip(&r).unwrap();
            assert_eq!(ip == IpAddr::V4(Ipv4Addr::UNSPECIFIED), blocked, "{name}");
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    d.shutdown().await;
}

#[tokio::test]
async fn cname_cloaking_is_blocked() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    // cloaked.example is not listed, but its CNAME target tracker.example is.
    let r = query(v4(&d.dns_addrs), "cloaked.example.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    d.shutdown().await;
}

#[tokio::test]
async fn local_names_never_leave_the_machine() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);
    let before = env.upstream.count();
    let r = query(dns, "1.1.168.192.in-addr.arpa.", RecordType::PTR)
        .await
        .unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    let r = query(dns, "printer.local.", RecordType::A).await.unwrap();
    assert_eq!(r.metadata.response_code, ResponseCode::NXDomain);
    let r = query(dns, "localhost.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let r = query(dns, "fuck-ads-probe.test.", RecordType::A)
        .await
        .unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(fuck_ads_dns::PROBE_ADDR)));
    assert_eq!(
        env.upstream.count(),
        before,
        "no local name may be forwarded"
    );
    d.shutdown().await;
}

#[tokio::test]
async fn forwarded_queries_do_not_leak_client_options() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    query(v4(&d.dns_addrs), "leak.example.", RecordType::A)
        .await
        .unwrap();
    let upstream_query = env.upstream.last_query.lock().unwrap().clone().unwrap();
    // A fresh EDNS record without client options (no Client Subnet).
    let edns = upstream_query.edns.expect("EDNS sent upstream");
    assert!(edns.options().as_ref().is_empty());
    d.shutdown().await;
}

#[tokio::test]
async fn malformed_packets_do_not_crash() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for junk in [
        &b""[..],
        b"\x00",
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xff\xff",
        &[0xffu8; 600][..],
    ] {
        sock.send_to(junk, dns).await.unwrap();
    }
    // Still serving.
    let r = query(dns, "ads.example.", RecordType::A).await.unwrap();
    assert_eq!(first_ip(&r), Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
    d.shutdown().await;
}

#[tokio::test]
async fn stats_record_blocked_but_not_allowed_domains() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);
    query(dns, "ads.example.", RecordType::A).await.unwrap();
    query(dns, "private-browsing-target.example.", RecordType::A)
        .await
        .unwrap();
    let today = d.daemon.stats.today();
    assert_eq!(today.blocked, 1);
    assert!(today.queries >= 2);
    assert!(today.blocked_domains.contains_key("ads.example"));
    assert!(
        !today
            .blocked_domains
            .keys()
            .any(|k| k.contains("private-browsing-target"))
    );
    d.shutdown().await;
    // Persisted on shutdown, and contains no allowed hostname.
    let file = std::fs::read_to_string(env.paths.stats_file()).unwrap();
    assert!(file.contains("ads.example"));
    assert!(!file.contains("private-browsing-target"));
}
