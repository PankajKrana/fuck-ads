//! `fuck-ads allow/block` behaviour through the control API.

use fuck_ads_core::protocol::{Request, Response};
use fuck_ads_tests::*;
use hickory_proto::rr::RecordType;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fn v4(addrs: &[SocketAddr]) -> SocketAddr {
    *addrs.iter().find(|a| a.is_ipv4()).unwrap()
}

async fn is_blocked(dns: SocketAddr, name: &str) -> bool {
    let r = query(dns, name, RecordType::A).await.unwrap();
    first_ip(&r) == Some(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
}

fn ok(r: Response) {
    assert!(matches!(r, Response::Ok { .. }), "{r:?}");
}

#[tokio::test]
async fn allow_and_block_take_effect_immediately() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);

    assert!(is_blocked(dns, "ads.example.").await);
    ok(env
        .control(Request::Allow {
            domain: "ads.example".into(),
        })
        .await);
    assert!(
        !is_blocked(dns, "ads.example.").await,
        "allowlist overrides filter lists (and cache)"
    );
    assert!(
        !is_blocked(dns, "cdn.ads.example.").await,
        "subdomains are covered"
    );

    assert!(!is_blocked(dns, "annoying.example.").await);
    ok(env
        .control(Request::Block {
            domain: "https://annoying.example/page".into(),
        })
        .await);
    assert!(is_blocked(dns, "annoying.example.").await);
    assert!(is_blocked(dns, "www.annoying.example.").await);

    assert_eq!(
        env.control(Request::ListAllow).await,
        Response::List(vec!["ads.example".into()])
    );
    assert_eq!(
        env.control(Request::ListBlock).await,
        Response::List(vec!["annoying.example".into()])
    );

    ok(env
        .control(Request::RemoveAllow {
            domain: "ads.example".into(),
        })
        .await);
    ok(env
        .control(Request::RemoveBlock {
            domain: "annoying.example".into(),
        })
        .await);
    assert!(is_blocked(dns, "ads.example.").await);
    assert!(!is_blocked(dns, "annoying.example.").await);
    d.shutdown().await;
}

#[tokio::test]
async fn allowing_moves_a_domain_out_of_the_blocklist() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    ok(env
        .control(Request::Block {
            domain: "x.example".into(),
        })
        .await);
    ok(env
        .control(Request::Allow {
            domain: "x.example".into(),
        })
        .await);
    assert_eq!(
        env.control(Request::ListBlock).await,
        Response::List(vec![])
    );
    d.shutdown().await;
}

#[tokio::test]
async fn invalid_input_is_rejected() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    for bad in [
        "",
        "not a domain",
        "com",
        "a..b",
        "$(reboot)",
        "../../etc/passwd",
        "x.example\nevil",
    ] {
        let r = env.control(Request::Allow { domain: bad.into() }).await;
        assert!(matches!(r, Response::Error { .. }), "{bad:?} -> {r:?}");
    }
    let r = env
        .control(Request::RemoveAllow {
            domain: "never-added.example".into(),
        })
        .await;
    assert!(matches!(r, Response::Error { .. }));
    d.shutdown().await;
}

#[tokio::test]
async fn persists_across_restarts() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    ok(env
        .control(Request::Allow {
            domain: "ads.example".into(),
        })
        .await);
    ok(env
        .control(Request::Block {
            domain: "persist.example".into(),
        })
        .await);
    d.shutdown().await;

    let d = env.start().await;
    let dns = v4(&d.dns_addrs);
    assert!(!is_blocked(dns, "ads.example.").await);
    assert!(is_blocked(dns, "persist.example.").await);
    d.shutdown().await;
}

#[tokio::test]
async fn pause_and_resume() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);
    ok(env.control(Request::SetEnabled { enabled: false }).await);
    assert!(!is_blocked(dns, "ads.example.").await);
    ok(env.control(Request::SetEnabled { enabled: true }).await);
    assert!(is_blocked(dns, "ads.example.").await);
    d.shutdown().await;
}

#[tokio::test]
async fn check_explains_decisions() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    ok(env
        .control(Request::Allow {
            domain: "good.example".into(),
        })
        .await);
    let Response::Check(c) = env
        .control(Request::Check {
            domain: "ads.example".into(),
        })
        .await
    else {
        panic!()
    };
    assert!(c.blocked && c.reason.contains("||ads.example^") && c.list.as_deref() == Some("local"));
    let Response::Check(c) = env
        .control(Request::Check {
            domain: "good.example".into(),
        })
        .await
    else {
        panic!()
    };
    assert!(!c.blocked && c.reason.contains("allowlisted"));
    d.shutdown().await;
}

#[tokio::test]
async fn allowlisting_a_cloaked_name_unblocks_it() {
    let env = TestEnv::new().await;
    let d = env.start().await;
    let dns = v4(&d.dns_addrs);
    // cloaked.example is a CNAME for the listed tracker.example.
    assert!(is_blocked(dns, "cloaked.example.").await);
    ok(env
        .control(Request::Allow {
            domain: "cloaked.example".into(),
        })
        .await);
    assert!(!is_blocked(dns, "cloaked.example.").await);
    d.shutdown().await;
}
