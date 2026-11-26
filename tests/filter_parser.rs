//! Filter syntax compatibility, malformed input and scale.

use fuck_ads_filter::cosmetic::CosmeticAction;
use fuck_ads_filter::{
    Category, Engine, EngineBuilder, HostVerdict, ListFormat, ParseError, Request, ResourceType,
    Rule, parse_line,
};
use std::time::Instant;

fn blocked(engine: &Engine, host: &str) -> bool {
    matches!(engine.check_hostname(host), HostVerdict::Blocked { .. })
}

fn url_blocked(engine: &Engine, url: &str, source: &str, ty: ResourceType) -> bool {
    engine
        .check_request(&Request::new(url, Some(source), ty).unwrap())
        .is_blocked()
}

#[test]
fn spec_examples() {
    let e = Engine::from_rules(
        "||ads.example.com^\n@@||example.com^\n||tracker.example.net^\nexample.com##.advertisement\n",
    );
    assert!(blocked(&e, "tracker.example.net"));
    assert!(blocked(&e, "x.tracker.example.net"));
    // `@@||example.com^` is an exception covering example.com and all its
    // subdomains, so it wins over the non-important `||ads.example.com^`.
    assert!(matches!(
        e.check_hostname("ads.example.com"),
        HostVerdict::Allowed { .. }
    ));
    assert!(matches!(
        e.check_hostname("www.example.com"),
        HostVerdict::Allowed { .. }
    ));
    let c = e.cosmetic_filters("example.com", &[], &[], true);
    assert_eq!(c.selectors, vec![".advertisement"]);
}

#[test]
fn hosts_and_domain_lists() {
    let mut b = EngineBuilder::new();
    b.add_list("hosts", Category::Ads, "# c\n127.0.0.1 localhost\n0.0.0.0 a.example b.example\n::1 ip6-localhost\n0.0.0.0 0.0.0.0\n", ListFormat::Hosts);
    b.add_list(
        "domains",
        Category::Trackers,
        "c.example\n*.d.example\n# x\n\n",
        ListFormat::Domains,
    );
    let e = b.build();
    for h in ["a.example", "b.example", "sub.c.example", "x.d.example"] {
        assert!(blocked(&e, h), "{h}");
    }
    assert!(!blocked(&e, "localhost"));
    assert!(matches!(
        e.check_hostname("c.example"),
        HostVerdict::Blocked { list: 1, .. }
    ));
}

#[test]
fn wildcard_rules() {
    let e = Engine::from_rules("||ad*.wild.example^\n||*.star.example^\n/banner*/ad.\n");
    assert!(blocked(&e, "adserver.wild.example"));
    assert!(blocked(&e, "ad.wild.example"));
    assert!(!blocked(&e, "cdn.wild.example"));
    assert!(blocked(&e, "x.star.example"));
    assert!(url_blocked(
        &e,
        "https://a.com/banner123/ad.png",
        "https://a.com/",
        ResourceType::Image
    ));
}

#[test]
fn domain_specific_rules() {
    let e = Engine::from_rules("||cdn.example/ad.js$domain=news.example|~sports.news.example\n");
    assert!(url_blocked(
        &e,
        "https://cdn.example/ad.js",
        "https://www.news.example/",
        ResourceType::Script
    ));
    assert!(!url_blocked(
        &e,
        "https://cdn.example/ad.js",
        "https://sports.news.example/",
        ResourceType::Script
    ));
    assert!(!url_blocked(
        &e,
        "https://cdn.example/ad.js",
        "https://other.example/",
        ResourceType::Script
    ));
    // Domain-specific rules are not DNS-enforceable.
    assert!(!blocked(&e, "cdn.example"));
}

#[test]
fn third_party_and_types() {
    let e = Engine::from_rules("||widgets.example^$third-party,script\n||img.example^$image\n");
    assert!(url_blocked(
        &e,
        "https://widgets.example/w.js",
        "https://site.test/",
        ResourceType::Script
    ));
    assert!(!url_blocked(
        &e,
        "https://widgets.example/w.js",
        "https://www.widgets.example/",
        ResourceType::Script
    ));
    assert!(!url_blocked(
        &e,
        "https://widgets.example/w.css",
        "https://site.test/",
        ResourceType::Stylesheet
    ));
    assert!(url_blocked(
        &e,
        "https://img.example/p.gif",
        "https://site.test/",
        ResourceType::Image
    ));
    assert!(!blocked(&e, "img.example"));
}

#[test]
fn important_overrides_exceptions() {
    let e = Engine::from_rules("||t.example^$important\n@@||t.example^\n");
    assert!(blocked(&e, "t.example"));
    let e = Engine::from_rules("||t.example^$important\n@@||t.example^$important\n");
    assert!(!blocked(&e, "t.example"));
}

#[test]
fn document_allowlisting() {
    let e = Engine::from_rules("||ads.example^\n@@||trusted.example^$document\n");
    assert!(url_blocked(
        &e,
        "https://ads.example/a.js",
        "https://news.example/",
        ResourceType::Script
    ));
    assert!(!url_blocked(
        &e,
        "https://ads.example/a.js",
        "https://trusted.example/",
        ResourceType::Script
    ));

    // A page exception must not unblock the site's ad subdomains elsewhere.
    let e = Engine::from_rules("||ads.example.com^\n@@||example.com^$document\n");
    assert!(blocked(&e, "ads.example.com"));
    assert!(url_blocked(
        &e,
        "https://ads.example.com/x.js",
        "https://news.example/",
        ResourceType::Script
    ));
}

#[test]
fn cosmetic_variants() {
    let e = Engine::from_rules(
        "##.generic\n###gid\nsite.example,~shop.site.example##.local\nsite.example#@#.generic\ngoogle.*##.entity-ad\n~exempt.example##.neg\n",
    );
    let c = |h: &str, cl: &[&str], ids: &[&str]| {
        let cl: Vec<String> = cl.iter().map(|s| s.to_string()).collect();
        let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        e.cosmetic_filters(h, &cl, &ids, true).selectors
    };
    assert!(c("site.example", &["generic"], &[]).contains(&".local".to_string()));
    assert!(!c("site.example", &["generic"], &[]).contains(&".generic".to_string()));
    assert!(c("other.example", &["generic"], &["gid"]).contains(&"#gid".to_string()));
    assert!(!c("shop.site.example", &[], &[]).contains(&".local".to_string()));
    assert!(c("www.google.de", &[], &[]).contains(&".entity-ad".to_string()));
    assert!(c("other.example", &["neg"], &[]).contains(&".neg".to_string()));
    assert!(!c("exempt.example", &["neg"], &[]).contains(&".neg".to_string()));
}

#[test]
fn scriptlets_are_names_with_data_arguments() {
    match parse_line("youtube.com##+js(json-prune, a b, c)", ListFormat::Adblock).unwrap() {
        Some(Rule::Cosmetic(f)) => assert_eq!(
            f.action,
            CosmeticAction::Scriptlet {
                name: "json-prune".into(),
                args: vec!["a b".into(), "c".into()]
            }
        ),
        other => panic!("{other:?}"),
    }
    // AdGuard arbitrary-JS and unknown scriptlets are refused.
    assert!(matches!(
        parse_line("x.com#%#window.location='//evil'", ListFormat::Adblock),
        Err(ParseError::Unsupported(_))
    ));
    assert!(matches!(
        parse_line("x.com##+js(eval, alert(1))", ListFormat::Adblock),
        Err(ParseError::Unsupported(_))
    ));
}

#[test]
fn malformed_rules_are_skipped_not_fatal() {
    let text = "||ok.example^\n||bad^$\n/[unclosed/\n##\n##div{x}\n*\n@@\n||x^$domain=\n\u{0}\u{1}junk\n||ok2.example^\n";
    let mut b = EngineBuilder::new();
    let stats = b.add_list("x", Category::Ads, text, ListFormat::Auto);
    let e = b.build();
    assert!(blocked(&e, "ok.example") && blocked(&e, "ok2.example"));
    assert!(stats.invalid + stats.unsupported >= 5, "{stats:?}");
}

#[test]
fn unsupported_options_never_approximate() {
    for rule in [
        "||x.example^$redirect=noopjs",
        "||x.example^$removeparam=utm",
        "||x.example^$csp=default-src",
        "||x.example^$popup",
        "||x.example^$header=via",
    ] {
        let e = Engine::from_rules(rule);
        assert!(!blocked(&e, "x.example"), "{rule}");
    }
}

/// Tiny deterministic PRNG (xorshift) for reproducible fuzzing on stable.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn parser_never_panics_on_random_input() {
    const ALPHABET: &[u8] = b"|^*$@#!~,=./:-_[]{}()+\"'\\ abcdefgjsx0129%?&";
    const FRAGMENTS: &[&str] = &[
        "||",
        "@@",
        "##",
        "#@#",
        "#?#",
        "+js(",
        "$domain=",
        "$third-party",
        "$~script",
        "/",
        "^",
        "*",
        "~",
        ",",
        "$important",
        "$badfilter",
        "##+js()",
        ":has(",
        "0.0.0.0 ",
        "$$",
        "#$#",
        "\u{1F600}",
        "é",
    ];
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut lines = Vec::new();
    for _ in 0..50_000 {
        let mut line = String::new();
        for _ in 0..(rng.next() % 40) {
            if rng.next().is_multiple_of(3) {
                line.push_str(FRAGMENTS[(rng.next() % FRAGMENTS.len() as u64) as usize]);
            } else {
                line.push(ALPHABET[(rng.next() % ALPHABET.len() as u64) as usize] as char);
            }
        }
        for fmt in [
            ListFormat::Auto,
            ListFormat::Adblock,
            ListFormat::Hosts,
            ListFormat::Domains,
        ] {
            let _ = parse_line(&line, fmt);
        }
        lines.push(line);
    }
    // The engine must also build and answer queries for whatever parsed.
    let e = Engine::from_rules(&lines.join("\n"));
    let _ = e.check_hostname("a.b.example");
    let r = Request::new(
        "https://a.b.example/x/y.js?z=1",
        Some("https://s.example/"),
        ResourceType::Script,
    )
    .unwrap();
    let _ = e.check_request(&r);
    let _ = e.cosmetic_filters("a.b.example", &["x".into()], &["y".into()], true);
}

#[test]
fn large_rule_lists() {
    let mut text = String::with_capacity(8_000_000);
    for i in 0..150_000 {
        text.push_str(&format!("||ad{i}.tracker{}.example^\n", i % 1000));
    }
    for i in 0..30_000 {
        text.push_str(&format!("/banner{i}/ad^$third-party\n"));
    }
    for i in 0..20_000 {
        text.push_str(&format!("site{i}.example##.ad-{i}\n"));
    }
    let start = Instant::now();
    let e = Engine::from_rules(&text);
    let build = start.elapsed();
    assert!(e.rule_count() >= 200_000);
    assert!(blocked(&e, "ad149999.tracker999.example"));
    assert!(!blocked(&e, "ad150000.tracker0.example"));

    let start = Instant::now();
    for i in 0..10_000 {
        let _ = e.check_hostname(&format!("www.site{i}.example"));
    }
    let lookups = start.elapsed();
    let r = Request::new(
        "https://cdn.x/banner29999/ad?id=1",
        Some("https://s.example/"),
        ResourceType::Image,
    )
    .unwrap();
    assert!(e.check_request(&r).is_blocked());
    // Generous bounds (debug builds, CI machines); release is far faster.
    assert!(build.as_secs() < 30, "build took {build:?}");
    assert!(lookups.as_millis() < 2_000, "10k lookups took {lookups:?}");
}
