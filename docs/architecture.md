# Architecture

## Components

FuckAds ships as **one binary**, `fuck-ads`, which runs in three roles:

| Role | Started by | Privileges |
|---|---|---|
| `fuck-ads daemon` | systemd / launchd | unprivileged service account (`fuck-ads` / `_fuck-ads`), only allowed to bind port 53 |
| `fuck-ads <command>` | the user | the user's own; `sudo` for commands that change system settings |
| `fuck-ads-native-host` (symlink) | the browser | the browser user's; can only forward read-only requests |

## Crates

```text
crates/
├── fuck-ads-filter    Filter parsing + matching engine. No I/O, no platform code.
├── fuck-ads-config    Config schema/validation, platform paths, atomic file writes.
├── fuck-ads-stats     Privacy-preserving daily counters.
├── fuck-ads-dns       UDP/TCP listener, filtering resolver, DoH/plain upstreams, cache.
├── fuck-ads-core      Daemon: live rules, updater, control API (Unix socket).
├── fuck-ads-platform  OS adapters: systemd + resolved/NM/resolv.conf, launchd + networksetup,
│                     browser native-host registration.
└── fuck-ads-cli       The `fuck-ads` binary: CLI, daemon entry, native messaging host.
```

Dependency direction: `filter ← config ← stats ← dns ← core ← cli` and
`platform ← cli`. The daemon (`core`) never depends on `platform`. Only the
privileged CLI commands touch OS configuration, so the long-running process
needs no root rights.

To add Windows later, implement `fuck_ads_platform::Platform` (Windows
Service, `netsh`/WMI DNS settings, registry-based native-host registration)
and swap the Unix socket for a named pipe in `fuck-ads-core::control`.

## Filter engine (`fuck-ads-filter`)

* **Parser.** Handles hosts files, plain domain lists, and Adblock Plus /
  uBlock Origin / AdGuard syntax. Unsupported syntax is counted and skipped,
  never approximated.
* **DNS index.** Filters that block a whole hostname (`||host^`, hosts
  entries) go into hash maps keyed by hostname. A lookup walks the name's
  suffixes (`a.b.c`, `b.c`, `c`), which takes O(labels) hash probes:
  40–120 ns.
* **URL index.** Each network filter is stored under its *rarest* complete
  token, chosen using token frequencies across the whole index. A URL is
  tokenized once, and only the buckets of its tokens, plus a small fallback
  bucket, are checked: about 0.3 µs per request.
* **Cosmetic index.** Site-specific selectors are keyed by hostname. Generic
  selectors are keyed by the class or id they require, so a page only
  receives selectors relevant to the tokens it actually contains. Selectors
  that can't be keyed are sent once per frame.
* **Procedural cosmetic filters.** Selectors that need more than CSS
  (`site.com##.card:has-text(Sponsored)`, `:matches-css()`, `:xpath()`,
  `:upward()`, `:remove()`, with native CSS before, between and after the
  operators) are parsed into typed steps (`procedural.rs`): operators are a
  fixed set, and each argument becomes plain text, a bounded regular
  expression (no backreferences, lookaround or nested quantifiers), an XPath
  expression, a number or a validated CSS selector. They are site-specific
  only (a generic one would walk every page) and are returned with the
  once-per-frame cosmetic request; the extension's `procedural.js` evaluates
  them in the page, in time-boxed slices, as the DOM changes. Other
  procedural operators are still skipped and counted as unsupported.
* **Precedence.** `$important` block > `$important` exception > page
  (`$document`) exception > exception > block. User allow/block lists sit
  above all filter lists. Hosts FuckAds needs to function (DoH upstreams,
  list servers) are never blocked.
* **Query-parameter stripping.** `$removeparam=name` filters (literal names
  only; regex and exception forms are skipped) never block and never reach
  the DNS layer. The DNR export emits them as lowest-priority `redirect` rules with a
  `queryTransform`, so they only run when nothing blocks or allows the
  request. Safari's content blocker cannot rewrite URLs, so they are
  not exported there.
* **Redirects.** `$redirect=noop.js` (also `noop.css`, `noop.html`,
  `noop.txt`, `1x1.gif`, `2x2.png`, plus analytics stand-ins `ga.js`,
  `analytics.js`, `gtm.js`, `gpt.js`, `apstag.js` and `beacon.js`, each with
  its uBO/ABP aliases such as `google-analytics.com/analytics.js`) blocks
  the request and serves a neutral stub packaged in
  `browser/common/resources/`, so pages that expect the file keep working.
  The analytics stubs are original code: they define the globals pages call
  (`ga()`, `dataLayer`, `googletag`, `apstag`), run queued callbacks and
  report nothing. They are tested in `browser/tests/resources.test.js`.
  Only names in `fuck_ads_filter::resources` are accepted; unknown names,
  `$redirect-rule` and exception forms are skipped. Redirect filters never
  apply to top-level documents and are kept out of the DNS layer (the page
  needs the stub, not a dead host). The DNR export emits a `redirect` rule
  with an `extensionPath`; Safari cannot do this, so they are not exported
  there. The stubs are listed in `web_accessible_resources`, which lets a
  page detect that the extension is installed.
* **Export.** Rules are converted to Chromium/Firefox `declarativeNetRequest`
  rules. Plain hostnames are packed into `requestDomains` rules, so tens of
  thousands of hostnames take only a few dozen of the 30,000 available
  dynamic rules. Rules can also be exported as Safari content-blocker JSON.

## DNS resolver (`fuck-ads-dns`)

```text
query → parse → local answers (localhost, probe, .local/.lan, private PTR)
      → filter (user lists → engine)  ──blocked──→ 0.0.0.0 / :: / NODATA
      → cache ──hit──→ answer (TTLs decremented)
      → forward zone? plain DNS to the router : DoH/plain upstreams with failover
      → CNAME targets checked against the filter (uncloaking)
      → cache insert → answer (truncated for UDP if larger than the client allows)
```

* Upstream responses are accepted only if the ID and question match.
  Plain-DNS queries use random IDs and a fresh random source port per query.
* DoH hostnames are resolved through dedicated bootstrap servers. Using the
  system resolver would loop back into FuckAds itself.
* Client EDNS options are never forwarded; each upstream query gets a fresh
  EDNS record.

## Daemon (`fuck-ads-core`)

* `LiveFilter` holds `Arc<Engine>` behind a `RwLock`. Updates build a new
  engine on a blocking thread and swap the pointer, so queries never wait on
  rule compilation.
* **Updater.** Downloads lists over HTTPS with conditional requests, then
  validates, stages, installs atomically (keeping `.prev`), builds,
  self-tests, and activates, rolling back on failure. Retries back off
  exponentially.
* **Control API.** Newline-delimited JSON over a Unix socket. Kernel-verified
  peer credentials gate every state-changing request. The protocol
  (`protocol.rs`) is the API for the CLI, the browser host, and a future GUI.

## Browser extension (`browser/`)

```text
content.js (isolated world): collects class/id tokens ──► background.js
background.js ◄──native messaging──► fuck-ads-native-host ◄──Unix socket──► daemon
  ├─ declarativeNetRequest dynamic rules (network blocking, evaluated by the browser)
  ├─ scripting.insertCSS(origin: USER) (cosmetic filtering)
  └─ userScripts / executeScript(world: MAIN) (scriptlets from scriptlets.js)
```

The extension keeps its last rules if the service is unreachable. Dynamic
DNR rules persist across browser restarts.

## On-disk layout (system mode)

| Path (Linux / macOS) | Owner | Content |
|---|---|---|
| `/etc/fuck-ads/config.toml` / `…/FuckAds/config.toml` | root | configuration |
| `/var/lib/fuck-ads/system-state.json` / `…/FuckAds/system-state.json` | root, 0600 | backup of the previous DNS settings |
| `…/data/lists/*.txt[.prev]` | service | downloaded lists |
| `…/data/update-state.json` | service | ETags, checksums, update timestamps |
| `…/data/user-rules.json` | service | `fuck-ads allow/block` entries |
| `…/data/stats.json` | service | daily counters |
| `/run/fuck-ads/control.sock` / `…/FuckAds/data/control.sock` | service | control API |
