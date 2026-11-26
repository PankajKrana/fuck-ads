# Platform service definitions

* `linux/fuck-ads.service`: systemd unit (unprivileged user,
  `CAP_NET_BIND_SERVICE` only, strict sandbox, `Type=notify`).
* `macos/com.fuckads.daemon.plist`: LaunchDaemon running as `_fuck-ads`.
* `macos/com.fuckads.sync.plist`: root LaunchDaemon that runs `fuck-ads _sync-dns`
  every 30 s, so system DNS falls back to the previous resolvers while the
  daemon is down (launchd has no stop hook).
* `macos/newsyslog-fuck-ads.conf`: log rotation for
  `/Library/Logs/FuckAds/fuck-ads.log`.

The platform *code* (DNS configuration, service control) lives in
`crates/fuck-ads-platform`. These templates are embedded into the binary, so
`sudo fuck-ads enable` can install the service itself (used by packages and
Homebrew), and the installers copy them as well. The path
`/usr/local/bin/fuck-ads` is replaced with the actual binary location.
