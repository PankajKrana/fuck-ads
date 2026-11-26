//! Listener, per-connection handling and relaying.

use crate::request::{Head, MAX_HEAD, ParseError, Target, parse_head};
use crate::{ProxyConfig, SharedFilter, Verdict, pac, policy};
use fuck_ads_stats::{Outcome, StatsStore};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::timeout;

const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// A tunnel with no traffic in either direction for this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);
const RELAY_BUF: usize = 16 * 1024;

pub struct Listeners {
    pub bound: Vec<SocketAddr>,
    listeners: Vec<TcpListener>,
}

/// Binds the proxy. Only loopback addresses are accepted: the proxy is
/// never offered to other machines.
pub async fn bind(addrs: &[SocketAddr]) -> io::Result<Listeners> {
    let mut listeners = Vec::new();
    let mut bound = Vec::new();
    for addr in addrs {
        if !addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("proxy address {addr} is not a loopback address"),
            ));
        }
        match TcpListener::bind(addr).await {
            Ok(l) => {
                bound.push(l.local_addr()?);
                listeners.push(l);
            }
            // IPv6 loopback may be unavailable; fine if another address works.
            Err(e) if addr.is_ipv6() && !listeners.is_empty() => {
                tracing::warn!(%addr, error = %e, "proxy: cannot listen on IPv6 loopback");
            }
            Err(e) => return Err(e),
        }
    }
    if listeners.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no proxy listen address",
        ));
    }
    Ok(Listeners { bound, listeners })
}

struct Ctx {
    filter: SharedFilter,
    stats: Arc<StatsStore>,
    cfg: ProxyConfig,
}

/// Runs until `shutdown` changes. Connections still open then are dropped.
pub async fn serve(
    listeners: Listeners,
    filter: SharedFilter,
    stats: Arc<StatsStore>,
    cfg: ProxyConfig,
    shutdown: watch::Receiver<bool>,
) {
    let slots = Arc::new(Semaphore::new(cfg.max_connections.max(1)));
    let ctx = Arc::new(Ctx { filter, stats, cfg });
    let mut loops = JoinSet::new();
    for listener in listeners.listeners {
        loops.spawn(accept_loop(
            listener,
            ctx.clone(),
            slots.clone(),
            shutdown.clone(),
        ));
    }
    while loops.join_next().await.is_some() {}
}

async fn accept_loop(
    listener: TcpListener,
    ctx: Arc<Ctx>,
    slots: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (sock, peer) = match accepted {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::debug!(error = %e, "proxy accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                // Defence in depth: the listener is loopback-only already.
                if !peer.ip().is_loopback() {
                    continue;
                }
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    continue; // at capacity: refuse by closing
                };
                let Ok(local) = sock.local_addr() else { continue };
                let ctx = ctx.clone();
                conns.spawn(async move {
                    handle(sock, local, &ctx).await;
                    drop(permit);
                });
                while conns.try_join_next().is_some() {}
            }
            _ = shutdown.changed() => {
                conns.abort_all();
                while conns.join_next().await.is_some() {}
                return;
            }
        }
    }
}

async fn respond(client: &mut TcpStream, status: &str, extra: &str, body: &str) {
    let msg = format!(
        "HTTP/1.1 {status}\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = client.write_all(msg.as_bytes()).await;
    let _ = client.shutdown().await;
}

async fn reject(client: &mut TcpStream, status: &str) {
    respond(client, status, "", "").await;
}

enum ReadError {
    Parse(ParseError),
    Io,
}

/// Reads until a full request head is available. Returns the head and any
/// bytes received after it.
async fn read_head(client: &mut TcpStream) -> Result<(Head, Vec<u8>), ReadError> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        match parse_head(&buf) {
            Ok(Some(head)) => {
                let rest = buf.split_off(head.len);
                return Ok((head, rest));
            }
            Ok(None) => {}
            Err(e) => return Err(ReadError::Parse(e)),
        }
        if buf.len() >= MAX_HEAD {
            return Err(ReadError::Parse(ParseError::TooLarge));
        }
        match client.read(&mut chunk).await {
            Ok(0) | Err(_) => return Err(ReadError::Io),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
    }
}

fn record_block(ctx: &Ctx, domain: &str, category: crate::Category) {
    ctx.stats.record(Outcome::Blocked { domain, category });
    if ctx.cfg.log_blocked {
        tracing::debug!(domain, "proxy blocked");
    }
}

/// Resolves and connects, refusing local and special-use targets.
async fn connect_upstream(host: &str, port: u16, ctx: &Ctx) -> Result<TcpStream, &'static str> {
    // Name resolution goes through the system resolver, which is FuckAds's
    // own DNS filter when system DNS is routed through it.
    let addrs: Vec<SocketAddr> = match host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => match timeout(CONNECT_TIMEOUT, tokio::net::lookup_host((host, port))).await {
            Ok(Ok(it)) => it.collect(),
            _ => return Err("502 Bad Gateway"),
        },
    };
    let usable: Vec<SocketAddr> = addrs
        .into_iter()
        .filter(|a| ctx.cfg.allow_local_targets || !policy::forbidden_target(a.ip()))
        .collect();
    if usable.is_empty() {
        return Err("403 Forbidden");
    }
    for addr in usable.into_iter().take(4) {
        if let Ok(Ok(s)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await {
            let _ = s.set_nodelay(true);
            return Ok(s);
        }
    }
    Err("502 Bad Gateway")
}

async fn handle(mut client: TcpStream, local: SocketAddr, ctx: &Ctx) {
    let _ = client.set_nodelay(true);
    let (head, rest) = match timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Ok(Ok(x)) => x,
        Ok(Err(ReadError::Parse(ParseError::TooLarge))) => {
            return reject(&mut client, "431 Request Header Fields Too Large").await;
        }
        Ok(Err(ReadError::Parse(ParseError::Unsupported))) => {
            return reject(&mut client, "501 Not Implemented").await;
        }
        Ok(Err(ReadError::Parse(ParseError::Malformed))) => {
            return reject(&mut client, "400 Bad Request").await;
        }
        _ => return,
    };

    match &head.target {
        Target::Pac => {
            let body = pac::pac_script(local);
            let extra =
                "Content-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\n";
            let body = if head.method == "HEAD" { "" } else { &body };
            respond(&mut client, "200 OK", extra, body).await;
        }
        Target::Connect { host, port } => {
            if !ctx.cfg.ports.contains(port) {
                return reject(&mut client, "403 Forbidden").await;
            }
            if let Verdict::Block { domain, category } = ctx.filter.check_host(host) {
                record_block(ctx, &domain, category);
                return reject(&mut client, "403 Forbidden").await;
            }
            let mut upstream = match connect_upstream(host, *port, ctx).await {
                Ok(s) => s,
                Err(status) => return reject(&mut client, status).await,
            };
            if client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .is_err()
            {
                return;
            }
            if !rest.is_empty() && upstream.write_all(&rest).await.is_err() {
                return;
            }
            relay(client, upstream).await;
        }
        Target::Http {
            host,
            port,
            url,
            path,
        } => {
            if !ctx.cfg.ports.contains(port) {
                return reject(&mut client, "403 Forbidden").await;
            }
            let verdict = match ctx.filter.check_host(host) {
                Verdict::Allow => ctx.filter.check_url(url, head.header("referer")),
                blocked => blocked,
            };
            if let Verdict::Block { domain, category } = verdict {
                record_block(ctx, &domain, category);
                return reject(&mut client, "403 Forbidden").await;
            }
            let mut upstream = match connect_upstream(host, *port, ctx).await {
                Ok(s) => s,
                Err(status) => return reject(&mut client, status).await,
            };
            let forwarded = origin_request(&head, path, host, *port);
            if upstream.write_all(forwarded.as_bytes()).await.is_err()
                || (!rest.is_empty() && upstream.write_all(&rest).await.is_err())
            {
                return;
            }
            relay(client, upstream).await;
        }
    }
}

/// The request to send to the origin: origin-form target, proxy-only headers
/// dropped, and `Connection: close` so one filtered request is exactly one
/// connection (a client cannot slip further requests past the filter).
/// `Upgrade` requests (WebSocket) keep their `Connection` header.
fn origin_request(head: &Head, path: &str, host: &str, port: u16) -> String {
    // Only WebSocket may keep the connection: any other upgrade (h2c) would
    // let further requests through unfiltered.
    let upgrade = head
        .header("upgrade")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("websocket"));
    let mut out = format!("{} {} {}\r\n", head.method, path, head.version);
    let mut has_host = false;
    for (name, value) in &head.headers {
        let lower = name.to_ascii_lowercase();
        if lower == "proxy-connection" || lower == "proxy-authorization" || lower == "keep-alive" {
            continue;
        }
        if (lower == "connection" || lower == "upgrade") && !upgrade {
            continue;
        }
        has_host |= lower == "host";
        out.push_str(name);
        out.push_str(": ");
        out.push_str(value);
        out.push_str("\r\n");
    }
    if !has_host {
        let shown = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_string()
        };
        if port == 80 {
            out.push_str(&format!("Host: {shown}\r\n"));
        } else {
            out.push_str(&format!("Host: {shown}:{port}\r\n"));
        }
    }
    if !upgrade {
        out.push_str("Connection: close\r\n");
    }
    out.push_str("\r\n");
    out
}

/// Copies one direction, closing the write side at EOF. Fails on idle
/// timeout or error.
async fn pump<R, W>(mut r: R, mut w: W) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; RELAY_BUF];
    loop {
        let n = match timeout(IDLE_TIMEOUT, r.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(io::ErrorKind::TimedOut.into()),
        };
        if n == 0 {
            let _ = w.shutdown().await;
            return Ok(());
        }
        w.write_all(&buf[..n]).await?;
    }
}

/// Relays both directions until both sides finish or either errors or idles.
async fn relay(client: TcpStream, upstream: TcpStream) {
    let (cr, cw) = client.into_split();
    let (ur, uw) = upstream.into_split();
    let up = pump(cr, uw);
    let down = pump(ur, cw);
    tokio::pin!(up, down);
    // If one direction fails (error or idle), tear down both.
    tokio::select! {
        r = &mut up => { if r.is_ok() { let _ = down.await; } }
        r = &mut down => { if r.is_ok() { let _ = up.await; } }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::parse_head;

    fn head(raw: &str) -> Head {
        parse_head(raw.as_bytes()).unwrap().unwrap()
    }

    #[test]
    fn forwarded_request_is_origin_form_without_proxy_headers() {
        let h = head(
            "GET http://example.com/a?b=1 HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic x\r\nConnection: keep-alive\r\nKeep-Alive: 5\r\nAccept: */*\r\n\r\n",
        );
        let Target::Http {
            path, host, port, ..
        } = &h.target
        else {
            panic!()
        };
        let out = origin_request(&h, path, host, *port);
        assert!(out.starts_with("GET /a?b=1 HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com\r\n"));
        assert!(out.contains("Accept: */*\r\n"));
        assert!(!out.to_ascii_lowercase().contains("proxy-"));
        assert!(!out.contains("keep-alive"));
        assert!(out.ends_with("Connection: close\r\n\r\n"));
    }

    #[test]
    fn host_header_is_added_when_missing_and_websocket_keeps_connection() {
        let h = head("GET http://example.com:8080/ HTTP/1.1\r\n\r\n");
        let out = origin_request(&h, "/", "example.com", 8080);
        assert!(out.contains("Host: example.com:8080\r\n"));
        let h = head(
            "GET http://example.com/ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        );
        let out = origin_request(&h, "/ws", "example.com", 80);
        assert!(out.contains("Connection: Upgrade\r\n"));
        assert!(!out.contains("Connection: close"));
        let h = head(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n",
        );
        let out = origin_request(&h, "/", "example.com", 80);
        assert!(!out.to_ascii_lowercase().contains("upgrade"));
        assert!(out.ends_with("Connection: close\r\n\r\n"));
    }
}
