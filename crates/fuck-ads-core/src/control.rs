//! Control API transport: a Unix domain socket speaking line-delimited JSON.
//!
//! Authorization uses kernel-verified peer credentials (`SO_PEERCRED` on
//! Linux, `getpeereid` on macOS): read-only requests are open to every local
//! user, state-changing requests require root or the daemon's own account.

use crate::protocol::{MAX_REQUEST_BYTES, Request, Response};
use std::future::Future;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Semaphore, watch};

const MAX_CONNECTIONS: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, thiserror::Error)]
pub enum ControlError {
    #[error("the FuckAds service is not running (no control socket at {0})")]
    NotRunning(String),
    #[error("permission denied connecting to {0}")]
    PermissionDenied(String),
    #[error("another FuckAds daemon is already running")]
    AlreadyRunning,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timed out waiting for the service")]
    Timeout,
    #[error("invalid response from the service: {0}")]
    Protocol(String),
}

/// Reads one `\n`-terminated line of at most `limit` bytes.
/// Returns `Ok(None)` at EOF.
pub async fn read_line_limited<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(if line.is_empty() { None } else { Some(line) });
        }
        if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
            line.extend_from_slice(&buf[..pos]);
            reader.consume(pos + 1);
            if line.len() > limit {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "request too large",
                ));
            }
            return Ok(Some(line));
        }
        let n = buf.len();
        line.extend_from_slice(buf);
        reader.consume(n);
        if line.len() > limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
    }
}

/// Binds the control socket, replacing a stale socket file left by a crash.
pub async fn bind(path: &Path) -> Result<UnixListener, ControlError> {
    // sockaddr_un.sun_path is 104 bytes on macOS and 108 on Linux.
    if path.as_os_str().len() >= 104 {
        return Err(ControlError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socket path {} is too long (limit 103 bytes); set a shorter [paths] socket",
                path.display()
            ),
        )));
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(ControlError::Io(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                format!(
                    "{} exists and is not a socket; refusing to remove it",
                    path.display()
                ),
            )));
        }
        if UnixStream::connect(path).await.is_ok() {
            return Err(ControlError::AlreadyRunning);
        }
        std::fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    // Every local user may connect; authorization happens per request.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))?;
    Ok(listener)
}

/// Serves control connections until shutdown.
pub async fn serve<H, F>(
    listener: UnixListener,
    handler: Arc<H>,
    mut shutdown: watch::Receiver<bool>,
) where
    H: Fn(Request, bool) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    // SAFETY: geteuid has no preconditions.
    let own_uid = unsafe { libc::geteuid() };
    loop {
        let stream = tokio::select! {
            r = listener.accept() => match r {
                Ok((s, _)) => s,
                Err(e) => {
                    tracing::debug!(error = %e, "control accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            _ = shutdown.changed() => return,
        };
        let privileged = match stream.peer_cred() {
            Ok(cred) => cred.uid() == 0 || cred.uid() == own_uid,
            Err(_) => false,
        };
        // Privileged peers bypass the limit, so another local user holding
        // every slot cannot lock root out.
        let permit = if privileged {
            None
        } else {
            let Ok(permit) = limit.clone().try_acquire_owned() else {
                continue;
            };
            Some(permit)
        };
        let handler = handler.clone();
        tokio::spawn(async move {
            let _ = connection(stream, privileged, handler).await;
            drop(permit);
        });
    }
}

async fn connection<H, F>(
    stream: UnixStream,
    privileged: bool,
    handler: Arc<H>,
) -> std::io::Result<()>
where
    H: Fn(Request, bool) -> F + Send + Sync + 'static,
    F: Future<Output = Response> + Send + 'static,
{
    let (read, mut write) = stream.into_split();
    let mut reader = BufReader::new(read);
    loop {
        let line = match tokio::time::timeout(
            IDLE_TIMEOUT,
            read_line_limited(&mut reader, MAX_REQUEST_BYTES),
        )
        .await
        {
            Ok(Ok(Some(line))) => line,
            Ok(Err(e)) => {
                let resp = Response::error(e.to_string());
                write.write_all(&encode(&resp)).await?;
                return Ok(());
            }
            _ => return Ok(()),
        };
        let response = match serde_json::from_slice::<Request>(&line) {
            Ok(req) if req.is_privileged() && !privileged => {
                Response::error("permission denied: run this command with sudo")
            }
            Ok(req) => handler(req, privileged).await,
            Err(e) => Response::error(format!("invalid request: {e}")),
        };
        write.write_all(&encode(&response)).await?;
    }
}

fn encode(resp: &Response) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(resp)
        .unwrap_or_else(|_| br#"{"type":"error","data":{"message":"encoding failed"}}"#.to_vec());
    bytes.push(b'\n');
    bytes
}

/// Client for the control API.
#[derive(Debug)]
pub struct Client {
    reader: BufReader<tokio::net::unix::OwnedReadHalf>,
    writer: tokio::net::unix::OwnedWriteHalf,
}

/// Responses (e.g. DNR rule pages) can be large.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

impl Client {
    pub async fn connect(path: &Path) -> Result<Client, ControlError> {
        let stream =
            match tokio::time::timeout(Duration::from_secs(5), UnixStream::connect(path)).await {
                Err(_) => return Err(ControlError::Timeout),
                Ok(Err(e)) => {
                    return Err(match e.kind() {
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                            ControlError::NotRunning(path.display().to_string())
                        }
                        std::io::ErrorKind::PermissionDenied => {
                            ControlError::PermissionDenied(path.display().to_string())
                        }
                        _ => ControlError::Io(e),
                    });
                }
                Ok(Ok(s)) => s,
            };
        let (read, writer) = stream.into_split();
        Ok(Client {
            reader: BufReader::new(read),
            writer,
        })
    }

    pub async fn request(
        &mut self,
        req: &Request,
        timeout: Duration,
    ) -> Result<Response, ControlError> {
        let mut line =
            serde_json::to_vec(req).map_err(|e| ControlError::Protocol(e.to_string()))?;
        line.push(b'\n');
        let fut = async {
            self.writer.write_all(&line).await?;
            let resp = read_line_limited(&mut self.reader, MAX_RESPONSE_BYTES)
                .await?
                .ok_or_else(|| ControlError::Protocol("connection closed".into()))?;
            serde_json::from_slice::<Response>(&resp)
                .map_err(|e| ControlError::Protocol(e.to_string()))
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ControlError::Timeout)?
    }
}

/// One-shot request helper.
pub async fn request(
    path: &Path,
    req: &Request,
    timeout: Duration,
) -> Result<Response, ControlError> {
    Client::connect(path).await?.request(req, timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn unprivileged_peers_cannot_change_state() {
        let (server, client) = UnixStream::pair().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let seen = called.clone();
        let handler = Arc::new(move |_: Request, _: bool| {
            seen.store(true, Ordering::SeqCst);
            async { Response::ok("changed") }
        });
        let served = tokio::spawn(connection(server, false, handler));

        let (read, mut write) = client.into_split();
        write
            .write_all(b"{\"cmd\":\"set_enabled\",\"enabled\":false}\n")
            .await
            .unwrap();
        let mut reply = String::new();
        BufReader::new(read).read_line(&mut reply).await.unwrap();
        drop(write);
        served.await.unwrap().unwrap();

        assert!(reply.contains("permission denied"), "{reply}");
        assert!(!called.load(Ordering::SeqCst));
    }
}
