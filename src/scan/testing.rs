//! Test helpers shared by the scanner tests.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(unix)]
/// Write `content` to `path` as an executable script, ready to exec.
///
/// A child `sh` does the write. If this process held the write fd, a sibling test's fork
/// could inherit it, and exec of the script would fail with `Text file busy (os error 26)`.
pub fn write_executable_script(path: &Path, content: &str) {
    let status = std::process::Command::new("sh")
        .args(["-c", r#"printf '%s' "$1" > "$2" && chmod 755 "$2""#, "sh"])
        .arg(content)
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("spawning sh to write {}: {e}", path.display()));
    assert!(status.success(), "writing {}: {status}", path.display());
}

/// Bound on every fake-server accept and read, so a missed request ends the server instead of
/// hanging the test.
const FAKE_SERVER_WAIT: Duration = Duration::from_secs(5);

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh, empty directory under the system temp dir, unique per call.
pub fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "scan-{name}-{}-{}",
        std::process::id(),
        TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("creating {}: {e}", dir.display()));
    dir
}

/// A local HTTP/1.1 server answering fixed routes, one request per connection, and counting the
/// requests per path. An unknown path gets 404. It stops after `FAKE_SERVER_WAIT` with no request.
pub struct FakeHttp {
    addr: String,
    routes: Arc<Mutex<Vec<(String, u16, String)>>>,
    requests: Arc<Mutex<Vec<String>>>,
}

impl FakeHttp {
    pub async fn start(routes: Vec<(&str, u16, String)>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let fake = Self {
            addr,
            routes: Arc::new(Mutex::new(Vec::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        };
        for (path, status, body) in routes {
            fake.add_route(path, status, body);
        }
        let routes = fake.routes.clone();
        let seen = fake.requests.clone();
        tokio::spawn(async move {
            while let Ok(Ok((mut socket, _))) = tokio::time::timeout(FAKE_SERVER_WAIT, listener.accept()).await {
                let Some(path) = read_request_path(&mut socket).await else {
                    continue;
                };
                seen.lock().unwrap().push(path.clone());
                let (status, body) = routes
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|(route, _, _)| *route == path)
                    .map(|(_, status, body)| (*status, body.clone()))
                    .unwrap_or((404, String::new()));
                let response = format!(
                    "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            }
        });
        fake
    }

    /// Adds a route after start, for a body that names the server's own address.
    pub fn add_route(&self, path: &str, status: u16, body: String) {
        self.routes.lock().unwrap().push((path.to_string(), status, body));
    }

    /// `http://<addr><path>`
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    /// Requests received so far for `path`.
    pub fn hits(&self, path: &str) -> usize {
        self.requests.lock().unwrap().iter().filter(|p| *p == path).count()
    }
}

/// The request path, read up to the end of the headers; `None` when the client sends nothing
/// readable in time.
async fn read_request_path(socket: &mut tokio::net::TcpStream) -> Option<String> {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(FAKE_SERVER_WAIT, socket.read(&mut buf))
            .await
            .ok()?
            .ok()?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
    }
    let text = String::from_utf8_lossy(&request);
    text.lines().next()?.split_whitespace().nth(1).map(str::to_string)
}

/// A URL on a local port nothing listens on, so a request to it is refused at once.
pub async fn dead_http_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    format!("http://{addr}/gone")
}

/// A URL whose server accepts one connection and never answers it.
pub async fn silent_http_url() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok(Ok((socket, _))) = tokio::time::timeout(FAKE_SERVER_WAIT, listener.accept()).await {
            tokio::time::sleep(Duration::from_secs(10)).await;
            drop(socket);
        }
    });
    format!("http://{addr}/silent")
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn written_script_is_executable_and_runs() {
        let dir = std::env::temp_dir().join(format!("scan-testing-script-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("hello");
        write_executable_script(&script, "#!/bin/sh\necho \"hi $1\"\n");
        let out = std::process::Command::new(&script).arg("there").output().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout), "hi there\n");
    }

    #[test]
    #[should_panic(expected = "writing")]
    fn unwritable_path_panics_loudly() {
        write_executable_script(Path::new("/nonexistent-dir/script"), "#!/bin/sh\n");
    }
}
