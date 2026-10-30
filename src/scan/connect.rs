//! The TCP connect seam shared by the Ports and TLS scanners, so a test can stand in for the
//! network and hand back a chosen errno.

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;

pub type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send>>;

/// Opens a TCP connection to an address. `system()` is the real `TcpStream::connect`.
#[derive(Clone)]
pub struct TcpConnector(Arc<dyn Fn(SocketAddr) -> ConnectFuture + Send + Sync>);

impl TcpConnector {
    pub fn system() -> Self {
        Self(Arc::new(|addr| Box::pin(TcpStream::connect(addr))))
    }

    /// A connector backed by `connect`, for tests that need a chosen connect outcome.
    #[cfg(test)]
    pub fn from_fn(connect: impl Fn(SocketAddr) -> ConnectFuture + Send + Sync + 'static) -> Self {
        Self(Arc::new(connect))
    }

    /// A connector whose every connect fails with the OS error `errno`.
    #[cfg(test)]
    pub fn failing_with(errno: i32) -> Self {
        Self::from_fn(move |_| Box::pin(async move { Err(io::Error::from_raw_os_error(errno)) }))
    }

    pub fn connect(&self, addr: SocketAddr) -> ConnectFuture {
        (self.0)(addr)
    }
}

impl Default for TcpConnector {
    fn default() -> Self {
        Self::system()
    }
}

impl fmt::Debug for TcpConnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TcpConnector")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn system_connector_reaches_a_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let stream = TcpConnector::system().connect(addr).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), addr);
    }

    #[tokio::test]
    async fn failing_connector_returns_the_chosen_errno() {
        let error = TcpConnector::failing_with(111)
            .connect("127.0.0.1:9".parse().unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(111));
    }
}
