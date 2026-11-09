use crate::connection::MorshConnection;
use crate::tcp_mux::TcpConnection;
use anyhow::{Context, Result};
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info};

/// TCP TLS fallback server listener.
pub struct TcpServer {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TcpServer {
    /// Binds a TCP listener on the specified socket address using the provided rustls ServerConfig.
    pub async fn bind(addr: SocketAddr, server_config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind TCP server on {}", addr))?;

        let acceptor = TlsAcceptor::from(server_config);
        info!("TCP fallback server bound to {}", listener.local_addr()?);
        Ok(Self { listener, acceptor })
    }

    /// Returns the local socket address this server is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.listener
            .local_addr()
            .context("Failed to get TCP local address")
    }

    /// Asynchronously waits for and accepts the next incoming TLS 1.3 over TCP connection.
    pub async fn accept(&self) -> Option<Result<MorshConnection>> {
        let (stream, peer_addr) = match self.listener.accept().await {
            Ok(res) => res,
            Err(e) => return Some(Err(anyhow::anyhow!("TCP accept error: {}", e))),
        };

        let acceptor = self.acceptor.clone();
        Some(Self::handshake(stream, peer_addr, acceptor).await)
    }

    async fn handshake(
        stream: TcpStream,
        peer_addr: SocketAddr,
        acceptor: TlsAcceptor,
    ) -> Result<MorshConnection> {
        debug!(remote = %peer_addr, "Performing TLS 1.3 handshake over incoming TCP stream");
        let tls_stream = acceptor
            .accept(stream)
            .await
            .with_context(|| format!("TLS handshake failed with {}", peer_addr))?;

        info!(remote = %peer_addr, "TLS 1.3 over TCP connection established");
        let conn = TcpConnection::new(tls_stream, peer_addr, false);
        Ok(MorshConnection::from_tcp(conn))
    }
}

/// TCP TLS fallback client connector.
pub struct TcpClient;

impl TcpClient {
    /// Connects to a remote server over TCP and completes the TLS 1.3 handshake.
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
        client_config: Arc<rustls::ClientConfig>,
    ) -> Result<MorshConnection> {
        debug!(
            target_addr = %server_addr,
            server_name = %server_name,
            "Connecting to morsh server over TCP (TLS 1.3 fallback)"
        );

        let stream = TcpStream::connect(server_addr)
            .await
            .with_context(|| format!("Failed to establish TCP connection to {}", server_addr))?;

        let _ = stream.set_nodelay(true);

        let connector = TlsConnector::from(client_config);
        let dns_name = ServerName::try_from(server_name.to_string())
            .with_context(|| format!("Invalid TLS server name: '{}'", server_name))?;

        let tls_stream = connector
            .connect(dns_name, stream)
            .await
            .with_context(|| format!("TLS 1.3 handshake over TCP failed with {}", server_addr))?;

        info!(
            remote = %server_addr,
            "Connected to morsh server via TLS 1.3 over TCP fallback"
        );

        let conn = TcpConnection::new(tls_stream, server_addr, true);
        Ok(MorshConnection::from_tcp(conn))
    }
}

/// A byte stream over a child process's stdio, used as the transport for
/// ProxyCommand-style connections. Owns the child so it is terminated
/// (kill_on_drop) when the stream is dropped.
pub struct ProxyStream {
    inner: tokio::io::Join<tokio::process::ChildStdout, tokio::process::ChildStdin>,
    _child: tokio::process::Child,
}

impl tokio::io::AsyncRead for ProxyStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for ProxyStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Expands OpenSSH-style ProxyCommand tokens: %h = host, %p = port, %% = %.
fn expand_proxy_command(template: &str, host: &str, port: u16) -> String {
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            match chars.next() {
                Some('h') => out.push_str(host),
                Some('p') => out.push_str(&port.to_string()),
                Some('%') => out.push('%'),
                Some(other) => {
                    out.push('%');
                    out.push(other);
                }
                None => out.push('%'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

impl TcpClient {
    /// Connects through a ProxyCommand: spawns the command (via `sh -c`) with
    /// %h/%p expanded and runs the TLS 1.3 handshake over its stdio.
    pub async fn connect_via_proxy(
        proxy_command: &str,
        host: &str,
        port: u16,
        server_name: &str,
        client_config: Arc<rustls::ClientConfig>,
    ) -> Result<MorshConnection> {
        let expanded = expand_proxy_command(proxy_command, host, port);
        debug!(command = %expanded, "Spawning ProxyCommand for TCP transport");

        let mut child = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&expanded)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Failed to spawn ProxyCommand '{}'", expanded))?;

        let stdout = child
            .stdout
            .take()
            .context("ProxyCommand stdout unavailable")?;
        let stdin = child.stdin.take().context("ProxyCommand stdin unavailable")?;
        let stream = ProxyStream {
            inner: tokio::io::join(stdout, stdin),
            _child: child,
        };

        let connector = TlsConnector::from(client_config);
        let dns_name = ServerName::try_from(server_name.to_string())
            .with_context(|| format!("Invalid TLS server name: '{}'", server_name))?;

        let tls_stream = connector
            .connect(dns_name, stream)
            .await
            .with_context(|| {
                format!(
                    "TLS 1.3 handshake over ProxyCommand '{}' failed",
                    expanded
                )
            })?;

        let remote_addr: SocketAddr = format!("{}:{}", host, port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], port)));
        info!(
            remote = %remote_addr,
            "Connected to morsh server via ProxyCommand (TLS 1.3 over stdio)"
        );
        let conn = TcpConnection::new(tls_stream, remote_addr, true);
        Ok(MorshConnection::from_tcp(conn))
    }
}
