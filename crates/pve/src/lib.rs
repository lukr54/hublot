//! Proxmox VE API client — the pieces Hublot's tier-2 console needs.
//!
//! Scope on purpose: ticket auth, `termproxy`, and the console websocket. Nothing else.
//!
//! TLS is **certificate-pinned**, not name-verified. Two reasons, both measured (DECISIONS.md D1):
//! the PVE cluster CA is not served in the handshake (leaf only), and the leaf's SANs list
//! `192.168.2.10` — an address this host no longer has — so name verification would fail against
//! the address we actually connect to. Pinning sidesteps both and is the stronger check anyway.

use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};

pub mod frame;

/// Pinning lives in its own crate so there is exactly one implementation of it in the codebase.
pub use pinning::{hex, parse_fingerprint};

fn tls_config(fingerprint: [u8; 32]) -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = pinning::PinnedCert::new(fingerprint, provider.clone());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("building rustls config")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(cfg)
}

/// A PVE login ticket. Valid ~2h.
#[derive(Debug, Clone)]
pub struct Ticket {
    pub ticket: String,
    pub csrf: String,
    pub username: String,
}

/// The short-lived console credentials returned by `termproxy`.
#[derive(Debug, Clone)]
pub struct TermProxy {
    pub user: String,
    pub ticket: String,
    pub port: String,
}

pub struct PveClient {
    base: String,
    host: String,
    http: reqwest::Client,
    tls: Arc<rustls::ClientConfig>,
}

impl PveClient {
    /// `host` is what we connect to (IP is fine — the pin does the verifying).
    pub fn new(host: &str, port: u16, fingerprint: [u8; 32]) -> Result<Self> {
        let tls = tls_config(fingerprint)?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(tls.clone())
            .build()
            .context("building http client")?;
        Ok(Self {
            base: format!("https://{host}:{port}/api2/json"),
            host: format!("{host}:{port}"),
            http,
            tls: Arc::new(tls),
        })
    }

    pub async fn login(&self, username: &str, password: &str) -> Result<Ticket> {
        let resp = self
            .http
            .post(format!("{}/access/ticket", self.base))
            .form(&[("username", username), ("password", password)])
            .send()
            .await
            .context("POST /access/ticket")?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.context("decoding ticket response")?;
        if !status.is_success() {
            bail!("login failed ({status}): {body}");
        }
        let data = body
            .get("data")
            .ok_or_else(|| anyhow!("no data in ticket response"))?;
        Ok(Ticket {
            ticket: str_field(data, "ticket")?,
            csrf: str_field(data, "CSRFPreventionToken")?,
            username: str_field(data, "username")?,
        })
    }

    /// Ask for a shell on the node itself. Requires `Sys.Console`.
    pub async fn termproxy(&self, ticket: &Ticket, node: &str) -> Result<TermProxy> {
        let resp = self
            .http
            .post(format!("{}/nodes/{node}/termproxy", self.base))
            .header(
                "Cookie",
                format!("PVEAuthCookie={}", urlencoding::encode(&ticket.ticket)),
            )
            .header("CSRFPreventionToken", &ticket.csrf)
            .send()
            .await
            .context("POST termproxy")?;

        let status = resp.status();
        let body: serde_json::Value = resp.json().await.context("decoding termproxy response")?;
        if !status.is_success() {
            bail!("termproxy failed ({status}): {body}");
        }
        let data = body
            .get("data")
            .ok_or_else(|| anyhow!("no data in termproxy response"))?;
        Ok(TermProxy {
            user: str_field(data, "user")?,
            ticket: str_field(data, "ticket")?,
            // PVE has returned this as both a string and a number across versions.
            port: match data.get("port") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Number(n)) => n.to_string(),
                _ => bail!("no port in termproxy response: {data}"),
            },
        })
    }

    /// Open the console websocket and complete the in-band auth handshake.
    ///
    /// Protocol (verified, DECISIONS.md D5): the first message is binary `user:ticket\n`, to which
    /// the server replies `OK`. Everything after that is the termproxy framing in `frame`.
    pub async fn open_console(
        &self,
        ticket: &Ticket,
        node: &str,
        tp: &TermProxy,
    ) -> Result<WsStream> {
        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        use tokio_tungstenite::tungstenite::Message;

        let url = format!(
            "wss://{}/api2/json/nodes/{node}/vncwebsocket?port={}&vncticket={}",
            self.host,
            urlencoding::encode(&tp.port),
            urlencoding::encode(&tp.ticket),
        );

        let mut req = url.into_client_request().context("building ws request")?;
        req.headers_mut().insert(
            "Cookie",
            format!("PVEAuthCookie={}", urlencoding::encode(&ticket.ticket))
                .parse()
                .context("cookie header")?,
        );

        let (mut ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
            req,
            None,
            false,
            Some(tokio_tungstenite::Connector::Rustls(self.tls.clone())),
        )
        .await
        .context("websocket connect")?;

        use futures_util::{SinkExt, StreamExt};
        ws.send(Message::Binary(
            format!("{}:{}\n", tp.user, tp.ticket).into_bytes().into(),
        ))
        .await
        .context("sending ws auth")?;

        // The server answers "OK" before any terminal data.
        match ws.next().await {
            Some(Ok(msg)) => {
                let bytes = msg.into_data();
                if !bytes.starts_with(b"OK") {
                    bail!(
                        "expected OK after ws auth, got {:?}",
                        String::from_utf8_lossy(&bytes)
                    );
                }
            }
            Some(Err(e)) => bail!("ws error during auth: {e}"),
            None => bail!("ws closed during auth"),
        }
        Ok(ws)
    }
}

pub type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Re-exported so callers speak the same tungstenite version we do.
pub use tokio_tungstenite::tungstenite::Message;

fn str_field(v: &serde_json::Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("missing field `{key}` in {v}"))
}
