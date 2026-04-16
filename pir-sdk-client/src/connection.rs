//! WebSocket connection utilities.

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use pir_sdk::{PirError, PirResult};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

/// PIR responses can be very large — a fresh-sync chunk batch against the
/// live `main` database returns ~32 MiB in a single WebSocket frame, which
/// blows past `tungstenite`'s defaults (16 MiB frame / 64 MiB message).
/// Bumping both limits to 256 MiB keeps normal PIR traffic well below the
/// ceiling while still bounding memory use against a malicious server.
const MAX_WS_MESSAGE_SIZE: usize = 256 * 1024 * 1024;
const MAX_WS_FRAME_SIZE: usize = 256 * 1024 * 1024;

/// A WebSocket connection to a PIR server.
pub struct WsConnection {
    sink: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    stream: SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    url: String,
}

/// Install the `ring` crypto provider for rustls exactly once per process.
///
/// rustls 0.23+ requires a process-wide default `CryptoProvider` before any
/// TLS handshake. We install `ring` (pure-Rust, no C toolchain). Multiple
/// threads calling `connect()` concurrently are serialized by `OnceLock`;
/// a pre-installed provider (e.g. by a consumer application) is left alone.
fn install_default_crypto_provider() {
    use std::sync::OnceLock;
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        // `install_default` returns `Err` if a provider was already installed
        // by a different crate (or a previous call). Either way the post-
        // condition "a provider is installed" holds, so the error is ignored.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

impl WsConnection {
    /// Connect to a WebSocket URL.
    ///
    /// Supports both `ws://` and `wss://` URLs. For `wss://` the rustls
    /// `ring` crypto provider is installed lazily on first call.
    ///
    /// The `tungstenite` 16 MiB default max frame size is bumped to
    /// [`MAX_WS_FRAME_SIZE`] so fresh-sync chunk batches (which can exceed
    /// 30 MiB against the main UTXO database) don't get rejected with
    /// `"Space limit exceeded: Message too long"`.
    pub async fn connect(url: &str) -> PirResult<Self> {
        install_default_crypto_provider();
        let config = WebSocketConfig {
            max_message_size: Some(MAX_WS_MESSAGE_SIZE),
            max_frame_size: Some(MAX_WS_FRAME_SIZE),
            ..Default::default()
        };
        let (ws, _) = tokio_tungstenite::connect_async_with_config(url, Some(config), false)
            .await
            .map_err(|e| PirError::ConnectionFailed(format!("{}: {}", url, e)))?;

        let (sink, stream) = ws.split();

        Ok(Self {
            sink,
            stream,
            url: url.to_string(),
        })
    }

    /// Get the URL this connection is connected to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Send a binary message.
    pub async fn send(&mut self, data: Vec<u8>) -> PirResult<()> {
        self.sink
            .send(Message::Binary(data.into()))
            .await
            .map_err(|e| PirError::ConnectionClosed(format!("send: {}", e)))
    }

    /// Receive a binary message, handling ping/pong automatically.
    pub async fn recv(&mut self) -> PirResult<Vec<u8>> {
        loop {
            let msg = self
                .stream
                .next()
                .await
                .ok_or_else(|| PirError::ConnectionClosed("stream ended".into()))?
                .map_err(|e| PirError::ConnectionClosed(format!("recv: {}", e)))?;

            match msg {
                Message::Binary(b) => return Ok(b.into()),
                Message::Ping(p) => {
                    let _ = self.sink.send(Message::Pong(p)).await;
                }
                Message::Pong(_) => continue,
                Message::Close(_) => {
                    return Err(PirError::ConnectionClosed("server closed".into()))
                }
                Message::Text(_) => continue,
                Message::Frame(_) => continue,
            }
        }
    }

    /// Send a request and receive a response.
    ///
    /// The request is encoded as: [4B length LE][payload]
    /// The response is: [4B length LE][payload]
    pub async fn roundtrip(&mut self, request: &[u8]) -> PirResult<Vec<u8>> {
        // Send request (already includes length prefix from protocol encoding)
        self.send(request.to_vec()).await?;

        // Receive response
        let response = self.recv().await?;

        // Skip 4-byte length prefix
        if response.len() < 4 {
            return Err(PirError::Protocol("response too short".into()));
        }

        Ok(response[4..].to_vec())
    }

    /// Close the connection.
    pub async fn close(&mut self) -> PirResult<()> {
        let _ = self.sink.send(Message::Close(None)).await;
        Ok(())
    }
}
