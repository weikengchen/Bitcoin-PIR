//! PIR server builder and runner.

use crate::config::{ConfigError, ServerConfig};
use crate::loader::DatabaseLoader;
use futures_util::{SinkExt, StreamExt};
use pir_sdk::{DatabaseCatalog, PirError, PirResult, ServerRole};
use pir_runtime_core::handler::RequestHandler;
use pir_runtime_core::protocol::{Request, Response};
use std::path::Path;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_tungstenite::tungstenite::Message;

/// Handle for graceful shutdown.
#[derive(Clone)]
pub struct ShutdownHandle {
    sender: watch::Sender<bool>,
}

impl ShutdownHandle {
    /// Signal the server to shut down.
    pub fn shutdown(&self) {
        let _ = self.sender.send(true);
    }
}

/// A running PIR server.
pub struct PirServer {
    config: ServerConfig,
    handler: Arc<RequestHandler>,
    catalog: DatabaseCatalog,
    listener: Option<TcpListener>,
    shutdown_rx: watch::Receiver<bool>,
    shutdown_tx: watch::Sender<bool>,
}

impl PirServer {
    /// Get the server configuration.
    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    /// Get the database catalog.
    pub fn catalog(&self) -> &DatabaseCatalog {
        &self.catalog
    }

    /// Get a shutdown handle.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            sender: self.shutdown_tx.clone(),
        }
    }

    /// Get the bound address.
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.listener.as_ref().and_then(|l| l.local_addr().ok())
    }

    /// Run the server until shutdown.
    pub async fn run(mut self) -> PirResult<()> {
        let listener = self
            .listener
            .take()
            .ok_or_else(|| PirError::InvalidState("server not bound".into()))?;

        let addr = listener.local_addr().map_err(PirError::Io)?;
        log::info!("PIR server listening on {}", addr);
        log::info!(
            "Serving {} databases, role={:?}",
            self.handler.databases().len(),
            self.config.role
        );

        // Main accept loop
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            log::debug!("New connection from {}", peer);
                            let handler = self.handler.clone();
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(stream, handler).await {
                                    log::error!("Connection error from {}: {}", peer, e);
                                }
                            });
                        }
                        Err(e) => {
                            log::error!("Accept error: {}", e);
                        }
                    }
                }
                _ = self.shutdown_rx.changed() => {
                    if *self.shutdown_rx.borrow() {
                        log::info!("Shutdown signal received");
                        break;
                    }
                }
            }
        }

        log::info!("PIR server stopped");
        Ok(())
    }
}

/// Handle a single WebSocket connection.
async fn handle_connection(stream: TcpStream, handler: Arc<RequestHandler>) -> PirResult<()> {
    let ws_stream = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| PirError::ConnectionFailed(format!("WebSocket handshake failed: {}", e)))?;

    let (mut sink, mut stream) = ws_stream.split();

    while let Some(msg) = stream.next().await {
        let msg = match msg {
            Ok(m) => m,
            Err(e) => {
                log::debug!("WebSocket read error: {}", e);
                break;
            }
        };

        match msg {
            Message::Binary(data) => {
                // Parse request (skip 4-byte length prefix)
                if data.len() < 5 {
                    log::warn!("Message too short: {} bytes", data.len());
                    continue;
                }

                let payload = &data[4..];
                let request = match Request::decode(payload) {
                    Ok(r) => r,
                    Err(e) => {
                        log::warn!("Failed to decode request: {}", e);
                        let error_resp = Response::Error(format!("decode error: {}", e));
                        let encoded = error_resp.encode();
                        let _ = sink.send(Message::Binary(encoded.into())).await;
                        continue;
                    }
                };

                // Handle request
                let response = handler.handle_request(&request);

                // Send response
                let encoded = response.encode();
                if let Err(e) = sink.send(Message::Binary(encoded.into())).await {
                    log::debug!("WebSocket send error: {}", e);
                    break;
                }
            }
            Message::Ping(data) => {
                let _ = sink.send(Message::Pong(data)).await;
            }
            Message::Close(_) => {
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

/// Builder for creating a PIR server.
pub struct PirServerBuilder {
    config: ServerConfig,
}

impl PirServerBuilder {
    /// Create a new server builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: ServerConfig::new(),
        }
    }

    /// Load configuration from a TOML file.
    pub fn from_config(mut self, path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        self.config = ServerConfig::load(path.as_ref())?;
        Ok(self)
    }

    /// Set the listening port.
    pub fn port(mut self, port: u16) -> Self {
        self.config.port = port;
        self
    }

    /// Set the server role.
    pub fn role(mut self, role: ServerRole) -> Self {
        self.config.role(role);
        self
    }

    /// Add a full snapshot database.
    pub fn add_full_db(mut self, path: impl AsRef<Path>, height: u32) -> Self {
        self.config.add_full_db(path.as_ref(), height);
        self
    }

    /// Add a delta database.
    pub fn add_delta_db(
        mut self,
        path: impl AsRef<Path>,
        base_height: u32,
        tip_height: u32,
    ) -> Self {
        self.config
            .add_delta_db(path.as_ref(), base_height, tip_height);
        self
    }

    /// Enable or disable warmup.
    pub fn warmup(mut self, enable: bool) -> Self {
        self.config.warmup = enable;
        self
    }

    /// Disable DPF backend.
    pub fn disable_dpf(mut self) -> Self {
        self.config.enable_dpf = false;
        self
    }

    /// Disable HarmonyPIR backend.
    pub fn disable_harmony(mut self) -> Self {
        self.config.enable_harmony = false;
        self
    }

    /// Disable OnionPIR backend.
    pub fn disable_onion(mut self) -> Self {
        self.config.enable_onion = false;
        self
    }

    /// Build and bind the server (but don't start accepting connections).
    pub async fn build(self) -> PirResult<PirServer> {
        // Load databases
        let mut loader = DatabaseLoader::new();
        loader.load_all(&self.config.databases)?;

        if loader.is_empty() {
            return Err(PirError::Config("no databases configured".into()));
        }

        log::info!("Loaded {} databases", loader.len());
        for db in loader.catalog().databases.iter() {
            log::info!(
                "  [{}] {} {:?} height={} index_bins={} chunk_bins={}",
                db.db_id,
                db.name,
                db.kind,
                db.height,
                db.index_bins,
                db.chunk_bins
            );
        }

        // Create request handler
        let catalog = loader.catalog().clone();
        let handler = Arc::new(RequestHandler::new(loader.into_databases()));

        // Bind listener
        let addr = format!("0.0.0.0:{}", self.config.port);
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| PirError::ConnectionFailed(format!("bind {}: {}", addr, e)))?;

        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        Ok(PirServer {
            config: self.config,
            handler,
            catalog,
            listener: Some(listener),
            shutdown_rx,
            shutdown_tx,
        })
    }
}

impl Default for PirServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
