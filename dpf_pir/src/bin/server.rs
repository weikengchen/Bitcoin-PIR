//! DPF-PIR WebSocket Server //!
//! A WebSocket-based PIR server for browser clients (PIR databases).
//! Supports multiple queries over a single WebSocket connection.
//!
//! ## Usage
//!
//! Plain WebSocket (ws://):
//! ```bash
//! cargo run --bin server -- --port 8092
//! ```
//!
//! Secure WebSocket (wss://) with TLS:
//! ```bash
//! cargo run --bin server -- --port 8092 --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem
//! ```
//!
//! Small databases:
//! ```bash
//! cargo run --bin server -- --port 8092 --small
//! ```
//!
//! The server accepts WebSocket connections and processes PIR queries
//! using the same binary protocol as the TCP server.

use dpf_pir::server_config::load_configuration;
use dpf_pir::pir_backend::PirBackend;
use dpf_pir::DpfPirBackend;
use dpf_pir::websocket::{DataStore, DataStoreManager};
use log::{error, info};
use std::net::SocketAddr;
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader;
use tokio::net::TcpListener;
use tokio_tungstenite::accept_hdr_async;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

// TLS support
use tokio_rustls::TlsAcceptor;
use rustls_pemfile::{certs, private_key};
use tokio_rustls::rustls::{self, ServerConfig};

/// Command line arguments
struct ServerArgs {
    port: u16,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    small: bool,
}

fn parse_args() -> ServerArgs {
    let args: Vec<String> = std::env::args().collect();
    let mut port = 8092;
    let mut tls_cert: Option<String> = None;
    let mut tls_key: Option<String> = None;
    let mut small = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse::<u16>().unwrap_or(8092);
                    i += 1;
                }
            }
            "--tls-cert" => {
                if i + 1 < args.len() {
                    tls_cert = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--tls-key" => {
                if i + 1 < args.len() {
                    tls_key = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "--small" => {
                small = true;
            }
            "--help" | "-h" => {
                println!("DPF-PIR WebSocket Server (Gen2)");
                println!("Usage: {} [OPTIONS]", args[0]);
                println!();
                println!("Options:");
                println!("  --port, -p <PORT>     Port to listen on (default: 8092)");
                println!("  --tls-cert <FILE>     TLS certificate file (PEM format)");
                println!("  --tls-key <FILE>      TLS private key file (PEM format)");
                println!("  --small               Use small database files");
                println!("  --help, -h            Show this help message");
                println!();
                println!("Examples:");
                println!("  # Plain WebSocket (ws://)");
                println!("  {} --port 8092", args[0]);
                println!();
                println!("  # Secure WebSocket (wss://)");
                println!("  {} --port 8092 --tls-cert /path/to/cert.pem --tls-key /path/to/key.pem", args[0]);
                println!();
                println!("  # Small databases");
                println!("  {} --port 8092 --small", args[0]);
                println!();
                println!("To generate self-signed certificates for testing:");
                println!("  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes");
                std::process::exit(0);
            }
            _ => {}
        }
        i += 1;
    }

    // Validate TLS arguments
    if tls_cert.is_some() != tls_key.is_some() {
        error!("Both --tls-cert and --tls-key must be provided together");
        std::process::exit(1);
    }

    ServerArgs { port, tls_cert, tls_key, small }
}

/// Load TLS configuration from certificate and key files
fn load_tls_config(cert_path: &str, key_path: &str) -> Result<TlsAcceptor, Box<dyn std::error::Error>> {
    // Load certificate
    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<rustls::pki_types::CertificateDer> = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()?;

    // Load private key
    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key_der = private_key(&mut key_reader)?
        .ok_or("No private key found in file")?;

    // Build TLS configuration
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

#[tokio::main]
async fn main() {
    // Initialize logger
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    // Parse command line arguments
    let args = parse_args();
    let port = args.port;

    // Load TLS configuration if provided
    let tls_acceptor = match (&args.tls_cert, &args.tls_key) {
        (Some(cert_path), Some(key_path)) => {
            info!("Loading TLS certificate from: {}", cert_path);
            info!("Loading TLS private key from: {}", key_path);
            match load_tls_config(cert_path, key_path) {
                Ok(acceptor) => {
                    info!("TLS configuration loaded successfully");
                    Some(acceptor)
                }
                Err(e) => {
                    error!("Failed to load TLS configuration: {}", e);
                    std::process::exit(1);
                }
            }
        }
        _ => {
            info!("Running in plain WebSocket mode (no TLS)");
            None
        }
    };

    // Load configuration (databases are registered in server_config.rs)
    let server_config = load_configuration(args.small);

    let protocol = if tls_acceptor.is_some() { "wss" } else { "ws" };
    info!("Starting DPF-PIR WebSocket server on port {} ({})", port, protocol);
    info!("Load to memory: {}", server_config.load_to_memory);
    info!("Small mode: {}", args.small);

    // Create data store manager
    let mut store_manager = DataStoreManager::new();

    // Initialize data stores for each registered database
    for db_id in server_config.registry.list() {
        if let Some(db) = server_config.registry.get(db_id) {
            info!("Initializing data store for database '{}':", db_id);
            info!("  Path: {}", db.data_path());
            info!("  Buckets: {}", db.num_buckets());
            info!("  Entry size: {} bytes", db.entry_size());
            info!("  Bucket size: {} entries", db.bucket_size());

            let store = DataStore::new(
                db.data_path(),
                db.num_buckets(),
                db.entry_size(),
                db.bucket_size(),
                server_config.load_to_memory,
            ).unwrap_or_else(|e| {
                error!("Failed to create data store for '{}': {}", db_id, e);
                std::process::exit(1);
            });

            store_manager.add(db_id.to_string(), store);
        }
    }

    info!("Registered {} database(s)", server_config.registry.len());

    // Check if any databases are registered
    if server_config.registry.is_empty() {
        error!("No databases registered. Edit dpf_pir/src/server_config.rs to add databases.");
        std::process::exit(1);
    }

    // Bind to the port
    let addr: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .expect("Invalid address");

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    if tls_acceptor.is_some() {
        info!("Secure WebSocket server listening on wss://{}", addr);
        info!("Connect from browser using: wss://your-domain:{}", port);
    } else {
        info!("WebSocket server listening on ws://{}", addr);
        info!("Connect from browser using: ws://localhost:{}", port);
    }

    // Create PIR backend (DPF-PIR by default, can be swapped for other protocols)
    let backend: Arc<dyn PirBackend> = Arc::new(DpfPirBackend::new());
    info!("Using PIR backend: {}", backend.name());

    // Wrap in Arc for sharing across tasks
    let store_manager = Arc::new(store_manager);
    let registry = Arc::new(server_config.registry);
    let tls_acceptor = Arc::new(tls_acceptor);

    // Accept connections loop
    loop {
        info!("[SERVER] Waiting for incoming connection...");
        let (stream, peer_addr) = match listener.accept().await {
            Ok(conn) => {
                info!("[SERVER] Step 1: Connection accepted from {}", conn.1);
                conn
            },
            Err(e) => {
                error!("[SERVER] Failed to accept connection: {}", e);
                continue;
            }
        };

        info!("[SERVER] Step 2: Spawning task to handle connection from {}", peer_addr);
        let store_manager = Arc::clone(&store_manager);
        let registry = Arc::clone(&registry);
        let tls_acceptor = Arc::clone(&tls_acceptor);
        let backend = Arc::clone(&backend);

        tokio::spawn(async move {
            info!("[SERVER] Step 3: Starting connection handling for {}", peer_addr);

            // Handle TLS if configured
            if let Some(acceptor) = tls_acceptor.as_ref() {
                info!("[SERVER] Step 3a: Performing TLS handshake for {}", peer_addr);
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => {
                        info!("[SERVER] TLS handshake successful for {}", peer_addr);
                        s
                    }
                    Err(e) => {
                        error!("[SERVER] TLS handshake failed for {}: {}", peer_addr, e);
                        return;
                    }
                };

                // WebSocket handshake over TLS stream
                handle_websocket_connection(tls_stream, peer_addr, store_manager, registry, backend).await;
            } else {
                // Plain WebSocket (no TLS)
                handle_websocket_connection(stream, peer_addr, store_manager, registry, backend).await;
            }
        });
    }
}

/// Handle WebSocket connection (works for both plain and TLS streams)
async fn handle_websocket_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    store_manager: Arc<DataStoreManager>,
    registry: Arc<dpf_pir::DatabaseRegistry>,
    backend: Arc<dyn PirBackend>,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    info!("[SERVER] Step 4: Starting WebSocket handshake for {}", peer_addr);

    // Use accept_hdr_async to handle CORS and allow connections from any origin
    let callback = |req: &Request, mut response: Response| {
        let origin = req.headers().get("origin").map(|v| v.to_str().unwrap_or("*")).unwrap_or("*");
        info!("[SERVER] Step 5: WebSocket handshake request from origin: {}", origin);

        // Add CORS headers to the response
        let headers = response.headers_mut();
        headers.insert(
            tokio_tungstenite::tungstenite::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            tokio_tungstenite::tungstenite::http::HeaderValue::from_static("*"),
        );
        headers.insert(
            tokio_tungstenite::tungstenite::http::header::ACCESS_CONTROL_ALLOW_METHODS,
            tokio_tungstenite::tungstenite::http::HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            tokio_tungstenite::tungstenite::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
            tokio_tungstenite::tungstenite::http::HeaderValue::from_static("Content-Type, Authorization"),
        );
        info!("[SERVER] Step 6: CORS headers added to response");
        Ok(response)
    };

    info!("[SERVER] Step 7: Calling accept_hdr_async to complete WebSocket handshake...");
    match accept_hdr_async(stream, callback).await {
        Ok(ws_stream) => {
            info!("[SERVER] Step 8: WebSocket handshake SUCCESS for {}", peer_addr);
            info!("[SERVER] Step 9: Starting WebSocket message handler for {}", peer_addr);
            dpf_pir::websocket::handle_websocket_connection(
                ws_stream, store_manager, registry, backend
            ).await;
            info!("[SERVER] Step 10: WebSocket handler completed for {}", peer_addr);
        }
        Err(e) => {
            error!("[SERVER] Step ERROR: WebSocket handshake FAILED for {}: {}", peer_addr, e);
            error!("[SERVER] Error details: {:?}", e);
        }
    }
}
