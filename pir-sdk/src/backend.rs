//! Server-side backend trait for PIR protocols.
//!
//! Each PIR protocol (DPF, HarmonyPIR, OnionPIR) implements this trait to handle
//! raw binary requests. The SDK server wraps backends in WebSocket dispatch.

use crate::error::PirResult;
use crate::types::{DatabaseCatalog, ServerRole};

/// Server-side backend for handling PIR requests.
///
/// This trait abstracts over the different PIR protocols. Implementations handle
/// the protocol-specific query evaluation while the server framework handles
/// connection management, dispatch, and framing.
///
/// # Request/Response Format
///
/// Requests and responses are raw binary payloads. The outer framing (4-byte
/// length prefix, variant byte) is handled by the server, not the backend.
///
/// # Thread Safety
///
/// Backends must be `Send + Sync` to allow concurrent request handling.
/// Implementations should use interior mutability (e.g., `RwLock`) if needed.
pub trait PirBackend: Send + Sync + 'static {
    /// Returns the backend name (for logging: "dpf", "harmony", "onion").
    fn name(&self) -> &'static str;

    /// Returns the server role this backend is configured for.
    fn role(&self) -> ServerRole;

    /// Returns true if this backend is ready to handle requests.
    fn is_ready(&self) -> bool;

    /// Handle a raw request payload and return the raw response payload.
    ///
    /// The variant byte is included in the payload. The caller handles the
    /// 4-byte length prefix framing.
    ///
    /// # Arguments
    ///
    /// * `payload` - Raw request bytes including variant byte
    ///
    /// # Returns
    ///
    /// Raw response bytes including variant byte, or an error.
    fn handle_raw(&self, payload: &[u8]) -> PirResult<Vec<u8>>;

    /// Get the database catalog.
    ///
    /// Returns information about all databases loaded by this backend.
    fn catalog(&self) -> &DatabaseCatalog;

    /// Optionally perform warmup (e.g., pre-compute FHE keys, touch pages).
    ///
    /// This is called after loading but before accepting connections.
    fn warmup(&self) -> PirResult<()> {
        Ok(())
    }

    /// Shutdown the backend gracefully.
    fn shutdown(&self) -> PirResult<()> {
        Ok(())
    }
}

/// Builder for configuring and creating a PIR backend.
pub trait PirBackendBuilder: Sized {
    /// The backend type this builder creates.
    type Backend: PirBackend;

    /// Set the server role.
    fn role(self, role: ServerRole) -> Self;

    /// Add a full snapshot database from a directory.
    fn add_full_db(self, path: &std::path::Path, height: u32) -> Self;

    /// Add a delta database from a directory.
    fn add_delta_db(self, path: &std::path::Path, base_height: u32, tip_height: u32) -> Self;

    /// Load database configuration from a TOML file.
    fn from_config(self, path: &std::path::Path) -> PirResult<Self>;

    /// Enable warmup after loading.
    fn warmup(self, enable: bool) -> Self;

    /// Build the backend.
    fn build(self) -> PirResult<Self::Backend>;
}

/// Configuration for a single database entry.
#[derive(Clone, Debug)]
pub struct DatabaseConfig {
    /// Path to the database directory.
    pub path: std::path::PathBuf,
    /// Human-readable name.
    pub name: Option<String>,
    /// Whether this is a delta (vs full snapshot).
    pub is_delta: bool,
    /// Base height (for deltas).
    pub base_height: u32,
    /// Tip height.
    pub height: u32,
}

/// Full server configuration.
#[derive(Clone, Debug, Default)]
pub struct ServerConfig {
    /// Server role.
    pub role: ServerRole,
    /// Port to listen on.
    pub port: u16,
    /// Database entries.
    pub databases: Vec<DatabaseConfig>,
    /// Whether to enable DPF backend.
    pub enable_dpf: bool,
    /// Whether to enable HarmonyPIR backend.
    pub enable_harmony: bool,
    /// Whether to enable OnionPIR backend.
    pub enable_onion: bool,
    /// Whether to perform warmup.
    pub warmup: bool,
}

impl ServerConfig {
    /// Create a new config with default settings.
    pub fn new() -> Self {
        Self {
            role: ServerRole::Primary,
            port: 8091,
            databases: Vec::new(),
            enable_dpf: true,
            enable_harmony: true,
            enable_onion: true,
            warmup: false,
        }
    }
}

// Note: this is a protocol-level config type intended to be built
// programmatically. For TOML loading, use `pir_sdk_server::ServerConfig::load`
// which has the deserialize impls wired up.
