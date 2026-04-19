//! Reference PIR server runtime: exposes the shared server primitives
//! (hosted in `pir-runtime-core`) alongside the binary-only helpers that
//! wire up the `unified_server` / `server` / CLI client binaries in
//! `src/bin/`.
//!
//! The library surface exists so the `src/bin/*` entry points can import
//! through `use runtime::{protocol, table, handler, eval, ...};`. Its
//! role is to be thin — feel free to re-export from `pir-runtime-core`
//! or to host strictly binary-only glue (warmup, TOML config, OnionPIR
//! wire constants).

// Re-exports of the publishable server primitives. Binaries keep their
// pre-refactor import paths (`use runtime::protocol::*`, etc.) so
// nothing in `src/bin/` needs to move.
pub use pir_runtime_core::{eval, handler, protocol, table};

// Binary-only modules. These stay here because only `src/bin/*` reaches
// for them.
pub mod config;
pub mod onionpir;
pub mod warmup;
