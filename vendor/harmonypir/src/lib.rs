//! # HarmonyPIR
//!
//! An independent Rust implementation of **HarmonyPIR**: Efficient Single-Server
//! Stateful Private Information Retrieval using Format-Preserving Encryption.
//!
//! Based on the paper by Arunachalaramanan and Ren (ePrint 2026/437).
//!
//! ## What is Stateful PIR?
//!
//! Private Information Retrieval (PIR) lets a client retrieve an entry from a
//! server's database without the server learning which entry was retrieved.
//!
//! **Stateful PIR** splits execution into two phases:
//! - **Offline phase**: The client streams the entire database once and computes
//!   compact "hints" (XOR parities of groups of entries).
//! - **Online phase**: For each query, the client uses its hints to retrieve a
//!   database entry with only O(√N) communication and computation.
//!
//! After O(√N) queries, the hints are exhausted and the offline phase must be re-run.
//!
//! ## Two variants
//!
//! Both variants are always available (no feature flags):
//!
//! - **HarmonyPIR0** ([`prp::hoang::HoangPrp`]): Uses an optimized Hoang et al.
//!   card-shuffle PRP. Security provably reduces to AES. Works for any database size.
//!   Slower client computation (O(T) AES calls per query).
//!
//! - **HarmonyPIR1** ([`prp::ff1::Ff1Prp`]): Uses NIST FF1 Format-Preserving
//!   Encryption. Much faster (~100× less client computation). Requires the database
//!   to have at least 500,000 entries (NIST minimum domain size for FF1).
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use harmonypir::prelude::*;
//! use rand::SeedableRng;
//! use rand_chacha::ChaCha20Rng;
//!
//! // Create a database: 1024 entries of 32 bytes each.
//! let n = 1024;
//! let w = 32;
//! let db: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; w]).collect();
//! let server = Server::new(db);
//!
//! // Choose parameters and PRP (HarmonyPIR0 for small databases).
//! let params = Params::with_balanced_t(n, w).unwrap();
//! let key = [0u8; 16]; // In practice, use a random key.
//! let prp = Box::new(HoangPrp::new(2 * n, params.r, &key));
//!
//! // Offline phase: stream DB and compute hints.
//! let mut client = Client::offline(params, prp, &server).unwrap();
//!
//! // Online phase: query index 42.
//! let mut rng = ChaCha20Rng::seed_from_u64(0);
//! let entry = client.query(42, &server, &mut rng).unwrap();
//! assert_eq!(entry, vec![42u8; w]);
//! ```
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐
//! │   Client     │     │   Server     │
//! │  (protocol)  │────▶│  (database)  │
//! │              │◀────│              │
//! └──────┬───────┘     └──────────────┘
//!        │
//!   ┌────┴─────┐
//!   │   DS'    │  Restricted Relocation Data Structure
//!   │(reloc.)  │  - Access / Locate / RelocateSegment
//!   └────┬─────┘
//!        │
//!   ┌────┴─────┐
//!   │   PRP    │  Pseudorandom Permutation over [2N]
//!   │          │  - HoangPrp       (AES card-shuffle)
//!   │          │  - Ff1Prp         (NIST FF1)
//!   │          │  - FastPrpWrapper (Stefanov & Shi)
//!   │          │  - AlfPrp         (ALF FPE)
//!   └────┬─────┘
//!        │
//!   ┌────┴─────┐
//!   │  Hist'   │  Segment-level relocation history
//!   └──────────┘
//! ```

pub mod error;
pub mod hist;
pub mod params;
pub mod prp;
pub mod protocol;
pub mod relocation;
pub mod server;
pub mod util;

/// Convenient re-exports for common usage.
pub mod prelude {
    pub use crate::error::{HarmonyPirError, Result};
    pub use crate::params::Params;
    pub use crate::prp::hoang::HoangPrp;
    pub use crate::prp::ff1::Ff1Prp;
    #[cfg(feature = "fastprp-prp")]
    pub use crate::prp::fast::FastPrpWrapper;
    #[cfg(feature = "alf")]
    pub use crate::prp::alf::{AlfPrp, AlfEngine};
    pub use crate::prp::{Prp, BatchPrp};
    pub use crate::protocol::{Client, PendingPair};
    pub use crate::server::Server;
}
