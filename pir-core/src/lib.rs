//! Core PIR library: hash functions, table parameters, codec, and cuckoo utilities.
//!
//! This crate provides the shared, parameterized building blocks used by both
//! the build pipeline and runtime server/clients. All functions accept explicit
//! parameters rather than reading global constants, enabling reuse across
//! INDEX, CHUNK, MERKLE, and DELTA sub-tables with different configurations.

pub mod params;
pub mod hash;
pub mod codec;
pub mod pbc;
pub mod cuckoo;
pub mod merkle;
