# Changelog

All notable changes to `pir-runtime-core` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Pre-publish note.** This crate depends on the `libdpf` git dependency,
> which must land on crates.io before `pir-runtime-core` itself can be
> published. See [`PUBLISHING.md`](../PUBLISHING.md) Blocker 1 for the
> refactoring sketch.

## [Unreleased]

## [0.1.0] — initial release (unpublished)

### Added

- `protocol` module — wire format encoder/decoder for PIR requests and
  responses (DPF, HarmonyPIR, OnionPIR, bucket-Merkle, catalog, info).
- `table` module — mmap'd on-disk cuckoo table reader with
  `DatabaseDescriptor`, `DatabaseType`, `MappedDatabase`. Supports full
  snapshots and delta tables, INDEX + CHUNK PBC sub-tables, and the
  optional bucket-Merkle sibling sub-tables.
- `eval` module — DPF evaluation primitives for INDEX-level and
  CHUNK-level PIR rounds, plus Merkle sibling evaluation. Includes x86_64
  software prefetch, u64-chunked XOR fold, and the cuckoo slot parsers
  that match the `pir-core::params` slot layout.
- `handler` module — `RequestHandler` dispatches decoded `Request`
  variants against a `Vec<MappedDatabase>` and produces `Response`
  values. Covers DPF single/batch queries, HarmonyPIR main and sibling
  queries, catalog / info / residency requests, and bucket-Merkle
  tree-tops and sibling-batch requests.

### Why this crate exists

Extracted from the workspace-internal `runtime/` binary crate so that
`pir-sdk-server` can depend on a publishable library rather than on a
`publish = false` binary crate. Both `pir-sdk-server` and the
`runtime/` binaries now consume the same types from `pir-runtime-core`.

🔒 PIR invariants preserved — this crate is a pure code move. It does
not alter the wire format, slot layout, DPF evaluation, or
request-dispatch semantics. K=75 INDEX / K_CHUNK=80 CHUNK / 25-MERKLE
padding remains enforced in `pir-sdk-client`; this crate is the
server-side counterpart that answers padded queries uniformly.

[Unreleased]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Bitcoin-PIR/Bitcoin-PIR/releases/tag/v0.1.0
