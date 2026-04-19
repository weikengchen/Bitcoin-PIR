# pir-runtime-core

Server-side runtime primitives for Bitcoin PIR. This crate contains the
parts of the server that are protocol-version- and data-format-specific,
but transport-agnostic: the wire protocol, the memory-mapped database
table layout, the DPF evaluation engine, and the request handler that
dispatches PIR queries against loaded databases.

It is consumed by two callers:

- **[`pir-sdk-server`](https://crates.io/crates/pir-sdk-server)** —
  the public SDK that wraps these primitives in a fluent
  `PirServerBuilder` with TOML config, WebSocket transport, and
  graceful shutdown.
- **`runtime/`** — the workspace-internal binary crate that owns the
  reference PIR server binaries (`unified_server`, `server`,
  `harmonypir_hint_server`, etc.) and CLI clients.

Modules:

- [`protocol`] — wire format for `Request` / `Response` variants.
- [`table`] — `MappedDatabase` / `DatabaseDescriptor` for mmap'd
  on-disk database layout.
- [`eval`] — DPF evaluation helpers and timing instrumentation.
- [`handler`] — `RequestHandler` that dispatches `Request` to the
  matching backend over a set of loaded databases.

This crate does not own a transport, a listener, or a config loader.
Those live in `pir-sdk-server`.

## Licence

Dual-licensed under MIT OR Apache-2.0.
