# YPIR-SP Integration Plan for BitcoinPIR

## Decisions

- **Protocol**: YPIR+SP (YPIR with SimplePIR internally) for all three databases
- **Coexistence**: YPIR-SP is a new backend alongside DPF-PIR (multi-backend architecture)
- **Layout**: Square matrix — each DB is tiled into a roughly square 2D matrix of ring elements
- **Client hint**: None — YPIR+SP uses a pseudorandom seed (SEED_0) shared between client and server; the server precomputes `A^T × DB` offline but never sends it
- **Client platform**: WASM in browser
- **Block size for chunks**: 1 KB (using current `utxo_chunks_data` at 130K × 1KB)

---

## Protocol Comparison

| | DPF-PIR (existing) | YPIR-SP (new) |
|---|---|---|
| **Servers needed** | **2** (XOR of DPF evals) | **1** (lattice-based) |
| **Offline hint** | None | **None** (seed-based) |
| **Query payload** | DPF keys (~λ·log N bits) | LWE/RLWE ciphertexts (~0.5–1.4 MB) |
| **Trust model** | Two non-colluding servers | Single server, computational privacy |
| **Client compute** | ~ms (DPF key gen) | ~10–44 ms WASM (NTTs + poly multiply) |

---

## Square Matrix Parameterization

The database is tiled as a 2D matrix of ring elements (poly_len=2048, pt_modulus=2^14=16384):
- `db_rows` = next_power_of_2(ceil(total_items / items_per_row))
- `db_cols` = `instances × poly_len`, where `instances = ⌈(row_bytes × 8) / (2048 × 14)⌉`
- Each ring element holds 2048 coefficients at 14 bits each = 3.5 KB of data
- Row width is a multiple of the entry size so that items align on row boundaries

| Database | Entry Size | Count | Total Size | Items/Row | Matrix Rows | nu_1 | instances | db_rows_padded |
|---|---|---|---|---|---|---|---|---|
| `utxo_cuckoo_index` | 96B | ~15M | 1.44 GB | ~395 | ~38K | 5 | 11 | 65,536 |
| `utxo_4b_to_32b` | 144B | ~30M | 4.32 GB | ~456 | ~66K | 6 | 19 | 131,072 |
| `utxo_chunks_data` | 1,024B | ~130K | ~130 MB | ~11 | ~12K | 2 | 4 | 8,192 |

### Row Retrieval

Client knows the cuckoo bucket index from hashing. It computes:
```
row = bucket_index / items_per_row
col = bucket_index % items_per_row
```
Queries `row`, gets back the entire row, extracts the target entry at offset `col × entry_size`. The ~395–456 other entries in the row are collateral — the server can't tell which one the client wanted.

---

## Upload / Download / Compute Summary

| Database | Query ↑ | Pub params ↑ | **Total ↑** | Response ↓ | Client WASM | Client memory |
|---|---|---|---|---|---|---|
| `utxo_cuckoo_index` | 450 KB | 462 KB | **~912 KB** | **~132 KB** | ~12–32 ms | ~1.5 MB |
| `utxo_4b_to_32b` | 900 KB | 462 KB | **~1.4 MB** | **~228 KB** | ~17–44 ms | ~2 MB |
| `utxo_chunks_data` | ~56 KB | 462 KB | **~518 KB** | **~48 KB** | ~10–20 ms | ~1 MB |

No offline hint download. Zero bytes.

---

## Server-Side Changes (Rust — `runtime/`)

### 1. New dependency in `Cargo.toml`
```toml
ypir = { git = "https://github.com/weikengchen/ypir-fork.git" }
```

### 2. New backend: `src/ypir_backend.rs`

```rust
pub struct YpirSpBackend {
    databases: HashMap<String, YpirDatabaseState>,
}

struct YpirDatabaseState {
    params: Params,
    y_server: YServer<'static, u16>,
    offline_vals: OfflinePrecomputedValues,
    items_per_row: usize,
    entry_size: usize,
}
```

Implements `PirBackend`:
- **`name()`** → `"ypir-sp"`
- **`process_query()`**: Deserialize the packed LWE query + packing pub params, call `y_server.perform_online_computation_simplepir()`, serialize and return the modulus-switched RLWE response ciphertexts.

### 3. Protocol messages

Add to `pir_protocol.rs`:

| New Request | ID | Fields |
|---|---|---|
| `GetParams` | 7 | `database_id: string` |

| New Response | ID | Fields |
|---|---|---|
| `ParamsData` | 6 | `database_id: string, params_json: string, items_per_row: u32, entry_size: u32` |

The client needs `params_json` (YPIR `Params` struct serialized) plus the layout metadata (`items_per_row`, `entry_size`) to know how to interpret a decrypted row.

The existing `QueryDatabaseSingle` (ID=3) works as-is for sending queries. No hint-related messages needed.

### 4. Server startup flow (`src/bin/server.rs`)

```
1. Load databases (existing)
2. For each database configured for YPIR-SP:
   a. Compute square matrix layout: items_per_row, matrix_rows
   b. params = params_for_scenario_simplepir(matrix_rows, row_bytes * 8)
   c. y_server = YServer::<u16>::new(&params, db_flat_iterator, true, false, true)
   d. offline_vals = y_server.perform_offline_precomputation_simplepir(None)
3. Store in YpirSpBackend
```

Offline precomputation is expensive (minutes) but runs once at startup.

### 5. Multi-backend architecture

```rust
// server_config.rs
pub enum BackendType { DpfPir, YpirSp }

pub struct DatabaseBackendConfig {
    pub database_id: String,
    pub backend: BackendType,
}
```

The server holds multiple backends. The WebSocket handler dispatches based on the database's configured backend:
```rust
// websocket.rs — in handle_request()
let backend = backend_registry.get_backend_for_database(&database_id);
let result = backend.process_query(query_data, store);
```

---

## Client-Side Changes (TypeScript/WASM — `web/`)

### 1. WASM bindings (built in ypir-fork repo)

The `ypir-wasm/` crate (in ypir-fork) exposes:
```rust
#[wasm_bindgen]
pub fn ypir_client_init(params_json: &str) -> YpirWasmClient;

#[wasm_bindgen]
pub fn ypir_generate_query(client: &mut YpirWasmClient, target_row: usize) -> Vec<u8>;

#[wasm_bindgen]
pub fn ypir_decode_response(client: &YpirWasmClient, response_bytes: &[u8]) -> Vec<u8>;
```

### 2. Client query flow (YPIR-SP)

```
┌─────────┐                              ┌──────────┐
│  Client  │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │  GetParams("utxo_cuckoo_index")         │
     │────────────────────────────────────────►│
     │◄────────────────────────────────────────│
     │  ParamsData(params, items_per_row, ...)  │
     │                                          │
     │  ── Client inits WASM, caches params ── │
     │                                          │
     │  ── Compute: row = bucket_idx / ipr ──  │
     │  ── WASM: generate_query(row) ──        │
     │                                          │
     │  QueryDatabaseSingle(db_id, query)      │
     │────────────────────────────────────────►│
     │◄────────────────────────────────────────│
     │         QueryResult(encrypted_response)  │
     │                                          │
     │  ── WASM: decode_response() ──          │
     │  ── Extract entry at col × entry_size ──│
```

For **cuckoo databases** (2 locations): client sends **two** `QueryDatabaseSingle` requests (one per cuckoo location) to the **same** server.

### 3. New TypeScript module: `ypir_client.ts`

```typescript
class YpirClient {
    private wasmClient: YpirWasmClient;
    private itemsPerRow: number;
    private entrySize: number;

    async init(ws: WebSocket, databaseId: string): Promise<void> {
        // Send GetParams, receive ParamsData
        // Initialize WASM client with params
    }

    async queryRow(ws: WebSocket, databaseId: string, bucketIndex: number): Promise<Uint8Array> {
        const row = Math.floor(bucketIndex / this.itemsPerRow);
        const col = bucketIndex % this.itemsPerRow;
        const queryBytes = ypir_generate_query(this.wasmClient, row);
        // Send QueryDatabaseSingle, receive QueryResult
        const fullRow = ypir_decode_response(this.wasmClient, responseBytes);
        return fullRow.slice(col * this.entrySize, (col + 1) * this.entrySize);
    }
}
```

---

## Implementation Order

| Phase | Task | Status | Effort |
|---|---|---|---|
| **Phase 1** | WASM client bindings in ypir-fork (`ypir-wasm/` crate) | **In progress** (other session) | Hard |
| **Phase 2** | Server: add ypir-fork dep, `YpirSpBackend`, square-matrix DB setup | Not started | Medium |
| **Phase 3** | Protocol: add `GetParams`/`ParamsData` messages | Not started | Small |
| **Phase 4** | Server: implement `process_query()` — deserialize query, run online computation, serialize response | Not started | Medium |
| **Phase 5** | Server: multi-backend dispatch (per-database backend selection) | Not started | Small |
| **Phase 6** | Client: `ypir_client.ts` — WASM init, query gen, response decrypt, entry extraction | Not started | Medium |
| **Phase 7** | End-to-end testing with all three databases | Not started | Medium |

---

## Client-Side Computation Detail (YPIR+SP, Square Matrix)

### Query Generation (3 steps)

**Step 1: RLWE Key Generation** (~microseconds)
- Ternary secret key, degree 2048, Hamming weight 256. Pure random sampling.

**Step 2: Expansion/Packing Public Parameters** (~1 ms native, ~5 ms WASM)
- 11 iterations × 3 RLWE encryptions = 33 total = ~99 NTTs over degree-2048.
- Output: 462 KB (constant, sent with every query).

**Step 3: Query Encryption** (dominant cost)
- `2^nu_1` RLWE ciphertexts, each: 1 NTT + 2 poly multiplies.
- Then `rlwes_to_lwes` (data copy) + `pack_query` (CRT packing).

| Database | nu_1 | RLWE encryptions | Est. native | Est. WASM (3–5×) |
|---|---|---|---|---|
| `utxo_cuckoo_index` | 5 | 32 | ~2–4 ms | ~6–20 ms |
| `utxo_4b_to_32b` | 6 | 64 | ~3–6 ms | ~10–30 ms |
| `utxo_chunks_data` | 2 | 4 | ~0.5–1 ms | ~2–5 ms |

### Response Decryption

- `instances` RLWE decryptions: 2 poly multiplies + 1 NTT + rescale each.

| Database | instances | Est. WASM |
|---|---|---|
| `utxo_cuckoo_index` | 11 | ~1–2 ms |
| `utxo_4b_to_32b` | 19 | ~2–4 ms |
| `utxo_chunks_data` | 4 | ~1 ms |

### End-to-End Client Timing (WASM, in browser)

| Phase | utxo_cuckoo_index | utxo_4b_to_32b | utxo_chunks_data |
|---|---|---|---|
| Key gen + exp params | ~5–10 ms | ~5–10 ms | ~5–10 ms |
| Query encryption | ~6–20 ms | ~10–30 ms | ~2–5 ms |
| **Total query gen** | **~12–30 ms** | **~15–40 ms** | **~7–15 ms** |
| Response decrypt | ~1–2 ms | ~2–4 ms | ~1 ms |
| **Total client compute** | **~13–32 ms** | **~17–44 ms** | **~8–16 ms** |

All under 50 ms. Imperceptible to the user.
