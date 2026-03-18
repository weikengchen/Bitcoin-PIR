# YPIR WASM Client — Implementation Plan

## Goal

Create a `ypir-wasm` crate that compiles the YPIR+SP client logic to WebAssembly, then write a test harness that verifies the WASM client produces identical results to the native client, and measures performance.

---

## Phase 1: Create the `ypir-wasm` crate

### 1.1 Crate setup

Create `ypir-wasm/` at the repo root (or as a sibling to ypir-fork):

```
ypir-wasm/
├── Cargo.toml
├── src/
│   └── lib.rs          # wasm_bindgen exports
├── tests/
│   └── native_test.rs  # native correctness test (not WASM)
└── www/                # optional: browser test page
    ├── index.html
    └── test.js
```

### 1.2 `Cargo.toml`

```toml
[package]
name = "ypir-wasm"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib", "rlib"]   # cdylib for WASM, rlib for native tests

[dependencies]
ypir = { git = "https://github.com/weikengchen/ypir-fork.git", default-features = false }
spiral-rs = { git = "https://github.com/weikengchen/spiral-rs-fork.git", default-features = false }
wasm-bindgen = "0.2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
rand = "0.8"
rand_chacha = "0.3"
getrandom = { version = "0.2", features = ["js"] }  # WASM RNG support

[dev-dependencies]
wasm-bindgen-test = "0.3"

[profile.release]
opt-level = 3
lto = true
```

**Key decisions:**
- `default-features = false` on ypir and spiral-rs to exclude server-side code (rayon, etc.)
- `getrandom` with `js` feature enables `OsRng`/`thread_rng` in WASM via `crypto.getRandomValues()`
- `cdylib` + `rlib` dual target: cdylib for wasm-pack, rlib for native tests

### 1.3 Feature-gating in ypir-fork and spiral-rs-fork

Before the WASM crate can compile, we need minor changes in the upstream forks:

**spiral-rs-fork** — already has `features = ["server"]` gating for rayon. Verify:
- `src/server.rs` is behind `#[cfg(feature = "server")]` ✅ (already done)
- No unconditional `use std::time::Instant` in library code paths (only in tests) ✅

**ypir-fork** — needs a new `client` feature (or `no-server` default):
- Gate `src/server.rs` behind `#[cfg(feature = "server")]`
- Gate `src/matmul.rs` behind `#[cfg(feature = "server")]` (uses C FFI / cc build)
- Gate `src/kernel.rs` behind `#[cfg(feature = "server")]` (AVX-512 code)
- Gate the `build.rs` C compilation behind `#[cfg(feature = "server")]`
- `src/scheme.rs` has `std::time::Instant` — gate measurement code behind `#[cfg(not(target_arch = "wasm32"))]`
- Keep unconditionally: `client.rs`, `lwe.rs`, `params.rs`, `packing.rs` (condense_matrix, pack_query), `modulus_switch.rs`, `bits.rs`, `convolution.rs`

### 1.4 WASM-bindgen API (`src/lib.rs`)

```rust
use wasm_bindgen::prelude::*;
use spiral_rs::client::Client;
use spiral_rs::params::Params;
use spiral_rs::poly::*;
use ypir::client::*;
use ypir::packing::{condense_matrix, pack_query};
use ypir::params::*;
use ypir::modulus_switch::*;
use ypir::scheme::SEED_0;
use rand_chacha::ChaCha20Rng;
use rand::SeedableRng;

/// Opaque handle to client state, stored on the WASM heap.
#[wasm_bindgen]
pub struct YpirWasmClient {
    params: Params,
    client: Client<'static>,     // needs lifetime management — see note below
    y_client: YClient<'static>,
    sk_reg_raw: Vec<u64>,
}

/// Initialize client from JSON-serialized Params.
/// Returns an opaque handle.
#[wasm_bindgen]
pub fn ypir_client_init(params_json: &str) -> YpirWasmClient { ... }

/// Generate query for a given row index.
/// Returns: { query: Uint8Array, pub_params: Uint8Array }
#[wasm_bindgen]
pub fn ypir_generate_query(client: &mut YpirWasmClient, target_row: usize) -> JsValue { ... }

/// Decode server response.
/// Returns: Uint8Array containing the plaintext row.
#[wasm_bindgen]
pub fn ypir_decode_response(client: &YpirWasmClient, response_bytes: &[u8]) -> Vec<u8> { ... }

/// Utility: compute params for a given database shape.
#[wasm_bindgen]
pub fn ypir_compute_params(num_items: usize, item_size_bits: usize) -> String { ... }
```

**Lifetime challenge**: `Client<'a>` borrows `&'a Params`. For WASM, we need to own both. Solutions:
- Use `Box::leak` to get `&'static Params` (acceptable since client lifetime = page lifetime)
- Or restructure to use `Arc<Params>` if the upstream allows it
- Or store `Params` in a `Box` and use unsafe to extend the lifetime (common pattern in FFI)

---

## Phase 2: Implement the three client operations

### 2.1 `ypir_client_init(params_json)`

```rust
fn ypir_client_init(params_json: &str) -> YpirWasmClient {
    let params: Params = serde_json::from_str(params_json).unwrap();
    let params_static: &'static Params = Box::leak(Box::new(params));

    let mut client = Client::init(params_static);
    client.generate_secret_keys();

    let y_client = YClient::new(&mut client, params_static);

    YpirWasmClient {
        params: params_static.clone(),
        client,
        y_client,
        sk_reg_raw: /* save for decode */,
    }
}
```

### 2.2 `ypir_generate_query(client, target_row)`

Follows scheme.rs lines 145–173:

```rust
fn ypir_generate_query(client: &mut YpirWasmClient, target_row: usize) -> JsValue {
    let params = &client.params;
    let sk_reg = client.client.get_sk_reg();

    // Step 1: Generate expansion/packing public params
    let pack_pub_params = raw_generate_expansion_params(
        params, &sk_reg, params.poly_len_log2, params.t_exp_left,
        &mut ChaCha20Rng::from_entropy(),
        &mut ChaCha20Rng::from_seed(STATIC_SEED_2),
    );

    // Extract row 1, condense
    let mut pack_pub_params_row_1s = Vec::new();
    for pp in &pack_pub_params {
        let row1 = pp.submatrix(1, 0, 1, pp.cols);
        pack_pub_params_row_1s.push(condense_matrix(params, &row1));
    }

    // Step 2: Generate encrypted query
    let query_row = client.y_client.generate_query(SEED_0, params.db_dim_1, true, target_row);
    let packed_query = pack_query(params, &query_row);

    // Serialize both into bytes for transmission
    // Return as JS object { query: Uint8Array, pub_params: Uint8Array }
    ...
}
```

### 2.3 `ypir_decode_response(client, response_bytes)`

Follows scheme.rs lines 231–253:

```rust
fn ypir_decode_response(client: &YpirWasmClient, response_bytes: &[u8]) -> Vec<u8> {
    let params = &client.params;
    let rlwe_q_prime_1 = params.get_q_prime_1();
    let rlwe_q_prime_2 = params.get_q_prime_2();
    let num_rlwe_outputs = params.instances;

    // Split response_bytes into per-ciphertext chunks
    // Each ct is modulus-switched: (q_prime_2 bits + q_prime_1 bits) * poly_len / 8 bytes
    let ct_size = /* compute from params */;

    let mut plaintext_row = Vec::new();
    for ct_bytes in response_bytes.chunks(ct_size) {
        let ct = PolyMatrixRaw::recover(params, rlwe_q_prime_1, rlwe_q_prime_2, ct_bytes);
        let decrypted = decrypt_ct_reg_measured(
            client.y_client.client(), params, &ct.ntt(), params.poly_len
        );
        plaintext_row.extend_from_slice(decrypted.as_slice());
    }

    // Convert plaintext coefficients to bytes
    // Each coefficient holds a value mod pt_modulus (14 bits)
    // Pack into the original row bytes
    ...
}
```

---

## Phase 3: Native correctness test

### 3.1 `tests/native_test.rs`

This test runs **natively** (not WASM) and verifies the WASM client API produces the same result as running ypir's `run_simple_ypir_on_params` end-to-end.

```rust
#[test]
fn test_ypir_wasm_client_matches_native() {
    // 1. Create a small test database (e.g., 1024 rows × 2048 cols)
    let params = params_for_scenario_simplepir(1024, 2048 * 14);

    // 2. Create server with random data
    let pt_iter = (0..1024 * 2048).map(|i| (i % 16384) as u16);
    let y_server = YServer::<u16>::new(&params, pt_iter, true, false, true);
    let offline_vals = y_server.perform_offline_precomputation_simplepir(None);

    // 3. Pick a random target row
    let target_row = 42;
    let expected_row = y_server.get_row(target_row);

    // 4. Run client operations through WASM API
    let params_json = serde_json::to_string(&params).unwrap();
    let mut wasm_client = ypir_client_init(&params_json);
    let query_result = ypir_generate_query(&mut wasm_client, target_row);

    // 5. Run server computation
    let response = y_server.perform_online_computation_simplepir(
        &query_result.packed_query,
        &offline_vals,
        &[&query_result.pub_params],
        None,
    );

    // 6. Decode through WASM API
    let decoded_row = ypir_decode_response(&wasm_client, &serialize_response(&response));

    // 7. Compare
    assert_eq!(decoded_row, expected_row);
}
```

### 3.2 Test with all three database shapes

```rust
#[test]
fn test_cuckoo_index_shape()   { test_shape(65_536, 11); }  // ~utxo_cuckoo_index

#[test]
fn test_txid_mapping_shape()   { test_shape(131_072, 19); }  // ~utxo_4b_to_32b

#[test]
fn test_chunks_shape()         { test_shape(8_192, 4); }     // ~utxo_chunks_data

fn test_shape(db_rows: usize, instances: usize) {
    // Same pattern as above but with specific dimensions
}
```

---

## Phase 4: WASM compilation and browser test

### 4.1 Build WASM

```bash
# Install wasm-pack if needed
cargo install wasm-pack

# Build
cd ypir-wasm
wasm-pack build --target web --release
```

This produces `pkg/ypir_wasm.js` + `pkg/ypir_wasm_bg.wasm`.

### 4.2 `wasm-bindgen-test` (headless browser test)

```rust
// tests/wasm_test.rs
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn test_ypir_client_init() {
    let params_json = r#"{ ... small test params ... }"#;
    let client = ypir_client_init(params_json);
    // Verify client was created without panic
}

#[wasm_bindgen_test]
fn test_ypir_query_gen_timing() {
    let client = setup_test_client();
    let start = js_sys::Date::now();
    let _query = ypir_generate_query(&mut client, 42);
    let elapsed = js_sys::Date::now() - start;
    web_sys::console::log_1(&format!("Query gen: {} ms", elapsed).into());
    assert!(elapsed < 100.0, "Query gen took too long: {} ms", elapsed);
}

#[wasm_bindgen_test]
fn test_ypir_decode_timing() {
    // Similar timing test for decode
}
```

Run with:
```bash
wasm-pack test --headless --chrome
```

### 4.3 Manual browser test (`www/`)

A simple HTML page that:
1. Loads the WASM module
2. Initializes a client with test params
3. Generates a query, measures time
4. Displays results in a table

---

## Phase 5: End-to-end correctness test (WASM client ↔ native server)

This is the critical test: WASM client generates a query, native server processes it, WASM client decodes the response.

### 5.1 Architecture

```
┌─────────────────────┐         ┌─────────────────────┐
│  Native Rust binary  │  HTTP   │  Browser (WASM)      │
│  "test-server"       │◄───────►│  ypir-wasm client    │
│  - YServer setup     │         │  - generate query    │
│  - process query     │         │  - decode response   │
└─────────────────────┘         └─────────────────────┘
```

### 5.2 Test server binary (`src/bin/test_server.rs`)

A minimal HTTP server that:
1. Creates a YServer with known test data
2. Exposes endpoints:
   - `GET /params` → JSON params
   - `POST /query` → accepts query bytes, returns response bytes
   - `GET /expected/:row` → returns the expected plaintext row (for verification)

### 5.3 Test flow

```
1. Start test server with a small DB (e.g., 4096 rows)
2. Open browser test page
3. WASM client:
   a. GET /params → init client
   b. Generate query for row 42
   c. POST /query → get encrypted response
   d. Decode response → plaintext row
   e. GET /expected/42 → compare
4. Report PASS/FAIL + timings
```

---

## Serialization Format

The query and response need a wire format. Define a simple binary protocol:

### Query (client → server)
```
[4 bytes] packed_query length (LE u32)
[N bytes] packed_query (CRT-packed u64 array)
[4 bytes] num_pub_params (LE u32)
For each pub_param:
  [4 bytes] param length (LE u32)
  [M bytes] condensed polynomial matrix bytes
```

### Response (server → client)
```
[4 bytes] num_ciphertexts (LE u32)
For each ciphertext:
  [4 bytes] ct length (LE u32)
  [L bytes] modulus-switched ciphertext bytes
```

These match the internal representations in scheme.rs — we just need to serialize/deserialize consistently.

---

## Upstream Changes Required (Summary)

### In `ypir-fork`:

| File | Change | Purpose |
|------|--------|---------|
| `Cargo.toml` | Add `[features] default = ["server"]`, `server = ["cc"]` | Feature-gate server code |
| `src/lib.rs` | Gate server, kernel, matmul modules behind `#[cfg(feature = "server")]` | Exclude from WASM build |
| `build.rs` | Gate C compilation behind `#[cfg(feature = "server")]` | No C compiler needed for WASM |
| `src/scheme.rs` | Gate `Instant` behind `#[cfg(not(target_arch = "wasm32"))]` | WASM has no `Instant` |
| `src/params.rs` | Derive `Serialize`/`Deserialize` for `Params` (if not already) | JSON params over wire |

### In `spiral-rs-fork`:

| File | Change | Purpose |
|------|--------|---------|
| `Cargo.toml` | Ensure `getrandom` has `js` feature | WASM RNG |
| `src/params.rs` | Derive `Serialize`/`Deserialize` for `Params` (if not already) | JSON params over wire |

---

## Estimated Effort

| Task | Effort | Notes |
|------|--------|-------|
| Feature-gate ypir-fork for client-only build | 1–2 hours | Mostly adding `#[cfg]` annotations |
| `ypir-wasm/src/lib.rs` core implementation | 3–4 hours | Lifetime management is the tricky part |
| Native correctness test | 2–3 hours | Need to match exact serialization |
| WASM compilation + debugging | 2–4 hours | Likely dependency issues to resolve |
| Browser test harness | 1–2 hours | Simple HTML + JS |
| End-to-end test (WASM client ↔ native server) | 2–3 hours | HTTP test server + test page |
| **Total** | **~12–18 hours** | |

---

## Success Criteria

1. ✅ `cargo test` passes natively — WASM client API produces correct results matching `run_simple_ypir_on_params`
2. ✅ `wasm-pack build` succeeds — compiles to `.wasm` without errors
3. ✅ `wasm-pack test --headless --chrome` passes — all WASM tests pass in browser
4. ✅ Query generation < 50 ms in WASM for all three database shapes
5. ✅ Response decryption < 10 ms in WASM for all three database shapes
6. ✅ WASM binary size < 2 MB (gzipped)
7. ✅ End-to-end test: WASM client → native server → WASM decode = correct plaintext
