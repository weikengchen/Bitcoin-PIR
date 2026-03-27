# Request: Pure Java HarmonyPIR Bucket Implementation

## Context

We are building a Java library (`bitcoinj-pir`) that integrates Private Information Retrieval with [bitcoinj](https://github.com/bitcoinj/bitcoinj), the widely-used Java Bitcoin library. The library implements bitcoinj's `UTXOProvider` interface so wallets can query UTXOs privately instead of using Bloom-filtered P2P peers.

We already support three PIR backends:
- **DPF** — fully working, pure Java
- **HarmonyPIR** — stub, needs bucket implementation
- **OnionPIR** — stub, needs native library

The DPF backend is pure Java (AES-ECB PRG, splitmix64 hashing, cuckoo placement). We would like **HarmonyPIR to also be pure Java** so that users don't need native libraries for the 2-server protocols.

## What We Need

A Java class `HarmonyBucket` that provides the same functionality as the existing Rust `PyHarmonyBucket` (used via PyO3 in the Electrum plugin) and the WASM `HarmonyBucket` (used in the web client).

### Interface

```java
public class HarmonyBucket {

    /**
     * Create a new HarmonyPIR bucket.
     *
     * @param n         number of database entries in this bucket's table
     * @param w         entry size in bytes (e.g. 39 for index level, 132 for chunk level)
     * @param t         parameter t (if 0, compute as round(sqrt(2*n)))
     * @param prpKey    16-byte master PRP key
     * @param bucketId  bucket identifier (0..K-1)
     */
    public HarmonyBucket(int n, int w, int t, byte[] prpKey, int bucketId);

    /**
     * Load hint parities downloaded from the hint server.
     * Called once during the offline phase.
     *
     * @param hintsData  raw hint bytes (m * w bytes, where m = params.m)
     */
    public void loadHints(byte[] hintsData);

    /**
     * Build a query request for a specific database row.
     *
     * @param q  the database row index to query
     * @return   request bytes to send to the query server
     *           (variable-length: a sequence of 4-byte LE u32 indices, sorted)
     */
    public byte[] buildRequest(int q);

    /**
     * Build a synthetic dummy request that is indistinguishable from a real one.
     * Used to pad unused buckets in batch queries.
     *
     * @return  dummy request bytes (same format as buildRequest)
     */
    public byte[] buildSyntheticDummy();

    /**
     * Process the query server's response and recover the entry data.
     * Also updates internal state (hint relocation) for future queries.
     *
     * @param response  server response bytes (count * w bytes)
     * @return          the recovered entry data (w bytes)
     */
    public byte[] processResponse(byte[] response);
}
```

### Supporting Functions Needed

```java
/**
 * Compute the optimal t parameter.
 * t = round(sqrt(2 * n)), clamped to >= 1
 */
public static int findBestT(int n);

/**
 * Compute the number of PRP rounds.
 * rounds = ceil((ceil(log2(2*n)) + 40) / BETA) * BETA, where BETA = 4
 */
public static int computeRounds(int n);
```

## Internal Algorithms

The bucket implementation requires these components:

### 1. PRP (Pseudo-Random Permutation) — Hoang PRP

- Used to map logical database indices to physical positions
- Constructed with `domain = 2 * padded_n`, `rounds`, and a 16-byte key
- The key is derived from the master PRP key by XORing `bucket_id` (as LE u32) into bytes 12-15:
  ```
  deriveBucketKey(masterKey, bucketId):
      key = copy(masterKey)  // 16 bytes
      key[12..16] ^= bucketId.to_le_bytes()
      return key
  ```
- The Hoang PRP itself is an AES-based Feistel construction. The existing Rust implementation is in the `harmonypir` crate (`harmonypir::prp::hoang::HoangPrp`).

### 2. RelocationDS (Relocation Data Structure)

- Manages the stateful mapping from logical indices to cells
- `locate(q)` → returns the cell index where item `q` currently resides
- `batch_access(cells)` → returns the logical values stored at given cells
- `relocate_segment(s)` → marks segment `s` as relocated, updating the PRP mapping
- `locate_extended(v)` → locate an extended value (for post-relocation hint updates)
- The existing Rust implementation is in `harmonypir::relocation::RelocationDS`.

### 3. Params

- Derived from `(n, w, t)`:
  - `padded_n` = pad `n` so that `2*padded_n` is divisible by `t` (or `2*t` if `t` is odd)
  - `m` = number of hint segments = `2 * padded_n / t`
- The existing Rust implementation is in `harmonypir::params::Params`.

### 4. ChaCha20 RNG

- Seeded from `(prpKey, bucketId, nonce=0)`:
  ```
  seed[0..16]  = prpKey
  seed[16..20] = bucketId.to_le_bytes()
  seed[20..24] = nonce.to_le_bytes()
  seed[24..32] = 0
  ```
- Used only in `buildSyntheticDummy()` to generate realistic-looking dummy requests
- Java option: Bouncy Castle's `ChaCha7539Engine` or any ChaCha20 CSPRNG

## Query Flow (How the Bucket is Used)

For context, here is how the Java PIR client uses `HarmonyBucket`. The flow is identical for index-level and chunk-level queries.

### Offline Phase (Once)

1. Client generates a random 16-byte `prpKey`
2. Client creates `K` buckets (K=75 for index, K=80 for chunks):
   ```java
   for (int b = 0; b < K; b++) {
       buckets[b] = new HarmonyBucket(n, w, 0, prpKey, b);
   }
   ```
3. Client connects to the **hint server** and requests hints for each bucket
4. Server returns `m * w` bytes of hint parities per bucket
5. Client calls `bucket.loadHints(hintsData)` for each

### Online Phase (Per Query Batch)

1. For each batch round, the client assigns queries to buckets (PBC cuckoo placement)
2. For each bucket `b`:
   - If bucket has a real query for bin index `binIdx`:
     ```java
     byte[] req = buckets[b].buildRequest(binIdx);
     ```
   - If bucket is unused (dummy):
     ```java
     byte[] req = buckets[b].buildSyntheticDummy();
     ```
3. All requests are sent to the **query server** in one batch message
4. Server returns a response for each bucket
5. For each real query:
   ```java
   byte[] entry = buckets[b].processResponse(response);
   // entry is w bytes; scan it for matching tag / chunk data
   ```

### Wire Protocol

The batch query message format (sent to query server):
```
[4B len LE][1B variant=0x43]
[1B level]         // 0 = index, 1 = chunk
[2B roundId LE]
[2B numBuckets LE]
[1B subQueriesPerBucket]   // always 1 for our use
Per bucket:
  [1B bucketId]
  [4B count LE]           // number of u32 indices in the request
  [count × 4B u32 LE]     // the sorted indices from buildRequest()
```

The server response format:
```
[4B len LE][1B variant=0x43]
[1B level]
[2B roundId LE]
[2B numBuckets LE]
[1B subResultsPerBucket]
Per bucket:
  [1B bucketId]
  [4B dataLen LE]
  [dataLen bytes]   // count * w bytes, passed to processResponse()
```

## Reference Implementations

- **Rust (PyO3)**: `electrum_plugin/harmonypir-python/src/lib.rs` — the exact implementation to port
- **Rust (WASM)**: `harmonypir-wasm/src/lib.rs` — equivalent WASM wrapper
- **Rust core**: `harmonypir` crate — `Params`, `HoangPrp`, `RelocationDS`

## Constants

```
BETA = 4                          // PRP round alignment
EMPTY = 0xFFFFFFFF (u32::MAX)     // sentinel for empty cells
```

## Constraints

- Must produce byte-identical results to the Rust implementation (same PRP outputs, same relocation behavior)
- Java 17+ (records, sealed interfaces available)
- Bouncy Castle is available as a dependency (already required by bitcoinj)
- No other native dependencies — must be pure Java
