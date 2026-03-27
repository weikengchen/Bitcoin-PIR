# HarmonyPIR JNI Bridge — Usage Guide

This document provides everything needed to integrate the HarmonyPIR bucket
implementation into a Java application. The core cryptography runs in Rust
via JNI; the Java side is a thin `AutoCloseable` wrapper.

## Build

```bash
cd /path/to/bitcoin-pir/harmonypir-jni
cargo build --release
# produces target/release/libharmonypir_jni.dylib  (macOS)
#         target/release/libharmonypir_jni.so     (Linux)
```

Set the library path so Java can find it:

```bash
# Option A: environment variable
export HARMONYPIR_LIB_DIR=/path/to/bitcoin-pir/harmonypir-jni/target/release

# Option B: JVM flag
java -Djava.library.path=/path/to/harmonypir-jni/target/release ...

# Option C: Gradle property (for tests)
./gradlew test -PnativeLibDir=/path/to/harmonypir-jni/target/release
```

The Gradle build file already defaults to `../../bitcoin-pir/harmonypir-jni/target/release`
relative to the project root.

Java 21+ is required. Add `--enable-native-access=ALL-UNNAMED` to suppress
restricted-method warnings.

## Quick Start

```java
import com.bitcoinpir.harmony.HarmonyBucket;
import java.security.SecureRandom;

// 1. Generate a random 16-byte master PRP key (once per session)
byte[] prpKey = new byte[16];
new SecureRandom().nextBytes(prpKey);

// 2. Create a bucket
//    n = database rows, w = entry size in bytes, t = 0 (auto-compute)
try (var bucket = new HarmonyBucket(262_144, 39, 0, prpKey, /*bucketId=*/0)) {

    // 3. Load hints from hint server (offline phase, once)
    //    Hint size = bucket.getM() * bucket.getW() bytes
    byte[] hints = downloadHintsFromServer(bucket.getM(), bucket.getW());
    bucket.loadHints(hints);

    // 4. Build a query request
    byte[] request = bucket.buildRequest(/*rowIndex=*/42);
    //    request is a sorted sequence of 4-byte little-endian u32 indices

    // 5. Send request to query server, receive response
    byte[] response = sendToQueryServer(request);

    // 6. Recover the entry
    byte[] entry = bucket.processResponse(response);
    //    entry is exactly w bytes (39 in this example)
}
```

## HarmonyBucket API

### Constructors

```java
// Default PRP backend (ALF — fastest)
new HarmonyBucket(int n, int w, int t, byte[] prpKey, int bucketId)

// Explicit PRP backend
new HarmonyBucket(int n, int w, int t, byte[] prpKey, int bucketId, int prpBackend)
```

| Parameter    | Type     | Description |
|-------------|----------|-------------|
| `n`         | `int`    | Number of database entries in this bucket's table |
| `w`         | `int`    | Entry size in bytes (e.g. 39 for index, 132 for chunk) |
| `t`         | `int`    | Segment size T. Pass **0** to auto-compute as `round(sqrt(2*n))` |
| `prpKey`    | `byte[]` | 16-byte master PRP key (shared across all buckets in a session) |
| `bucketId`  | `int`    | Bucket identifier, 0 .. K-1 |
| `prpBackend`| `int`    | One of `PRP_ALF` (0), `PRP_HOANG` (1), `PRP_FASTPRP` (2) |

The constructor internally:
- Derives a per-bucket key: `masterKey[12..16] ^= bucketId (as u32 LE)`
- Pads `n` so that `2*n` is divisible by `t`
- Creates the PRP and relocation data structure
- Seeds a ChaCha20 RNG from `(masterKey, bucketId)` for dummy generation

### Core Methods

| Method | Input | Output | Description |
|--------|-------|--------|-------------|
| `loadHints(byte[])` | `m * w` raw bytes | — | Load hint parities from the hint server. Call once. |
| `buildRequest(int q)` | Row index `q` (0..n-1) | Sorted u32 LE byte array | Build a real query request. Saves internal state for `processResponse`. |
| `buildSyntheticDummy()` | — | Sorted u32 LE byte array | Build a dummy request for padding unused buckets. Does **not** alter query state. |
| `processResponse(byte[])` | `count * w` bytes | `w` bytes (the recovered entry) | Decode the server response. Applies relocation + hint update (Algorithm 7). |

### Accessors

| Method | Returns | Description |
|--------|---------|-------------|
| `getM()` | `int` | Number of hint segments. Hint download size = `getM() * getW()` bytes. |
| `getMaxQueries()` | `int` | Maximum queries before hints must be re-downloaded. |
| `getW()` | `int` | Entry size in bytes. |
| `getN()` | `int` | Padded database size (may be larger than constructor `n`). |
| `getT()` | `int` | Segment size T (auto-computed if constructor `t` was 0). |

### Static Helpers (pure Java, no native library needed)

```java
// Optimal segment size for a given database size
int t = HarmonyBucket.findBestT(262_144);   // → divisor of 2*n near sqrt(2*n)

// PRP rounds for a given database size
int r = HarmonyBucket.computeRounds(262_144); // → multiple of 4, typically 56-64

// Check native library availability
boolean ok = HarmonyBucket.isNativeLoaded();
```

### Resource Management

`HarmonyBucket` implements `AutoCloseable`. Always use try-with-resources or
call `close()` explicitly. After closing, all methods throw `IllegalStateException`.

## PRP Backends

| Constant | Value | Native Latency | Notes |
|----------|-------|---------------|-------|
| `PRP_ALF` | 0 | ~198 ns/op | Default. Requires domain >= 65536 (auto-falls back to Hoang if smaller). |
| `PRP_HOANG` | 1 | ~6 us/op | Always available. AES-based Feistel card-shuffle. |
| `PRP_FASTPRP` | 2 | ~36 us/op | Stefanov-Shi recursive PRP. Best for server-side batch. |

All three backends are compiled into the native library by default.

## Bitcoin UTXO Parameters

These are the standard parameters used by the Bitcoin PIR system:

| Level | Buckets (K) | n (rows) | w (entry bytes) | Domain (2n) | T | M (segments) | Max queries |
|-------|------------|----------|-----------------|-------------|---|--------------|-------------|
| INDEX | 75 | 2^18 (262,144) | 39 | 2^19 | 512 | 1,024 | 512 |
| CHUNK | 80 | 2^19 (524,288) | 132 | 2^20 | 1,024 | 1,024 | 512 |

**Hint size per bucket**: M * w bytes (39 KB index, 132 KB chunk).
**Total hints**: ~40 MB across all 155 buckets.

Relevant constants from `PirConstants`:

```java
PirConstants.K              = 75    // index buckets
PirConstants.K_CHUNK        = 80    // chunk buckets
PirConstants.HARMONY_INDEX_W = 39   // index entry size
PirConstants.HARMONY_CHUNK_W = 132  // chunk entry size
PirConstants.HARMONY_EMPTY  = 0xFFFFFFFF  // empty sentinel
```

## Wire Protocol

### Batch Query Request (variant `0x43`)

Sent to the query server:

```
[4B totalLen LE] [1B 0x43]
[1B level]                    // 0 = index, 1 = chunk
[2B roundId LE]
[2B numBuckets LE]
[1B subQueriesPerBucket]      // always 1

Per bucket (repeated numBuckets times):
  [1B bucketId]
  [4B count LE]               // number of u32 indices
  [count * 4B u32 LE]         // sorted indices from buildRequest()
```

### Batch Query Response (variant `0x43`)

Received from the query server:

```
[4B totalLen LE] [1B 0x43]
[1B level]
[2B roundId LE]
[2B numBuckets LE]
[1B subResultsPerBucket]      // always 1

Per bucket:
  [1B bucketId]
  [4B dataLen LE]             // = count * w
  [dataLen bytes]             // passed to processResponse()
```

### Hint Request (variant `0x41`)

Sent to the hint server (once per bucket during offline phase):

```
[4B len LE] [1B 0x41]
[16B prpKey]
[1B level]                    // 0 = index, 1 = chunk
[1B bucketId]
```

### Hint Response (variant `0x41`)

```
[4B len LE] [1B 0x41]
[4B dataLen LE]               // = m * w
[dataLen bytes]               // passed to loadHints()
```

## Complete Query Flow

### Offline Phase (once per session)

```java
byte[] prpKey = new byte[16];
new SecureRandom().nextBytes(prpKey);

int K = PirConstants.K;              // 75
int K_CHUNK = PirConstants.K_CHUNK;  // 80

// Create all buckets
HarmonyBucket[] indexBuckets = new HarmonyBucket[K];
for (int b = 0; b < K; b++) {
    indexBuckets[b] = new HarmonyBucket(indexBins, PirConstants.HARMONY_INDEX_W, 0, prpKey, b);
}
HarmonyBucket[] chunkBuckets = new HarmonyBucket[K_CHUNK];
for (int b = 0; b < K_CHUNK; b++) {
    chunkBuckets[b] = new HarmonyBucket(chunkBins, PirConstants.HARMONY_CHUNK_W, 0, prpKey, b);
}

// Download and load hints for each bucket
for (int b = 0; b < K; b++) {
    byte[] hintReq = encodeHintRequest(prpKey, b, /*level=*/0);
    byte[] hintResp = hintWs.sendSync(hintReq);
    byte[] hintData = parseHintPayload(hintResp);  // m * w bytes
    indexBuckets[b].loadHints(hintData);
}
for (int b = 0; b < K_CHUNK; b++) {
    byte[] hintReq = encodeHintRequest(prpKey, b, /*level=*/1);
    byte[] hintResp = hintWs.sendSync(hintReq);
    byte[] hintData = parseHintPayload(hintResp);
    chunkBuckets[b].loadHints(hintData);
}
```

### Online Phase (per batch of address lookups)

```java
// Step 1: Derive bin indices via cuckoo hashing
//   Each script hash maps to NUM_HASHES=3 candidate buckets

// Step 2: Plan rounds via PBC (probabilistic batch codes)
//   Assigns each query to a bucket, pads unused buckets with dummies

// Step 3: For each round, build requests
byte[][] requests = new byte[K][];
boolean[] isReal = new boolean[K];
int[] realBinIdx = new int[K];

for (int b = 0; b < K; b++) {
    if (bucketHasRealQuery(b)) {
        requests[b] = indexBuckets[b].buildRequest(realBinIdx[b]);
        isReal[b] = true;
    } else {
        requests[b] = indexBuckets[b].buildSyntheticDummy();
        isReal[b] = false;
    }
}

// Step 4: Encode and send batch query
byte[] batchMsg = encodeBatchQuery(requests, /*level=*/0, roundId);
byte[] batchResp = queryWs.sendSync(batchMsg);

// Step 5: Process responses
for (int b = 0; b < K; b++) {
    byte[] respData = extractBucketResponse(batchResp, b);
    if (isReal[b]) {
        byte[] entry = indexBuckets[b].processResponse(respData);
        // entry is 39 bytes: scan 3 slots of (8B tag, 4B startChunkId, 1B numChunks)
        scanForMatchingTag(entry, targetTag);
    } else {
        // Dummy — still call processResponse to keep relocation state consistent
        indexBuckets[b].processResponse(respData);
    }
}

// Step 6: Repeat for chunk level (K_CHUNK=80 buckets, w=132)
// Step 7: Reassemble UTXO data from recovered chunks
```

### Cleanup

```java
for (HarmonyBucket b : indexBuckets) b.close();
for (HarmonyBucket b : chunkBuckets) b.close();
```

## Error Handling

| Exception | Cause |
|-----------|-------|
| `UnsatisfiedLinkError` | Native library not found. Check `java.library.path`. |
| `IllegalArgumentException` | Invalid `prpKey` (not 16 bytes), or invalid `n`/`t` for helpers. |
| `IllegalStateException` | Bucket already closed, or calling `processResponse` without a prior `buildRequest`. |
| `RuntimeException` | Native-side panic (assertion failure, chain-walk exceeded, etc.). Message contains details. |

## Key Internals (for debugging)

- **EMPTY sentinel**: `0xFFFFFFFF` (u32 max). Cells without a database value.
- **Relocation**: After each query, the queried segment is relocated. The
  hint parities are updated. After `maxQueries` queries, all empty slots are
  exhausted and new hints must be downloaded.
- **Chain-walking**: `locate(v)` and `access(c)` follow relocation chains
  through the history. Fixed-point cycles are detected and treated as EMPTY.
- **Dummy requests** are seeded from `ChaCha20(masterKey || bucketId_LE || 0...)`,
  so the same bucket always produces the same sequence of dummies (deterministic
  but indistinguishable from real requests).

## File Locations

```
bitcoin-pir/
  harmonypir/                    # Rust core library (Params, PRP, RelocationDS, protocol)
    src/prp/hoang.rs             #   HoangPrp (AES Feistel)
    src/prp/alf.rs               #   AlfPrp (ALF FPE)
    src/prp/fast.rs              #   FastPrpWrapper
    src/relocation.rs            #   RelocationDS (chain-walking)
    src/protocol.rs              #   Client (offline + online protocol)
    src/params.rs                #   Params (N, w, T, M, rounds)
    src/hist.rs                  #   HistPrime (segment history)
  harmonypir-jni/                # JNI bridge (this crate)
    Cargo.toml
    src/lib.rs                   #   Bucket struct + JNI exports
  ALF/                           # ALF PRP dependency
  fastprp/                       # FastPRP dependency

BitcoinPIR/bitcoinj-pir/         # Java project
  src/main/java/com/bitcoinpir/
    harmony/
      HarmonyBucket.java         #   JNI wrapper (public API)
      HarmonyPirClient.java      #   PIR client using HarmonyBucket
    PirConstants.java            #   K, K_CHUNK, HARMONY_*_W, protocol codes
    codec/ProtocolCodec.java     #   Wire format encoding/decoding
    net/PirWebSocket.java        #   WebSocket transport (FIFO + streaming)
  src/test/java/com/bitcoinpir/
    harmony/
      HarmonyBucketTest.java     #   Unit tests (pure Java + JNI)
      HarmonyPirClientIntegrationTest.java  # Integration tests (live servers)
  build.gradle                   #   Native library path config
```

## Integration Tests

All integration tests are `@Disabled` by default — they require live HarmonyPIR
servers and the native library.

### Test Classes

**`HarmonyBucketTest`** — runs without servers:
- `testFindBestT`, `testComputeRounds`, `testCeilLog2`, `testFindNearbyDivisor` — pure Java helpers
- `testCreateAndClose`, `testAutoComputeT`, `testBuildDummy` — JNI tests (skipped if native unavailable)
- `testInvalidKeyLength`, `testNullKey`, `testUseAfterClose` — validation tests

**`HarmonyPirClientIntegrationTest`** — requires live servers:
- `testConnectAndGetInfo` — WebSocket connect + GetInfo (0x40), verifies server parameters
- `testHintDownloadSingleBucket` — downloads one bucket's hints, verifies sizes, loads into bucket
- `testSingleBucketQueryRoundTrip` — hint download → buildRequest → batch query → processResponse
- `testFullQuerySatoshiAddress` — full two-level query for Satoshi's address (index + chunk)
- `testMultiAddressQuery` — batch query for multiple addresses

### Running Integration Tests

```bash
# Start servers first:
#   Hint server: ws://localhost:8094
#   Query server: ws://localhost:8095

# Run a single integration test (remove @Disabled first, or use JUnit filter):
cd BitcoinPIR/bitcoinj-pir
./gradlew test --tests "*.HarmonyPirClientIntegrationTest.testConnectAndGetInfo"

# Run all integration tests:
./gradlew test --tests "*.HarmonyPirClientIntegrationTest"

# Run with specific native library path:
./gradlew test -PnativeLibDir=/path/to/harmonypir-jni/target/release \
  --tests "*.HarmonyPirClientIntegrationTest"
```

### Important: T Computation Mismatch

The JNI bridge auto-computes T using `find_nearby_divisor(2*n, sqrt(2*n))`,
while the hint server uses `pad_n_for_t(n, round(sqrt(2*n)))` (pads n up
instead of adjusting T). **When creating buckets for use with the hint server,
always pass the server's explicit `(padded_n, t)` from the hint response:**

```java
// Download hints first to learn server's T and padded_n
HintData hint = downloadHintForBucket(bucketId);

// Create bucket with server's exact values — NOT t=0 (auto-compute)
var bucket = new HarmonyBucket(hint.n(), w, hint.t(), prpKey, bucketId, backend);
bucket.loadHints(hint.hintBytes());
```

`HarmonyPirClient.connect()` handles this automatically via
`downloadHintsAndCreateBuckets()`.

### PRP Backend Constant Mapping

Java-side and server-side PRP constants differ:

| PRP | Java (`HarmonyBucket.PRP_*`) | Server (`PirConstants.SERVER_PRP_*`) |
|-----|-----|--------|
| ALF | 0 | 2 |
| Hoang | 1 | 0 |
| FastPRP | 2 | 1 |

Use `PirConstants.SERVER_PRP_*` when encoding hint requests for the server.
`HarmonyPirClient` handles the mapping internally via `toServerPrpBackend()`.
