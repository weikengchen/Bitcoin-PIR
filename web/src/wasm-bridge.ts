/**
 * WASM bridge for pir-core-wasm.
 *
 * Provides lazy initialization and TypeScript-friendly wrappers around the
 * WASM module's (hi, lo) u32-pair API, converting to/from BigInt to match
 * the existing hash.ts signatures.
 *
 * If WASM is not loaded, all functions return `undefined` so callers can
 * fall back to the pure-TS implementation.
 */

// ─── WASM module type (subset we use) ─────────────────────────────────────

interface PirCoreWasm {
  splitmix64(x_hi: number, x_lo: number): Uint8Array;
  compute_tag(tag_seed_hi: number, tag_seed_lo: number, script_hash: Uint8Array): Uint8Array;
  derive_buckets(script_hash: Uint8Array, k: number): Uint32Array;
  derive_cuckoo_key(master_seed_hi: number, master_seed_lo: number, bucket_id: number, hash_fn: number): Uint8Array;
  cuckoo_hash(script_hash: Uint8Array, key_hi: number, key_lo: number, num_bins: number): number;
  derive_chunk_buckets(chunk_id: number, k: number): Uint32Array;
  derive_chunk_cuckoo_key(master_seed_hi: number, master_seed_lo: number, bucket_id: number, hash_fn: number): Uint8Array;
  cuckoo_hash_int(chunk_id: number, key_hi: number, key_lo: number, num_bins: number): number;
}

// ─── State ────────────────────────────────────────────────────────────────

let wasmModule: PirCoreWasm | null = null;
let wasmInitPromise: Promise<boolean> | null = null;

// ─── Conversion helpers ───────────────────────────────────────────────────

function bigintToHiLo(v: bigint): [number, number] {
  const lo = Number(v & 0xFFFFFFFFn);
  const hi = Number((v >> 32n) & 0xFFFFFFFFn);
  return [hi, lo];
}

function leBytes8ToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 7; i >= 0; i--) result = (result << 8n) | BigInt(bytes[i]);
  return result;
}

// ─── Initialization ──────────────────────────────────────────────────────

/**
 * Attempt to load and initialize the WASM module.
 * Returns true if WASM is now available, false otherwise.
 * Safe to call multiple times; only the first call triggers loading.
 */
export async function initWasm(): Promise<boolean> {
  if (wasmModule) return true;
  if (wasmInitPromise) return wasmInitPromise;

  wasmInitPromise = (async () => {
    try {
      // Dynamic import — the bundler resolves the WASM package.
      // The pir-core-wasm pkg/ directory should be available as a dependency
      // or via a path alias in the bundler config.
      const mod = await import('pir-core-wasm');
      // wasm-pack generates an init() default export for web targets;
      // call it if present.
      if (typeof mod.default === 'function') {
        await mod.default();
      }
      wasmModule = mod as unknown as PirCoreWasm;
      console.log('[PIR-WASM] WASM module loaded successfully');
      return true;
    } catch (e) {
      console.warn('[PIR-WASM] Failed to load WASM module, using pure-TS fallback:', e);
      return false;
    }
  })();

  return wasmInitPromise;
}

/** Returns true if the WASM module has been successfully loaded. */
export function isWasmReady(): boolean {
  return wasmModule !== null;
}

// ─── WASM-accelerated functions ──────────────────────────────────────────
//
// Each function returns `undefined` when WASM is not loaded, signalling the
// caller to use its own TS implementation.

export function wasmSplitmix64(x: bigint): bigint | undefined {
  if (!wasmModule) return undefined;
  const [hi, lo] = bigintToHiLo(x);
  const result = wasmModule.splitmix64(hi, lo);
  return leBytes8ToBigint(result);
}

export function wasmComputeTag(tagSeed: bigint, scriptHash: Uint8Array): bigint | undefined {
  if (!wasmModule) return undefined;
  const [hi, lo] = bigintToHiLo(tagSeed);
  const result = wasmModule.compute_tag(hi, lo, scriptHash);
  return leBytes8ToBigint(result);
}

export function wasmDeriveBuckets(scriptHash: Uint8Array, k: number): number[] | undefined {
  if (!wasmModule) return undefined;
  const result = wasmModule.derive_buckets(scriptHash, k);
  return Array.from(result);
}

export function wasmDeriveCuckooKey(
  masterSeed: bigint,
  bucketId: number,
  hashFn: number,
): bigint | undefined {
  if (!wasmModule) return undefined;
  const [hi, lo] = bigintToHiLo(masterSeed);
  const result = wasmModule.derive_cuckoo_key(hi, lo, bucketId, hashFn);
  return leBytes8ToBigint(result);
}

export function wasmCuckooHash(
  scriptHash: Uint8Array,
  key: bigint,
  numBins: number,
): number | undefined {
  if (!wasmModule) return undefined;
  const [hi, lo] = bigintToHiLo(key);
  return wasmModule.cuckoo_hash(scriptHash, hi, lo, numBins);
}

export function wasmDeriveChunkBuckets(chunkId: number, k: number): number[] | undefined {
  if (!wasmModule) return undefined;
  const result = wasmModule.derive_chunk_buckets(chunkId, k);
  return Array.from(result);
}

export function wasmDeriveChunkCuckooKey(
  masterSeed: bigint,
  bucketId: number,
  hashFn: number,
): bigint | undefined {
  if (!wasmModule) return undefined;
  const [hi, lo] = bigintToHiLo(masterSeed);
  const result = wasmModule.derive_chunk_cuckoo_key(hi, lo, bucketId, hashFn);
  return leBytes8ToBigint(result);
}

export function wasmCuckooHashInt(
  chunkId: number,
  key: bigint,
  numBins: number,
): number | undefined {
  if (!wasmModule) return undefined;
  const [hi, lo] = bigintToHiLo(key);
  return wasmModule.cuckoo_hash_int(chunkId, hi, lo, numBins);
}
