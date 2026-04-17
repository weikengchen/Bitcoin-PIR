/**
 * IndexedDB persistence for HarmonyPIR hint state (v2 schema).
 *
 * Stores the opaque byte blob produced by `WasmHarmonyClient.saveHints()`
 * (self-describing, fingerprinted — see `pir-sdk-client/src/hint_cache.rs`)
 * together with the random master PRP key that the WASM client generated
 * at construction time. A page reload throws away the in-memory `WasmHarmonyClient`
 * instance and its random key, so the key has to be persisted next to the
 * hint blob — otherwise a restored hint bundle can't be replayed.
 *
 * Records are keyed by `(serverUrl, dbId, prpBackend)`. The 16-byte
 * `fingerprintHex` is an integrity/debug field; the authoritative
 * cross-check happens inside `WasmHarmonyClient.loadHints(bytes, catalog, db_id)`
 * which re-derives and compares the fingerprint before accepting the blob.
 * A fingerprint mismatch surfaces as a thrown `JsError` from the WASM
 * boundary — the caller treats that as "cache stale" and re-fetches.
 *
 * Schema version is bumped to 2 when migrating from the old per-group
 * `Map<number, Uint8Array>` layout. IndexedDB's `onupgradeneeded`
 * handler deletes the store and re-creates it, so pre-Session-6
 * entries are discarded cleanly on first load.
 */

const DB_NAME = 'harmonypir-hints';
const DB_VERSION = 2;
const STORE = 'hints';
const SCHEMA_VERSION = 2;

/** Stored IndexedDB record (v2). */
export interface StoredHints {
  cacheKey: string;
  serverUrl: string;
  dbId: number;
  backend: number;
  /** 16-byte master PRP key used to regenerate the hint bytes. */
  masterKey: Uint8Array;
  /** Self-describing hint blob from `WasmHarmonyClient.saveHints()`. */
  bytes: Uint8Array;
  /** 16-byte fingerprint (hex) — informational; authoritative check is in WASM. */
  fingerprintHex: string;
  savedAt: number;
  schemaVersion: number;
}

export function buildCacheKey(serverUrl: string, dbId: number, backend: number): string {
  return `${serverUrl}|${dbId}|${backend}`;
}

function idbAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      // v1 -> v2 schema migration: drop any legacy store and re-create.
      // The old record shape (`groups: Map<number, Uint8Array>`) can't be
      // replayed by the native Rust client, so salvaging it isn't useful.
      if (db.objectStoreNames.contains(STORE)) {
        db.deleteObjectStore(STORE);
      }
      db.createObjectStore(STORE, { keyPath: 'cacheKey' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('IndexedDB open failed'));
    req.onblocked = () => reject(new Error('IndexedDB open blocked'));
  });
}

export async function putHints(record: StoredHints): Promise<void> {
  if (!idbAvailable()) throw new Error('IndexedDB not available');
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB put failed'));
      tx.onabort = () => reject(tx.error ?? new Error('IndexedDB put aborted'));
      tx.objectStore(STORE).put(record);
    });
  } finally {
    db.close();
  }
}

export async function getHints(cacheKey: string): Promise<StoredHints | undefined> {
  if (!idbAvailable()) return undefined;
  const db = await openDb();
  try {
    return await new Promise<StoredHints | undefined>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readonly');
      const req = tx.objectStore(STORE).get(cacheKey);
      req.onsuccess = () => {
        const rec = req.result as StoredHints | undefined;
        // Defensive check: if something older than v2 survived the
        // upgrade handler (e.g. a browser that delivered onupgradeneeded
        // for a different reason), reject it silently so callers
        // re-download.
        if (rec && rec.schemaVersion !== SCHEMA_VERSION) resolve(undefined);
        else resolve(rec);
      };
      req.onerror = () => reject(req.error ?? new Error('IndexedDB get failed'));
    });
  } finally {
    db.close();
  }
}

export async function deleteHints(cacheKey: string): Promise<void> {
  if (!idbAvailable()) return;
  const db = await openDb();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error ?? new Error('IndexedDB delete failed'));
      tx.objectStore(STORE).delete(cacheKey);
    });
  } finally {
    db.close();
  }
}

export const HINT_SCHEMA_VERSION = SCHEMA_VERSION;

/** Format a 16-byte fingerprint as a hex string for storage/debug. */
export function fingerprintToHex(fp: Uint8Array): string {
  let out = '';
  for (const b of fp) out += b.toString(16).padStart(2, '0');
  return out;
}
