/**
 * IndexedDB persistence for HarmonyPIR hint state.
 *
 * Stores serialized worker-pool group state (`pool.serializeAll()` output)
 * so a returning client can restore hints without re-downloading GBs of
 * data from the Hint Server. Records are keyed by (serverUrl, dbId,
 * prpBackend) and include a fingerprint of server parameters so stale
 * entries from a rebuilt server database are detected on load.
 */

/** Validation fingerprint tying cached hints to a specific server state. */
export interface HintFingerprint {
  indexBinsPerTable: number;
  chunkBinsPerTable: number;
  tagSeed: string;
  superRoot?: string;
}

/** Stored IndexedDB record. */
export interface StoredHints {
  cacheKey: string;
  serverUrl: string;
  dbId: number;
  backend: number;
  prpKey: Uint8Array;
  groups: Map<number, Uint8Array>;
  totalHintBytes: number;
  fingerprint: HintFingerprint;
  hasMainHints: boolean;
  hasSiblingHints: boolean;
  savedAt: number;
  schemaVersion: number;
}

const DB_NAME = 'harmonypir-hints';
const DB_VERSION = 1;
const STORE = 'hints';
const SCHEMA_VERSION = 1;

export function buildCacheKey(serverUrl: string, dbId: number, backend: number): string {
  return `${serverUrl}|${dbId}|${backend}`;
}

export function fingerprintsEqual(a: HintFingerprint, b: HintFingerprint): boolean {
  if (a.indexBinsPerTable !== b.indexBinsPerTable) return false;
  if (a.chunkBinsPerTable !== b.chunkBinsPerTable) return false;
  if (a.tagSeed !== b.tagSeed) return false;
  if ((a.superRoot ?? '') !== (b.superRoot ?? '')) return false;
  return true;
}

function idbAvailable(): boolean {
  return typeof indexedDB !== 'undefined';
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: 'cacheKey' });
      }
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
      req.onsuccess = () => resolve(req.result as StoredHints | undefined);
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
