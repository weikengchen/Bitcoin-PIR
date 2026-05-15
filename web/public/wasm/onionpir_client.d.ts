// TypeScript declarations for the OnionPIRv2 WASM client.
//
// The build emits `onionpir_client.mjs` (ES module) + `onionpir_client.wasm`.
// Import the factory and instantiate the module:
//
//   import createOnionPir from "./onionpir_client.mjs";
//   const m = await createOnionPir();
//   const info = m.paramsInfo();
//   const client = new m.OnionPirClient();

export interface OnionPirParamsInfo {
    numEntries:     number;
    entrySize:      number;
    numPlaintexts:  number;
    fstDimSz:       number;
    otherDimSz:     number;
    polyDegree:     number;
    rnsModCount:    number;
    coeffValCnt:    number;
    dbSizeMB:       number;
    physicalSizeMB: number;
}

export interface OnionPirClient {
    /** Auto-assigned client id. Use with server.setGaloisKeys / setGswKey. */
    id(): number;

    /** Serialized BV galois keys. Send to server.setGaloisKeys. */
    galoisKeys(): Uint8Array;

    /** Serialized GSW(s) key. Send to server.setGswKey. */
    gswKey(): Uint8Array;

    /** Serialized PIR query for plaintext index ptIdx. */
    generateQuery(ptIdx: number): Uint8Array;

    /**
     * Decrypt a server response. Input is the bit-packed bytes returned by
     * server.answerQuery. Output is `[u32 N (LE)][u64 coeff_0]…` matching
     * the format from server.getOriginalPlaintext for direct equality checks.
     */
    decryptResponse(response: Uint8Array): Uint8Array;

    /**
     * Export this client's secret key. Treat as sensitive — these bytes
     * fully recover the client's identity. Pair with `createClientFromSecretKey`
     * to persist a client across page loads.
     */
    exportSecretKey(): Uint8Array;

    /** Free the underlying C++ object. Call when done. */
    delete(): void;
}

export interface OnionPirClientConstructor {
    new(): OnionPirClient;
}

export interface OnionPirModule {
    /** Inspect the compiled-in PIR shape. */
    paramsInfo(): OnionPirParamsInfo;

    /** PIR client class. */
    OnionPirClient: OnionPirClientConstructor;

    /**
     * Reconstruct a client from a previously-exported secret key and the id
     * the server already knows. Returns `null` on size / format mismatch.
     */
    createClientFromSecretKey(
        clientId: number,
        secretKey: Uint8Array,
    ): OnionPirClient | null;

    // ----- Application helpers (Bitcoin-PIR cuckoo plumbing) -----

    /** 64-bit splitmix64 finalizer; returns as JS number (safe < 2^53). */
    splitmix64(x: number): number;

    /** Single cuckoo bucket index for (entryId, key) mod numBins. */
    cuckooHashInt(entryId: number, key: number, numBins: number): number;

    /**
     * Build a cuckoo hash table for a group of entries.
     * - entries: sorted Uint32Array of entry ids in this group
     * - keys: Float64Array (treated as uint64s) of 6 hash function keys
     * - numBins: table size
     * Returns Uint32Array of length numBins; bin == 0xFFFFFFFF means empty.
     */
    buildCuckooBs1(
        entries: Uint32Array,
        keys: Float64Array,
        numBins: number,
    ): Uint32Array;
}

declare const createOnionPir: () => Promise<OnionPirModule>;
export default createOnionPir;
