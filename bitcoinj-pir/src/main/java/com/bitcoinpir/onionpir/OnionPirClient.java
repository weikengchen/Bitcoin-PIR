package com.bitcoinpir.onionpir;

import com.bitcoinpir.PirClient;
import com.bitcoinpir.PirConstants;
import com.bitcoinpir.codec.ProtocolCodec;
import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.net.PirWebSocket;

import java.util.*;
import java.util.logging.Logger;

/**
 * OnionPIRv2 single-server FHE-based PIR client.
 *
 * Requires JNI native library (onionpir-jni) wrapping the C++ OnionPIRv2
 * library for FHE operations:
 * - Key generation (Galois keys, GSW keys)
 * - Query generation (FHE encryption)
 * - Response decryption
 *
 * Build the native library:
 * <pre>
 *   cd onionpir-jni && mkdir build && cd build
 *   cmake .. -DCMAKE_BUILD_TYPE=Release && make -j
 * </pre>
 *
 * Privacy model: single server, computational privacy via lattice-based FHE.
 * No trust assumptions between servers, but significantly slower (~50s/query).
 */
public class OnionPirClient implements PirClient {
    private static final Logger log = Logger.getLogger(OnionPirClient.class.getName());

    private final String serverUrl;

    private PirWebSocket ws;
    private boolean connected;
    private boolean keysRegistered;

    // Server parameters
    private int indexBins;
    private int chunkBins;
    private int indexK;
    private int chunkK;
    private long tagSeed;

    public OnionPirClient(String serverUrl) {
        this.serverUrl = serverUrl;
    }

    @Override
    public void connect() throws Exception {
        checkNativeLibrary();

        ws = new PirWebSocket(serverUrl);
        ws.connect();

        // Fetch server info
        byte[] infoPayload = ws.sendSync(ProtocolCodec.encodeGetInfo());
        var info = ProtocolCodec.decodeServerInfo(infoPayload);
        indexBins = info.indexBins();
        chunkBins = info.chunkBins();
        indexK = info.indexK();
        chunkK = info.chunkK();
        tagSeed = info.tagSeed();

        // Register FHE keys with server
        registerKeys();

        connected = true;
        log.info("OnionPIR connected: indexBins=" + indexBins + " chunkBins=" + chunkBins);
    }

    @Override
    public boolean isConnected() {
        return connected;
    }

    @Override
    public Map<Integer, List<UtxoDecoder.UtxoEntry>> queryBatch(List<byte[]> scriptHashes) throws Exception {
        // The query flow is structurally similar to DPF:
        //
        // 1. Index phase: derive buckets → plan rounds → for each round:
        //    - For each bucket: call nativeGenerateQuery(indexClient, binIndex) → FHE ciphertext
        //    - Send REQ_ONIONPIR_INDEX_QUERY to server
        //    - For each result: call nativeDecryptResponse(indexClient, binIndex, ciphertext)
        //    - Scan for matching tags
        //
        // 2. Chunk phase: same with chunk-level client
        //    NOTE: OnionPIR uses different chunk cuckoo params (NUM_HASHES=6)
        //
        // 3. Reassemble UTXO data

        throw new UnsupportedOperationException(
            "OnionPIR requires the onionpir-jni native library. " +
            "Build with: cd OnionPIRv2 && mkdir build && cd build && " +
            "cmake .. -DBUILD_SHARED_LIBS=ON && make -j"
        );
    }

    @Override
    public void close() {
        connected = false;
        if (ws != null) ws.close();
        // TODO: release native FHE client handles
    }

    // ── JNI native methods (to be implemented in onionpir-jni) ──────────────

    /** Create an FHE client for a given database dimension. */
    // private static native long nativeCreateClient(int numEntries, int entrySize);

    /** Generate Galois keys (for server-side FHE evaluation). */
    // private static native byte[] nativeGenerateGaloisKeys(long handle);

    /** Generate GSW keys (for server-side FHE evaluation). */
    // private static native byte[] nativeGenerateGswKeys(long handle);

    /** Generate an FHE-encrypted query for a specific bin index. */
    // private static native byte[] nativeGenerateQuery(long handle, int binIndex);

    /** Decrypt an FHE-encrypted response. */
    // private static native byte[] nativeDecryptResponse(long handle, int binIndex, byte[] ciphertext);

    /** Free a native FHE client. */
    // private static native void nativeDestroyClient(long handle);

    // ── Internal ─────────────────────────────────────────────────────────────

    private void registerKeys() {
        // In the full implementation:
        // 1. Create index + chunk FHE clients via JNI
        // 2. Generate Galois and GSW keys
        // 3. Send REQ_REGISTER_KEYS to server
        // 4. Wait for RESP_KEYS_ACK
        log.info("OnionPIR key registration would happen here (requires JNI)");
    }

    private void checkNativeLibrary() {
        try {
            System.loadLibrary("onionpir_jni");
        } catch (UnsatisfiedLinkError e) {
            log.warning("onionpir_jni native library not loaded: " + e.getMessage());
        }
    }
}
