package com.bitcoinpir;

import com.bitcoinpir.codec.UtxoDecoder;

import java.util.List;
import java.util.Map;

/**
 * Common interface for all PIR backend clients (DPF, HarmonyPIR, OnionPIR).
 */
public interface PirClient extends AutoCloseable {

    /** Connect to the PIR server(s). */
    void connect() throws Exception;

    /** Whether the client is connected. */
    boolean isConnected();

    /**
     * Query UTXOs for a batch of script hashes.
     *
     * @param scriptHashes list of 20-byte HASH160 values
     * @return map from query index to list of UTXO entries (empty list = not found)
     */
    Map<Integer, List<UtxoDecoder.UtxoEntry>> queryBatch(List<byte[]> scriptHashes) throws Exception;

    /** Disconnect from servers. */
    @Override
    void close();
}
