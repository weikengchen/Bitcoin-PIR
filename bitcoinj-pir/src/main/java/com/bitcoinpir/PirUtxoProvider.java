package com.bitcoinpir;

import com.bitcoinpir.codec.UtxoDecoder;
import com.bitcoinpir.dpf.DpfPirClient;
import com.bitcoinpir.harmony.HarmonyPirClient;
import com.bitcoinpir.hash.PirHash;
import com.bitcoinpir.onionpir.OnionPirClient;

import org.bitcoinj.base.BitcoinNetwork;
import org.bitcoinj.base.Coin;
import org.bitcoinj.base.Network;
import org.bitcoinj.base.Sha256Hash;
import org.bitcoinj.core.UTXO;
import org.bitcoinj.core.UTXOProvider;
import org.bitcoinj.core.UTXOProviderException;
import org.bitcoinj.crypto.ECKey;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptBuilder;

import java.util.*;
import java.util.logging.Logger;

/**
 * bitcoinj {@link UTXOProvider} backed by Private Information Retrieval.
 *
 * Supports three PIR backends:
 * <ul>
 *   <li><b>DPF</b> — 2-server, pure Java, fastest (~100ms/query)</li>
 *   <li><b>HarmonyPIR</b> — 2-server, stateful, requires JNI (~2s/query after hints)</li>
 *   <li><b>OnionPIR</b> — single-server FHE, requires JNI (~50s/query)</li>
 * </ul>
 *
 * Usage:
 * <pre>{@code
 * PirUtxoProvider provider = new PirUtxoProvider(new PirBackendConfig.Dpf());
 * provider.connect();
 * wallet.setUTXOProvider(provider);
 * Coin balance = wallet.getBalance();
 * }</pre>
 */
public class PirUtxoProvider implements UTXOProvider, AutoCloseable {
    private static final Logger log = Logger.getLogger(PirUtxoProvider.class.getName());

    private final PirBackendConfig config;
    private final String esploraUrl;
    private PirClient client;
    private EsploraClient esplora;

    public PirUtxoProvider(PirBackendConfig config) {
        this(config, null);
    }

    /**
     * @param config     PIR backend configuration
     * @param esploraUrl Esplora REST API base URL (null for default)
     */
    public PirUtxoProvider(PirBackendConfig config, String esploraUrl) {
        this.config = config;
        this.esploraUrl = esploraUrl;
    }

    /** Connect to PIR servers. Must be called before use. */
    public void connect() throws Exception {
        esplora = esploraUrl != null ? new EsploraClient(esploraUrl) : new EsploraClient();

        client = switch (config) {
            case PirBackendConfig.Dpf dpf ->
                new DpfPirClient(dpf.server0Url(), dpf.server1Url());
            case PirBackendConfig.Harmony harmony ->
                new HarmonyPirClient(harmony.hintServerUrl(), harmony.queryServerUrl(), harmony.prpBackend());
            case PirBackendConfig.OnionPir onionPir ->
                new OnionPirClient(onionPir.serverUrl());
        };

        client.connect();
        log.info("PirUtxoProvider connected with backend: " + config.getClass().getSimpleName());
    }

    @Override
    public List<UTXO> getOpenTransactionOutputs(List<ECKey> keys) throws UTXOProviderException {
        try {
            // 1. For each ECKey, derive address types and their scriptPubKeys
            List<ScriptQuery> queries = new ArrayList<>();
            for (ECKey key : keys) {
                // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
                Script p2pkh = ScriptBuilder.createP2PKHOutputScript(key);
                queries.add(new ScriptQuery(key, p2pkh, "P2PKH"));

                // P2WPKH: OP_0 <pubKeyHash>
                Script p2wpkh = ScriptBuilder.createP2WPKHOutputScript(key);
                queries.add(new ScriptQuery(key, p2wpkh, "P2WPKH"));

                // P2SH-P2WPKH: OP_HASH160 <hash(redeemScript)> OP_EQUAL
                // where redeemScript = OP_0 <pubKeyHash>
                Script redeemScript = ScriptBuilder.createP2WPKHOutputScript(key);
                Script p2shP2wpkh = ScriptBuilder.createP2SHOutputScript(redeemScript);
                queries.add(new ScriptQuery(key, p2shP2wpkh, "P2SH-P2WPKH"));
            }

            // 2. Compute HASH160 for each scriptPubKey
            List<byte[]> scriptHashes = new ArrayList<>(queries.size());
            for (ScriptQuery q : queries) {
                byte[] spk = q.script.program();
                scriptHashes.add(PirHash.hash160(spk));
            }

            // 3. Batch PIR query
            Map<Integer, List<UtxoDecoder.UtxoEntry>> results = client.queryBatch(scriptHashes);

            // 4. Convert to bitcoinj UTXO objects
            List<UTXO> utxos = new ArrayList<>();
            for (int i = 0; i < queries.size(); i++) {
                List<UtxoDecoder.UtxoEntry> entries = results.getOrDefault(i, List.of());
                ScriptQuery q = queries.get(i);

                for (UtxoDecoder.UtxoEntry entry : entries) {
                    // Reverse txid bytes for display order
                    byte[] txidReversed = PirHash.reverseBytes(entry.txid());
                    Sha256Hash hash = Sha256Hash.wrap(txidReversed);

                    UTXO utxo = new UTXO(
                        hash,
                        entry.vout(),
                        Coin.valueOf(entry.amount()),
                        0,      // height — unknown, set to 0 (see design doc)
                        false,  // coinbase — assume false (see design doc)
                        q.script
                    );
                    utxos.add(utxo);
                }
            }

            log.fine("Queried " + keys.size() + " keys (" + queries.size() + " scripts), found " + utxos.size() + " UTXOs");
            return utxos;

        } catch (Exception e) {
            throw new UTXOProviderException(e);
        }
    }

    @Override
    public int getChainHeadHeight() throws UTXOProviderException {
        try {
            return esplora.fetchBlockHeight();
        } catch (Exception e) {
            throw new UTXOProviderException(e);
        }
    }

    @Override
    public Network network() {
        return BitcoinNetwork.MAINNET;
    }

    @Override
    public void close() {
        if (client != null) client.close();
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /** Tracks which ECKey + script type produced each PIR query. */
    private record ScriptQuery(ECKey key, Script script, String type) {}
}
