package com.bitcoinpir;

/**
 * Configuration for PIR backend selection.
 * Mirrors the TypeScript PirBackend union type from explorer/src/types.ts.
 */
public sealed interface PirBackendConfig {

    /** DPF 2-server PIR (pure Java, no native dependencies). */
    record Dpf(String server0Url, String server1Url) implements PirBackendConfig {
        /** Use default public servers. */
        public Dpf() {
            this(PirConstants.DEFAULT_DPF_SERVER0_URL, PirConstants.DEFAULT_DPF_SERVER1_URL);
        }
    }

    /** HarmonyPIR 2-server stateful PIR (requires JNI native library). */
    record Harmony(String hintServerUrl, String queryServerUrl, int prpBackend) implements PirBackendConfig {
        public Harmony(String hintServerUrl, String queryServerUrl) {
            this(hintServerUrl, queryServerUrl, 0);
        }
    }

    /** OnionPIR single-server FHE PIR (requires JNI native library). */
    record OnionPir(String serverUrl) implements PirBackendConfig {}
}
