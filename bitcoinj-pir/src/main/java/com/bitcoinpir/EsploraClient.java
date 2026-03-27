package com.bitcoinpir;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

/**
 * Minimal Esplora REST client for non-privacy-sensitive operations.
 * Used internally by PirUtxoProvider for chain height queries.
 */
public class EsploraClient {
    private static final String DEFAULT_BASE_URL = "https://blockstream.info/api";

    private final String baseUrl;
    private final OkHttpClient http;

    public EsploraClient() {
        this(DEFAULT_BASE_URL);
    }

    public EsploraClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.http = new OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .build();
    }

    /** Fetch the current block height. */
    public int fetchBlockHeight() throws IOException {
        Request req = new Request.Builder()
                .url(baseUrl + "/blocks/tip/height")
                .build();
        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful()) {
                throw new IOException("Esplora request failed: " + resp.code());
            }
            return Integer.parseInt(resp.body().string().trim());
        }
    }

    /** Broadcast a raw transaction hex. Returns the txid. */
    public String broadcastTx(String txHex) throws IOException {
        Request req = new Request.Builder()
                .url(baseUrl + "/tx")
                .post(RequestBody.create(txHex, MediaType.parse("text/plain")))
                .build();
        try (Response resp = http.newCall(req).execute()) {
            if (!resp.isSuccessful()) {
                throw new IOException("Broadcast failed: " + resp.code() + " " + resp.body().string());
            }
            return resp.body().string().trim();
        }
    }
}
