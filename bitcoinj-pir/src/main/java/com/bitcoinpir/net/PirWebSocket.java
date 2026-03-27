package com.bitcoinpir.net;

import com.bitcoinpir.PirConstants;
import com.bitcoinpir.codec.ProtocolCodec;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

/**
 * WebSocket transport for PIR servers.
 * Manages a binary WebSocket connection with FIFO request/response matching,
 * heartbeat ping, and pong filtering.
 */
public class PirWebSocket implements AutoCloseable {
    private static final Logger log = Logger.getLogger(PirWebSocket.class.getName());

    private static final long HEARTBEAT_INTERVAL_MS = 30_000;
    private static final long REQUEST_TIMEOUT_MS = 120_000;

    private final String url;
    private final OkHttpClient httpClient;

    private WebSocket ws;
    private final ConcurrentLinkedQueue<CompletableFuture<byte[]>> pendingCallbacks = new ConcurrentLinkedQueue<>();
    private final AtomicBoolean connected = new AtomicBoolean(false);
    private ScheduledExecutorService heartbeatExecutor;

    public PirWebSocket(String url) {
        this.url = url;
        this.httpClient = new OkHttpClient.Builder()
                .readTimeout(0, TimeUnit.MILLISECONDS) // no read timeout for WS
                .build();
    }

    /** Connect to the WebSocket server. Blocks until connection is established. */
    public void connect() throws Exception {
        CompletableFuture<Void> openFuture = new CompletableFuture<>();

        Request request = new Request.Builder().url(url).build();
        ws = httpClient.newWebSocket(request, new WebSocketListener() {
            @Override
            public void onOpen(WebSocket webSocket, Response response) {
                connected.set(true);
                openFuture.complete(null);
            }

            @Override
            public void onMessage(WebSocket webSocket, ByteString bytes) {
                handleMessage(bytes.toByteArray());
            }

            @Override
            public void onFailure(WebSocket webSocket, Throwable t, Response response) {
                connected.set(false);
                openFuture.completeExceptionally(t);
                // Fail all pending callbacks
                CompletableFuture<byte[]> cb;
                while ((cb = pendingCallbacks.poll()) != null) {
                    cb.completeExceptionally(t);
                }
            }

            @Override
            public void onClosed(WebSocket webSocket, int code, String reason) {
                connected.set(false);
            }
        });

        openFuture.get(30, TimeUnit.SECONDS);
        startHeartbeat();
    }

    /** Send a framed message and return a future for the response payload. */
    public CompletableFuture<byte[]> send(byte[] framedMessage) {
        CompletableFuture<byte[]> future = new CompletableFuture<>();

        // Apply timeout
        CompletableFuture.delayedExecutor(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .execute(() -> future.completeExceptionally(
                        new TimeoutException("PIR request timed out after " + REQUEST_TIMEOUT_MS + "ms")));

        pendingCallbacks.add(future);
        ws.send(ByteString.of(framedMessage));
        return future;
    }

    /** Send a framed message and block for the response. */
    public byte[] sendSync(byte[] framedMessage) throws Exception {
        return send(framedMessage).get(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS);
    }

    /**
     * Send a framed message that will produce N streamed responses.
     * Pre-registers N callbacks in the FIFO queue so each streamed response
     * is matched to its own future.
     *
     * @param framedMessage the message to send
     * @param n             number of expected responses
     * @return list of N futures, one per streamed response
     */
    public List<CompletableFuture<byte[]>> sendExpectingN(byte[] framedMessage, int n) {
        List<CompletableFuture<byte[]>> futures = new ArrayList<>(n);
        for (int i = 0; i < n; i++) {
            CompletableFuture<byte[]> f = new CompletableFuture<>();
            CompletableFuture.delayedExecutor(REQUEST_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                    .execute(() -> f.completeExceptionally(
                            new TimeoutException("PIR hint request timed out after " + REQUEST_TIMEOUT_MS + "ms")));
            pendingCallbacks.add(f);
            futures.add(f);
        }
        ws.send(ByteString.of(framedMessage));
        return futures;
    }

    public boolean isConnected() {
        return connected.get();
    }

    @Override
    public void close() {
        connected.set(false);
        if (heartbeatExecutor != null) {
            heartbeatExecutor.shutdownNow();
        }
        if (ws != null) {
            ws.close(1000, "Client closing");
        }
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    private void handleMessage(byte[] raw) {
        // Parse length prefix to get payload
        if (raw.length < 4) return;
        int len = ByteBuffer.wrap(raw, 0, 4).order(ByteOrder.LITTLE_ENDIAN).getInt();
        byte[] payload = new byte[len];
        System.arraycopy(raw, 4, payload, 0, Math.min(len, raw.length - 4));

        // Filter out Pong responses — don't consume a callback
        if (ProtocolCodec.isPong(payload)) {
            return;
        }

        // Pop the first pending callback and complete it
        CompletableFuture<byte[]> cb = pendingCallbacks.poll();
        if (cb != null) {
            // Check for error response
            if (payload.length > 0 && payload[0] == PirConstants.RESP_ERROR) {
                cb.completeExceptionally(new RuntimeException(
                        "Server error: " + ProtocolCodec.decodeError(payload)));
            } else {
                cb.complete(payload);
            }
        }
    }

    private void startHeartbeat() {
        heartbeatExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "pir-heartbeat-" + url);
            t.setDaemon(true);
            return t;
        });
        heartbeatExecutor.scheduleAtFixedRate(() -> {
            if (connected.get()) {
                try {
                    ws.send(ByteString.of(ProtocolCodec.encodePing()));
                } catch (Exception e) {
                    log.warning("Heartbeat failed: " + e.getMessage());
                }
            }
        }, HEARTBEAT_INTERVAL_MS, HEARTBEAT_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }
}
