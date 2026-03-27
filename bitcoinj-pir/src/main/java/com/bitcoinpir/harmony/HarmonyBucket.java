package com.bitcoinpir.harmony;

/**
 * A single HarmonyPIR bucket backed by native Rust code (via JNI).
 *
 * <p>Each bucket represents one slot in the Batch PIR scheme. The client
 * creates K buckets (one per cuckoo hash function), downloads hints for
 * each during the offline phase, then uses them for online queries.
 *
 * <p>Lifecycle:
 * <pre>
 *   try (var bucket = new HarmonyBucket(n, w, 0, prpKey, bucketId)) {
 *       bucket.loadHints(hintBytes);           // offline phase
 *       byte[] req = bucket.buildRequest(q);   // online: build request
 *       // ... send req to query server, receive response ...
 *       byte[] entry = bucket.processResponse(response);
 *   }
 * </pre>
 *
 * <p>Thread safety: each bucket must be used from a single thread.
 * Multiple buckets may exist concurrently on different threads.
 */
public class HarmonyBucket implements AutoCloseable {

    // ── PRP backend constants ───────────────────────────────────────────

    /** ALF format-preserving encryption (fastest, ~198 ns/op native). */
    public static final int PRP_ALF = 0;

    /** Hoang et al. card-shuffle (always available, ~6 us/op). */
    public static final int PRP_HOANG = 1;

    /** Stefanov-Shi recursive PRP (~36 us/op, good batch perf). */
    public static final int PRP_FASTPRP = 2;

    // ── Native library loading ──────────────────────────────────────────

    private static boolean nativeLoaded;
    private static String loadError;

    static {
        try {
            System.loadLibrary("harmonypir_jni");
            nativeLoaded = true;
        } catch (UnsatisfiedLinkError e) {
            nativeLoaded = false;
            loadError = e.getMessage();
        }
    }

    /** Check if the native library is available. */
    public static boolean isNativeLoaded() {
        return nativeLoaded;
    }

    // ── Instance state ──────────────────────────────────────────────────

    private long nativeHandle;

    // ── Constructors ────────────────────────────────────────────────────

    /**
     * Create a new HarmonyPIR bucket using the default PRP (ALF).
     *
     * @param n         number of database entries in this bucket's table
     * @param w         entry size in bytes (e.g. 39 for index level, 132 for chunk level)
     * @param t         segment size T (if 0, auto-compute as round(sqrt(2*n)))
     * @param prpKey    16-byte master PRP key
     * @param bucketId  bucket identifier (0..K-1)
     */
    public HarmonyBucket(int n, int w, int t, byte[] prpKey, int bucketId) {
        this(n, w, t, prpKey, bucketId, PRP_ALF);
    }

    /**
     * Create a new HarmonyPIR bucket with an explicit PRP backend.
     *
     * @param n          number of database entries in this bucket's table
     * @param w          entry size in bytes
     * @param t          segment size T (if 0, auto-compute)
     * @param prpKey     16-byte master PRP key
     * @param bucketId   bucket identifier (0..K-1)
     * @param prpBackend one of {@link #PRP_ALF}, {@link #PRP_HOANG}, {@link #PRP_FASTPRP}
     */
    public HarmonyBucket(int n, int w, int t, byte[] prpKey, int bucketId, int prpBackend) {
        if (!nativeLoaded) {
            throw new UnsatisfiedLinkError(
                "harmonypir_jni native library not available: " + loadError);
        }
        if (prpKey == null || prpKey.length != 16) {
            throw new IllegalArgumentException("prpKey must be 16 bytes");
        }
        this.nativeHandle = nativeCreate(n, w, t, prpKey, bucketId, prpBackend);
        if (this.nativeHandle == 0) {
            throw new RuntimeException("nativeCreate returned null handle");
        }
    }

    // ── Public API ──────────────────────────────────────────────────────

    /**
     * Load hint parities downloaded from the hint server.
     * Called once during the offline phase.
     *
     * @param hintsData raw hint bytes ({@link #getM()} * w bytes)
     */
    public void loadHints(byte[] hintsData) {
        checkOpen();
        nativeLoadHints(nativeHandle, hintsData);
    }

    /**
     * Build a query request for a specific database row.
     *
     * @param q the database row index to query (0 .. n-1)
     * @return  request bytes to send to the query server
     *          (a sequence of 4-byte LE u32 indices, sorted)
     */
    public byte[] buildRequest(int q) {
        checkOpen();
        return nativeBuildRequest(nativeHandle, q);
    }

    /**
     * Build a synthetic dummy request that is indistinguishable from a real one.
     * Used to pad unused buckets in batch queries.
     *
     * @return dummy request bytes (same format as {@link #buildRequest})
     */
    public byte[] buildSyntheticDummy() {
        checkOpen();
        return nativeBuildDummy(nativeHandle);
    }

    /**
     * Process the query server's response and recover the entry data.
     * Also updates internal state (hint relocation) for future queries.
     *
     * @param response server response bytes (count * w bytes, where count
     *                 is the number of indices in the request)
     * @return         the recovered entry data (w bytes)
     */
    public byte[] processResponse(byte[] response) {
        checkOpen();
        return nativeProcessResponse(nativeHandle, response);
    }

    // ── Accessors ───────────────────────────────────────────────────────

    /** Number of hint segments (M = 2N/T). Determines hint download size: M * w bytes. */
    public int getM() {
        checkOpen();
        return nativeGetM(nativeHandle);
    }

    /** Maximum queries before the offline phase must be re-run. */
    public int getMaxQueries() {
        checkOpen();
        return nativeGetMaxQueries(nativeHandle);
    }

    /** Entry size in bytes (w). */
    public int getW() {
        checkOpen();
        return nativeGetW(nativeHandle);
    }

    /** Database size after padding (n). */
    public int getN() {
        checkOpen();
        return nativeGetN(nativeHandle);
    }

    /** Segment size (T). */
    public int getT() {
        checkOpen();
        return nativeGetT(nativeHandle);
    }

    // ── Resource management ─────────────────────────────────────────────

    @Override
    public void close() {
        if (nativeHandle != 0) {
            nativeDestroy(nativeHandle);
            nativeHandle = 0;
        }
    }

    private void checkOpen() {
        if (nativeHandle == 0) {
            throw new IllegalStateException("HarmonyBucket is closed");
        }
    }

    // ── Pure Java helpers (no native library needed) ────────────────────

    /**
     * Compute the optimal segment size T for a given database size.
     * T = round(sqrt(2 * n)), adjusted to divide 2*n evenly.
     *
     * @param n number of database entries
     * @return  the optimal T value
     */
    public static int findBestT(int n) {
        if (n <= 0) throw new IllegalArgumentException("n must be > 0");
        int twoN = 2 * n;
        int tApprox = (int) Math.round(Math.sqrt(twoN));
        return findNearbyDivisor(twoN, Math.max(1, tApprox));
    }

    /**
     * Compute the number of PRP rounds for a given database size.
     * rounds = ceil((ceil(log2(2*n)) + 40) / 4) * 4
     *
     * @param n number of database entries
     * @return  number of PRP rounds (multiple of 4)
     */
    public static int computeRounds(int n) {
        if (n <= 0) throw new IllegalArgumentException("n must be > 0");
        int twoN = 2 * n;
        int logDomain = ceilLog2(twoN);
        int rRaw = logDomain + 40;
        return ((rRaw + 3) / 4) * 4; // round up to multiple of 4
    }

    static int findNearbyDivisor(int n, int target) {
        if (target == 0) return 1;
        if (n % target == 0) return target;
        for (int delta = 1; delta < target; delta++) {
            if (target + delta <= n && n % (target + delta) == 0) return target + delta;
            if (target > delta && n % (target - delta) == 0) return target - delta;
        }
        return 1;
    }

    static int ceilLog2(int n) {
        if (n <= 1) return 0;
        return 32 - Integer.numberOfLeadingZeros(n - 1);
    }

    // ── Native method declarations ──────────────────────────────────────

    private static native long nativeCreate(int n, int w, int t,
                                            byte[] prpKey, int bucketId, int prpBackend);
    private static native void nativeLoadHints(long handle, byte[] hintsData);
    private static native byte[] nativeBuildRequest(long handle, int q);
    private static native byte[] nativeBuildDummy(long handle);
    private static native byte[] nativeProcessResponse(long handle, byte[] response);
    private static native void nativeDestroy(long handle);
    private static native int nativeGetM(long handle);
    private static native int nativeGetMaxQueries(long handle);
    private static native int nativeGetW(long handle);
    private static native int nativeGetN(long handle);
    private static native int nativeGetT(long handle);
}
