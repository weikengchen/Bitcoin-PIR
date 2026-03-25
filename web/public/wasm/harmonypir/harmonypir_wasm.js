let wasm_bindgen = (function(exports) {
    let script_src;
    if (typeof document !== 'undefined' && document.currentScript !== null) {
        script_src = new URL(document.currentScript.src, location.href).toString();
    }

    /**
     * Per-PBC-bucket HarmonyPIR client state.
     */
    class HarmonyBucket {
        static __wrap(ptr) {
            ptr = ptr >>> 0;
            const obj = Object.create(HarmonyBucket.prototype);
            obj.__wbg_ptr = ptr;
            HarmonyBucketFinalization.register(obj, obj.__wbg_ptr, obj);
            return obj;
        }
        __destroy_into_raw() {
            const ptr = this.__wbg_ptr;
            this.__wbg_ptr = 0;
            HarmonyBucketFinalization.unregister(this);
            return ptr;
        }
        free() {
            const ptr = this.__destroy_into_raw();
            wasm.__wbg_harmonybucket_free(ptr, 0);
        }
        /**
         * Build a dummy request for a bucket the client doesn't actually need.
         *
         * Picks a random bin in `[0, real_n)` and builds a real-looking request.
         * The client discards the server's response — **no `process_response`
         * call, no hint consumed, no relocation**.
         *
         * The Query Server cannot distinguish this from a real request because it
         * does not know the PRP key — it just sees sorted indices into the table.
         *
         * # TODO (privacy)
         *
         * The count of non-empty indices per segment follows a distribution that
         * depends on T and N.  A truly indistinguishable dummy would need to sample
         * from that same distribution (~Binomial(T, 0.5)) rather than using an
         * actual segment.  For now we query a random real bin, which produces a
         * realistic but not perfectly simulated count.  This must be revisited
         * before production — see the protocol's privacy analysis.
         * @returns {HarmonyRequest}
         */
        build_dummy_request() {
            const ret = wasm.harmonybucket_build_dummy_request(this.__wbg_ptr);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return HarmonyRequest.__wrap(ret[0]);
        }
        /**
         * Build a request for database row `q`.
         *
         * Returns only the non-empty indices from the segment (excluding the
         * dummy at position r), sorted for server cache efficiency.  The dummy
         * is omitted entirely — the server never sees it.
         * @param {number} q
         * @returns {HarmonyRequest}
         */
        build_request(q) {
            const ret = wasm.harmonybucket_build_request(this.__wbg_ptr, q);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return HarmonyRequest.__wrap(ret[0]);
        }
        /**
         * Build a **synthetic** dummy request that is distribution-matched with
         * real queries but touches NO real segment or DS' state.
         *
         * Privacy rationale: `build_dummy_request()` queries a real segment
         * without relocating it, which could let the server correlate the
         * dummy with future real queries to the same segment.  Synthetic
         * dummies avoid this — they sample random indices that look
         * statistically identical to a real query:
         *
         * - count ~ Binomial(T, 0.5) — each of T cells has ~50% chance of
         *   being non-empty (N values fill 2N cells).
         * - indices: `count` unique values drawn uniformly from [0, real_n),
         *   sorted ascending — matches the distribution of non-empty cell
         *   values in a real segment (PRP makes them uniform in [0, N)).
         *
         * Returns raw bytes: `count × 4B u32 LE` (same format as
         * `HarmonyRequest.request`).
         *
         * **No state mutation**: hints, DS', query count, and RNG-derived
         * segment state are untouched.  (The RNG *is* advanced, which is fine.)
         * @returns {Uint8Array}
         */
        build_synthetic_dummy() {
            const ret = wasm.harmonybucket_build_synthetic_dummy(this.__wbg_ptr);
            var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
            return v1;
        }
        /**
         * Restore a bucket from serialized bytes.
         *
         * Reconstructs the PRP from key + params (+ cache for FastPRP),
         * creates a fresh DS', then replays all relocated segments to
         * restore the exact same DS' state.
         * @param {Uint8Array} data
         * @param {Uint8Array} prp_key
         * @param {number} bucket_id
         * @returns {HarmonyBucket}
         */
        static deserialize(data, prp_key, bucket_id) {
            const ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(prp_key, wasm.__wbindgen_malloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.harmonybucket_deserialize(ptr0, len0, ptr1, len1, bucket_id);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return HarmonyBucket.__wrap(ret[0]);
        }
        /**
         * Load pre-computed hint parities (M × w bytes, flat).
         * @param {Uint8Array} hints_data
         */
        load_hints(hints_data) {
            const ptr0 = passArray8ToWasm0(hints_data, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.harmonybucket_load_hints(this.__wbg_ptr, ptr0, len0);
            if (ret[1]) {
                throw takeFromExternrefTable0(ret[0]);
            }
        }
        /**
         * @returns {number}
         */
        m() {
            const ret = wasm.harmonybucket_m(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * @returns {number}
         */
        max_queries() {
            const ret = wasm.harmonybucket_max_queries(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * Padded N (PRP domain = 2*padded_n). Always >= real_n.
         * @returns {number}
         */
        n() {
            const ret = wasm.harmonybucket_n(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * Create a new HarmonyBucket with Hoang PRP (default).
         * @param {number} n
         * @param {number} w
         * @param {number} t
         * @param {Uint8Array} prp_key
         * @param {number} bucket_id
         */
        constructor(n, w, t, prp_key, bucket_id) {
            const ptr0 = passArray8ToWasm0(prp_key, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.harmonybucket_new(n, w, t, ptr0, len0, bucket_id);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            this.__wbg_ptr = ret[0] >>> 0;
            HarmonyBucketFinalization.register(this, this.__wbg_ptr, this);
            return this;
        }
        /**
         * Create with a specific PRP backend.
         *
         * `n` is the real number of DB rows. Internally, N is padded up so
         * that `2*padded_n % T == 0`. Rows in `[n, padded_n)` are virtual
         * empty rows (the server returns zeros for them).
         * @param {number} n
         * @param {number} w
         * @param {number} t
         * @param {Uint8Array} prp_key
         * @param {number} bucket_id
         * @param {number} prp_backend
         * @returns {HarmonyBucket}
         */
        static new_with_backend(n, w, t, prp_key, bucket_id, prp_backend) {
            const ptr0 = passArray8ToWasm0(prp_key, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.harmonybucket_new_with_backend(n, w, t, ptr0, len0, bucket_id, prp_backend);
            if (ret[2]) {
                throw takeFromExternrefTable0(ret[1]);
            }
            return HarmonyBucket.__wrap(ret[0]);
        }
        /**
         * Process the Query Server's response and recover the target entry.
         *
         * Response contains `count` entries of w bytes each, in the same sorted
         * order as the request indices.  The answer is H[s] ⊕ XOR(all entries).
         * @param {Uint8Array} response
         * @returns {Uint8Array}
         */
        process_response(response) {
            const ptr0 = passArray8ToWasm0(response, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.harmonybucket_process_response(this.__wbg_ptr, ptr0, len0);
            if (ret[3]) {
                throw takeFromExternrefTable0(ret[2]);
            }
            var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
            return v2;
        }
        /**
         * @returns {number}
         */
        prp_backend() {
            const ret = wasm.harmonybucket_prp_backend(this.__wbg_ptr);
            return ret;
        }
        /**
         * @returns {number}
         */
        queries_remaining() {
            const ret = wasm.harmonybucket_queries_remaining(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * @returns {number}
         */
        queries_used() {
            const ret = wasm.harmonybucket_queries_used(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * Original (unpadded) N — the actual number of DB rows.
         * @returns {number}
         */
        real_n() {
            const ret = wasm.harmonybucket_real_n(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * Serialize this bucket's full mutable state to bytes.
         *
         * Format:
         * ```text
         * [4B padded_n][4B w][4B t][4B query_count][1B prp_backend][4B real_n]
         * [4B num_relocated][num_relocated × 4B segments]
         * [4B prp_cache_len][prp_cache bytes]
         * [M × w bytes: hints]
         * ```
         * @returns {Uint8Array}
         */
        serialize() {
            const ret = wasm.harmonybucket_serialize(this.__wbg_ptr);
            var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
            return v1;
        }
        /**
         * @returns {number}
         */
        t() {
            const ret = wasm.harmonybucket_t(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * @returns {number}
         */
        w() {
            const ret = wasm.harmonybucket_w(this.__wbg_ptr);
            return ret >>> 0;
        }
    }
    if (Symbol.dispose) HarmonyBucket.prototype[Symbol.dispose] = HarmonyBucket.prototype.free;
    exports.HarmonyBucket = HarmonyBucket;

    class HarmonyRequest {
        static __wrap(ptr) {
            ptr = ptr >>> 0;
            const obj = Object.create(HarmonyRequest.prototype);
            obj.__wbg_ptr = ptr;
            HarmonyRequestFinalization.register(obj, obj.__wbg_ptr, obj);
            return obj;
        }
        __destroy_into_raw() {
            const ptr = this.__wbg_ptr;
            this.__wbg_ptr = 0;
            HarmonyRequestFinalization.unregister(this);
            return ptr;
        }
        free() {
            const ptr = this.__destroy_into_raw();
            wasm.__wbg_harmonyrequest_free(ptr, 0);
        }
        /**
         * @returns {number}
         */
        get position() {
            const ret = wasm.harmonyrequest_position(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * @returns {number}
         */
        get query_index() {
            const ret = wasm.harmonyrequest_query_index(this.__wbg_ptr);
            return ret >>> 0;
        }
        /**
         * @returns {Uint8Array}
         */
        get request() {
            const ret = wasm.harmonyrequest_request(this.__wbg_ptr);
            var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
            return v1;
        }
        /**
         * @returns {number}
         */
        get segment() {
            const ret = wasm.harmonyrequest_segment(this.__wbg_ptr);
            return ret >>> 0;
        }
    }
    if (Symbol.dispose) HarmonyRequest.prototype[Symbol.dispose] = HarmonyRequest.prototype.free;
    exports.HarmonyRequest = HarmonyRequest;

    /**
     * @param {number} n
     * @returns {number}
     */
    function compute_balanced_t(n) {
        const ret = wasm.compute_balanced_t(n);
        return ret >>> 0;
    }
    exports.compute_balanced_t = compute_balanced_t;

    /**
     * @param {number} n
     * @param {number} w
     * @returns {boolean}
     */
    function verify_protocol(n, w) {
        const ret = wasm.verify_protocol(n, w);
        return ret !== 0;
    }
    exports.verify_protocol = verify_protocol;

    function __wbg_get_imports() {
        const import0 = {
            __proto__: null,
            __wbg_Error_83742b46f01ce22d: function(arg0, arg1) {
                const ret = Error(getStringFromWasm0(arg0, arg1));
                return ret;
            },
            __wbg___wbindgen_throw_6ddd609b62940d55: function(arg0, arg1) {
                throw new Error(getStringFromWasm0(arg0, arg1));
            },
            __wbindgen_init_externref_table: function() {
                const table = wasm.__wbindgen_externrefs;
                const offset = table.grow(4);
                table.set(0, undefined);
                table.set(offset + 0, undefined);
                table.set(offset + 1, null);
                table.set(offset + 2, true);
                table.set(offset + 3, false);
            },
        };
        return {
            __proto__: null,
            "./harmonypir_wasm_bg.js": import0,
        };
    }

    const HarmonyBucketFinalization = (typeof FinalizationRegistry === 'undefined')
        ? { register: () => {}, unregister: () => {} }
        : new FinalizationRegistry(ptr => wasm.__wbg_harmonybucket_free(ptr >>> 0, 1));
    const HarmonyRequestFinalization = (typeof FinalizationRegistry === 'undefined')
        ? { register: () => {}, unregister: () => {} }
        : new FinalizationRegistry(ptr => wasm.__wbg_harmonyrequest_free(ptr >>> 0, 1));

    function getArrayU8FromWasm0(ptr, len) {
        ptr = ptr >>> 0;
        return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
    }

    function getStringFromWasm0(ptr, len) {
        ptr = ptr >>> 0;
        return decodeText(ptr, len);
    }

    let cachedUint8ArrayMemory0 = null;
    function getUint8ArrayMemory0() {
        if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
            cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
        }
        return cachedUint8ArrayMemory0;
    }

    function passArray8ToWasm0(arg, malloc) {
        const ptr = malloc(arg.length * 1, 1) >>> 0;
        getUint8ArrayMemory0().set(arg, ptr / 1);
        WASM_VECTOR_LEN = arg.length;
        return ptr;
    }

    function takeFromExternrefTable0(idx) {
        const value = wasm.__wbindgen_externrefs.get(idx);
        wasm.__externref_table_dealloc(idx);
        return value;
    }

    let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
    cachedTextDecoder.decode();
    function decodeText(ptr, len) {
        return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
    }

    let WASM_VECTOR_LEN = 0;

    let wasmModule, wasm;
    function __wbg_finalize_init(instance, module) {
        wasm = instance.exports;
        wasmModule = module;
        cachedUint8ArrayMemory0 = null;
        wasm.__wbindgen_start();
        return wasm;
    }

    async function __wbg_load(module, imports) {
        if (typeof Response === 'function' && module instanceof Response) {
            if (typeof WebAssembly.instantiateStreaming === 'function') {
                try {
                    return await WebAssembly.instantiateStreaming(module, imports);
                } catch (e) {
                    const validResponse = module.ok && expectedResponseType(module.type);

                    if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                        console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                    } else { throw e; }
                }
            }

            const bytes = await module.arrayBuffer();
            return await WebAssembly.instantiate(bytes, imports);
        } else {
            const instance = await WebAssembly.instantiate(module, imports);

            if (instance instanceof WebAssembly.Instance) {
                return { instance, module };
            } else {
                return instance;
            }
        }

        function expectedResponseType(type) {
            switch (type) {
                case 'basic': case 'cors': case 'default': return true;
            }
            return false;
        }
    }

    function initSync(module) {
        if (wasm !== undefined) return wasm;


        if (module !== undefined) {
            if (Object.getPrototypeOf(module) === Object.prototype) {
                ({module} = module)
            } else {
                console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
            }
        }

        const imports = __wbg_get_imports();
        if (!(module instanceof WebAssembly.Module)) {
            module = new WebAssembly.Module(module);
        }
        const instance = new WebAssembly.Instance(module, imports);
        return __wbg_finalize_init(instance, module);
    }

    async function __wbg_init(module_or_path) {
        if (wasm !== undefined) return wasm;


        if (module_or_path !== undefined) {
            if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
                ({module_or_path} = module_or_path)
            } else {
                console.warn('using deprecated parameters for the initialization function; pass a single object instead')
            }
        }

        if (module_or_path === undefined && script_src !== undefined) {
            module_or_path = script_src.replace(/\.js$/, "_bg.wasm");
        }
        const imports = __wbg_get_imports();

        if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
            module_or_path = fetch(module_or_path);
        }

        const { instance, module } = await __wbg_load(await module_or_path, imports);

        return __wbg_finalize_init(instance, module);
    }

    return Object.assign(__wbg_init, { initSync }, exports);
})({ __proto__: null });
