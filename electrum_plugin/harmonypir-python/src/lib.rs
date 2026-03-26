//! PyO3 bindings for HarmonyPIR — standalone reimplementation.
//!
//! Uses harmonypir core crate (PRP, RelocationDS) directly,
//! reimplementing the bucket logic from harmonypir-wasm/src/lib.rs.

use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError};

use harmonypir::params::Params;
use harmonypir::prp::hoang::HoangPrp;
use harmonypir::relocation::{RelocationDS, EMPTY};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use rand::Rng;

const BETA: usize = 4;

// ── Parameter helpers (matching harmonypir-wasm exactly) ─────────────────

fn compute_rounds(n: u32) -> usize {
    let domain = 2 * n as usize;
    let log_domain = (domain as f64).log2().ceil() as usize;
    let r_raw = log_domain + 40;
    ((r_raw + BETA - 1) / BETA) * BETA
}

fn find_best_t(n: u32) -> u32 {
    let two_n = 2 * n as u64;
    (two_n as f64).sqrt().round().max(1.0) as u32
}

fn pad_n_for_t(n: u32, t: u32) -> (u32, u32) {
    let two_n = 2 * n as u64;
    let t64 = t as u64;
    let unit = if t64 % 2 == 0 { t64 } else { t64 * 2 };
    let padded_2n = ((two_n + unit - 1) / unit) * unit;
    let padded_n = (padded_2n / 2) as u32;
    (padded_n, t)
}

/// XORs bucket_id into bytes 12-15 of key (matching harmonypir-wasm).
fn derive_bucket_key(master_key: &[u8], bucket_id: u32) -> [u8; 16] {
    let mut key = [0u8; 16];
    let len = master_key.len().min(16);
    key[..len].copy_from_slice(&master_key[..len]);
    let id_bytes = bucket_id.to_le_bytes();
    for i in 0..4 {
        key[12 + i] ^= id_bytes[i];
    }
    key
}

fn make_rng_seed(key: &[u8; 16], bucket_id: u32, nonce: u32) -> [u8; 32] {
    let mut seed = [0u8; 32];
    seed[..16].copy_from_slice(key);
    seed[16..20].copy_from_slice(&bucket_id.to_le_bytes());
    seed[20..24].copy_from_slice(&nonce.to_le_bytes());
    seed
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

// ── PyO3 wrapper ─────────────────────────────────────────────────────────

#[pyclass(unsendable)]
struct PyHarmonyBucket {
    params: Params,
    ds: RelocationDS,
    hints: Vec<Vec<u8>>,
    query_count: usize,
    rng: ChaCha20Rng,
    real_n: u32,
    relocated_segments: Vec<u32>,
    last_segment: usize,
    last_position: usize,
    last_position_map: Vec<usize>,
    deferred_entries: Option<Vec<Vec<u8>>>,
    deferred_answer: Option<Vec<u8>>,
}

#[pymethods]
impl PyHarmonyBucket {
    #[new]
    fn new(n: u32, w: u32, t: u32, prp_key: &[u8], bucket_id: u32) -> PyResult<Self> {
        let w_usize = w as usize;
        let t_val = if t == 0 { find_best_t(n) } else { t };
        let (padded_n, t_val) = pad_n_for_t(n, t_val);
        let padded_n_usize = padded_n as usize;
        let t_usize = t_val as usize;

        let params = Params::new(padded_n_usize, w_usize, t_usize)
            .map_err(|e| PyRuntimeError::new_err(format!("invalid params: {e:?}")))?;

        let key = derive_bucket_key(prp_key, bucket_id);
        let domain = 2 * padded_n_usize;
        let r = compute_rounds(padded_n);
        let prp = Box::new(HoangPrp::new(domain, r, &key));
        let ds = RelocationDS::new(padded_n_usize, t_usize, prp)
            .map_err(|e| PyRuntimeError::new_err(format!("DS init failed: {e:?}")))?;

        let m = params.m;
        let hints: Vec<Vec<u8>> = (0..m).map(|_| vec![0u8; w_usize]).collect();
        let seed = make_rng_seed(&key, bucket_id, 0);

        Ok(PyHarmonyBucket {
            params,
            ds,
            hints,
            query_count: 0,
            rng: ChaCha20Rng::from_seed(seed),
            real_n: n,
            relocated_segments: Vec::new(),
            last_segment: 0,
            last_position: 0,
            last_position_map: Vec::new(),
            deferred_entries: None,
            deferred_answer: None,
        })
    }

    fn load_hints(&mut self, hints_data: &[u8]) -> PyResult<()> {
        let m = self.params.m;
        let w = self.params.w;
        let expected = m * w;
        if hints_data.len() != expected {
            return Err(PyValueError::new_err(format!(
                "expected {} bytes ({} × {}), got {}", expected, m, w, hints_data.len()
            )));
        }
        for (i, hint) in self.hints.iter_mut().enumerate() {
            hint.copy_from_slice(&hints_data[i * w..(i + 1) * w]);
        }
        Ok(())
    }

    /// Build a query request for database row `q`.
    /// Returns (request_bytes, segment, position, query_index).
    ///
    /// Matches harmonypir-wasm build_request: uses batch_access for PRP
    /// pipelining, filters EMPTY cells, sorts by DB index.
    fn build_request(&mut self, q: u32) -> PyResult<(Vec<u8>, u32, u32, u32)> {
        let t = self.params.t;

        let cell = self.ds.locate(q as usize)
            .map_err(|e| PyRuntimeError::new_err(format!("locate failed: {e:?}")))?;
        let s = cell / t;
        let r = cell % t;

        self.last_segment = s;
        self.last_position = r;

        // Batch-access all cells in segment except position r.
        let mut cells: Vec<usize> = Vec::with_capacity(t);
        let mut cell_positions: Vec<usize> = Vec::with_capacity(t);
        for i in 0..t {
            if i != r {
                cells.push(s * t + i);
                cell_positions.push(i);
            }
        }
        let values = self.ds.batch_access(&cells)
            .map_err(|e| PyRuntimeError::new_err(format!("batch_access failed: {e:?}")))?;

        // Filter non-empty entries, pair with position.
        let mut filtered: Vec<(u32, usize)> = Vec::new();
        for (k, &val) in values.iter().enumerate() {
            if val != EMPTY {
                filtered.push((val as u32, cell_positions[k]));
            }
        }

        // Sort by DB index for cache-friendly server lookups.
        filtered.sort_unstable_by_key(|&(idx, _)| idx);

        self.last_position_map = filtered.iter().map(|&(_, pos)| pos).collect();

        let mut bytes = Vec::with_capacity(filtered.len() * 4);
        for &(idx, _) in &filtered {
            bytes.extend_from_slice(&idx.to_le_bytes());
        }

        Ok((bytes, s as u32, r as u32, self.query_count as u32))
    }

    /// Build a synthetic dummy request (matching harmonypir-wasm exactly).
    /// Uses Binomial(T, 0.5) count sampling + uniform random indices.
    fn build_synthetic_dummy(&mut self) -> Vec<u8> {
        let t = self.params.t;
        let n = self.real_n;

        // count ~ Binomial(T, 0.5)
        let mut count = 0u32;
        for _ in 0..t {
            if self.rng.gen::<u32>() & 1 == 0 {
                count += 1;
            }
        }

        // Sample `count` unique values from [0, real_n), sort.
        let mut seen = std::collections::HashSet::with_capacity(count as usize);
        let mut indices: Vec<u32> = Vec::with_capacity(count as usize);
        while indices.len() < count as usize {
            let v = self.rng.gen::<u32>() % n;
            if seen.insert(v) {
                indices.push(v);
            }
        }
        indices.sort_unstable();

        let mut bytes = Vec::with_capacity(indices.len() * 4);
        for &idx in &indices {
            bytes.extend_from_slice(&idx.to_le_bytes());
        }
        bytes
    }

    fn process_response(&mut self, response: &[u8]) -> PyResult<Vec<u8>> {
        let w = self.params.w;
        let count = self.last_position_map.len();
        let expected = count * w;
        if response.len() != expected {
            return Err(PyValueError::new_err(format!(
                "expected {} bytes ({} entries × {}B), got {}",
                expected, count, w, response.len()
            )));
        }

        let s = self.last_segment;
        let r = self.last_position;
        let t = self.params.t;
        let n = self.params.n;

        let entries: Vec<&[u8]> = (0..count)
            .map(|i| &response[i * w..(i + 1) * w])
            .collect();

        // answer = H[s] ⊕ all entries
        let mut answer = self.hints[s].clone();
        for entry in &entries {
            xor_into(&mut answer, entry);
        }

        // Relocate and update hints.
        let m = self.ds.relocated_segment_count();
        self.ds.relocate_segment(s)
            .map_err(|e| PyRuntimeError::new_err(format!("relocate failed: {e:?}")))?;
        self.relocated_segments.push(s as u32);

        let mut pos_to_entry: Vec<Option<usize>> = vec![None; t];
        for (entry_idx, &pos) in self.last_position_map.iter().enumerate() {
            pos_to_entry[pos] = Some(entry_idx);
        }

        for i in 0..t {
            let empty_value = n + m * t + i;
            let dest_cell = self.ds.locate_extended(empty_value)
                .map_err(|e| PyRuntimeError::new_err(format!("locate_extended failed: {e:?}")))?;
            let d_i = dest_cell / t;
            if i == r {
                xor_into(&mut self.hints[d_i], &answer);
            } else if let Some(entry_idx) = pos_to_entry[i] {
                xor_into(&mut self.hints[d_i], entries[entry_idx]);
            }
        }

        self.query_count += 1;
        Ok(answer)
    }

    fn process_response_xor_only(&mut self, response: &[u8]) -> PyResult<Vec<u8>> {
        let w = self.params.w;
        let count = self.last_position_map.len();
        let expected = count * w;
        if response.len() != expected {
            return Err(PyValueError::new_err(format!(
                "expected {} bytes, got {}", expected, response.len()
            )));
        }

        let entries: Vec<Vec<u8>> = (0..count)
            .map(|i| response[i * w..(i + 1) * w].to_vec())
            .collect();

        let mut answer = self.hints[self.last_segment].clone();
        for entry in &entries {
            xor_into(&mut answer, entry);
        }

        self.deferred_entries = Some(entries);
        self.deferred_answer = Some(answer.clone());
        Ok(answer)
    }

    fn finish_relocation(&mut self) -> PyResult<()> {
        let entries = self.deferred_entries.take()
            .ok_or_else(|| PyRuntimeError::new_err("no deferred state"))?;
        let answer = self.deferred_answer.take()
            .ok_or_else(|| PyRuntimeError::new_err("no deferred answer"))?;

        let s = self.last_segment;
        let r = self.last_position;
        let t = self.params.t;
        let n = self.params.n;
        let m = self.ds.relocated_segment_count();

        self.ds.relocate_segment(s)
            .map_err(|e| PyRuntimeError::new_err(format!("relocate failed: {e:?}")))?;
        self.relocated_segments.push(s as u32);

        let mut pos_to_entry: Vec<Option<usize>> = vec![None; t];
        for (entry_idx, &pos) in self.last_position_map.iter().enumerate() {
            pos_to_entry[pos] = Some(entry_idx);
        }

        for i in 0..t {
            let empty_value = n + m * t + i;
            let dest_cell = self.ds.locate_extended(empty_value)
                .map_err(|e| PyRuntimeError::new_err(format!("locate_extended failed: {e:?}")))?;
            let d_i = dest_cell / t;
            if i == r {
                xor_into(&mut self.hints[d_i], &answer);
            } else if let Some(entry_idx) = pos_to_entry[i] {
                xor_into(&mut self.hints[d_i], &entries[entry_idx]);
            }
        }

        self.query_count += 1;
        Ok(())
    }

    fn queries_remaining(&self) -> u32 { (self.params.max_queries - self.query_count) as u32 }
    fn queries_used(&self) -> u32 { self.query_count as u32 }
    fn n(&self) -> u32 { self.params.n as u32 }
    fn real_n(&self) -> u32 { self.real_n }
    fn w(&self) -> u32 { self.params.w as u32 }
    fn t(&self) -> u32 { self.params.t as u32 }
    fn m(&self) -> u32 { self.params.m as u32 }
    fn max_queries(&self) -> u32 { self.params.max_queries as u32 }

    fn serialize(&self) -> Vec<u8> {
        let m = self.params.m;
        let w = self.params.w;
        let mut buf = Vec::with_capacity(m * w + 64);
        buf.extend_from_slice(&(self.params.n as u32).to_le_bytes());
        buf.extend_from_slice(&(self.params.w as u32).to_le_bytes());
        buf.extend_from_slice(&(self.params.t as u32).to_le_bytes());
        buf.extend_from_slice(&(self.query_count as u32).to_le_bytes());
        buf.push(0u8);
        buf.extend_from_slice(&self.real_n.to_le_bytes());
        buf.extend_from_slice(&(self.relocated_segments.len() as u32).to_le_bytes());
        for &seg in &self.relocated_segments {
            buf.extend_from_slice(&seg.to_le_bytes());
        }
        buf.extend_from_slice(&0u32.to_le_bytes());
        for hint in &self.hints {
            buf.extend_from_slice(hint);
        }
        buf
    }
}

// ── Module-level functions ───────────────────────────────────────────────

#[pyfunction]
fn compute_balanced_t(n: u32) -> u32 { find_best_t(n) }

#[pyfunction]
fn verify_protocol(n: u32, _w: u32) -> bool {
    let t = find_best_t(n);
    let (padded_n, t) = pad_n_for_t(n, t);
    let domain = 2 * padded_n as usize;
    let m = domain / t as usize;
    m > 0 && domain % (t as usize) == 0
}

#[pyfunction]
fn py_derive_bucket_key(master_key: &[u8], bucket_id: u32) -> Vec<u8> {
    derive_bucket_key(master_key, bucket_id).to_vec()
}

#[pymodule]
fn harmonypir_python(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyHarmonyBucket>()?;
    m.add_function(wrap_pyfunction!(compute_balanced_t, m)?)?;
    m.add_function(wrap_pyfunction!(verify_protocol, m)?)?;
    m.add_function(wrap_pyfunction!(py_derive_bucket_key, m)?)?;
    Ok(())
}
