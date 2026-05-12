//! Non-interactive Schnorr compiler for linear relations over P-256.
//!
//! Spec: draft-ietf-privacypass-arc-crypto-01 §5 ("Zero-Knowledge Proofs"),
//! with byte-for-byte challenge derivation delegated to the SIGMA reference
//! at `mmaker/draft-irtf-cfrg-sigma-protocols` (tracked as a submodule inside
//! `ietf-wg-privacypass/draft-arc/poc/sigma/`).
//!
//! Ciphersuite binding: **`NISchnorrProofShake128P256`**. The challenge is
//! derived by a **SHAKE128 duplex sponge** — not by a plain hash call. The
//! layout below is byte-for-byte compatible with the WG ARC PoC test vectors
//! (`draft-arc/poc/vectors/allVectors.json`), which were generated with the
//! pre-`41b316a348f9` SIGMA reference that still exposed `codec.init()`:
//!
//! ```text
//!   main_sponge = SHAKE128( initial_block = IV_MAIN(64) || 0x00 * 104 )
//!     where IV_MAIN = "sigma-proofs_Shake128_P256" right-padded with NULs
//!                     to 64 bytes.
//!
//!   main_sponge.absorb( I2OSP(len(session_bytes), 4) || session_bytes )
//!     where session_bytes = raw caller-supplied bytes, e.g.
//!                           b"ARCV1-P256CredentialRequest"
//!                           (see ciphersuite::proof_session). No helper
//!                           sponge derivation — the session string is
//!                           absorbed directly with a 4-byte big-endian
//!                           length prefix (OS2IP convention, matching
//!                           `codec.init` in pre-`41b316a348f9` SIGMA).
//!
//!   main_sponge.absorb( I2OSP(len(instance_label), 4) || instance_label )
//!     // prefix-free inner encoding, see below; length-prefixed at absorb.
//!
//!   main_sponge.absorb( commitments )
//!     // num_equations compressed SEC1 points, 33 bytes each, no lengths
//!
//!   challenge_bytes = main_sponge.squeeze( 32 + 16 = 48 )
//!   challenge       = OS2IP(challenge_bytes) mod n
//! ```
//!
//! **`instance_label` encoding** (all integers u32 little-endian):
//!
//! ```text
//!   num_equations                                              (u32)
//!   for each equation:
//!     target_element_idx                                       (u32)
//!     num_terms                                                (u32)
//!     for each term:  (scalar_idx, element_idx)                (u32, u32)
//!   concat( SerializeElement(e) for e in all_elements )  // 33 bytes each
//! ```
//!
//! `num_scalars` and `num_elements` are not explicitly encoded — they are
//! derivable from the indices referenced and from the tail byte count.
//!
//! **Response formula is additive**: `r_i = k_i + c · w_i`. Verifier rebuilds
//! each commitment as `F(response) − c · image = commitment`, equivalently
//! `commitment = Σ_j r_j · B_j − c · Y` (see `sigma_protocols.sage:120-127`).
//!
//! **Witness ordering**: scalars are passed to `prove` in their
//! `allocate_scalars` order. `responses[i]` corresponds to scalar `i`.
//!
//! ## Model
//!
//! A statement is a system of linear equations in a set of scalar and element
//! variables, of the form
//!
//! ```text
//! elements[result_i] = Σ_j scalars[s_ij] * elements[e_ij]
//! ```
//!
//! Element variables can be either *set* (public input to the proof) or
//! *computed* (the equation defines them). The prover knows witnesses for all
//! scalar variables; the verifier knows the values of all set element
//! variables and reconstructs the computed ones from the proof.
//!
//! ## API (mirrors draft-01 wording)
//!
//! ```ignore
//! let mut st = LinearRelation::new();
//! let [m1, r1] = st.allocate_scalars();           // witnesses
//! let [g, h, enc] = st.allocate_elements();       // public inputs
//! st.set_elements(&[(g, generator_g()), (h, generator_h()), (enc, m1_enc)]);
//! st.append_equation(enc, &[(m1, g), (r1, h)]);
//!
//! let proof = NISchnorrProofShake128P256::new(b"session id", &st)
//!     .prove(&[m1_value, r1_value], &mut rng)?;
//!
//! NISchnorrProofShake128P256::new(b"session id", &st).verify(&proof)?;
//! ```

use elliptic_curve::PrimeField;
use rand_core::{CryptoRng, RngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake128;
use subtle::ConstantTimeEq;

use crate::ciphersuite::SCHNORR_PROTOCOL_ID_RAW;
use crate::error::{Error, Result};
use crate::group::{serialize_element, Element, Scalar};

// ---- Variable handles -------------------------------------------------------

/// Opaque index for a scalar witness inside a [`LinearRelation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ScalarVar(pub(crate) usize);

/// Opaque index for an element (public input or computed) inside a
/// [`LinearRelation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElementVar(pub(crate) usize);

// ---- Statement --------------------------------------------------------------

/// One linear equation `elements[result] = Σ (scalars[s_i] · elements[e_i])`.
#[derive(Debug, Clone)]
pub struct Equation {
    pub result: ElementVar,
    pub terms: Vec<(ScalarVar, ElementVar)>,
}

/// A system of linear equations over a shared variable pool.
///
/// This is the draft's `statement` / `LinearRelation` object. It is built
/// identically by prover and verifier; the only difference is that the
/// verifier's copy has `set_elements` called on the *computed* elements too
/// (since they're carried in the proof's response or in the wire format).
#[derive(Debug, Clone, Default)]
pub struct LinearRelation {
    /// Number of scalar variables allocated so far.
    pub(crate) n_scalars: usize,
    /// Element values, indexed by `ElementVar.0`. `None` means "not yet set"
    /// (will be reconstructed from an equation during proof/verify).
    pub(crate) elements: Vec<Option<Element>>,
    /// Equations in insertion order — the canonical order is part of the
    /// Fiat-Shamir transcript.
    pub(crate) equations: Vec<Equation>,
}

impl LinearRelation {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate `count` fresh scalar variables. The returned handles are
    /// consecutive and ordered.
    pub fn allocate_scalars(&mut self, count: usize) -> Vec<ScalarVar> {
        let base = self.n_scalars;
        self.n_scalars += count;
        (base..base + count).map(ScalarVar).collect()
    }

    /// Allocate `count` fresh element variables, all initially unset.
    pub fn allocate_elements(&mut self, count: usize) -> Vec<ElementVar> {
        let base = self.elements.len();
        self.elements.resize(base + count, None);
        (base..base + count).map(ElementVar).collect()
    }

    /// Bind concrete group elements to previously allocated element variables.
    pub fn set_elements(&mut self, bindings: &[(ElementVar, Element)]) -> Result<()> {
        for (var, value) in bindings {
            let slot = self
                .elements
                .get_mut(var.0)
                .ok_or(Error::UnknownVariable)?;
            *slot = Some(*value);
        }
        Ok(())
    }

    /// Append a linear constraint.
    ///
    /// The equation is *not* evaluated here; for the prover, `result` may be
    /// bound before or after appending, but must be bound before `prove` is
    /// called (so the Fiat-Shamir transcript is complete).
    pub fn append_equation(
        &mut self,
        result: ElementVar,
        terms: &[(ScalarVar, ElementVar)],
    ) -> Result<()> {
        if result.0 >= self.elements.len() {
            return Err(Error::UnknownVariable);
        }
        for (s, e) in terms {
            if s.0 >= self.n_scalars || e.0 >= self.elements.len() {
                return Err(Error::UnknownVariable);
            }
        }
        self.equations.push(Equation {
            result,
            terms: terms.to_vec(),
        });
        Ok(())
    }

    /// Number of scalar variables, i.e. expected witness vector length.
    pub fn num_scalars(&self) -> usize {
        self.n_scalars
    }

    /// Number of equations (i.e. of commitment elements in a proof).
    pub fn num_equations(&self) -> usize {
        self.equations.len()
    }
}

// ---- Proof ------------------------------------------------------------------

/// A non-interactive Schnorr proof for a [`LinearRelation`].
///
/// Wire format (Section 5.1.1 wording, per-proof widths in §§5.1, 5.2, 5.3):
///
/// * `challenge` — `Ns` bytes.
/// * `responses` — `num_scalars()` scalars, each `Ns` bytes, ordered by
///   `ScalarVar` index.
#[derive(Debug, Clone)]
pub struct Proof {
    pub challenge: Scalar,
    pub responses: Vec<Scalar>,
}

// ---- NISchnorrProofShake128P256 --------------------------------------------

/// Fiat-Shamir compiler instance. The `session_id` (sometimes called the
/// *transcript label*) provides per-call-site domain separation so that a
/// proof from one ARC step cannot be replayed into another.
pub struct NISchnorrProofShake128P256<'a> {
    pub session_id: &'a [u8],
    pub statement: &'a LinearRelation,
}

impl<'a> NISchnorrProofShake128P256<'a> {
    pub fn new(session_id: &'a [u8], statement: &'a LinearRelation) -> Self {
        Self { session_id, statement }
    }

    /// Produce a non-interactive proof.
    ///
    /// Algorithm (additive — `r_i = k_i + c · w_i`, matching the WG PoC at
    /// `sigma_protocols.sage:110-115`):
    ///
    /// 1. Sample random blindings `k_i` for each scalar variable.
    /// 2. For each equation `Y = Σ w · B`, compute the commitment element
    ///    `T = Σ k · B`.
    /// 3. Derive challenge `c` via the SHAKE128 duplex sponge described at
    ///    the top of this module: seed(protocol_id), absorb(session_id),
    ///    absorb(instance_label), absorb(commitments), squeeze 48 bytes,
    ///    reduce mod `n`.
    /// 4. Compute responses `r_i = k_i + c · w_i`.
    pub fn prove<R: RngCore + CryptoRng>(
        &self,
        witness: &[Scalar],
        rng: &mut R,
    ) -> Result<Proof> {
        if witness.len() != self.statement.num_scalars() {
            return Err(Error::MalformedProof);
        }
        // 1. Sample blindings for each scalar variable.
        let k: Vec<Scalar> = (0..witness.len())
            .map(|_| {
                use elliptic_curve::Field;
                Scalar::random(&mut *rng)
            })
            .collect();

        // 2. Compute commitment elements T_j = Σ k · B for each equation.
        let commitments = self.evaluate_equations(&k)?;

        // 3. Derive challenge from the sponge.
        let challenge = self.compose_challenge(&commitments);

        // 4. Responses r_i = k_i + c · w_i.
        let responses: Vec<Scalar> =
            k.iter().zip(witness).map(|(ki, wi)| *ki + challenge * *wi).collect();

        Ok(Proof { challenge, responses })
    }

    /// Verify a proof. Returns `Err(Error::Verify)` on any failure.
    ///
    /// Algorithm (additive variant):
    ///
    /// 1. For each equation, reconstruct the commitment as
    ///    `T = Σ r_i · B_i − c · Y`.
    /// 2. Feed `(session_id, instance_label, commitments)` back through the
    ///    sponge and re-derive `c'`.
    /// 3. Constant-time compare `c' == proof.challenge`.
    pub fn verify(&self, proof: &Proof) -> Result<()> {
        if proof.responses.len() != self.statement.num_scalars() {
            return Err(Error::MalformedProof);
        }

        // Reconstruct T_j = Σ r · B − c · Y for each equation.
        let neg_c = -proof.challenge;
        let mut commitments = Vec::with_capacity(self.statement.equations.len());
        for eq in &self.statement.equations {
            let y = self
                .statement
                .elements
                .get(eq.result.0)
                .and_then(|slot| *slot)
                .ok_or(Error::UnknownVariable)?;
            let mut acc = y * neg_c;
            for (s, e) in &eq.terms {
                let base = self
                    .statement
                    .elements
                    .get(e.0)
                    .and_then(|slot| *slot)
                    .ok_or(Error::UnknownVariable)?;
                acc += base * proof.responses[s.0];
            }
            commitments.push(acc);
        }

        let c2 = self.compose_challenge(&commitments);
        if bool::from(c2.ct_eq(&proof.challenge)) {
            Ok(())
        } else {
            Err(Error::Verify)
        }
    }

    /// Evaluate each equation's RHS with a given scalar assignment, producing
    /// the commitment / image element list. Used by `prove` (with blindings
    /// `k_i`) and could be used as a sanity check elsewhere.
    fn evaluate_equations(&self, scalars: &[Scalar]) -> Result<Vec<Element>> {
        let mut out = Vec::with_capacity(self.statement.equations.len());
        for eq in &self.statement.equations {
            let mut acc = Element::default(); // identity
            for (s, e) in &eq.terms {
                let base = self
                    .statement
                    .elements
                    .get(e.0)
                    .and_then(|slot| *slot)
                    .ok_or(Error::UnknownVariable)?;
                acc += base * scalars[s.0];
            }
            out.push(acc);
        }
        Ok(out)
    }

    /// Derive the Fiat-Shamir challenge with the SHAKE128 duplex sponge
    /// described at the top of this module.
    pub(crate) fn compose_challenge(&self, commitments: &[Element]) -> Scalar {
        let instance_label = self.instance_label_bytes();
        let mut hasher = seeded_shake128(SCHNORR_PROTOCOL_ID_RAW);
        // Pre-`41b316a348f9` SIGMA `codec.init` layout: the session bytes and
        // instance label are each prefixed with their big-endian u32 length and
        // concatenated into a single buffer. (Absorbed with one `update` call;
        // the duplex sponge treats that as equivalent to two sequential
        // absorbs because there is no pad-and-permute between them.)
        hasher.update(&(self.session_id.len() as u32).to_be_bytes());
        hasher.update(self.session_id);
        hasher.update(&(instance_label.len() as u32).to_be_bytes());
        hasher.update(&instance_label);
        for c in commitments {
            hasher.update(&serialize_element(c));
        }
        let mut out = [0u8; 48];
        hasher.finalize_xof().read(&mut out);

        if std::env::var_os("ARC_DEBUG_SPONGE").is_some() {
            let hex = |b: &[u8]| -> String {
                let mut s = String::with_capacity(b.len() * 2);
                for byte in b {
                    s.push_str(&format!("{:02x}", byte));
                }
                s
            };
            eprintln!("=== compose_challenge trace ===");
            eprintln!("session_bytes    ({:3}B) = {}", self.session_id.len(), hex(self.session_id));
            eprintln!("instance_label   ({:3}B) = {}", instance_label.len(), hex(&instance_label));
            for (i, c) in commitments.iter().enumerate() {
                eprintln!("commitment[{i}]    ( 33B) = {}", hex(&serialize_element(c)));
            }
            eprintln!("squeeze (48B)           = {}", hex(&out));
        }

        // OS2IP(out) mod n. Replicates p256's `FromOkm` reduction:
        // split 48 bytes into top-24 || bottom-24, interpret each as a
        // big-endian integer < 2^192, and compute `d0 * 2^192 + d1` in the
        // scalar field.
        reduce_48_be_to_scalar(&out)
    }

    /// `instance_label` encoding (all integers u32 little-endian):
    ///
    /// ```text
    ///   num_equations                                              (u32)
    ///   for each equation:
    ///     target_element_idx                                       (u32)
    ///     num_terms                                                (u32)
    ///     for each term:  (scalar_idx, element_idx)                (u32, u32)
    ///   concat( SerializeElement(e) for e in all_elements )   // 33 bytes each
    /// ```
    ///
    /// All element variables referenced by any equation must be bound (see
    /// [`LinearRelation::set_elements`]) before this is called. The serialized
    /// elements are emitted in `ElementVar` allocation order.
    fn instance_label_bytes(&self) -> Vec<u8> {
        let st = self.statement;
        let mut out = Vec::new();
        out.extend_from_slice(&(st.equations.len() as u32).to_le_bytes());
        for eq in &st.equations {
            out.extend_from_slice(&(eq.result.0 as u32).to_le_bytes());
            out.extend_from_slice(&(eq.terms.len() as u32).to_le_bytes());
            for (s, e) in &eq.terms {
                out.extend_from_slice(&(s.0 as u32).to_le_bytes());
                out.extend_from_slice(&(e.0 as u32).to_le_bytes());
            }
        }
        for slot in &st.elements {
            let e = slot.expect("all element variables must be bound before compose_challenge");
            out.extend_from_slice(&serialize_element(&e));
        }
        out
    }
}

// ---- SHAKE128 duplex sponge primitives --------------------------------------

/// SHAKE128 rate (bytes). One absorb block.
const SHAKE128_RATE: usize = 168;

/// Build a fresh SHAKE128 hasher pre-seeded with the 168-byte IV block
/// described at the top of this file: `iv_raw` NUL-right-padded to 64 bytes,
/// followed by 104 additional NUL bytes.
fn seeded_shake128(iv_raw: &[u8]) -> Shake128 {
    assert!(iv_raw.len() <= 64, "sigma IV strings must be ≤ 64 bytes");
    let mut iv_padded = [0u8; 64];
    iv_padded[..iv_raw.len()].copy_from_slice(iv_raw);
    let zeros = [0u8; SHAKE128_RATE - 64];
    let mut hasher = Shake128::default();
    hasher.update(&iv_padded);
    hasher.update(&zeros);
    hasher
}

/// Reduce a 48-byte big-endian integer modulo the P-256 group order `n`.
///
/// Mirrors the RFC 9380 `hash_to_field` / `FromOkm` reduction for L=48:
/// split into top-24 (`d0`) and bottom-24 (`d1`), left-pad each with 8 NUL
/// bytes to form 32-byte scalar encodings (both strictly less than `n`),
/// and compute `d0 * 2^192 + d1` in the scalar field. This is equivalent to
/// `OS2IP(bytes) mod n`.
fn reduce_48_be_to_scalar(bytes: &[u8; 48]) -> Scalar {
    // 2^192 as a scalar (top 8 bytes hold a single 0x01; lower 24 are 0x00).
    // This is strictly less than `n`, so `from_repr` is guaranteed to succeed.
    let two_to_192 = {
        let mut repr = [0u8; 32];
        repr[7] = 0x01; // big-endian: byte 7 holds 2^(31*8 - 7*8) = 2^192
        scalar_from_be_32(&repr)
    };

    let mut d0_be = [0u8; 32];
    d0_be[8..].copy_from_slice(&bytes[..24]);
    let d0 = scalar_from_be_32(&d0_be);

    let mut d1_be = [0u8; 32];
    d1_be[8..].copy_from_slice(&bytes[24..]);
    let d1 = scalar_from_be_32(&d1_be);

    d0 * two_to_192 + d1
}

/// Parse a 32-byte big-endian integer as a `Scalar`. Caller must guarantee
/// the integer is strictly less than the group order (our uses here pass
/// values bounded by 2^192).
fn scalar_from_be_32(bytes: &[u8; 32]) -> Scalar {
    let repr: elliptic_curve::FieldBytes<p256::NistP256> = (*bytes).into();
    Scalar::from_repr(repr).expect("bytes < n by construction")
}
