//! IETF test-vector harness for `ARCV1-P256`.
//!
//! Sourced from `draft-ietf-privacypass-arc-crypto-01` §10.2 and the WG PoC
//! (`ietf-wg-privacypass/draft-arc/poc/vectors/allVectors.json`). A local
//! copy is staged at `test-vectors-draft-01.json` in the crate root.
//!
//! **Do not mix with Apple swift-crypto's vectors** — Apple tracks an older
//! draft and uses a different seed, so every scalar and point differs.
//!
//! All tests are currently `#[ignore]`d because the crate is scaffolding: the
//! core operations are `todo!()` and would panic if invoked. Remove
//! `#[ignore]` once the corresponding module is implemented.

#![allow(dead_code)]

// Constants below are hex strings taken verbatim from the WG JSON. Using
// string constants (rather than a JSON parse at test time) keeps the harness
// dependency-free and makes test failures point at the exact value that
// mismatched.

// ---- Test-vector context ---------------------------------------------------

pub const REQUEST_CONTEXT: &str = "74657374207265717565737420636f6e74657874";
// "test request context"
pub const PRESENTATION_CONTEXT: &str = "746573742070726573656e746174696f6e20636f6e74657874";
// "test presentation context"
pub const PRESENTATION_LIMIT: u64 = 2;

// ---- Server key -------------------------------------------------------------

pub const X0: &str = "1008f2c706ae2157c75e41b2d75695c7bf480d0632a1ef447036cafe4cabb021";
pub const X1: &str = "526e009578f6f25fdec992343f09f5e6c58489c31fcf8a934bbaf85797121bdd";
pub const X2: &str = "549075ccd3d1c36b3546725c43e71943414409a23b980b2c47a3fc2b9c37679b";
pub const XB: &str = "7276533ce3c89f04a007c2e8aa7d2e3b36829d0eaab5631347d8336c2da09a8e";
pub const CAP_X0: &str = "03bad54cc48293ef3472ac1ada55c9c9fdb3eb99ee47369bbe1d3ce46b300cd7b3";
pub const CAP_X1: &str = "02a0323862a05707d76862bfa8477eed468441ceae14c8fb1659e0b3020b8a24e1";
pub const CAP_X2: &str = "031d16ef08ede5a347e94a8eca071bec7bedb9d8ba943d24bde912a4e1578e529b";

// ---- CreateCredentialRequest -----------------------------------------------

pub const REQ_M1: &str = "141c4ca5e614af8e5e323eb47a7e7673ebb67caf49dfa8e109f45f231227f7a0";
pub const REQ_M2: &str = "911fb315257d9ae29d47ecb48c6fa27074dee6860a0489f8db6ac9a486be6a3e";
pub const REQ_R1: &str = "5c183d2dea942eb2780afb90cfd94983ae6575d60e350021c8c93008ac503973";
pub const REQ_R2: &str = "044d4a5b5daf00dd1fb4444ca2f8c3facc95d537d5ad0e0a2815c912e98a431d";
pub const REQ_M1_ENC: &str = "033fe5d950712f711e5d292d68f804fad4c35fb7f3f1866516448647d4aab12590";
pub const REQ_M2_ENC: &str = "026502a833ed1d972ee27175e750b1719adee12726c653125887c0d32b1f3747ab";
pub const REQ_PROOF: &str = concat!(
    "2a088673e302502a3dc80d6100a1bb709083ac7b31da34f9a7c52e7cfeaa2ea3",
    "0b7341133086e64b79dfc6cdac9f348ddbed0b087746f0167ea238d3ddf17e61",
    "3880b73e85f499c7eddc6555355ea71487b49862400091b5b32cb219d7104f57",
    "1306bc6f2487bab299bb2e9a1078dee94d83b6536ed570f8114ee9c97b8b602b",
    "facbeb3764f6a22915a19c24895a6bf7048c663337f7690f0182a1f866586d9e",
);

// ---- CreateCredentialResponse ----------------------------------------------

pub const RSP_B: &str = "9ac9d836ef405f4c6c1de4de18d210c929a8dc786c95e3eac3a828cc19e1636e";
pub const RSP_U: &str = "021cf52318c97c33472cc8fb42a5b5a774f83c3b36e6c782209d53e5945d99a493";
pub const RSP_ENC_U_PRIME: &str = "02ae23020d5427c7f785a72d77c24997f955e66ab7c378c334b7c259dabdf572d7";
pub const RSP_X0_AUX: &str = "031523abe64e436e65e592abdae322dc556fcbea707757e18d4160ba57d574cd87";
pub const RSP_X1_AUX: &str = "023cc3b53807f6e0082b675794ae9f6b370483ca5a3e6d688c3b81f2fdb6d4ec00";
pub const RSP_X2_AUX: &str = "0329dc7c93f8a231a1f16ec69f0fba446e022ce69945b20f37386a7fda3e573b79";
pub const RSP_H_AUX: &str = "0389746891b6dbf062511619eae7d72ae87630bea1e277a925708fdfef8363a1d4";
pub const RSP_PROOF: &str = concat!(
    "ec342aee0d481435379ea6bbe919edd5d2eb9c12198a083e0e899da1f14dbc46",
    "a8048f5a12c5cae21e5f5949fe08d1c15c266c63544615400def4ce9a6cf8aee",
    "32052ced26e7a9d854f2c45ea23ffea0f6bf977f6155d412991abc0e2d1ad835",
    "04129c1ac8319b2a45940c52c4b41bde80969313641b9cb727445e20b44d0ea8",
    "84e9b180cd152442883038b97d72772201f281d76a18d22e374bd989accd7654",
    "8067399162428c4d25daf1b7f68f3580a38cc4564a88f28494649064500f06c5",
    "b946dde032a389f8fe337605627ce91a92c20db911100a2c7c42ae15fde5a5cb",
    "d9d078b819a80423593192c40d70ce77f1a6d377770fe5c05781782bd1eaa43f",
);

// ---- FinalizeCredential -----------------------------------------------------

pub const CRED_U_PRIME: &str = "02646199272c28911165b4d1c5f4ffbd8a83f686948fd4c7250e28c81dbfecd354";
// (Credential.U, .X1, .m1 reuse the constants above.)

// ---- Presentation 1 (nonce = 0) --------------------------------------------

pub const P1_A: &str = "a3c469d2d55062b463b17f45acd2fb17c038b18df4c8d6c9c745866ba961de9a";
pub const P1_R: &str = "54925f70e9ec2128114c6ae8bfc6e1a2914a8fdd383e5ff03d8c2992edd081a9";
pub const P1_Z: &str = "9ed3c3ddb1b5ff64e55b1d0a4f58eee67351fea7de16baf644e80f4d0949cf5f";
pub const P1_NONCE_BLINDING: &str =
    "ed8b643e3c8ba74cc417b5bbfc4f42bee6dcd2d6c5ea48fb2273afec7b6505a4";
pub const P1_NONCE: u64 = 0;
pub const P1_U: &str = "0216af8901c1ad38a703bf9003fabea440b411b4f072fd23b5254cb17d1b5bf33d";
pub const P1_U_PRIME_COMMIT: &str =
    "03140f8e6f6c5eab3d03a7fba5d542362a9bc00a89d80caa5051b4e4446b0b01f3";
pub const P1_M1_COMMIT: &str = "0214d0297c21120d621cc6fed75852569de3cbf0bd9f5a8a812cf6b024bf51e627";
pub const P1_TAG: &str = "0281428e61688f4e7989dbe8dab170705c81b294c4a73b785a0754712fc968eb40";
pub const P1_NONCE_COMMIT: &str =
    "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8";
pub const P1_D_0: &str = "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8";
// For presentationLimit = 2, k = ceil(log2(2)) = 1, and bases = [1], so
// D_0 == nonce_commit. For k > 1 they differ.
pub const P1_PROOF: &str = concat!(
    "032326abcd4eb2fd1a47053ec9ce1aab3ee91e98373d610e9752a7d16a5c1e38d8", // D_0
    "946f5f0b44e34f826b41ec59a4e2dcfaa826b8a39cc278e10b1b02b5dbaafdb6",   // challenge
    "e789639885a8d2d69269a9fea55830f1d7e1fd0a771183b7b4eebe5e03e0c025",   // r_0
    "5d1ba614de7e31d4f46eb93a24e0ffe9864b002527109a516a10dc1ad718b8d9",   // r_1
    "84efd16ab245d7a5dfabe2d0027e23796981422b19c2821a831cb46a8e9b8b56",   // r_2
    "6bbdb55b649021bf2f777b9130c2e375f560eee4691d04bd38e9571d94512578",   // r_3
    "58d9128002a2f8908d7e4521510a2185244fa533e2502b61e502fd157d974f91",   // r_4
    "acc4f2ba0d724f2bfd182d5df4d038e74b5c35cc7c4aa7622c2682e040877eeb",   // r_5
    "cc18fe822cc6abab5d3adc9db836991d3d1ecf699658245b8b0756946ba0d775",   // r_6
    "6b433aae3b476ccbc2186b2fe2ecc2fe0da30df264802829254df8196a8307f0",   // r_7
);

// ---- Presentation 2 (nonce = 1) --------------------------------------------

pub const P2_A: &str = "ae14ddaf96907f2fee72069664e1883fee4582cefcfbb2f3fae380c317018ab2";
pub const P2_R: &str = "f994bf66d0c7943ce97331da186e231281b691eb271c7c524ff9f8bc7804b41d";
pub const P2_Z: &str = "fa27efc5066bca91121642d629477eb1c7812fa9c473b30dea3eaba8a1731568";
pub const P2_NONCE_BLINDING: &str =
    "90b8387fe4145c2d47a0f042c26119939bcbcc8c2c32f81d1034db3958b9af39";
pub const P2_NONCE: u64 = 1;
pub const P2_U: &str = "0357e53851143e7cc34311bdba0d44d4d3c9192180434ce247b8766232b5de1e08";
pub const P2_U_PRIME_COMMIT: &str =
    "02bad8dc9b0179dff7a1d63d03d92810520085cbc41b65b667d3cbe2203eb7c544";
pub const P2_M1_COMMIT: &str = "02455589d2b92a24e49ff8c2e8287f6eeb05cbfddc16aba66dfe9ab97702bc3c35";
pub const P2_TAG: &str = "02ad6c293325d0c2c388c8b2240b6d8ab9e52395297ef5921fb78ace6a1274b03b";
pub const P2_NONCE_COMMIT: &str =
    "0363d6bd2969b64a42354ba896be33a4abce479261d7dec0001fa1af7fbdeecb41";
pub const P2_D_0: &str = "0363d6bd2969b64a42354ba896be33a4abce479261d7dec0001fa1af7fbdeecb41";
pub const P2_PROOF: &str = concat!(
    "0363d6bd2969b64a42354ba896be33a4abce479261d7dec0001fa1af7fbdeecb41",
    "7c59300e0aafb0d58e3f85423030401dabe5dd39566924f07e99cae5b3be62f4",
    "5e736890857cfe0950c22c93c52d56e6ade5f5a1c1d486e9261e7788b7454387",
    "0115370c46e62e376b17844a287bbb6722dc5e5848fdbd8d19d259ec1cec8385",
    "1a1ef4a21dadefeef3f5222eb19361facbb2ec3ba640aef22cd5700a17ea17fc",
    "3ece772f5b5cca1e119bf32cfa7f3459c2184d6d8c777d281c91b416187ee949",
    "c9557fece8afb0ac785c7b8c4854e622f8b005daf5c0682cfdc2d900150087ba",
    "e0090d44b7bac130c7f4067bb8b3374b159106d0c03e30f9577063de0b52d15d",
    "1f5f41328b335ee23d10ca7dc4e0717bd9e919e3f6f580e594b3c48b358baa7a",
    "320ec9e1019260efe2cbf6e9cba6871ffee3b5566d5e865c729c5e1d48529559",
);

// ---- Tiny helpers for the tests --------------------------------------------

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).expect("test-vector constant should be valid hex")
}

// ===========================================================================
// Structural tests — these run today because they only check byte lengths and
// the invariants of the test-vector set itself.
// ===========================================================================

#[test]
fn byte_lengths_match_wire_format() {
    // Scalars: Ns = 32.
    for s in [X0, X1, X2, XB, REQ_M1, REQ_M2, REQ_R1, REQ_R2, RSP_B] {
        assert_eq!(hx(s).len(), 32, "scalar should be 32 bytes: {s}");
    }
    // Elements: Ne = 33.
    for e in [
        CAP_X0, CAP_X1, CAP_X2, REQ_M1_ENC, REQ_M2_ENC, RSP_U, RSP_ENC_U_PRIME, RSP_X0_AUX,
        RSP_X1_AUX, RSP_X2_AUX, RSP_H_AUX, CRED_U_PRIME, P1_U, P1_U_PRIME_COMMIT, P1_M1_COMMIT,
        P1_TAG, P1_NONCE_COMMIT, P1_D_0,
    ] {
        assert_eq!(hx(e).len(), 33, "element should be 33 bytes: {e}");
    }
    // Request proof: 5 * Ns = 160.
    assert_eq!(hx(REQ_PROOF).len(), 160);
    // Response proof: 8 * Ns = 256.
    assert_eq!(hx(RSP_PROOF).len(), 256);
    // Presentation proof (k = 1): Ne + Ns + (5 + 3k) * Ns = 33 + 32 + 8 * 32 = 321.
    assert_eq!(hx(P1_PROOF).len(), 321);
    assert_eq!(hx(P2_PROOF).len(), 321);
}

#[test]
fn d0_equals_nonce_commit_when_k_is_one() {
    // Sanity: bases[0] = 1 when presentation_limit = 2, so D[0] = nonce_commit.
    assert_eq!(P1_D_0, P1_NONCE_COMMIT);
    assert_eq!(P2_D_0, P2_NONCE_COMMIT);
}

// ===========================================================================
// Schnorr compiler tests — exercise the SHAKE128 duplex sponge and the
// additive-Schnorr verifier directly against the WG JSON CredentialRequest
// test vector. This is the tightest possible byte-for-byte check since
// `verify` re-derives the challenge from scratch and constant-time compares
// it against `proof.challenge`.
// ===========================================================================

/// Rebuild the `LinearRelation` that `make_credential_request_proof` will
/// construct, from the already-deserialized public inputs. The Schnorr
/// compiler's transcript is sensitive to both allocation order and equation
/// order, so this must mirror `request.rs` exactly.
fn build_credential_request_statement(
    m1_enc: arc::Element,
    m2_enc: arc::Element,
) -> arc::schnorr::LinearRelation {
    let mut st = arc::schnorr::LinearRelation::new();
    let sv = st.allocate_scalars(4); // [m1, m2, r1, r2]
    let ev = st.allocate_elements(4); // [g, h, m1_enc, m2_enc]
    st.set_elements(&[
        (ev[0], arc::group::generator_g()),
        (ev[1], arc::group::generator_h()),
        (ev[2], m1_enc),
        (ev[3], m2_enc),
    ])
    .unwrap();
    // m1Enc = m1·G + r1·H
    st.append_equation(ev[2], &[(sv[0], ev[0]), (sv[2], ev[1])]).unwrap();
    // m2Enc = m2·G + r2·H
    st.append_equation(ev[3], &[(sv[1], ev[0]), (sv[3], ev[1])]).unwrap();
    st
}

/// Parse `challenge || r_0 || r_1 || ...` from a flat byte string. Does not
/// reject zero scalars — a wire proof is allowed to contain them in theory,
/// and the verification result will reject malformed inputs.
fn parse_proof_bytes(bytes: &[u8], num_responses: usize) -> arc::schnorr::Proof {
    use elliptic_curve::PrimeField;
    let scalar = |slice: &[u8]| -> arc::Scalar {
        let arr: [u8; 32] = slice.try_into().expect("32-byte chunk");
        let repr: elliptic_curve::FieldBytes<p256::NistP256> = arr.into();
        arc::Scalar::from_repr(repr).expect("scalar < n")
    };
    assert_eq!(bytes.len(), 32 * (1 + num_responses));
    let challenge = scalar(&bytes[..32]);
    let responses: Vec<arc::Scalar> = (0..num_responses)
        .map(|i| scalar(&bytes[32 + i * 32..32 + (i + 1) * 32]))
        .collect();
    arc::schnorr::Proof { challenge, responses }
}

#[test]
fn schnorr_verifies_credential_request_proof_vector() {
    let m1_enc = arc::group::deserialize_element(&hx(REQ_M1_ENC)).unwrap();
    let m2_enc = arc::group::deserialize_element(&hx(REQ_M2_ENC)).unwrap();
    let st = build_credential_request_statement(m1_enc, m2_enc);
    let proof = parse_proof_bytes(&hx(REQ_PROOF), 4);

    arc::schnorr::NISchnorrProofShake128P256::new(b"ARCV1-P256CredentialRequest", &st)
        .verify(&proof)
        .expect("CredentialRequest proof from WG test vector should verify");
}

#[test]
fn verify_credential_response_proof_vector() {
    // Byte-exact verification of the WG RSP_PROOF. If this passes, the
    // 11-equation statement construction, witness ordering, and sponge
    // transcript in `response.rs` all match the reference implementation.
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let pk = sk.public_key();
    let request = arc::CredentialRequest {
        m1_enc: arc::group::deserialize_element(&hx(REQ_M1_ENC)).unwrap(),
        m2_enc: arc::group::deserialize_element(&hx(REQ_M2_ENC)).unwrap(),
        request_proof: parse_proof_bytes(&hx(REQ_PROOF), 4),
    };
    let response = arc::CredentialResponse {
        u: arc::group::deserialize_element(&hx(RSP_U)).unwrap(),
        enc_u_prime: arc::group::deserialize_element(&hx(RSP_ENC_U_PRIME)).unwrap(),
        x0_aux: arc::group::deserialize_element(&hx(RSP_X0_AUX)).unwrap(),
        x1_aux: arc::group::deserialize_element(&hx(RSP_X1_AUX)).unwrap(),
        x2_aux: arc::group::deserialize_element(&hx(RSP_X2_AUX)).unwrap(),
        h_aux: arc::group::deserialize_element(&hx(RSP_H_AUX)).unwrap(),
        response_proof: parse_proof_bytes(&hx(RSP_PROOF), 7),
    };
    arc::response::verify_credential_response_proof(&pk, &response, &request)
        .expect("CredentialResponse proof from WG test vector should verify");
}

#[test]
fn debug_credential_request_proof_reconstruction() {
    // Reconstruct commitments two ways and print them, so when
    // `schnorr_verifies_credential_request_proof_vector` fails we can tell
    // whether the sponge is wrong or the sign convention is wrong.
    let m1_enc = arc::group::deserialize_element(&hx(REQ_M1_ENC)).unwrap();
    let m2_enc = arc::group::deserialize_element(&hx(REQ_M2_ENC)).unwrap();
    let g = arc::group::generator_g();
    let h = arc::group::generator_h();
    let proof = parse_proof_bytes(&hx(REQ_PROOF), 4);
    let c = proof.challenge;
    let r = &proof.responses;

    // Additive convention: r = k + c·w  ⇒  T = Σr·B − c·Y
    let t0_add = g * r[0] + h * r[2] + m1_enc * (-c);
    let t1_add = g * r[1] + h * r[3] + m2_enc * (-c);
    // Subtractive convention: r = k − c·w  ⇒  T = Σr·B + c·Y
    let t0_sub = g * r[0] + h * r[2] + m1_enc * c;
    let t1_sub = g * r[1] + h * r[3] + m2_enc * c;

    eprintln!("challenge  = {}", hex::encode(arc::group::serialize_scalar(&c)));
    eprintln!("T0 (add)   = {}", hex::encode(arc::group::serialize_element(&t0_add)));
    eprintln!("T1 (add)   = {}", hex::encode(arc::group::serialize_element(&t1_add)));
    eprintln!("T0 (sub)   = {}", hex::encode(arc::group::serialize_element(&t0_sub)));
    eprintln!("T1 (sub)   = {}", hex::encode(arc::group::serialize_element(&t1_sub)));
    eprintln!("m1_enc     = {}", hex::encode(arc::group::serialize_element(&m1_enc)));
    eprintln!("m2_enc     = {}", hex::encode(arc::group::serialize_element(&m2_enc)));
}

/// Verify my SHAKE128 implementation against one of SIGMA's own duplex-sponge
/// test vectors at pinned commit `1d243b47`. This exercises the same code path
/// `compose_challenge` uses (64-byte IV padded to 168, absorb, squeeze).
#[test]
fn dump_generator_h() {
    let g = arc::group::generator_g();
    let h = arc::group::generator_h();
    eprintln!("G = {}", hex::encode(arc::group::serialize_element(&g)));
    eprintln!("H = {}", hex::encode(arc::group::serialize_element(&h)));
}

#[test]
fn sigma_sponge_test_vector_iv_affects_output() {
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake128;
    let iv = hex::decode(
        "646f6d61696e2d6f6e652d6469666665\
         72732d68657265000000000000000000\
         00000000000000000000000000000000\
         00000000000000000000000000000000",
    )
    .unwrap();
    assert_eq!(iv.len(), 64);
    let padding = vec![0u8; 168 - 64];
    let mut h = Shake128::default();
    h.update(&iv);
    h.update(&padding);
    h.update(&hex::decode("697620646966666572656e63652074657374").unwrap());
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    assert_eq!(
        hex::encode(out),
        "7650642267cc544abf0e01ce28e2595aec4c2f5b5e5e3720ab551449637b35f2"
    );
}

#[test]
fn schnorr_round_trip_credential_request() {
    // Prove a statement whose witnesses we know, then verify the generated
    // proof with a freshly constructed verifier instance. Exercises `prove`
    // independently of the WG challenge bytes (since blindings are random).
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xA4C4_A4C4);

    let g = arc::group::generator_g();
    let h = arc::group::generator_h();
    let m1 = arc::group::deserialize_scalar(&hx(REQ_M1)).unwrap();
    let m2 = arc::group::deserialize_scalar(&hx(REQ_M2)).unwrap();
    let r1 = arc::group::deserialize_scalar(&hx(REQ_R1)).unwrap();
    let r2 = arc::group::deserialize_scalar(&hx(REQ_R2)).unwrap();
    let m1_enc = g * m1 + h * r1;
    let m2_enc = g * m2 + h * r2;

    // Cross-check our recomputation of m1_enc / m2_enc against the WG JSON
    // before we depend on them.
    assert_eq!(&arc::group::serialize_element(&m1_enc)[..], &hx(REQ_M1_ENC));
    assert_eq!(&arc::group::serialize_element(&m2_enc)[..], &hx(REQ_M2_ENC));

    let st = build_credential_request_statement(m1_enc, m2_enc);
    let fs = arc::schnorr::NISchnorrProofShake128P256::new(b"ARCV1-P256CredentialRequest", &st);
    let proof = fs.prove(&[m1, m2, r1, r2], &mut rng).expect("prove");
    fs.verify(&proof).expect("verify round-trip");
}

// ===========================================================================
// End-to-end tests — ignored until the corresponding module is implemented.
// Each test is a single milestone; un-ignore as you fill in logic.
// ===========================================================================

#[test]
fn m2_matches_hash_to_scalar_of_request_context() {
    // Spec: m2 = G.HashToScalar(requestContext, "requestContext").
    let m2 = arc::group::hash_to_scalar(&hx(REQUEST_CONTEXT), b"requestContext");
    let expected = hx(REQ_M2);
    assert_eq!(&arc::group::serialize_scalar(&m2)[..], &expected);
}

#[test]
fn server_public_key_matches_private_key() {
    // Build a ServerPrivateKey from the four test-vector scalars, derive the
    // public key, and confirm every compressed SEC1 encoding matches the WG
    // JSON byte-for-byte.
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let pk = sk.public_key();
    assert_eq!(
        &arc::group::serialize_element(&pk.x0)[..],
        &hx(CAP_X0),
        "X0 mismatch"
    );
    assert_eq!(
        &arc::group::serialize_element(&pk.x1)[..],
        &hx(CAP_X1),
        "X1 mismatch"
    );
    assert_eq!(
        &arc::group::serialize_element(&pk.x2)[..],
        &hx(CAP_X2),
        "X2 mismatch"
    );
}

#[test]
fn credential_request_round_trips_with_test_vector_blinds() {
    // We can't reproduce REQ_PROOF byte-for-byte without replicating the WG
    // PoC's `TestDRNG` (see `TODO.md → Deterministic-RNG harness`). Instead:
    //
    //  1. Recompute `m1Enc` / `m2Enc` from the test-vector scalars and confirm
    //     they match `REQ_M1_ENC` / `REQ_M2_ENC` byte-for-byte.
    //  2. Produce a fresh proof over the same statement with those scalars as
    //     witnesses; `verify_credential_request_proof` must accept it.
    //  3. Round-trip the wire format.
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xA4C4_A4C4);

    let m1 = arc::group::deserialize_scalar(&hx(REQ_M1)).unwrap();
    let m2 = arc::group::deserialize_scalar(&hx(REQ_M2)).unwrap();
    let r1 = arc::group::deserialize_scalar(&hx(REQ_R1)).unwrap();
    let r2 = arc::group::deserialize_scalar(&hx(REQ_R2)).unwrap();

    let g = arc::group::generator_g();
    let h = arc::group::generator_h();
    let m1_enc = g * m1 + h * r1;
    let m2_enc = g * m2 + h * r2;
    assert_eq!(&arc::group::serialize_element(&m1_enc)[..], &hx(REQ_M1_ENC));
    assert_eq!(&arc::group::serialize_element(&m2_enc)[..], &hx(REQ_M2_ENC));

    let proof = arc::request::make_credential_request_proof(
        &m1, &m2, &r1, &r2, &m1_enc, &m2_enc, &mut rng,
    )
    .expect("prove");
    let request = arc::CredentialRequest { m1_enc, m2_enc, request_proof: proof };
    arc::request::verify_credential_request_proof(&request).expect("verify own proof");

    let bytes = request.to_bytes();
    assert_eq!(bytes.len(), arc::CredentialRequest::SIZE);
    assert_eq!(&bytes[..33], &hx(REQ_M1_ENC)[..]);
    assert_eq!(&bytes[33..66], &hx(REQ_M2_ENC)[..]);

    let parsed = arc::CredentialRequest::from_bytes(&bytes).expect("from_bytes");
    arc::request::verify_credential_request_proof(&parsed).expect("verify parsed");
}

#[test]
fn create_credential_request_round_trip() {
    // End-to-end exercise of `create_credential_request`: fresh randomness,
    // but `m2` is deterministic from `requestContext`, so we check that
    // against the WG test vector's `REQ_M2`.
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xA4C4_A4C4);

    let req_ctx = hx(REQUEST_CONTEXT);
    let (secrets, request) =
        arc::create_credential_request(&req_ctx, &mut rng).expect("create request");

    assert_eq!(&arc::group::serialize_scalar(&secrets.m2)[..], &hx(REQ_M2));
    arc::request::verify_credential_request_proof(&request).expect("verify");

    let bytes = request.to_bytes();
    let parsed = arc::CredentialRequest::from_bytes(&bytes).expect("from_bytes");
    arc::request::verify_credential_request_proof(&parsed).expect("verify parsed");
}

#[test]
fn credential_response_round_trips() {
    // Like the request test: we can't reproduce RSP_PROOF byte-for-byte
    // without TestDRNG, but given the test-vector blinding scalar `b` we
    // *can* reproduce every wire element (U, encUPrime, X0Aux, X1Aux,
    // X2Aux, HAux) byte-for-byte, then generate a fresh proof with a
    // chacha RNG and confirm it verifies.
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xB0B0_B0B0);

    // Server keys (from WG vectors).
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let pk = sk.public_key();

    // Client request with the WG test-vector encrypted attributes.
    let m1_enc = arc::group::deserialize_element(&hx(REQ_M1_ENC)).unwrap();
    let m2_enc = arc::group::deserialize_element(&hx(REQ_M2_ENC)).unwrap();
    let req_proof = parse_proof_bytes(&hx(REQ_PROOF), 4);
    let request = arc::CredentialRequest {
        m1_enc,
        m2_enc,
        request_proof: req_proof,
    };

    // Reproduce the response elements from the WG blinding scalar `b`.
    let b = arc::group::deserialize_scalar(&hx(RSP_B)).unwrap();
    let t1 = b * sk.x1;
    let t2 = b * sk.x2;
    let g = arc::group::generator_g();
    let h = arc::group::generator_h();
    let u = g * b;
    let h_aux = h * b;
    let x0_aux = h * (b * sk.x0_blinding);
    let x1_aux = pk.x1 * b;
    let x2_aux = pk.x2 * b;
    let enc_u_prime = pk.x0 * b + m1_enc * t1 + m2_enc * t2;

    assert_eq!(&arc::group::serialize_element(&u)[..], &hx(RSP_U), "U mismatch");
    assert_eq!(&arc::group::serialize_element(&h_aux)[..], &hx(RSP_H_AUX), "HAux mismatch");
    assert_eq!(&arc::group::serialize_element(&x0_aux)[..], &hx(RSP_X0_AUX), "X0Aux mismatch");
    assert_eq!(&arc::group::serialize_element(&x1_aux)[..], &hx(RSP_X1_AUX), "X1Aux mismatch");
    assert_eq!(&arc::group::serialize_element(&x2_aux)[..], &hx(RSP_X2_AUX), "X2Aux mismatch");
    assert_eq!(
        &arc::group::serialize_element(&enc_u_prime)[..],
        &hx(RSP_ENC_U_PRIME),
        "encUPrime mismatch"
    );

    // Produce a fresh proof and verify.
    let proof = arc::response::make_credential_response_proof(
        &sk, &pk, &request, &b, &t1, &t2, &u, &enc_u_prime, &x0_aux, &x1_aux, &x2_aux, &h_aux,
        &mut rng,
    )
    .expect("prove");
    let response = arc::CredentialResponse {
        u,
        enc_u_prime,
        x0_aux,
        x1_aux,
        x2_aux,
        h_aux,
        response_proof: proof,
    };
    arc::response::verify_credential_response_proof(&pk, &response, &request)
        .expect("verify own proof");

    // Wire format round-trip.
    let bytes = response.to_bytes();
    assert_eq!(bytes.len(), arc::CredentialResponse::SIZE);
    assert_eq!(&bytes[..33], &hx(RSP_U)[..]);
    assert_eq!(&bytes[33..66], &hx(RSP_ENC_U_PRIME)[..]);
    assert_eq!(&bytes[66..99], &hx(RSP_X0_AUX)[..]);
    assert_eq!(&bytes[99..132], &hx(RSP_X1_AUX)[..]);
    assert_eq!(&bytes[132..165], &hx(RSP_X2_AUX)[..]);
    assert_eq!(&bytes[165..198], &hx(RSP_H_AUX)[..]);
    let parsed = arc::CredentialResponse::from_bytes(&bytes).expect("from_bytes");
    arc::response::verify_credential_response_proof(&pk, &parsed, &request)
        .expect("verify parsed");
}

#[test]
fn create_credential_response_round_trip() {
    // End-to-end `create_credential_response`: fresh client + fresh server
    // blinding, then verify everything round-trips. This also exercises the
    // internal `verify_credential_request_proof` guard.
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0xB0B0_B0B1);

    let (sk, pk) = arc::setup_server(&mut rng);
    let (_secrets, request) = arc::create_credential_request(&hx(REQUEST_CONTEXT), &mut rng)
        .expect("create request");
    let response = arc::create_credential_response(&sk, &pk, &request, &mut rng)
        .expect("create response");

    arc::response::verify_credential_response_proof(&pk, &response, &request).expect("verify");

    let bytes = response.to_bytes();
    let parsed = arc::CredentialResponse::from_bytes(&bytes).expect("from_bytes");
    arc::response::verify_credential_response_proof(&pk, &parsed, &request)
        .expect("verify parsed");
}

#[test]
fn finalize_credential_matches_test_vector() {
    // Byte-exact check that finalize_credential reproduces the WG CRED_U_PRIME
    // given the test-vector request, response, and client secrets. This is
    // the tightest test of the full issuance flow: if the response proof
    // doesn't verify or the `r·H` cancellation arithmetic is wrong, this
    // will fail.
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let pk = sk.public_key();

    let secrets = arc::ClientSecrets {
        m1: arc::group::deserialize_scalar(&hx(REQ_M1)).unwrap(),
        m2: arc::group::deserialize_scalar(&hx(REQ_M2)).unwrap(),
        r1: arc::group::deserialize_scalar(&hx(REQ_R1)).unwrap(),
        r2: arc::group::deserialize_scalar(&hx(REQ_R2)).unwrap(),
    };
    let request = arc::CredentialRequest {
        m1_enc: arc::group::deserialize_element(&hx(REQ_M1_ENC)).unwrap(),
        m2_enc: arc::group::deserialize_element(&hx(REQ_M2_ENC)).unwrap(),
        request_proof: parse_proof_bytes(&hx(REQ_PROOF), 4),
    };
    let response = arc::CredentialResponse {
        u: arc::group::deserialize_element(&hx(RSP_U)).unwrap(),
        enc_u_prime: arc::group::deserialize_element(&hx(RSP_ENC_U_PRIME)).unwrap(),
        x0_aux: arc::group::deserialize_element(&hx(RSP_X0_AUX)).unwrap(),
        x1_aux: arc::group::deserialize_element(&hx(RSP_X1_AUX)).unwrap(),
        x2_aux: arc::group::deserialize_element(&hx(RSP_X2_AUX)).unwrap(),
        h_aux: arc::group::deserialize_element(&hx(RSP_H_AUX)).unwrap(),
        response_proof: parse_proof_bytes(&hx(RSP_PROOF), 7),
    };

    let credential = arc::finalize_credential(&secrets, &pk, &request, &response)
        .expect("finalize should accept the WG test vector");
    assert_eq!(
        &arc::group::serialize_element(&credential.u_prime)[..],
        &hx(CRED_U_PRIME),
        "UPrime mismatch"
    );
    assert_eq!(&arc::group::serialize_element(&credential.u)[..], &hx(RSP_U));
    assert_eq!(&arc::group::serialize_element(&credential.x1)[..], &hx(CAP_X1));
    assert_eq!(&arc::group::serialize_scalar(&credential.m1)[..], &hx(REQ_M1));
}

// ---- Presentation-layer tests ---------------------------------------------

/// Parse `challenge || r_0 || r_1 || ...` from the tail of P{1,2}_PROOF. The
/// P{1,2}_PROOF hex string is `D[0] || challenge || r_0..r_7`; callers slice
/// off `D[0]` before invoking this.
fn parse_presentation_proof(bytes: &[u8]) -> arc::Presentation {
    use elliptic_curve::PrimeField;
    let scalar = |slice: &[u8]| -> arc::Scalar {
        let arr: [u8; 32] = slice.try_into().expect("32-byte chunk");
        let repr: elliptic_curve::FieldBytes<p256::NistP256> = arr.into();
        arc::Scalar::from_repr(repr).expect("scalar < n")
    };
    assert_eq!(bytes.len(), 33 + 32 + 8 * 32); // D_0 + challenge + 8 responses
    let d0 = arc::group::deserialize_element(&bytes[..33]).unwrap();
    let challenge = scalar(&bytes[33..65]);
    let responses: Vec<arc::Scalar> =
        (0..8).map(|i| scalar(&bytes[65 + i * 32..65 + (i + 1) * 32])).collect();
    arc::Presentation {
        u: arc::Element::default(),           // filled in by caller
        u_prime_commit: arc::Element::default(),
        m1_commit: arc::Element::default(),
        tag: arc::Element::default(),
        nonce_commit: arc::Element::default(),
        presentation_proof: arc::PresentationProof {
            d: vec![d0],
            schnorr: arc::schnorr::Proof { challenge, responses },
        },
    }
}

#[test]
fn verify_presentation_p1_vector() {
    // Byte-exact verification of the first WG presentation test vector.
    // Tests that the 4 base equations + 2 range equations + sum check all
    // match the reference implementation byte-for-byte.
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let pk = sk.public_key();

    let mut presentation = parse_presentation_proof(&hx(P1_PROOF));
    presentation.u = arc::group::deserialize_element(&hx(P1_U)).unwrap();
    presentation.u_prime_commit = arc::group::deserialize_element(&hx(P1_U_PRIME_COMMIT)).unwrap();
    presentation.m1_commit = arc::group::deserialize_element(&hx(P1_M1_COMMIT)).unwrap();
    presentation.tag = arc::group::deserialize_element(&hx(P1_TAG)).unwrap();
    presentation.nonce_commit = arc::group::deserialize_element(&hx(P1_NONCE_COMMIT)).unwrap();

    let tag = arc::verify_presentation(
        &sk,
        &pk,
        &hx(REQUEST_CONTEXT),
        &hx(PRESENTATION_CONTEXT),
        &presentation,
        PRESENTATION_LIMIT,
    )
    .expect("P1 presentation from WG vector should verify");
    assert_eq!(&arc::group::serialize_element(&tag)[..], &hx(P1_TAG));
}

#[test]
fn verify_presentation_p2_vector() {
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let pk = sk.public_key();

    let mut presentation = parse_presentation_proof(&hx(P2_PROOF));
    presentation.u = arc::group::deserialize_element(&hx(P2_U)).unwrap();
    presentation.u_prime_commit = arc::group::deserialize_element(&hx(P2_U_PRIME_COMMIT)).unwrap();
    presentation.m1_commit = arc::group::deserialize_element(&hx(P2_M1_COMMIT)).unwrap();
    presentation.tag = arc::group::deserialize_element(&hx(P2_TAG)).unwrap();
    presentation.nonce_commit = arc::group::deserialize_element(&hx(P2_NONCE_COMMIT)).unwrap();

    let tag = arc::verify_presentation(
        &sk,
        &pk,
        &hx(REQUEST_CONTEXT),
        &hx(PRESENTATION_CONTEXT),
        &presentation,
        PRESENTATION_LIMIT,
    )
    .expect("P2 presentation from WG vector should verify");
    assert_eq!(&arc::group::serialize_element(&tag)[..], &hx(P2_TAG));
}

#[test]
fn presentation_wire_round_trip() {
    // Build a presentation from the WG vector, round-trip through
    // to_bytes/from_bytes, and re-verify. Exercises the variable-length
    // (`k`-dependent) serialization path.
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let pk = sk.public_key();

    let mut p = parse_presentation_proof(&hx(P1_PROOF));
    p.u = arc::group::deserialize_element(&hx(P1_U)).unwrap();
    p.u_prime_commit = arc::group::deserialize_element(&hx(P1_U_PRIME_COMMIT)).unwrap();
    p.m1_commit = arc::group::deserialize_element(&hx(P1_M1_COMMIT)).unwrap();
    p.tag = arc::group::deserialize_element(&hx(P1_TAG)).unwrap();
    p.nonce_commit = arc::group::deserialize_element(&hx(P1_NONCE_COMMIT)).unwrap();

    let bytes = p.to_bytes();
    assert_eq!(bytes.len(), arc::Presentation::size(1));
    assert_eq!(&bytes[..33], &hx(P1_U)[..]);
    assert_eq!(&bytes[33..66], &hx(P1_U_PRIME_COMMIT)[..]);
    assert_eq!(&bytes[66..99], &hx(P1_M1_COMMIT)[..]);
    assert_eq!(&bytes[99..132], &hx(P1_TAG)[..]);
    assert_eq!(&bytes[132..165], &hx(P1_NONCE_COMMIT)[..]);
    assert_eq!(&bytes[165..165 + 321], &hx(P1_PROOF)[..]);

    let parsed = arc::Presentation::from_bytes(&bytes, PRESENTATION_LIMIT).expect("from_bytes");
    arc::verify_presentation(
        &sk,
        &pk,
        &hx(REQUEST_CONTEXT),
        &hx(PRESENTATION_CONTEXT),
        &parsed,
        PRESENTATION_LIMIT,
    )
    .expect("verify parsed");
}

#[test]
fn full_protocol_round_trip() {
    // End-to-end, both presentations, fresh randomness: setup → request →
    // response → finalize → present × 2 → verify × 2 → third present fails.
    use rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x7070_7070);

    let (sk, pk) = arc::setup_server(&mut rng);
    let (secrets, request) =
        arc::create_credential_request(&hx(REQUEST_CONTEXT), &mut rng).expect("request");
    let response =
        arc::create_credential_response(&sk, &pk, &request, &mut rng).expect("response");
    let credential =
        arc::finalize_credential(&secrets, &pk, &request, &response).expect("finalize");

    let state = arc::make_presentation_state(credential, &hx(PRESENTATION_CONTEXT), 2);

    let (state, nonce_a, pres_a) = arc::present(&state, &mut rng).expect("present #1");
    assert_eq!(nonce_a, 0);
    let tag_a = arc::verify_presentation(
        &sk,
        &pk,
        &hx(REQUEST_CONTEXT),
        &hx(PRESENTATION_CONTEXT),
        &pres_a,
        2,
    )
    .expect("verify #1");
    assert_eq!(tag_a, pres_a.tag);

    let (state, nonce_b, pres_b) = arc::present(&state, &mut rng).expect("present #2");
    assert_eq!(nonce_b, 1);
    let tag_b = arc::verify_presentation(
        &sk,
        &pk,
        &hx(REQUEST_CONTEXT),
        &hx(PRESENTATION_CONTEXT),
        &pres_b,
        2,
    )
    .expect("verify #2");
    assert_eq!(tag_b, pres_b.tag);

    // Tags must differ across presentations (nonce is part of the tag denom).
    assert_ne!(tag_a, tag_b);

    // Third call exceeds the limit.
    assert!(matches!(
        arc::present(&state, &mut rng),
        Err(arc::Error::LimitExceeded)
    ));
}

// ---- ServerPublicKey wire round-trip ---------------------------------------

#[test]
fn server_public_key_wire_round_trip() {
    // to_bytes / from_bytes / to_bytes fixed point, and the reconstructed
    // public key verifies a response proof from the WG vector (the tightest
    // check: if deserialization silently swaps X1 and X2, the 11-equation
    // response proof rejects).
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let pk = sk.public_key();

    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), arc::ServerPublicKey::SIZE);
    assert_eq!(&bytes[..33], &hx(CAP_X0)[..]);
    assert_eq!(&bytes[33..66], &hx(CAP_X1)[..]);
    assert_eq!(&bytes[66..99], &hx(CAP_X2)[..]);

    let parsed = arc::ServerPublicKey::from_bytes(&bytes).expect("from_bytes");
    assert_eq!(
        &arc::group::serialize_element(&parsed.x0)[..],
        &arc::group::serialize_element(&pk.x0)[..]
    );
    assert_eq!(
        &arc::group::serialize_element(&parsed.x1)[..],
        &arc::group::serialize_element(&pk.x1)[..]
    );
    assert_eq!(
        &arc::group::serialize_element(&parsed.x2)[..],
        &arc::group::serialize_element(&pk.x2)[..]
    );

    // Cross-verify: the reconstructed pk must accept the WG response proof.
    let request = arc::CredentialRequest {
        m1_enc: arc::group::deserialize_element(&hx(REQ_M1_ENC)).unwrap(),
        m2_enc: arc::group::deserialize_element(&hx(REQ_M2_ENC)).unwrap(),
        request_proof: parse_proof_bytes(&hx(REQ_PROOF), 4),
    };
    let response = arc::CredentialResponse {
        u: arc::group::deserialize_element(&hx(RSP_U)).unwrap(),
        enc_u_prime: arc::group::deserialize_element(&hx(RSP_ENC_U_PRIME)).unwrap(),
        x0_aux: arc::group::deserialize_element(&hx(RSP_X0_AUX)).unwrap(),
        x1_aux: arc::group::deserialize_element(&hx(RSP_X1_AUX)).unwrap(),
        x2_aux: arc::group::deserialize_element(&hx(RSP_X2_AUX)).unwrap(),
        h_aux: arc::group::deserialize_element(&hx(RSP_H_AUX)).unwrap(),
        response_proof: parse_proof_bytes(&hx(RSP_PROOF), 7),
    };
    arc::response::verify_credential_response_proof(&parsed, &response, &request)
        .expect("reconstructed pk should accept the WG response proof");
}

#[test]
fn server_public_key_from_bytes_rejects_wrong_length() {
    let sk = arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    };
    let mut bytes = sk.public_key().to_bytes().to_vec();
    bytes.push(0); // 100 bytes, one too many
    assert!(matches!(
        arc::ServerPublicKey::from_bytes(&bytes),
        Err(arc::Error::InvalidLength { expected: 99, got: 100 })
    ));
    bytes.truncate(98); // one short
    assert!(matches!(
        arc::ServerPublicKey::from_bytes(&bytes),
        Err(arc::Error::InvalidLength { expected: 99, got: 98 })
    ));
}

// ---- Range proof: presentation_limit > 2 -----------------------------------
//
// The WG JSON only provides vectors for `presentation_limit = 2` (k = 1, the
// `D[0] == nonce_commit` reuse path). These tests exercise the k > 1 branch
// where the range helper allocates fresh `D[i]` element variables and the
// verifier runs the non-trivial sum check `nonce_commit ?= Σ bases[i] · D[i]`.
//
// We run a fresh setup → request → response → finalize → exhaust all `limit`
// presentations. If any bit decomposition, blinding schedule, or sum check is
// wrong, one of the `verify_presentation` calls will fail.

fn run_exhaustive_presentation_round_trip(seed: u64, presentation_limit: u64) {
    use rand_core::SeedableRng;
    use std::collections::HashSet;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);

    let (sk, pk) = arc::setup_server(&mut rng);
    let (secrets, request) =
        arc::create_credential_request(&hx(REQUEST_CONTEXT), &mut rng).expect("request");
    let response =
        arc::create_credential_response(&sk, &pk, &request, &mut rng).expect("response");
    let credential =
        arc::finalize_credential(&secrets, &pk, &request, &response).expect("finalize");

    let mut state = arc::make_presentation_state(
        credential,
        &hx(PRESENTATION_CONTEXT),
        presentation_limit,
    );
    let mut tags: HashSet<Vec<u8>> = HashSet::new();

    for expected_nonce in 0..presentation_limit {
        let (new_state, nonce, pres) = arc::present(&state, &mut rng)
            .unwrap_or_else(|e| panic!("present #{expected_nonce} (limit {presentation_limit}) failed: {e:?}"));
        assert_eq!(nonce, expected_nonce);

        // Range-proof dimension sanity.
        let k = arc::range_proof::compute_bases(presentation_limit).len();
        assert_eq!(pres.presentation_proof.d.len(), k);

        // Verify via the server API.
        let tag = arc::verify_presentation(
            &sk,
            &pk,
            &hx(REQUEST_CONTEXT),
            &hx(PRESENTATION_CONTEXT),
            &pres,
            presentation_limit,
        )
        .unwrap_or_else(|e| panic!("verify #{nonce} (limit {presentation_limit}) failed: {e:?}"));
        assert_eq!(tag, pres.tag);

        // Wire round-trip: parse back and re-verify.
        let bytes = pres.to_bytes();
        assert_eq!(bytes.len(), arc::Presentation::size(k));
        let parsed = arc::Presentation::from_bytes(&bytes, presentation_limit)
            .expect("presentation from_bytes");
        arc::verify_presentation(
            &sk,
            &pk,
            &hx(REQUEST_CONTEXT),
            &hx(PRESENTATION_CONTEXT),
            &parsed,
            presentation_limit,
        )
        .expect("verify parsed");

        // Tag uniqueness: different nonces must produce different tags (the
        // denominator `m1 + nonce` differs).
        let tag_bytes = arc::group::serialize_element(&tag).to_vec();
        assert!(
            tags.insert(tag_bytes),
            "tag collision at nonce {nonce} (limit {presentation_limit})"
        );

        state = new_state;
    }

    // Exhausting the limit makes the next call fail.
    assert!(matches!(
        arc::present(&state, &mut rng),
        Err(arc::Error::LimitExceeded)
    ));
}

#[test]
fn range_proof_limit_4_power_of_two() {
    // k = 2, bases = [2, 1]. Exercises the k > 1 fresh-element-allocation
    // branch. `D[0]` and `D[1]` are distinct from `nonce_commit`, so the
    // range helper appends 2 fresh element variables and binds them.
    run_exhaustive_presentation_round_trip(0xD4D4_D4D4, 4);
}

#[test]
fn range_proof_limit_8_power_of_two() {
    // k = 3, bases = [4, 2, 1]. Three bits to decompose; the last-base
    // inverse is 1 (smallest base after descending sort).
    run_exhaustive_presentation_round_trip(0xE8E8_E8E8, 8);
}

#[test]
fn range_proof_limit_10_non_power_of_two() {
    // k = 4, bases = [4, 2, 2, 1] (descending). Unsorted: power-of-two loop
    // produces [1, 2, 4] with remainder = 3, then the final truncated base
    // is `remainder - 1 = 2`, giving [1, 2, 4, 2] which sorts to [4, 2, 2, 1].
    // After descending-sort the *smallest* base is still 1, so the
    // `scalar_inverse(bases[last])` call happens to be inverse(1) here too;
    // the novelty vs. limit = 8 is the duplicate 2 in the middle and the
    // bit-decomposition having to greedily pick between bases of equal value.
    run_exhaustive_presentation_round_trip(0x1010_1010, 10);
}

// ===========================================================================
// Negative tests — tampered-but-well-formed proofs must be rejected with
// `Err(Verify)`. The byte-exact positive tests already pin down the
// verifier's accept path; these pin down the reject path. Every one of these
// tests starts from a valid WG vector (so the fresh-baseline state verifies)
// and mutates exactly one field before re-verifying.
// ===========================================================================

fn wg_sk() -> arc::ServerPrivateKey {
    arc::ServerPrivateKey {
        x0: arc::group::deserialize_scalar(&hx(X0)).unwrap(),
        x1: arc::group::deserialize_scalar(&hx(X1)).unwrap(),
        x2: arc::group::deserialize_scalar(&hx(X2)).unwrap(),
        x0_blinding: arc::group::deserialize_scalar(&hx(XB)).unwrap(),
    }
}

fn wg_request() -> arc::CredentialRequest {
    arc::CredentialRequest {
        m1_enc: arc::group::deserialize_element(&hx(REQ_M1_ENC)).unwrap(),
        m2_enc: arc::group::deserialize_element(&hx(REQ_M2_ENC)).unwrap(),
        request_proof: parse_proof_bytes(&hx(REQ_PROOF), 4),
    }
}

fn wg_response() -> arc::CredentialResponse {
    arc::CredentialResponse {
        u: arc::group::deserialize_element(&hx(RSP_U)).unwrap(),
        enc_u_prime: arc::group::deserialize_element(&hx(RSP_ENC_U_PRIME)).unwrap(),
        x0_aux: arc::group::deserialize_element(&hx(RSP_X0_AUX)).unwrap(),
        x1_aux: arc::group::deserialize_element(&hx(RSP_X1_AUX)).unwrap(),
        x2_aux: arc::group::deserialize_element(&hx(RSP_X2_AUX)).unwrap(),
        h_aux: arc::group::deserialize_element(&hx(RSP_H_AUX)).unwrap(),
        response_proof: parse_proof_bytes(&hx(RSP_PROOF), 7),
    }
}

fn wg_p1_presentation() -> arc::Presentation {
    let mut p = parse_presentation_proof(&hx(P1_PROOF));
    p.u = arc::group::deserialize_element(&hx(P1_U)).unwrap();
    p.u_prime_commit = arc::group::deserialize_element(&hx(P1_U_PRIME_COMMIT)).unwrap();
    p.m1_commit = arc::group::deserialize_element(&hx(P1_M1_COMMIT)).unwrap();
    p.tag = arc::group::deserialize_element(&hx(P1_TAG)).unwrap();
    p.nonce_commit = arc::group::deserialize_element(&hx(P1_NONCE_COMMIT)).unwrap();
    p
}

// ---- Request-proof negative tests -----------------------------------------

#[test]
fn tampered_request_proof_challenge_rejected() {
    let mut request = wg_request();
    // Baseline: original request verifies.
    arc::request::verify_credential_request_proof(&request).expect("baseline verify");

    request.request_proof.challenge += arc::Scalar::ONE;
    assert_eq!(
        arc::request::verify_credential_request_proof(&request),
        Err(arc::Error::Verify),
    );
}

#[test]
fn tampered_request_proof_response_rejected() {
    let mut request = wg_request();
    request.request_proof.responses[2] += arc::Scalar::ONE;
    assert_eq!(
        arc::request::verify_credential_request_proof(&request),
        Err(arc::Error::Verify),
    );
}

#[test]
fn tampered_request_m1_enc_rejected() {
    // Replace m1_enc with a different valid element. The proof's Schnorr
    // commitments still reconstruct to *something*, but the challenge
    // re-derivation hashes the wrong element, so the challenge comparison
    // in `verify` fails.
    let mut request = wg_request();
    request.m1_enc = arc::group::generator_g() + arc::group::generator_h();
    assert_eq!(
        arc::request::verify_credential_request_proof(&request),
        Err(arc::Error::Verify),
    );
}

// ---- Response-proof negative tests ----------------------------------------

#[test]
fn tampered_response_proof_challenge_rejected() {
    let sk = wg_sk();
    let pk = sk.public_key();
    let request = wg_request();
    let mut response = wg_response();
    arc::response::verify_credential_response_proof(&pk, &response, &request).expect("baseline");

    response.response_proof.challenge += arc::Scalar::ONE;
    assert_eq!(
        arc::response::verify_credential_response_proof(&pk, &response, &request),
        Err(arc::Error::Verify),
    );
}

#[test]
fn tampered_response_x1_x2_swap_rejected() {
    // Swapping X1Aux and X2Aux keeps both elements well-formed but breaks
    // equations 6–9 (which tie X1Aux to x1·H / b·X1 and X2Aux to x2·H /
    // b·X2). Catches a class of deserialization or proof-builder bugs that
    // can't be caught by length checks alone.
    let sk = wg_sk();
    let pk = sk.public_key();
    let request = wg_request();
    let mut response = wg_response();
    std::mem::swap(&mut response.x1_aux, &mut response.x2_aux);
    assert_eq!(
        arc::response::verify_credential_response_proof(&pk, &response, &request),
        Err(arc::Error::Verify),
    );
}

#[test]
fn tampered_response_h_aux_rejected() {
    let sk = wg_sk();
    let pk = sk.public_key();
    let request = wg_request();
    let mut response = wg_response();
    response.h_aux = arc::group::generator_g() + arc::group::generator_h();
    assert_eq!(
        arc::response::verify_credential_response_proof(&pk, &response, &request),
        Err(arc::Error::Verify),
    );
}

// ---- Presentation-proof negative tests -------------------------------------

#[test]
fn tampered_presentation_proof_challenge_rejected() {
    let sk = wg_sk();
    let pk = sk.public_key();
    let mut p = wg_p1_presentation();
    // Baseline: unmodified presentation verifies.
    arc::verify_presentation(
        &sk,
        &pk,
        &hx(REQUEST_CONTEXT),
        &hx(PRESENTATION_CONTEXT),
        &p,
        PRESENTATION_LIMIT,
    )
    .expect("baseline verify");

    p.presentation_proof.schnorr.challenge += arc::Scalar::ONE;
    assert_eq!(
        arc::verify_presentation(
            &sk,
            &pk,
            &hx(REQUEST_CONTEXT),
            &hx(PRESENTATION_CONTEXT),
            &p,
            PRESENTATION_LIMIT,
        ),
        Err(arc::Error::Verify),
    );
}

#[test]
fn tampered_presentation_tag_rejected() {
    // The tag participates in equation 4 (`generatorT = m1·tag + nonce·tag`),
    // so substituting a different valid element breaks the proof.
    let sk = wg_sk();
    let pk = sk.public_key();
    let mut p = wg_p1_presentation();
    p.tag = arc::group::generator_g() + arc::group::generator_h();
    assert_eq!(
        arc::verify_presentation(
            &sk,
            &pk,
            &hx(REQUEST_CONTEXT),
            &hx(PRESENTATION_CONTEXT),
            &p,
            PRESENTATION_LIMIT,
        ),
        Err(arc::Error::Verify),
    );
}

#[test]
fn tampered_presentation_nonce_commit_rejected() {
    // Changing `nonce_commit` desynchronizes it from D[0] (which in the
    // k=1 case shares its variable). The range sum check alone catches
    // this before Schnorr verify even runs.
    let sk = wg_sk();
    let pk = sk.public_key();
    let mut p = wg_p1_presentation();
    p.nonce_commit = arc::group::generator_g() + arc::group::generator_h();
    assert_eq!(
        arc::verify_presentation(
            &sk,
            &pk,
            &hx(REQUEST_CONTEXT),
            &hx(PRESENTATION_CONTEXT),
            &p,
            PRESENTATION_LIMIT,
        ),
        Err(arc::Error::Verify),
    );
}

#[test]
fn tampered_presentation_wrong_request_context_rejected() {
    // The verifier reconstructs V using `m2 = HashToScalar(requestContext,
    // "requestContext")`. A different `requestContext` yields a different
    // m2 and therefore a different V, which breaks equation 2.
    let sk = wg_sk();
    let pk = sk.public_key();
    let p = wg_p1_presentation();
    assert_eq!(
        arc::verify_presentation(
            &sk,
            &pk,
            b"different request context",
            &hx(PRESENTATION_CONTEXT),
            &p,
            PRESENTATION_LIMIT,
        ),
        Err(arc::Error::Verify),
    );
}

#[test]
fn tampered_presentation_wrong_presentation_context_rejected() {
    // `generator_T = HashToGroup(presentationContext, "Tag")`. A different
    // presentationContext yields a different generator_T, breaking
    // equation 4 (`generator_T = m1·tag + nonce·tag`).
    let sk = wg_sk();
    let pk = sk.public_key();
    let p = wg_p1_presentation();
    assert_eq!(
        arc::verify_presentation(
            &sk,
            &pk,
            &hx(REQUEST_CONTEXT),
            b"different presentation context",
            &p,
            PRESENTATION_LIMIT,
        ),
        Err(arc::Error::Verify),
    );
}
