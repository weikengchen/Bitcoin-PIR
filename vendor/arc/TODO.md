# ARC Rust port — remaining work

Tracks implementation progress for `draft-ietf-privacypass-arc-crypto-01`
(ciphersuite `ARCV1-P256`) against the WG PoC test vectors in
`test-vectors-draft-01.json`.

## Status legend

- [x] done & covered by a byte-exact vector test (or explicit `#[ignore]`
      explaining why a vector can't cover it)
- [~] partially done — code exists, test missing or passing for the wrong reason
- [ ] not started

---

## Foundation — DONE

- [x] `group.rs` — `serialize/deserialize_element`, `serialize/deserialize_scalar`,
      `hash_to_group`, `hash_to_scalar`, `generator_g`, `generator_h`.
      Covered by `server_public_key_matches_private_key`,
      `m2_matches_hash_to_scalar_of_request_context`, `dump_generator_h`.
- [x] `ciphersuite.rs` — constants, DST builders, `proof_session`,
      `SCHNORR_PROTOCOL_ID_RAW`.
- [x] `server.rs` — `ServerPrivateKey`, `ServerPublicKey`, `setup_server`.
      Covered by `server_public_key_matches_private_key`.
- [x] `error.rs` — enum with the variants the modules already reference.
- [x] `schnorr.rs` — full Schnorr compiler (`LinearRelation`,
      `NISchnorrProofShake128P256` prove/verify) with pre-`41b316a348f9`
      SIGMA codec.init sponge format. Covered by
      `schnorr_verifies_credential_request_proof_vector` (byte-exact against
      `REQ_PROOF`) + `schnorr_round_trip_credential_request` (round-trip).

## Issuance — DONE

- [x] `request.rs` — `create_credential_request`,
      `make_credential_request_proof`, `verify_credential_request_proof`,
      `CredentialRequest::{to_bytes,from_bytes}`. Covered by
      `credential_request_round_trips_with_test_vector_blinds` (byte-exact
      `m1_enc`/`m2_enc` against the WG vector) + `create_credential_request_round_trip`
      (end-to-end with fresh RNG, `m2` matches WG deterministic derivation).
- [x] `response.rs` — `create_credential_response`,
      `make_credential_response_proof` (11 equations with `t1=b*x1`,
      `t2=b*x2` linearization), `verify_credential_response_proof`,
      `CredentialResponse::{to_bytes,from_bytes}`. Covered by
      `credential_response_round_trips` (byte-exact
      `U`/`encUPrime`/`X0Aux`/`X1Aux`/`X2Aux`/`HAux` against the WG vector)
      + `create_credential_response_round_trip` (end-to-end with fresh keys
      and RNG, exercises internal `verify_credential_request_proof` guard).
- [x] `finalize.rs` — `finalize_credential`: verifies the response proof,
      decrypts `UPrime = encUPrime − X0Aux − r1·X1Aux − r2·X2Aux`, returns
      `Credential`. Covered by `finalize_credential_matches_test_vector`
      (byte-exact `UPrime` against `CRED_U_PRIME`) and
      `verify_credential_response_proof_vector` (byte-exact RSP_PROOF
      verification — implicitly exercised by finalize too).

## Presentation — DONE

- [x] `range_proof.rs` — `compute_bases` (descending order with truncation
      rule from §5.4.1), `make_range_proof_helper`, `verify_range_proof_helper`.
      k = 1 special case reuses `nonce_commit_var` for `D[0]` to match the WG
      PoC's Fiat-Shamir transcript. Covered by the in-file
      `compute_bases_*` unit tests plus the presentation byte-exact tests
      (any mistake in the range proof would flip the challenge).
- [x] `presentation.rs` — `make_presentation_state`, `present`,
      `verify_presentation`, `make_presentation_proof`,
      `verify_presentation_proof`, `Presentation::{to_bytes,from_bytes}`,
      `PresentationProof::size`. 4 base equations + 2k range equations,
      5 base scalars + 3k range scalars, 10 base element vars (k fewer if
      the k=1 reuse kicks in). Covered by:
        * `verify_presentation_p1_vector` — byte-exact verification of WG
          `P1_PROOF` (nonce = 0, k = 1, D[0] == nonceCommit reuse path).
        * `verify_presentation_p2_vector` — byte-exact verification of WG
          `P2_PROOF` (nonce = 1, k = 1, different commit).
        * `presentation_wire_round_trip` — `to_bytes`/`from_bytes` on the
          P1 vector; the parsed presentation still verifies.
        * `full_protocol_round_trip` — end-to-end with fresh `setup_server`,
          both presentations verify, third `present` returns `LimitExceeded`.

## Follow-ups — DONE

- [x] `ServerPublicKey::{to_bytes,from_bytes}` round-trip coverage. Covered
      by `server_public_key_wire_round_trip` (byte-exact `CAP_X0/1/2`,
      `from_bytes` recovers the original elements, and the reconstructed
      `pk` verifies the WG `RSP_PROOF` — which catches any silent X1/X2
      swap) and `server_public_key_from_bytes_rejects_wrong_length`
      (98- and 100-byte inputs both rejected as `InvalidLength`).
- [x] Wider range proof integration tests. Three exhaustive tests that
      exercise the k > 1 fresh-element-allocation branch of the range
      helper, running every nonce in `[0, limit)` through
      present→verify→wire-round-trip and confirming all tags are distinct:
        * `range_proof_limit_4_power_of_two`  — k = 2, bases = [2, 1].
        * `range_proof_limit_8_power_of_two`  — k = 3, bases = [4, 2, 1].
        * `range_proof_limit_10_non_power_of_two` — k = 4,
          bases = [4, 2, 2, 1] (truncated last base sorts to a duplicate
          middle slot). Each test also checks that the `limit+1`-th
          `present` returns `LimitExceeded`.
- [x] Negative tests for proof verification. Eleven tests take a valid
      WG vector (request / response / presentation), mutate exactly one
      field, and assert the verifier returns `Err(Verify)`:
        * Request: challenge flip, response flip, `m1_enc` swap.
        * Response: challenge flip, X1Aux/X2Aux swap, `h_aux` swap.
        * Presentation: challenge flip, `tag` swap, `nonce_commit` swap
          (exercises the range sum-check reject path), wrong
          `requestContext` (breaks V reconstruction), wrong
          `presentationContext` (breaks `generator_T`).
- [x] Stale scaffolding stripped from `lib.rs` (status comment claiming
      `todo!()` bodies; `#![allow(dead_code)]`, `#![allow(unused_variables)]`,
      `#![allow(clippy::todo)]`). Build is clean without them; clippy is
      clean too (one pre-existing `doc_overindented_list_items` warning in
      `response.rs` rewrapped at the same time).

## Deterministic-RNG harness — DEFERRED

The WG PoC uses a seeded `TestDRNG` so `allVectors.json` is fully
reproducible. Our tests inject the vector scalars as witnesses and check
that the *resulting proof's* bytes match, which avoids a bit-exact
RNG replica. If we ever want to regen vectors from scratch, we'd need
to match `TestDRNG`'s reduction (witness: `% (order-1)`, nonces:
`% order`) — that exploration is documented in the completed todo history.

## Known subtle points — keep in mind if touching these modules

- **Response-proof witness ordering**: `[x0, x1, x2, x0Blinding, b, t1, t2]`
  (7 scalars). The WG PoC `arc_proofs.sage` is the source of truth —
  double-check the order before comparing responses byte-for-byte.
- **Session labels**: `"ARCV1-P256CredentialRequest"` (27 bytes),
  `"ARCV1-P256CredentialResponse"` (28), `"ARCV1-P256CredentialPresentation"`
  (32). Use `ciphersuite::proof_session(name)` to build them.
- **Element-variable order inside `instance_label`**: follows
  `allocate_elements` order, serialized as 33-byte compressed SEC1. Any
  reshuffling silently mismatches the challenge.
- **Nonzero scalar sampling**: reuse `group::nonzero_random_scalar`
  (moved from `server.rs` once request.rs needs it).
- **Wire format serialization**: `to_bytes` returns fixed-size arrays
  (`[u8; SIZE]`). `from_bytes` does strict length check first, then field
  parse. Don't relax either — the tests assert exact byte lengths.
