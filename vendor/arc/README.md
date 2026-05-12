# arc

Rust implementation of **Anonymous Rate-limited Credentials (ARC)** over P-256,
following [`draft-ietf-privacypass-arc-crypto-01`][draft] (ciphersuite
`ARCV1-P256`).

## Security notice — UNAUDITED

**This code has not been audited in any way.** It has not received a formal
security review, a cryptographic review, or an independent implementation
review. It has not been tested against side-channel attacks, fault-injection
attacks, or any other adversarial model beyond "does the output match the
IETF test vectors byte-for-byte."

Do **not** deploy this crate in production or use it to protect anything you
care about. It exists for research, interoperability experiments, and as a
reference for the draft-01 wire format.

The authors make no warranty of any kind. Use at your own risk.

## Status

The full draft-01 protocol is implemented and byte-exact against the WG PoC
test vectors (`test-vectors-draft-01.json`, mirroring
`ietf-wg-privacypass/draft-arc/poc/vectors/allVectors.json`):

| Layer         | Module                                  | Coverage                                |
| ------------- | --------------------------------------- | --------------------------------------- |
| Ciphersuite   | [`ciphersuite`](src/ciphersuite.rs)     | DST builders, session-label helpers     |
| Group         | [`group`](src/group.rs)                 | P-256, RFC 9380 hash-to-curve/scalar    |
| Schnorr       | [`schnorr`](src/schnorr.rs)             | Linear-relation compiler, SHAKE128 sponge |
| Server        | [`server`](src/server.rs)               | Key setup, `X0`/`X1`/`X2` derivation    |
| Issuance      | [`request`](src/request.rs), [`response`](src/response.rs), [`finalize`](src/finalize.rs) | `CreateCredentialRequest`, `CreateCredentialResponse`, `FinalizeCredential` |
| Presentation  | [`presentation`](src/presentation.rs)   | `Present`, `VerifyPresentation`         |
| Range proof   | [`range_proof`](src/range_proof.rs)     | Per-bit Pedersen range proof (§5.4)     |

See [TODO.md](TODO.md) for per-module notes and the test coverage table.

## Comparison with Cashu BDHKE

[`cashubtc/cdk`][cdk] implements a similar-but-simpler anonymous-token
protocol (BDHKE over secp256k1). Upstream code that wants to support both
ARC and Cashu as interchangeable backends can use this table as a name
cross-reference. The crates do **not** share a function surface — the
names differ deliberately because the protocols differ (see "Where they
diverge" below).

### Name cross-reference

| Step                    | Cashu `cashu::dhke`         | This crate (`arc`)               |
| ----------------------- | --------------------------- | -------------------------------- |
| Key setup (server)      | *(mint keyset generation)*  | `setup_server`                   |
| Blind (client)          | `blind_message`             | `create_credential_request`      |
| Sign (server)           | `sign_message`              | `create_credential_response`     |
| Unblind (client)        | `unblind_message`           | `finalize_credential`            |
| Spend / show (client)   | *(reveal `(secret, C)`)*    | `present`                        |
| Spend verify (server)   | `verify_message`            | `verify_presentation`            |

### End-to-end: Cashu (BDHKE over secp256k1)

```rust
// Pseudocode using `cashubtc/cdk` / `cashu` crate shapes.
use cashu::dhke::{blind_message, sign_message, unblind_message, verify_message};

// --- Server setup (once) --------------------------------------------------
let mint_sk: SecretKey = /* mint's keyset private key */;
let mint_pk: PublicKey = mint_sk.public_key();

// --- Issuance ------------------------------------------------------------
let secret: &[u8] = b"user-chosen secret";

// Client: blind. `r` is the blinding factor the client keeps.
let (blinded, r) = blind_message(secret, None)?;

// Server: sign the blinded point.
let signed = sign_message(&mint_sk, &blinded)?;

// Client: unblind to get the un-blinded token `C`.
let token = unblind_message(&signed, &r, &mint_pk)?;

// --- Spend (single-show) -------------------------------------------------
// Client sends `(secret, token)` to the server.
// Server: DDH-check that `token == mint_sk · hash_to_curve(secret)`.
verify_message(&mint_sk, token, secret)?;
```

### End-to-end: ARC (draft-01 over P-256)

```rust
// Any `RngCore + CryptoRng` works.  For real use: `OsRng` from
// `rand_core` (with feature "getrandom") or `rand`.  For deterministic
// tests: `rand_chacha::ChaCha20Rng::seed_from_u64(...)`.
let mut rng = /* your CryptoRng */;
let req_ctx = b"session metadata bound to this credential";
let pres_ctx = b"spend-time context (e.g. rate-limit window)";
let limit: u64 = 2; // this credential may be presented twice

// --- Server setup (once) -------------------------------------------------
let (sk, pk) = arc::setup_server(&mut rng);

// --- Issuance ------------------------------------------------------------
// Client: blind the request context + a random credential message.
let (secrets, request) =
    arc::create_credential_request(req_ctx, &mut rng)?;

// Server: verify the request's Schnorr proof and issue the response.
let response =
    arc::create_credential_response(&sk, &pk, &request, &mut rng)?;

// Client: verify the response's Schnorr proof and decrypt the credential.
let credential =
    arc::finalize_credential(&secrets, &pk, &request, &response)?;

// --- Presentation (multi-show, up to `limit` times) ----------------------
let mut state = arc::make_presentation_state(credential, pres_ctx, limit);

for expected_nonce in 0..limit {
    let (next_state, nonce, presentation) = arc::present(&state, &mut rng)?;
    assert_eq!(nonce, expected_nonce);
    state = next_state;

    // Server: verify the presentation (Schnorr + per-bit range proof).
    // `tag` is a deterministic function of `(credential, nonce, pres_ctx)`;
    // the server stores seen tags to detect reuse within this context.
    let tag = arc::verify_presentation(
        &sk, &pk, req_ctx, pres_ctx, &presentation, limit,
    )?;
    assert_eq!(tag, presentation.tag);
}

// The (limit + 1)-th call returns Err(LimitExceeded).
assert!(matches!(
    arc::present(&state, &mut rng),
    Err(arc::Error::LimitExceeded),
));
```

### Where they diverge

- **Curve.** Cashu: secp256k1. ARC: P-256.
- **Primitive.** Cashu: BDHKE (one DH exponentiation, no ZK). ARC:
  algebraic MAC (MAC_GGM) with Schnorr proofs on both sides of issuance
  and presentation.
- **Amounts / denominations.** Cashu encodes an amount per token via the
  mint's keyset. ARC has no built-in amount.
- **Multi-show.** Cashu tokens are single-show: a spent `(secret, C)`
  pair is public and the mint blacklists `secret`. ARC credentials are
  multi-show up to `presentation_limit`, with per-nonce tags and a range
  proof binding `nonce ∈ [0, limit)`.
- **Context binding.** Cashu binds the secret implicitly. ARC has two
  explicit context inputs: `request_context` (bound at issuance) and
  `presentation_context` (bound at each spend).
- **Token visibility at spend.** Both protocols are unlinkable from
  issuance to redemption (that is the whole point of the blinding). They
  differ in what the verifier sees at spend time: in Cashu the client
  reveals `(secret, C)` in the clear, so anyone observing the spend
  message learns the full token. In ARC the credential is never exposed;
  the server sees only a zero-knowledge presentation and a per-nonce tag.

See `tests/test_vectors.rs::full_protocol_round_trip` for the ARC flow
above as an executable end-to-end test with byte-exact vectors.

## Building and testing

```
cargo build
cargo test
```

The test harness in [`tests/test_vectors.rs`](tests/test_vectors.rs) runs 35
integration tests plus 4 in-crate unit tests: positive vector checks
(byte-exact), wire-format round-trips, fresh-randomness end-to-end flows at
several `presentation_limit` values, and negative tests that tamper with
proof bytes and assert rejection.

## License

MIT — see [LICENSE](LICENSE).

[draft]: https://datatracker.ietf.org/doc/draft-ietf-privacypass-arc-crypto/
[cdk]: https://github.com/cashubtc/cdk
