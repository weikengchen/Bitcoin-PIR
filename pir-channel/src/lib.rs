//! Bitcoin PIR end-to-end encrypted channel primitives.
//!
//! This crate provides the *pure-crypto* pieces of the BPIR encrypted
//! channel: handshake-key derivation, AEAD frame wrap/unwrap, and the
//! tiny set of constants both sides need to agree on. It is callable
//! from native Rust (server: `pir-runtime-core::channel`) and from
//! wasm32 Rust (client: `pir-sdk-client::channel`) without
//! divergence.
//!
//! ## Why this exists
//!
//! The PIR property hides *which* scripthash a client queries from
//! the *server*. It does NOT hide the query bytes from anything in
//! between — the production deployment has cloudflared terminating
//! TLS at the tunnel edge and seeing every PIR frame in plaintext.
//! This crate's primitives let the browser and `unified_server`
//! establish an inner encrypted+authenticated channel keyed off
//! something cloudflared cannot influence: the server's long-lived
//! X25519 pubkey, which is bound into the SEV-SNP attestation report
//! via [`pir_core::attest`] (V2 layout).
//!
//! ## Handshake protocol
//!
//! Single round trip, after the client has fetched + verified the
//! server's V2 attestation:
//!
//! ```text
//! client → server:  REQ_HANDSHAKE { client_eph_pub: [u8;32], nonce: [u8;32] }
//! server → client:  RESP_HANDSHAKE { server_eph_pub: [u8;32] }
//!
//! both compute:
//!   ecdh_static = X25519(client_eph_priv, server_static_pub)   // identity
//!   ecdh_eph    = X25519(client_eph_priv, server_eph_pub)      // forward secrecy
//!   session_key = HKDF-SHA256(
//!       salt = nonce,
//!       ikm  = ecdh_static || ecdh_eph,
//!       info = "BPIR-CHANNEL-V1",
//!   )                                                          // 32 bytes
//! ```
//!
//! The server uses its long-lived `server_static_pub` (whose secret
//! never leaves the SEV-SNP guest) as the identity key, plus a fresh
//! per-session `server_eph_pub` for forward secrecy. A passive observer
//! who later compromises the static secret cannot retroactively
//! decrypt past sessions.
//!
//! ## Frame format
//!
//! After the handshake completes, every WebSocket frame is wrapped:
//!
//! ```text
//! [u8 magic = 0xfe]
//! [u64 sequence number, little-endian]
//! [chacha20poly1305 ciphertext+tag of inner_payload]
//! ```
//!
//! `magic` distinguishes encrypted frames from cleartext (for
//! pre-handshake / no-handshake compatibility on the same opcode
//! space). `sequence number` is the AEAD nonce input — see
//! [`Aead::nonce_for`]. Each side maintains independent send/recv
//! counters; reuse or skip is a decryption error (replay protection).

use chacha20poly1305::{
    aead::{Aead as RustCryptoAead, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// Length of an X25519 public key (RFC 7748 §6.1, 32 bytes).
pub const X25519_PUBKEY_LEN: usize = 32;

/// Length of the symmetric session key derived from the handshake.
pub const SESSION_KEY_LEN: usize = 32;

/// Size of the per-frame AEAD nonce (ChaCha20-Poly1305: 96 bits).
pub const AEAD_NONCE_LEN: usize = 12;

/// Size of the AEAD authentication tag (Poly1305: 128 bits).
pub const AEAD_TAG_LEN: usize = 16;

/// Magic byte at the start of every encrypted frame after handshake.
/// Distinguishes encrypted frames from cleartext (for the pre-handshake
/// compat window). Chosen to not collide with any existing opcode.
pub const ENCRYPTED_FRAME_MAGIC: u8 = 0xfe;

/// HKDF `info` string — domain-separates the BPIR-channel KDF from any
/// other use of the same handshake primitives.
pub const HKDF_INFO: &[u8] = b"BPIR-CHANNEL-V1";

/// Direction byte mixed into the per-frame AEAD nonce. The two sides
/// of the connection each derive their own nonce stream from the same
/// session key + their direction byte; that prevents reflection (a
/// frame the server sent is not decryptable as a frame from the
/// client at the same sequence number).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// Client → server frames. Bound into nonce position 0.
    ClientToServer = 0,
    /// Server → client frames. Bound into nonce position 0.
    ServerToClient = 1,
}

/// Errors from handshake or AEAD operations.
#[derive(Debug)]
pub enum ChannelError {
    /// The chacha20poly1305 backend rejected the ciphertext (tag
    /// mismatch — tampering, wrong key, wrong nonce, or wrong AAD).
    AeadFailure,
    /// The `next_recv_seq` counter rolled over u64::MAX. Should be
    /// unreachable in practice (2⁶⁴ frames at PIR rates is centuries),
    /// but explicit so callers don't have to think about it.
    SequenceExhausted,
    /// Encrypted frame too short to contain magic + seq + tag.
    FrameTooShort,
    /// Wire framing error: missing or wrong magic byte.
    BadFrameMagic,
}

impl core::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AeadFailure => write!(f, "AEAD authentication failed"),
            Self::SequenceExhausted => write!(f, "sequence number exhausted"),
            Self::FrameTooShort => write!(f, "encrypted frame too short"),
            Self::BadFrameMagic => write!(f, "encrypted frame has wrong magic byte"),
        }
    }
}

impl std::error::Error for ChannelError {}

// ─── Handshake derivation ────────────────────────────────────────────

/// Compute the X25519 public key corresponding to a 32-byte seed,
/// without minting a [`ClientHandshake`]. Useful when the caller needs
/// the pubkey ahead of time — e.g. to bind it into an attestation
/// nonce via [`pir_core::attest::derive_attest_nonce`] BEFORE running
/// REQ_ATTEST / REQ_HANDSHAKE.
///
/// The seed must remain stable between this call and the subsequent
/// [`ClientHandshake::new`] call so the eph pubkey committed-to in
/// REPORT_DATA matches the eph pubkey sent in REQ_HANDSHAKE. In
/// practice: generate `eph_seed` once, derive `client_eph_pub` here,
/// derive the attest nonce, run REQ_ATTEST, then pass the same
/// `eph_seed` into [`ClientHandshake::new`].
pub fn eph_pub_from_seed(seed: [u8; 32]) -> [u8; X25519_PUBKEY_LEN] {
    let secret = StaticSecret::from(seed);
    *PublicKey::from(&secret).as_bytes()
}

fn derive_from_dh(
    ecdh_static: &[u8; 32],
    ecdh_eph: &[u8; 32],
    nonce: &[u8; 32],
) -> [u8; SESSION_KEY_LEN] {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ecdh_static);
    ikm[32..].copy_from_slice(ecdh_eph);

    let hk = Hkdf::<Sha256>::new(Some(nonce), &ikm);
    let mut out = [0u8; SESSION_KEY_LEN];
    hk.expand(HKDF_INFO, &mut out)
        .expect("HKDF-SHA256 32-byte expand cannot fail");
    out
}

// ─── Per-side session state ──────────────────────────────────────────

/// Client-side handshake + session state.
///
/// Lifecycle:
/// 1. [`Self::new`] — creates a fresh ephemeral keypair to send to the
///    server.
/// 2. Send `client_eph_pub()` + a fresh `nonce` over the wire.
/// 3. Receive `server_eph_pub` + know `server_static_pub` (from prior
///    attestation).
/// 4. [`Self::complete_handshake`] — derives the session key,
///    consuming the ephemeral secret. After this returns, an `Aead`
///    is ready for sealing/opening frames.
pub struct ClientHandshake {
    /// Held as StaticSecret (Clone) so we can use it for both ECDH
    /// derivations. The wire still treats it as an "ephemeral" key:
    /// it's freshly minted per session and dropped when the session
    /// ends.
    client_eph_secret: StaticSecret,
    client_eph_pub: PublicKey,
    nonce: [u8; 32],
}

impl ClientHandshake {
    /// Mint a fresh ephemeral keypair from the supplied 32-byte seed.
    /// Production callers should pass cryptographically random bytes
    /// (e.g., from `rand_core::OsRng`); tests can pass a fixed seed
    /// for reproducibility.
    pub fn new(eph_secret_seed: [u8; 32], nonce: [u8; 32]) -> Self {
        let client_eph_secret = StaticSecret::from(eph_secret_seed);
        let client_eph_pub = PublicKey::from(&client_eph_secret);
        Self {
            client_eph_secret,
            client_eph_pub,
            nonce,
        }
    }

    /// Public half of the client's ephemeral key — send this to the
    /// server in REQ_HANDSHAKE.
    pub fn client_eph_pub(&self) -> [u8; X25519_PUBKEY_LEN] {
        *self.client_eph_pub.as_bytes()
    }

    /// Nonce the client picked for HKDF salting — send this to the
    /// server in REQ_HANDSHAKE.
    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    /// Complete the handshake using the server's two pubkeys: the
    /// long-lived `server_static_pub` (known from attestation) and
    /// the ephemeral `server_eph_pub` (received in RESP_HANDSHAKE).
    ///
    /// Returns the established session ready for AEAD wrapping.
    pub fn complete_handshake(
        self,
        server_static_pub: &[u8; X25519_PUBKEY_LEN],
        server_eph_pub: &[u8; X25519_PUBKEY_LEN],
    ) -> Session {
        let server_static = PublicKey::from(*server_static_pub);
        let server_eph = PublicKey::from(*server_eph_pub);
        let ecdh_static = self.client_eph_secret.diffie_hellman(&server_static);
        let ecdh_eph = self.client_eph_secret.diffie_hellman(&server_eph);
        let key = derive_from_dh(ecdh_static.as_bytes(), ecdh_eph.as_bytes(), &self.nonce);
        Session::new(key)
    }
}

/// Server-side handshake + session state.
///
/// Lifecycle:
/// 1. [`Self::new`] — wraps the server's long-lived static secret +
///    mints a per-session ephemeral keypair.
/// 2. Server sends `server_eph_pub()` over the wire in RESP_HANDSHAKE.
/// 3. [`Self::complete_handshake`] — given the client's ephemeral
///    pubkey + nonce from REQ_HANDSHAKE, derives the session key.
pub struct ServerHandshake<'a> {
    server_static_secret: &'a StaticSecret,
    server_eph_secret: StaticSecret,
    server_eph_pub: PublicKey,
}

impl<'a> ServerHandshake<'a> {
    pub fn new(server_static_secret: &'a StaticSecret, eph_secret_seed: [u8; 32]) -> Self {
        let server_eph_secret = StaticSecret::from(eph_secret_seed);
        let server_eph_pub = PublicKey::from(&server_eph_secret);
        Self {
            server_static_secret,
            server_eph_secret,
            server_eph_pub,
        }
    }

    /// Public half of the server's ephemeral key — send in
    /// RESP_HANDSHAKE.
    pub fn server_eph_pub(&self) -> [u8; X25519_PUBKEY_LEN] {
        *self.server_eph_pub.as_bytes()
    }

    /// Complete the handshake using the client's ephemeral pubkey +
    /// nonce from REQ_HANDSHAKE.
    pub fn complete_handshake(
        self,
        client_eph_pub: &[u8; X25519_PUBKEY_LEN],
        nonce: &[u8; 32],
    ) -> Session {
        let client_eph = PublicKey::from(*client_eph_pub);
        let ecdh_static = self.server_static_secret.diffie_hellman(&client_eph);
        let ecdh_eph = self.server_eph_secret.diffie_hellman(&client_eph);
        let key = derive_from_dh(ecdh_static.as_bytes(), ecdh_eph.as_bytes(), nonce);
        Session::new(key)
    }
}

// ─── Session: AEAD wrap/unwrap with replay protection ────────────────

/// An established encrypted session. Holds the symmetric key + per-
/// direction sequence counters. Both sides drive their own `Session`
/// independently; they agree on the derived key but not on the
/// counters (which start at 0 on each side).
pub struct Session {
    key: [u8; SESSION_KEY_LEN],
    /// Next sequence number to use when sealing an outgoing frame.
    next_send_seq: u64,
    /// Next sequence number expected on an incoming frame.
    next_recv_seq: u64,
}

impl Session {
    fn new(key: [u8; SESSION_KEY_LEN]) -> Self {
        Self {
            key,
            next_send_seq: 0,
            next_recv_seq: 0,
        }
    }

    /// Seal `plaintext` for delivery in direction `dir`. Returns the
    /// wire bytes: `[magic][seq:u64 LE][ciphertext+tag]`.
    pub fn seal(&mut self, dir: Direction, plaintext: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let seq = self.next_send_seq;
        self.next_send_seq = self
            .next_send_seq
            .checked_add(1)
            .ok_or(ChannelError::SequenceExhausted)?;
        let nonce_bytes = nonce_for(dir, seq);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        let ct = cipher
            .encrypt((&nonce_bytes).into(), plaintext)
            .map_err(|_| ChannelError::AeadFailure)?;
        let mut out = Vec::with_capacity(1 + 8 + ct.len());
        out.push(ENCRYPTED_FRAME_MAGIC);
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Open a sealed frame received in direction `dir`. Verifies the
    /// magic, parses the sequence number, checks it matches
    /// `next_recv_seq` (no skip / no replay), then AEAD-decrypts.
    pub fn open(&mut self, dir: Direction, frame: &[u8]) -> Result<Vec<u8>, ChannelError> {
        // Frame layout: [magic:1][seq:8][ct+tag:N]. Minimum N=16 (the
        // Poly1305 tag of an empty plaintext).
        if frame.len() < 1 + 8 + AEAD_TAG_LEN {
            return Err(ChannelError::FrameTooShort);
        }
        if frame[0] != ENCRYPTED_FRAME_MAGIC {
            return Err(ChannelError::BadFrameMagic);
        }
        let seq = u64::from_le_bytes(frame[1..9].try_into().unwrap());
        if seq != self.next_recv_seq {
            // Strict in-order delivery: any reorder, replay, or skip is
            // an AEAD failure. The decryption would also fail because
            // the nonce is derived from seq, but failing fast here gives
            // a clearer error.
            return Err(ChannelError::AeadFailure);
        }
        self.next_recv_seq = self
            .next_recv_seq
            .checked_add(1)
            .ok_or(ChannelError::SequenceExhausted)?;
        let nonce_bytes = nonce_for(dir, seq);
        let cipher = ChaCha20Poly1305::new((&self.key).into());
        cipher
            .decrypt((&nonce_bytes).into(), &frame[9..])
            .map_err(|_| ChannelError::AeadFailure)
    }

    #[cfg(test)]
    fn key_bytes(&self) -> &[u8; SESSION_KEY_LEN] {
        &self.key
    }
}

/// Compute the 12-byte AEAD nonce for a given direction + sequence
/// number. Layout: `[direction:u32 LE][seq:u64 LE]`. Two sides whose
/// frames are at the same `seq` get distinct nonces because their
/// directions differ.
pub fn nonce_for(dir: Direction, seq: u64) -> [u8; AEAD_NONCE_LEN] {
    let mut out = [0u8; AEAD_NONCE_LEN];
    out[..4].copy_from_slice(&(dir as u32).to_le_bytes());
    out[4..].copy_from_slice(&seq.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    fn random_seed() -> [u8; 32] {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    }

    fn server_static() -> (StaticSecret, [u8; 32]) {
        let seed = random_seed();
        let secret = StaticSecret::from(seed);
        let pub_bytes = *PublicKey::from(&secret).as_bytes();
        (secret, pub_bytes)
    }

    #[test]
    fn eph_pub_from_seed_matches_client_handshake_pub() {
        // The standalone helper and the ClientHandshake constructor
        // must agree on the eph_pub for the same seed, so a caller
        // can pre-compute the pubkey for nonce binding and trust that
        // the subsequent handshake will send the same bytes.
        let seed = random_seed();
        let helper_pub = eph_pub_from_seed(seed);
        let hs = ClientHandshake::new(seed, [0u8; 32]);
        assert_eq!(helper_pub, hs.client_eph_pub());
    }

    #[test]
    fn eph_pub_from_seed_is_deterministic() {
        let seed = [0x42u8; 32];
        assert_eq!(eph_pub_from_seed(seed), eph_pub_from_seed(seed));
    }

    #[test]
    fn handshake_derives_same_key_on_both_sides() {
        let (server_static_secret, server_static_pub) = server_static();

        // Client side
        let client_eph_seed = random_seed();
        let nonce = random_seed();
        let client_hs = ClientHandshake::new(client_eph_seed, nonce);
        let client_eph_pub = client_hs.client_eph_pub();

        // Server side
        let server_eph_seed = random_seed();
        let server_hs = ServerHandshake::new(&server_static_secret, server_eph_seed);
        let server_eph_pub = server_hs.server_eph_pub();

        // Cross-derivation
        let server_session = server_hs.complete_handshake(&client_eph_pub, &nonce);
        let client_session = client_hs.complete_handshake(&server_static_pub, &server_eph_pub);

        // Both sides agree on the session key.
        assert_eq!(client_session.key_bytes(), server_session.key_bytes());
    }

    #[test]
    fn session_keys_differ_per_handshake() {
        // Same long-lived server keys, two sessions, fresh ephemerals
        // each time → fresh session keys (forward secrecy property).
        let (server_static_secret, server_static_pub) = server_static();

        let session_a = {
            let nonce = random_seed();
            let client = ClientHandshake::new(random_seed(), nonce);
            let server = ServerHandshake::new(&server_static_secret, random_seed());
            let server_eph_pub = server.server_eph_pub();
            let _ = server.complete_handshake(&client.client_eph_pub(), &nonce);
            client.complete_handshake(&server_static_pub, &server_eph_pub)
        };
        let session_b = {
            let nonce = random_seed();
            let client = ClientHandshake::new(random_seed(), nonce);
            let server = ServerHandshake::new(&server_static_secret, random_seed());
            let server_eph_pub = server.server_eph_pub();
            let _ = server.complete_handshake(&client.client_eph_pub(), &nonce);
            client.complete_handshake(&server_static_pub, &server_eph_pub)
        };
        assert_ne!(session_a.key_bytes(), session_b.key_bytes());
    }

    #[test]
    fn mitm_with_wrong_static_cannot_agree_on_session_key() {
        // The point of binding the static pubkey via attestation: a
        // MITM standing in for the real server can offer its own
        // ephemeral pubkey, but cannot make ECDH agree on the static
        // half — because the static half depends on a secret only the
        // real server holds. The client, having verified the real
        // server's static_pub via SEV-SNP attestation, will derive a
        // different session key than the MITM derives. No data flows.
        let (real_server_secret, real_server_pub) = server_static();
        let (mitm_server_secret, mitm_server_pub) = server_static();
        assert_ne!(real_server_pub, mitm_server_pub);

        let nonce = random_seed();
        let client_eph_seed = random_seed();
        let server_eph_seed = random_seed();

        // Server side: MITM holds mitm_server_secret. Runs its own
        // ServerHandshake (it has no choice; the real_server_secret
        // is inside the SEV-SNP guest where the MITM cannot reach it).
        let server_mitm = ServerHandshake::new(&mitm_server_secret, server_eph_seed);
        let mitm_eph_pub = server_mitm.server_eph_pub();

        // Client side: knows real_server_pub from attestation. Sends
        // its REQ_HANDSHAKE; MITM forwards it; MITM responds with its
        // own ephemeral pubkey.
        let client_hs = ClientHandshake::new(client_eph_seed, nonce);
        let client_eph_pub = client_hs.client_eph_pub();
        let client_session = client_hs.complete_handshake(&real_server_pub, &mitm_eph_pub);

        // MITM completes its server-side handshake using the client's
        // eph pub + nonce.
        let mitm_session = server_mitm.complete_handshake(&client_eph_pub, &nonce);

        // Client computed a key against real_server_pub; MITM's server-
        // side derivation used mitm_server_secret. The two key streams
        // are uncorrelated → MITM cannot decrypt anything the client
        // sends and vice versa.
        assert_ne!(client_session.key_bytes(), mitm_session.key_bytes());
    }

    #[test]
    fn seal_open_roundtrip() {
        let key = [0xABu8; 32];
        let mut sender = Session::new(key);
        let mut receiver = Session::new(key);
        let plaintext = b"hello PIR world";

        let frame = sender.seal(Direction::ClientToServer, plaintext).unwrap();
        let recovered = receiver.open(Direction::ClientToServer, &frame).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn frame_layout_starts_with_magic_then_seq() {
        let mut sender = Session::new([0u8; 32]);
        let frame = sender.seal(Direction::ClientToServer, b"x").unwrap();
        assert_eq!(frame[0], ENCRYPTED_FRAME_MAGIC);
        assert_eq!(&frame[1..9], &0u64.to_le_bytes());
        // ciphertext is 1 byte + 16-byte tag = 17 bytes after magic+seq
        assert_eq!(frame.len(), 1 + 8 + 1 + AEAD_TAG_LEN);
    }

    #[test]
    fn seq_increments_per_send() {
        let mut sender = Session::new([0u8; 32]);
        let f0 = sender.seal(Direction::ClientToServer, b"a").unwrap();
        let f1 = sender.seal(Direction::ClientToServer, b"b").unwrap();
        assert_eq!(&f0[1..9], &0u64.to_le_bytes());
        assert_eq!(&f1[1..9], &1u64.to_le_bytes());
    }

    #[test]
    fn replay_is_rejected() {
        let key = [0u8; 32];
        let mut sender = Session::new(key);
        let mut receiver = Session::new(key);
        let f0 = sender.seal(Direction::ClientToServer, b"first").unwrap();
        let _ = sender.seal(Direction::ClientToServer, b"second").unwrap();

        // Receive frame 0 → ok
        receiver.open(Direction::ClientToServer, &f0).unwrap();
        // Receive frame 0 again → replay rejected (next_recv_seq is now 1)
        let err = receiver.open(Direction::ClientToServer, &f0).unwrap_err();
        assert!(matches!(err, ChannelError::AeadFailure));
    }

    #[test]
    fn reorder_is_rejected() {
        let key = [0u8; 32];
        let mut sender = Session::new(key);
        let mut receiver = Session::new(key);
        let _f0 = sender.seal(Direction::ClientToServer, b"first").unwrap();
        let f1 = sender.seal(Direction::ClientToServer, b"second").unwrap();

        // Receive f1 before f0 → rejected (out of order; expected seq=0)
        let err = receiver.open(Direction::ClientToServer, &f1).unwrap_err();
        assert!(matches!(err, ChannelError::AeadFailure));
    }

    #[test]
    fn direction_mismatch_is_rejected() {
        let key = [0u8; 32];
        let mut sender = Session::new(key);
        let mut receiver = Session::new(key);
        let frame = sender.seal(Direction::ClientToServer, b"x").unwrap();

        // Receiver tries to open as if it were a server-to-client
        // frame: nonce mismatch → AEAD failure (after the seq check
        // passes with seq=0).
        let err = receiver.open(Direction::ServerToClient, &frame).unwrap_err();
        assert!(matches!(err, ChannelError::AeadFailure));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let key = [0u8; 32];
        let mut sender = Session::new(key);
        let mut receiver = Session::new(key);
        let mut frame = sender
            .seal(Direction::ClientToServer, b"original payload")
            .unwrap();
        let last = frame.len() - 1;
        frame[last] ^= 0x01;
        let err = receiver.open(Direction::ClientToServer, &frame).unwrap_err();
        assert!(matches!(err, ChannelError::AeadFailure));
    }

    #[test]
    fn bad_magic_is_rejected() {
        let key = [0u8; 32];
        let mut sender = Session::new(key);
        let mut receiver = Session::new(key);
        let mut frame = sender.seal(Direction::ClientToServer, b"x").unwrap();
        frame[0] = 0x00;
        let err = receiver.open(Direction::ClientToServer, &frame).unwrap_err();
        assert!(matches!(err, ChannelError::BadFrameMagic));
    }

    #[test]
    fn frame_too_short_is_rejected() {
        let mut receiver = Session::new([0u8; 32]);
        // Only 8 bytes total; less than magic(1) + seq(8) + tag(16) = 25.
        let frame = vec![ENCRYPTED_FRAME_MAGIC, 0, 0, 0, 0, 0, 0, 0];
        let err = receiver.open(Direction::ClientToServer, &frame).unwrap_err();
        assert!(matches!(err, ChannelError::FrameTooShort));
    }

    #[test]
    fn nonce_for_distinguishes_directions() {
        let n_c2s = nonce_for(Direction::ClientToServer, 42);
        let n_s2c = nonce_for(Direction::ServerToClient, 42);
        assert_ne!(n_c2s, n_s2c);
    }

    #[test]
    fn nonce_for_distinguishes_sequence() {
        let n_a = nonce_for(Direction::ClientToServer, 0);
        let n_b = nonce_for(Direction::ClientToServer, 1);
        assert_ne!(n_a, n_b);
    }

    #[test]
    fn end_to_end_handshake_then_bidirectional_traffic() {
        // Full integration: handshake → client sends → server responds → client receives.
        let (server_static_secret, server_static_pub) = server_static();
        let nonce = random_seed();

        // Client kicks off the handshake.
        let client_hs = ClientHandshake::new(random_seed(), nonce);
        let client_eph_pub = client_hs.client_eph_pub();

        // Server completes its half.
        let server_hs = ServerHandshake::new(&server_static_secret, random_seed());
        let server_eph_pub = server_hs.server_eph_pub();
        let mut server_session = server_hs.complete_handshake(&client_eph_pub, &nonce);

        // Client completes its half.
        let mut client_session = client_hs.complete_handshake(&server_static_pub, &server_eph_pub);

        // Bi-directional ping/pong: client → server → client.
        let req = b"REQ_PING";
        let req_frame = client_session.seal(Direction::ClientToServer, req).unwrap();
        let req_recovered = server_session.open(Direction::ClientToServer, &req_frame).unwrap();
        assert_eq!(req_recovered, req);

        let resp = b"PONG";
        let resp_frame = server_session.seal(Direction::ServerToClient, resp).unwrap();
        let resp_recovered = client_session.open(Direction::ServerToClient, &resp_frame).unwrap();
        assert_eq!(resp_recovered, resp);

        // Second roundtrip: sequence numbers should advance independently.
        let req2 = b"REQ_GET_INFO";
        let req2_frame = client_session.seal(Direction::ClientToServer, req2).unwrap();
        // The seq should be 1 now (independent counter on this side).
        assert_eq!(&req2_frame[1..9], &1u64.to_le_bytes());
        server_session.open(Direction::ClientToServer, &req2_frame).unwrap();
    }
}
