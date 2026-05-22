//! Two-tier operator-signed identity for BitcoinPIR servers.
//!
//! ## Why this exists
//!
//! The PIR encrypted channel ([`pir_channel`]) terminates inside the
//! unified_server process, *behind* cloudflared. For hosts with SEV-SNP
//! (pir2), the channel's long-lived X25519 pubkey is bound into the
//! chip-signed REPORT_DATA via [`pir_core::attest::build_report_data`]
//! — so a client verifying the SEV report can trust that the pubkey it
//! handshakes against came from the attested guest.
//!
//! Hosts without hardware attestation (pir1, on Hetzner) have no such
//! anchor. The wire-returned `server_static_pub` is just self-asserted,
//! and a TLS-terminating middlebox (cloudflared) could substitute it
//! at will. This crate closes that gap with operator-signed identity:
//!
//! ```text
//!   Operator's long-term Ed25519 key   (offline; eventually broadcast
//!     │                                 via Nostr or similar)
//!     │ signs once per server identity rotation
//!     ▼
//!   IdentityCert  { server_id, identity_pubkey, valid_from, valid_until }
//!     │
//!     │ identity_pubkey signs once per server boot
//!     ▼
//!   ChannelManifest  { server_id, channel_pub, binary_sha256, git_rev,
//!                       manifest_roots, issued_at }
//! ```
//!
//! A client that has the operator pubkey pinned can therefore prove
//! that `channel_pub` was endorsed by the operator (transitively, via
//! the identity key on the server). Cloudflare-position adversaries
//! cannot forge either layer without the offline operator key.
//!
//! ## What this crate exposes
//!
//! - [`IdentityCert`] + [`sign_identity_cert`] / [`IdentityCert::verify`]
//! - [`ChannelManifest`] + [`sign_channel_manifest`] / [`ChannelManifest::verify`]
//! - Canonical wire encoding (`encode` / `decode`) for both. Stable;
//!   any layout change requires a version bump.
//!
//! Pure-crypto only — no filesystem, no networking. Server-side I/O
//! (loading the identity key from disk, broadcasting the bundle over
//! REQ_ANNOUNCE) lives in `pir-runtime-core`. Operator tooling for
//! offline signing lives in `bpir-admin`.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Length of an Ed25519 public key (RFC 8032).
pub const ED25519_PUBKEY_LEN: usize = 32;
/// Length of an Ed25519 signature (RFC 8032).
pub const ED25519_SIG_LEN: usize = 64;
/// Length of an X25519 public key (RFC 7748 §6.1).
pub const X25519_PUBKEY_LEN: usize = 32;
/// Length of a SHA-256 digest.
pub const HASH_LEN: usize = 32;

/// Domain separation prefix for IdentityCert signing preimage. Bump
/// to V2 if the [`IdentityCert`] field set or canonical encoding
/// changes.
pub const IDENTITY_CERT_DOMAIN_TAG: &[u8] = b"BPIR-IDENTITY-CERT-V1";

/// Domain separation prefix for ChannelManifest signing preimage.
pub const CHANNEL_MANIFEST_DOMAIN_TAG: &[u8] = b"BPIR-CHANNEL-MANIFEST-V1";

/// Wire-format / verification errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// Wire decode found a length-prefixed field whose body would
    /// extend past the end of the input.
    Truncated(&'static str),
    /// Wire decode found a `version` byte the crate doesn't know how
    /// to parse. New layouts MUST bump the version; verifiers reject
    /// unknown ones rather than fall through.
    UnknownVersion { kind: &'static str, version: u8 },
    /// A `server_id` / `git_rev` length prefix exceeded a sanity cap.
    /// Caps are large enough for realistic operator strings but
    /// prevent a malicious blob from forcing huge allocations.
    FieldTooLong { field: &'static str, len: usize },
    /// `manifest_roots` count exceeded the per-server cap. PIR
    /// servers serve a handful of DBs (today: 4); we cap at 32 to
    /// allow growth without admitting absurd blobs.
    TooManyManifestRoots(usize),
    /// Provided bytes are not the right length for the field they
    /// were assigned to.
    BadLength { field: &'static str, expected: usize, got: usize },
    /// Ed25519 signature failed verification.
    BadSignature,
    /// The Ed25519 pubkey bytes are not a valid point.
    BadPubkey,
    /// Trailing bytes after the structure's declared end. Strict
    /// decode rejects this — easier to catch protocol drift early.
    TrailingBytes(usize),
}

impl core::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated(s) => write!(f, "truncated: {}", s),
            Self::UnknownVersion { kind, version } => {
                write!(f, "{}: unknown version {}", kind, version)
            }
            Self::FieldTooLong { field, len } => {
                write!(f, "field {} too long: {}", field, len)
            }
            Self::TooManyManifestRoots(n) => write!(f, "manifest_roots count {} > 32", n),
            Self::BadLength { field, expected, got } => write!(
                f,
                "bad length for {}: expected {}, got {}",
                field, expected, got
            ),
            Self::BadSignature => write!(f, "Ed25519 signature verification failed"),
            Self::BadPubkey => write!(f, "Ed25519 pubkey is not a valid point"),
            Self::TrailingBytes(n) => write!(f, "{} trailing bytes after structure", n),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Caps on variable-length fields. Plenty of headroom for realistic
/// operator strings while preventing OOM blowup from a malicious blob.
const MAX_SERVER_ID_LEN: usize = 256;
const MAX_GIT_REV_LEN: usize = 256;
const MAX_MANIFEST_ROOTS: usize = 32;

/// Operator-signed Tier-1 cert. Bound: a single `server_id` is endorsed
/// to use `identity_pubkey` between `valid_from` and `valid_until`.
///
/// The operator signs this OFFLINE — `identity_pubkey` is generated
/// server-side; the operator receives it out-of-band (e.g., via
/// `bpir-admin generate-identity` output) and produces this blob with
/// `bpir-admin sign-identity`. Rotating the operator key requires
/// publishing the new pubkey through the agreed channel (Nostr,
/// eventually). Rotating just the `identity_pubkey` requires re-signing
/// the cert with the unchanged operator key.
///
/// `valid_from` and `valid_until` are unix-seconds (i64 for negative
/// values; in practice always positive). Use `0` for `valid_from` if
/// no lower bound is desired.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityCert {
    pub version: u8,
    pub operator_pubkey: [u8; ED25519_PUBKEY_LEN],
    pub server_id: String,
    pub identity_pubkey: [u8; ED25519_PUBKEY_LEN],
    pub valid_from: i64,
    pub valid_until: i64,
    pub signature: [u8; ED25519_SIG_LEN],
}

impl IdentityCert {
    pub const CURRENT_VERSION: u8 = 1;

    /// Build the canonical preimage that gets signed by the operator
    /// key. Exposed for tests; production callers should use
    /// [`sign_identity_cert`].
    pub fn signing_preimage(
        version: u8,
        operator_pubkey: &[u8; ED25519_PUBKEY_LEN],
        server_id: &str,
        identity_pubkey: &[u8; ED25519_PUBKEY_LEN],
        valid_from: i64,
        valid_until: i64,
    ) -> Vec<u8> {
        let server_id_bytes = server_id.as_bytes();
        let mut p = Vec::with_capacity(
            IDENTITY_CERT_DOMAIN_TAG.len()
                + 1
                + ED25519_PUBKEY_LEN
                + 2
                + server_id_bytes.len()
                + ED25519_PUBKEY_LEN
                + 8
                + 8,
        );
        p.extend_from_slice(IDENTITY_CERT_DOMAIN_TAG);
        p.push(version);
        p.extend_from_slice(operator_pubkey);
        p.extend_from_slice(&(server_id_bytes.len() as u16).to_le_bytes());
        p.extend_from_slice(server_id_bytes);
        p.extend_from_slice(identity_pubkey);
        p.extend_from_slice(&valid_from.to_le_bytes());
        p.extend_from_slice(&valid_until.to_le_bytes());
        p
    }

    /// Verify the signature on this cert. Does NOT check that
    /// `operator_pubkey` matches an expected operator (that's a caller
    /// policy decision: pin one or more operator pubkeys client-side).
    /// Does NOT check `valid_from` / `valid_until` against the current
    /// time — call [`Self::check_validity`] for that.
    pub fn verify(&self) -> Result<(), IdentityError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(IdentityError::UnknownVersion {
                kind: "IdentityCert",
                version: self.version,
            });
        }
        let pk = VerifyingKey::from_bytes(&self.operator_pubkey)
            .map_err(|_| IdentityError::BadPubkey)?;
        let sig = Signature::from_bytes(&self.signature);
        let preimage = Self::signing_preimage(
            self.version,
            &self.operator_pubkey,
            &self.server_id,
            &self.identity_pubkey,
            self.valid_from,
            self.valid_until,
        );
        pk.verify(&preimage, &sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    /// Return `Ok(())` iff `now_unix_seconds` falls in
    /// `[valid_from, valid_until]` (inclusive). `valid_until == 0`
    /// is treated as "no upper bound" — useful for indefinite certs.
    pub fn check_validity(&self, now_unix_seconds: i64) -> Result<(), IdentityError> {
        if now_unix_seconds < self.valid_from {
            return Err(IdentityError::BadSignature); // re-use; cert is not yet valid
        }
        if self.valid_until != 0 && now_unix_seconds > self.valid_until {
            return Err(IdentityError::BadSignature); // cert is expired
        }
        Ok(())
    }

    /// Encode as wire bytes (stable layout — see module docs).
    pub fn encode(&self) -> Vec<u8> {
        let server_id_bytes = self.server_id.as_bytes();
        let mut out = Vec::with_capacity(
            2 + ED25519_PUBKEY_LEN
                + 2
                + server_id_bytes.len()
                + ED25519_PUBKEY_LEN
                + 8
                + 8
                + ED25519_SIG_LEN,
        );
        out.push(self.version);
        out.push(1); // type discriminator: 1 = IdentityCert
        out.extend_from_slice(&self.operator_pubkey);
        out.extend_from_slice(&(server_id_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(server_id_bytes);
        out.extend_from_slice(&self.identity_pubkey);
        out.extend_from_slice(&self.valid_from.to_le_bytes());
        out.extend_from_slice(&self.valid_until.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    /// Strict decode — fails on trailing bytes or unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut p = 0;
        let version = read_u8(bytes, &mut p, "IdentityCert.version")?;
        if version != Self::CURRENT_VERSION {
            return Err(IdentityError::UnknownVersion {
                kind: "IdentityCert",
                version,
            });
        }
        let cert_type = read_u8(bytes, &mut p, "IdentityCert.type")?;
        if cert_type != 1 {
            return Err(IdentityError::UnknownVersion {
                kind: "IdentityCert.type",
                version: cert_type,
            });
        }
        let operator_pubkey = read_fixed::<ED25519_PUBKEY_LEN>(
            bytes,
            &mut p,
            "IdentityCert.operator_pubkey",
        )?;
        let server_id_len =
            read_u16_le(bytes, &mut p, "IdentityCert.server_id_len")? as usize;
        if server_id_len > MAX_SERVER_ID_LEN {
            return Err(IdentityError::FieldTooLong {
                field: "server_id",
                len: server_id_len,
            });
        }
        let server_id_bytes = read_slice(bytes, &mut p, server_id_len, "IdentityCert.server_id")?;
        let server_id = String::from_utf8(server_id_bytes.to_vec())
            .map_err(|_| IdentityError::FieldTooLong {
                field: "server_id (utf8)",
                len: server_id_len,
            })?;
        let identity_pubkey = read_fixed::<ED25519_PUBKEY_LEN>(
            bytes,
            &mut p,
            "IdentityCert.identity_pubkey",
        )?;
        let valid_from = read_i64_le(bytes, &mut p, "IdentityCert.valid_from")?;
        let valid_until = read_i64_le(bytes, &mut p, "IdentityCert.valid_until")?;
        let signature =
            read_fixed::<ED25519_SIG_LEN>(bytes, &mut p, "IdentityCert.signature")?;
        if p != bytes.len() {
            return Err(IdentityError::TrailingBytes(bytes.len() - p));
        }
        Ok(Self {
            version,
            operator_pubkey,
            server_id,
            identity_pubkey,
            valid_from,
            valid_until,
            signature,
        })
    }
}

/// Sign an [`IdentityCert`] with the operator's secret key. Used by
/// `bpir-admin sign-identity` on the operator's workstation; production
/// servers never have the operator secret.
pub fn sign_identity_cert(
    operator_sk: &SigningKey,
    server_id: &str,
    identity_pubkey: [u8; ED25519_PUBKEY_LEN],
    valid_from: i64,
    valid_until: i64,
) -> IdentityCert {
    let operator_pubkey = operator_sk.verifying_key().to_bytes();
    let preimage = IdentityCert::signing_preimage(
        IdentityCert::CURRENT_VERSION,
        &operator_pubkey,
        server_id,
        &identity_pubkey,
        valid_from,
        valid_until,
    );
    let sig = operator_sk.sign(&preimage);
    IdentityCert {
        version: IdentityCert::CURRENT_VERSION,
        operator_pubkey,
        server_id: server_id.to_string(),
        identity_pubkey,
        valid_from,
        valid_until,
        signature: sig.to_bytes(),
    }
}

/// Per-boot Tier-2 manifest. Signed by the server's identity key (held
/// on disk inside the SEV guest / on pir1's filesystem). Commits the
/// long-lived X25519 channel pubkey along with build identifiers so a
/// client can cross-check what binary + git rev + DB manifest the
/// channel pubkey came from.
///
/// `issued_at` is unix-seconds. There is no `valid_until` — the manifest
/// is implicitly fresh because a server reboot mints a new one
/// (per the project's per-boot channel-key rotation invariant).
/// Clients that want to bound replay should check `issued_at` against
/// their own clock and apply a local freshness policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelManifest {
    pub version: u8,
    pub identity_pubkey: [u8; ED25519_PUBKEY_LEN],
    pub server_id: String,
    pub channel_pub: [u8; X25519_PUBKEY_LEN],
    pub binary_sha256: [u8; HASH_LEN],
    pub git_rev: String,
    pub manifest_roots: Vec<[u8; HASH_LEN]>,
    pub issued_at: i64,
    pub signature: [u8; ED25519_SIG_LEN],
}

impl ChannelManifest {
    pub const CURRENT_VERSION: u8 = 1;

    pub fn signing_preimage(
        version: u8,
        identity_pubkey: &[u8; ED25519_PUBKEY_LEN],
        server_id: &str,
        channel_pub: &[u8; X25519_PUBKEY_LEN],
        binary_sha256: &[u8; HASH_LEN],
        git_rev: &str,
        manifest_roots: &[[u8; HASH_LEN]],
        issued_at: i64,
    ) -> Vec<u8> {
        let server_id_bytes = server_id.as_bytes();
        let git_rev_bytes = git_rev.as_bytes();
        let mut p = Vec::with_capacity(
            CHANNEL_MANIFEST_DOMAIN_TAG.len()
                + 1
                + ED25519_PUBKEY_LEN
                + 2
                + server_id_bytes.len()
                + X25519_PUBKEY_LEN
                + HASH_LEN
                + 2
                + git_rev_bytes.len()
                + 1
                + manifest_roots.len() * HASH_LEN
                + 8,
        );
        p.extend_from_slice(CHANNEL_MANIFEST_DOMAIN_TAG);
        p.push(version);
        p.extend_from_slice(identity_pubkey);
        p.extend_from_slice(&(server_id_bytes.len() as u16).to_le_bytes());
        p.extend_from_slice(server_id_bytes);
        p.extend_from_slice(channel_pub);
        p.extend_from_slice(binary_sha256);
        p.extend_from_slice(&(git_rev_bytes.len() as u16).to_le_bytes());
        p.extend_from_slice(git_rev_bytes);
        p.push(manifest_roots.len() as u8);
        for r in manifest_roots {
            p.extend_from_slice(r);
        }
        p.extend_from_slice(&issued_at.to_le_bytes());
        p
    }

    pub fn verify(&self) -> Result<(), IdentityError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(IdentityError::UnknownVersion {
                kind: "ChannelManifest",
                version: self.version,
            });
        }
        let pk = VerifyingKey::from_bytes(&self.identity_pubkey)
            .map_err(|_| IdentityError::BadPubkey)?;
        let sig = Signature::from_bytes(&self.signature);
        let preimage = Self::signing_preimage(
            self.version,
            &self.identity_pubkey,
            &self.server_id,
            &self.channel_pub,
            &self.binary_sha256,
            &self.git_rev,
            &self.manifest_roots,
            self.issued_at,
        );
        pk.verify(&preimage, &sig)
            .map_err(|_| IdentityError::BadSignature)
    }

    pub fn encode(&self) -> Vec<u8> {
        let server_id_bytes = self.server_id.as_bytes();
        let git_rev_bytes = self.git_rev.as_bytes();
        let mut out = Vec::with_capacity(
            2 + ED25519_PUBKEY_LEN
                + 2
                + server_id_bytes.len()
                + X25519_PUBKEY_LEN
                + HASH_LEN
                + 2
                + git_rev_bytes.len()
                + 1
                + self.manifest_roots.len() * HASH_LEN
                + 8
                + ED25519_SIG_LEN,
        );
        out.push(self.version);
        out.push(2); // type discriminator: 2 = ChannelManifest
        out.extend_from_slice(&self.identity_pubkey);
        out.extend_from_slice(&(server_id_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(server_id_bytes);
        out.extend_from_slice(&self.channel_pub);
        out.extend_from_slice(&self.binary_sha256);
        out.extend_from_slice(&(git_rev_bytes.len() as u16).to_le_bytes());
        out.extend_from_slice(git_rev_bytes);
        out.push(self.manifest_roots.len() as u8);
        for r in &self.manifest_roots {
            out.extend_from_slice(r);
        }
        out.extend_from_slice(&self.issued_at.to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut p = 0;
        let version = read_u8(bytes, &mut p, "ChannelManifest.version")?;
        if version != Self::CURRENT_VERSION {
            return Err(IdentityError::UnknownVersion {
                kind: "ChannelManifest",
                version,
            });
        }
        let manifest_type = read_u8(bytes, &mut p, "ChannelManifest.type")?;
        if manifest_type != 2 {
            return Err(IdentityError::UnknownVersion {
                kind: "ChannelManifest.type",
                version: manifest_type,
            });
        }
        let identity_pubkey = read_fixed::<ED25519_PUBKEY_LEN>(
            bytes,
            &mut p,
            "ChannelManifest.identity_pubkey",
        )?;
        let server_id_len =
            read_u16_le(bytes, &mut p, "ChannelManifest.server_id_len")? as usize;
        if server_id_len > MAX_SERVER_ID_LEN {
            return Err(IdentityError::FieldTooLong {
                field: "server_id",
                len: server_id_len,
            });
        }
        let server_id_bytes =
            read_slice(bytes, &mut p, server_id_len, "ChannelManifest.server_id")?;
        let server_id = String::from_utf8(server_id_bytes.to_vec())
            .map_err(|_| IdentityError::FieldTooLong {
                field: "server_id (utf8)",
                len: server_id_len,
            })?;
        let channel_pub = read_fixed::<X25519_PUBKEY_LEN>(
            bytes,
            &mut p,
            "ChannelManifest.channel_pub",
        )?;
        let binary_sha256 =
            read_fixed::<HASH_LEN>(bytes, &mut p, "ChannelManifest.binary_sha256")?;
        let git_rev_len =
            read_u16_le(bytes, &mut p, "ChannelManifest.git_rev_len")? as usize;
        if git_rev_len > MAX_GIT_REV_LEN {
            return Err(IdentityError::FieldTooLong {
                field: "git_rev",
                len: git_rev_len,
            });
        }
        let git_rev_bytes = read_slice(bytes, &mut p, git_rev_len, "ChannelManifest.git_rev")?;
        let git_rev = String::from_utf8(git_rev_bytes.to_vec())
            .map_err(|_| IdentityError::FieldTooLong {
                field: "git_rev (utf8)",
                len: git_rev_len,
            })?;
        let n_roots = read_u8(bytes, &mut p, "ChannelManifest.n_roots")? as usize;
        if n_roots > MAX_MANIFEST_ROOTS {
            return Err(IdentityError::TooManyManifestRoots(n_roots));
        }
        let mut manifest_roots = Vec::with_capacity(n_roots);
        for i in 0..n_roots {
            let root = read_fixed::<HASH_LEN>(
                bytes,
                &mut p,
                if i == 0 {
                    "ChannelManifest.manifest_roots[0]"
                } else {
                    "ChannelManifest.manifest_roots[i]"
                },
            )?;
            manifest_roots.push(root);
        }
        let issued_at = read_i64_le(bytes, &mut p, "ChannelManifest.issued_at")?;
        let signature =
            read_fixed::<ED25519_SIG_LEN>(bytes, &mut p, "ChannelManifest.signature")?;
        if p != bytes.len() {
            return Err(IdentityError::TrailingBytes(bytes.len() - p));
        }
        Ok(Self {
            version,
            identity_pubkey,
            server_id,
            channel_pub,
            binary_sha256,
            git_rev,
            manifest_roots,
            issued_at,
            signature,
        })
    }
}

/// Sign a [`ChannelManifest`] with the server's identity key. Used by
/// the unified_server at boot.
pub fn sign_channel_manifest(
    identity_sk: &SigningKey,
    server_id: &str,
    channel_pub: [u8; X25519_PUBKEY_LEN],
    binary_sha256: [u8; HASH_LEN],
    git_rev: &str,
    manifest_roots: Vec<[u8; HASH_LEN]>,
    issued_at: i64,
) -> ChannelManifest {
    let identity_pubkey = identity_sk.verifying_key().to_bytes();
    let preimage = ChannelManifest::signing_preimage(
        ChannelManifest::CURRENT_VERSION,
        &identity_pubkey,
        server_id,
        &channel_pub,
        &binary_sha256,
        git_rev,
        &manifest_roots,
        issued_at,
    );
    let sig = identity_sk.sign(&preimage);
    ChannelManifest {
        version: ChannelManifest::CURRENT_VERSION,
        identity_pubkey,
        server_id: server_id.to_string(),
        channel_pub,
        binary_sha256,
        git_rev: git_rev.to_string(),
        manifest_roots,
        issued_at,
        signature: sig.to_bytes(),
    }
}

/// Full server announcement bundle returned by REQ_ANNOUNCE. The
/// client verifies it in this order:
///
/// 1. `cert.verify()` using a pinned `operator_pubkey` (caller policy).
/// 2. `cert.check_validity(now)` for the current wall-clock time.
/// 3. `manifest.verify()` using `manifest.identity_pubkey`.
/// 4. Cross-checks:
///    * `manifest.identity_pubkey == cert.identity_pubkey`
///    * `manifest.server_id == cert.server_id`
/// 5. Apply the caller's freshness policy on `manifest.issued_at`.
///
/// Step 1 is currently optional in the client (the operator pubkey
/// publishing mechanism is being designed — see the project notes on
/// Nostr distribution). When the operator pubkey becomes pinned, the
/// caller MUST run step 1, otherwise the chain is unauthenticated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnnouncementBundle {
    pub cert: IdentityCert,
    pub manifest: ChannelManifest,
}

impl AnnouncementBundle {
    /// Run the chain check (steps 3 + 4 of the verify flow above).
    /// Caller still owns steps 1 / 2 / 5 (pinning policy + freshness).
    pub fn verify_chain(&self) -> Result<(), IdentityError> {
        self.manifest.verify()?;
        if self.manifest.identity_pubkey != self.cert.identity_pubkey {
            return Err(IdentityError::BadSignature);
        }
        if self.manifest.server_id != self.cert.server_id {
            return Err(IdentityError::BadSignature);
        }
        Ok(())
    }

    /// Encode bundle as `[cert_len:u32 LE][cert bytes][manifest_len:u32 LE][manifest bytes]`.
    pub fn encode(&self) -> Vec<u8> {
        let cert_bytes = self.cert.encode();
        let manifest_bytes = self.manifest.encode();
        let mut out =
            Vec::with_capacity(4 + cert_bytes.len() + 4 + manifest_bytes.len());
        out.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&cert_bytes);
        out.extend_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&manifest_bytes);
        out
    }

    /// Strict decode, mirroring [`Self::encode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        let mut p = 0;
        let cert_len = read_u32_le(bytes, &mut p, "AnnouncementBundle.cert_len")? as usize;
        let cert_bytes = read_slice(bytes, &mut p, cert_len, "AnnouncementBundle.cert")?;
        let cert = IdentityCert::decode(cert_bytes)?;
        let manifest_len =
            read_u32_le(bytes, &mut p, "AnnouncementBundle.manifest_len")? as usize;
        let manifest_bytes =
            read_slice(bytes, &mut p, manifest_len, "AnnouncementBundle.manifest")?;
        let manifest = ChannelManifest::decode(manifest_bytes)?;
        if p != bytes.len() {
            return Err(IdentityError::TrailingBytes(bytes.len() - p));
        }
        Ok(Self { cert, manifest })
    }
}

// ───── decode helpers ─────────────────────────────────────────────────

fn read_u8(buf: &[u8], pos: &mut usize, field: &'static str) -> Result<u8, IdentityError> {
    if *pos + 1 > buf.len() {
        return Err(IdentityError::Truncated(field));
    }
    let v = buf[*pos];
    *pos += 1;
    Ok(v)
}

fn read_u16_le(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<u16, IdentityError> {
    if *pos + 2 > buf.len() {
        return Err(IdentityError::Truncated(field));
    }
    let v = u16::from_le_bytes(buf[*pos..*pos + 2].try_into().unwrap());
    *pos += 2;
    Ok(v)
}

fn read_u32_le(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<u32, IdentityError> {
    if *pos + 4 > buf.len() {
        return Err(IdentityError::Truncated(field));
    }
    let v = u32::from_le_bytes(buf[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Ok(v)
}

fn read_i64_le(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<i64, IdentityError> {
    if *pos + 8 > buf.len() {
        return Err(IdentityError::Truncated(field));
    }
    let v = i64::from_le_bytes(buf[*pos..*pos + 8].try_into().unwrap());
    *pos += 8;
    Ok(v)
}

fn read_fixed<const N: usize>(
    buf: &[u8],
    pos: &mut usize,
    field: &'static str,
) -> Result<[u8; N], IdentityError> {
    if *pos + N > buf.len() {
        return Err(IdentityError::Truncated(field));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}

fn read_slice<'a>(
    buf: &'a [u8],
    pos: &mut usize,
    n: usize,
    field: &'static str,
) -> Result<&'a [u8], IdentityError> {
    if *pos + n > buf.len() {
        return Err(IdentityError::Truncated(field));
    }
    let out = &buf[*pos..*pos + n];
    *pos += n;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fake_sk(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn identity_cert_sign_then_verify_ok() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            1_700_000_000,
            1_800_000_000,
        );
        cert.verify().expect("honest cert must verify");
    }

    #[test]
    fn identity_cert_tampered_server_id_fails() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let mut cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        cert.server_id = "pir2".into(); // attacker re-targets
        assert!(matches!(cert.verify(), Err(IdentityError::BadSignature)));
    }

    #[test]
    fn identity_cert_tampered_identity_pub_fails() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let mut cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        cert.identity_pubkey = fake_sk(0x33).verifying_key().to_bytes();
        assert!(matches!(cert.verify(), Err(IdentityError::BadSignature)));
    }

    #[test]
    fn identity_cert_wrong_operator_pubkey_fails() {
        let op_sk = fake_sk(0x11);
        let attacker_sk = fake_sk(0x99);
        let id_sk = fake_sk(0x22);
        let mut cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        // Attacker swaps the bound operator_pubkey — preimage diverges
        // and the signature (still made by op_sk) no longer matches.
        cert.operator_pubkey = attacker_sk.verifying_key().to_bytes();
        assert!(matches!(cert.verify(), Err(IdentityError::BadSignature)));
    }

    #[test]
    fn identity_cert_roundtrip_encode_decode() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1.example.org",
            id_sk.verifying_key().to_bytes(),
            42,
            1_800_000_000,
        );
        let bytes = cert.encode();
        let parsed = IdentityCert::decode(&bytes).expect("roundtrip decode");
        assert_eq!(cert, parsed);
        parsed.verify().expect("parsed cert verifies");
    }

    #[test]
    fn identity_cert_trailing_bytes_rejected() {
        let op_sk = fake_sk(0x11);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            fake_sk(0x22).verifying_key().to_bytes(),
            0,
            0,
        );
        let mut bytes = cert.encode();
        bytes.push(0xff);
        assert!(matches!(
            IdentityCert::decode(&bytes),
            Err(IdentityError::TrailingBytes(_))
        ));
    }

    #[test]
    fn identity_cert_unknown_version_rejected() {
        let op_sk = fake_sk(0x11);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            fake_sk(0x22).verifying_key().to_bytes(),
            0,
            0,
        );
        let mut bytes = cert.encode();
        bytes[0] = 99; // mangle version
        assert!(matches!(
            IdentityCert::decode(&bytes),
            Err(IdentityError::UnknownVersion { .. })
        ));
    }

    #[test]
    fn identity_cert_validity_window_checks() {
        let op_sk = fake_sk(0x11);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            fake_sk(0x22).verifying_key().to_bytes(),
            100,
            200,
        );
        assert!(cert.check_validity(50).is_err()); // before
        assert!(cert.check_validity(150).is_ok()); // inside
        assert!(cert.check_validity(250).is_err()); // after

        // valid_until == 0 → indefinite upper bound
        let cert2 = sign_identity_cert(
            &op_sk,
            "pir1",
            fake_sk(0x22).verifying_key().to_bytes(),
            100,
            0,
        );
        assert!(cert2.check_validity(50).is_err()); // still has lower bound
        assert!(cert2.check_validity(1_000_000_000).is_ok()); // indefinite up
    }

    #[test]
    fn channel_manifest_sign_then_verify_ok() {
        let id_sk = fake_sk(0x22);
        let manifest = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0xCCu8; 32],
            [0xAAu8; 32],
            "abc1234",
            vec![[0x11u8; 32], [0x22u8; 32]],
            1_700_000_000,
        );
        manifest.verify().expect("honest manifest must verify");
    }

    #[test]
    fn channel_manifest_tampered_channel_pub_fails() {
        let id_sk = fake_sk(0x22);
        let mut m = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0xCCu8; 32],
            [0xAAu8; 32],
            "abc",
            vec![],
            0,
        );
        m.channel_pub = [0xDDu8; 32];
        assert!(matches!(m.verify(), Err(IdentityError::BadSignature)));
    }

    #[test]
    fn channel_manifest_tampered_binary_sha_fails() {
        let id_sk = fake_sk(0x22);
        let mut m = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0xCCu8; 32],
            [0xAAu8; 32],
            "abc",
            vec![],
            0,
        );
        m.binary_sha256 = [0xBBu8; 32];
        assert!(matches!(m.verify(), Err(IdentityError::BadSignature)));
    }

    #[test]
    fn channel_manifest_roundtrip_with_empty_roots() {
        let id_sk = fake_sk(0x22);
        let m = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0x55u8; 32],
            [0x66u8; 32],
            "deadbeef",
            vec![],
            1_700_000_001,
        );
        let bytes = m.encode();
        let parsed = ChannelManifest::decode(&bytes).unwrap();
        assert_eq!(m, parsed);
        parsed.verify().unwrap();
    }

    #[test]
    fn channel_manifest_roundtrip_with_max_roots() {
        let id_sk = fake_sk(0x22);
        let roots = (0..MAX_MANIFEST_ROOTS).map(|i| [i as u8; 32]).collect();
        let m = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0u8; 32],
            [0u8; 32],
            "v1",
            roots,
            0,
        );
        let bytes = m.encode();
        let parsed = ChannelManifest::decode(&bytes).unwrap();
        assert_eq!(m, parsed);
        parsed.verify().unwrap();
    }

    #[test]
    fn channel_manifest_too_many_roots_rejected_on_decode() {
        // Craft a malicious blob claiming 200 roots — must reject.
        let id_sk = fake_sk(0x22);
        let m = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0u8; 32],
            [0u8; 32],
            "v1",
            vec![],
            0,
        );
        let mut bytes = m.encode();
        // Find the n_roots byte position: header is 2 + 32 + 2 + |server_id|
        // + 32 + 32 + 2 + |git_rev| = 2 + 32 + 2 + 4 + 32 + 32 + 2 + 2 = 108
        let nroots_offset =
            2 + ED25519_PUBKEY_LEN + 2 + "pir1".len() + X25519_PUBKEY_LEN + HASH_LEN + 2 + "v1".len();
        bytes[nroots_offset] = 200;
        assert!(matches!(
            ChannelManifest::decode(&bytes),
            Err(IdentityError::TooManyManifestRoots(200)) | Err(IdentityError::Truncated(_))
        ));
    }

    #[test]
    fn announcement_bundle_chain_check_ok() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        let manifest = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0xCCu8; 32],
            [0xAAu8; 32],
            "abc",
            vec![],
            1_700_000_000,
        );
        let bundle = AnnouncementBundle { cert, manifest };
        bundle.verify_chain().expect("matching chain must verify");
    }

    #[test]
    fn announcement_bundle_server_id_mismatch_fails() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            0,
            0,
        );
        // Attacker takes a valid cert for pir1 but pairs it with a
        // manifest claiming server_id = "pir2". Even though both
        // signatures verify in isolation, the chain cross-check
        // catches the mismatch.
        let manifest = sign_channel_manifest(
            &id_sk,
            "pir2", // ≠ cert.server_id
            [0xCCu8; 32],
            [0xAAu8; 32],
            "abc",
            vec![],
            0,
        );
        let bundle = AnnouncementBundle { cert, manifest };
        assert!(matches!(
            bundle.verify_chain(),
            Err(IdentityError::BadSignature)
        ));
    }

    #[test]
    fn announcement_bundle_identity_pub_mismatch_fails() {
        let op_sk = fake_sk(0x11);
        let id_sk_a = fake_sk(0x22);
        let id_sk_b = fake_sk(0x33);
        // cert endorses id_sk_a, but manifest is signed by id_sk_b.
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk_a.verifying_key().to_bytes(),
            0,
            0,
        );
        let manifest = sign_channel_manifest(
            &id_sk_b,
            "pir1",
            [0u8; 32],
            [0u8; 32],
            "v",
            vec![],
            0,
        );
        let bundle = AnnouncementBundle { cert, manifest };
        assert!(matches!(
            bundle.verify_chain(),
            Err(IdentityError::BadSignature)
        ));
    }

    #[test]
    fn announcement_bundle_encode_decode_roundtrip() {
        let op_sk = fake_sk(0x11);
        let id_sk = fake_sk(0x22);
        let cert = sign_identity_cert(
            &op_sk,
            "pir1",
            id_sk.verifying_key().to_bytes(),
            42,
            1_800_000_000,
        );
        let manifest = sign_channel_manifest(
            &id_sk,
            "pir1",
            [0xCCu8; 32],
            [0xAAu8; 32],
            "abc",
            vec![[0x11u8; 32]],
            1_700_000_000,
        );
        let bundle = AnnouncementBundle { cert, manifest };
        let bytes = bundle.encode();
        let parsed = AnnouncementBundle::decode(&bytes).unwrap();
        assert_eq!(bundle, parsed);
        parsed.verify_chain().unwrap();
    }

    #[test]
    fn domain_tags_are_distinct() {
        // No risk of cross-protocol confusion: a signature over an
        // IdentityCert preimage cannot be re-used as a ChannelManifest
        // signature (or vice versa) because the domain tags differ.
        assert_ne!(IDENTITY_CERT_DOMAIN_TAG, CHANNEL_MANIFEST_DOMAIN_TAG);
    }
}
