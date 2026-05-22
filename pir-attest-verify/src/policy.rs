// Variants in `PolicyError` and pinned-field structs in
// `PolicyRequirements` are self-documenting from context (their
// Display impls + the surrounding docstrings), and adding /// to
// every `actual`/`expected` field pair clutters the source without
// adding information. Allow missing-docs on this module's struct
// fields and enum payloads — the module-level docstring covers it.
#![allow(missing_docs)]

//! Policy checks on a parsed [`SnpReport`].
//!
//! Cryptographic verification ([`crate::verify_chain`] +
//! [`crate::verify_report_against_vcek`]) only proves the report was
//! signed by an AMD SEV-SNP chip whose VCEK chains back to AMD's ARK.
//! It does NOT prove the report's *contents* are acceptable — a fully
//! valid signature is no use if the guest was launched with debug
//! mode enabled, or VMPL ≠ 0, or running an old TCB the operator
//! considers vulnerable.
//!
//! This module bundles the runtime-configurable policy that production
//! verifiers should apply ON TOP of the signature check. The default
//! [`PolicyRequirements`] is what BitcoinPIR's `unified_server`
//! expects: VMPL 0, no debug, no MA migration, TCB-monotonic (no
//! claimed-newer-than-committed downgrade attack).
//!
//! ## What this module does NOT check
//!
//! - **`chip_id` vs the VCEK's HWID extension.** Modern VCEKs have a
//!   1.3.6.1.4.1.3704.1.4 OID extension binding the cert to a
//!   specific chip's hardware ID; the report's `chip_id` field
//!   should match. The `sev` crate doesn't currently expose the
//!   parsed VCEK extension fields, and writing an X.509-extension
//!   walker for the wasm32 target is out of scope here. If the
//!   server-supplied VCEK is the wrong one for this chip, the
//!   report-signature check still catches it (the VCEK pubkey
//!   wouldn't verify the chip-emitted signature). The HWID check is
//!   strictly defense-in-depth.
//! - **Replay across boots.** A report's `report_data` covers a
//!   one-shot client nonce in BitcoinPIR's V2 layout, so a captured
//!   report can't be re-used against a different client. This
//!   module doesn't enforce that — it's a `pir-sdk-client::attest`
//!   concern.

use crate::SnpReport;
use sev::firmware::host::TcbVersion;

/// Caller-supplied policy: which contents are acceptable when the
/// chain + signature already passed.
///
/// Default = strictest production stance: VMPL 0, debug forbidden, MA
/// migration forbidden, TCB-monotonic. Override individual fields if
/// you need a looser stance (e.g. tests that mint debug guests).
#[derive(Clone, Debug)]
pub struct PolicyRequirements {
    /// Maximum allowed VMPL. Production wants `0` (highest
    /// privilege; only the guest itself can sign reports at that
    /// level). Tests may relax.
    pub max_vmpl: u32,
    /// Whether the guest's `policy.debug_allowed` bit may be set.
    /// Production: `false` (a debug-mode guest can dump memory to
    /// the host).
    pub allow_debug: bool,
    /// Whether the guest's `policy.migrate_ma_allowed` bit may be set.
    /// Production: `false` (a migration agent can exfiltrate guest
    /// state at migration time).
    pub allow_migrate_ma: bool,
    /// If `true`, require the guest's `policy.single_socket_required`
    /// bit to be set. Defaults to `false` — VPSBG's deployments are
    /// single-host without needing the assertion. Tighten if you
    /// want explicit anti-cross-socket-side-channel coverage.
    pub require_single_socket: bool,
    /// Minimum TCB version the operator considers safe. `None`
    /// disables the lower-bound check (only TCB monotonicity is
    /// enforced — `reported_tcb` ≤ `committed_tcb`). Set to the
    /// last-known-good TCB after a microcode/firmware update.
    pub min_tcb: Option<TcbVersion>,
    /// Pinned MEASUREMENT bytes. `None` skips. Set to the operator-
    /// published value (e.g. from the production attest-pin file)
    /// to lock the verifier to a specific UKI build.
    pub expected_measurement: Option<[u8; 48]>,
    /// Pinned family/image ID pair. `None` skips. Useful for
    /// catching the case where the chain + sig validate but the
    /// guest was launched with a different launch-data set than the
    /// operator runs in production.
    pub expected_family_id: Option<[u8; 16]>,
    pub expected_image_id: Option<[u8; 16]>,
}

impl Default for PolicyRequirements {
    fn default() -> Self {
        Self {
            max_vmpl: 0,
            allow_debug: false,
            allow_migrate_ma: false,
            require_single_socket: false,
            min_tcb: None,
            expected_measurement: None,
            expected_family_id: None,
            expected_image_id: None,
        }
    }
}

/// Things the policy can reject. Distinct from
/// [`crate::VerifyError`] because policy failures are *configurable*
/// — a different verifier could legitimately accept what this one
/// rejects (e.g. a CI rig that allows debug guests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Report's VMPL exceeds the policy maximum.
    VmplTooHigh { actual: u32, max: u32 },
    /// `policy.debug_allowed` was set but the verifier disallows it.
    DebugNotAllowed,
    /// `policy.migrate_ma_allowed` was set but the verifier
    /// disallows it.
    MigrateMaNotAllowed,
    /// Verifier required `policy.single_socket_required` but it was
    /// clear in the report.
    NotSingleSocket,
    /// Reported TCB exceeds the chip's committed TCB — i.e. the
    /// firmware is claiming a higher security version than the chip
    /// has actually shipped. Should be impossible on real hardware;
    /// fail loud.
    ReportedTcbExceedsCommitted {
        reported: TcbVersion,
        committed: TcbVersion,
    },
    /// Reported TCB is below the operator-configured minimum.
    /// Indicates the guest is running on chip firmware older than
    /// the operator's "last-known-safe" threshold.
    TcbBelowMinimum {
        reported: TcbVersion,
        min: TcbVersion,
    },
    /// MEASUREMENT field doesn't match the operator pin.
    MeasurementMismatch {
        actual: [u8; 48],
        expected: [u8; 48],
    },
    /// `family_id` doesn't match the operator pin.
    FamilyIdMismatch {
        actual: [u8; 16],
        expected: [u8; 16],
    },
    /// `image_id` doesn't match the operator pin.
    ImageIdMismatch {
        actual: [u8; 16],
        expected: [u8; 16],
    },
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VmplTooHigh { actual, max } => {
                write!(f, "VMPL {} exceeds max {}", actual, max)
            }
            Self::DebugNotAllowed => write!(f, "guest policy allows debug"),
            Self::MigrateMaNotAllowed => {
                write!(f, "guest policy allows MA migration")
            }
            Self::NotSingleSocket => {
                write!(f, "guest policy lacks single_socket_required")
            }
            Self::ReportedTcbExceedsCommitted {
                reported,
                committed,
            } => write!(
                f,
                "reported TCB {:?} > committed TCB {:?}",
                reported, committed
            ),
            Self::TcbBelowMinimum { reported, min } => {
                write!(f, "reported TCB {:?} < required min {:?}", reported, min)
            }
            Self::MeasurementMismatch { actual, expected } => write!(
                f,
                "MEASUREMENT mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual),
            ),
            Self::FamilyIdMismatch { actual, expected } => write!(
                f,
                "family_id mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual),
            ),
            Self::ImageIdMismatch { actual, expected } => write!(
                f,
                "image_id mismatch: expected {}, got {}",
                hex::encode(expected),
                hex::encode(actual),
            ),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Apply the policy to a parsed [`SnpReport`]. Returns `Ok(())` if
/// every check passes; otherwise the first failure (checks are
/// short-circuiting in a stable order — see the source).
///
/// **Order matters for readability of failure messages**: VMPL → policy
/// bits → TCB monotonicity → TCB minimum → measurement → family/image.
/// Callers should NOT depend on a specific order of multiple
/// concurrent violations, but the order is stable for a given build.
pub fn verify_policy(report: &SnpReport, req: &PolicyRequirements) -> Result<(), PolicyError> {
    if report.vmpl > req.max_vmpl {
        return Err(PolicyError::VmplTooHigh {
            actual: report.vmpl,
            max: req.max_vmpl,
        });
    }
    if !req.allow_debug && report.policy.debug_allowed() {
        return Err(PolicyError::DebugNotAllowed);
    }
    if !req.allow_migrate_ma && report.policy.migrate_ma_allowed() {
        return Err(PolicyError::MigrateMaNotAllowed);
    }
    if req.require_single_socket && !report.policy.single_socket_required() {
        return Err(PolicyError::NotSingleSocket);
    }
    // TCB monotonicity: the firmware claiming a higher reported_tcb
    // than what's been actually committed by the chip would be a
    // bug-or-tamper signal.
    if report.reported_tcb > report.committed_tcb {
        return Err(PolicyError::ReportedTcbExceedsCommitted {
            reported: report.reported_tcb,
            committed: report.committed_tcb,
        });
    }
    if let Some(min) = req.min_tcb {
        if report.reported_tcb < min {
            return Err(PolicyError::TcbBelowMinimum {
                reported: report.reported_tcb,
                min,
            });
        }
    }
    if let Some(exp) = req.expected_measurement {
        if report.measurement != exp {
            return Err(PolicyError::MeasurementMismatch {
                actual: report.measurement,
                expected: exp,
            });
        }
    }
    if let Some(exp) = req.expected_family_id {
        if report.family_id != exp {
            return Err(PolicyError::FamilyIdMismatch {
                actual: report.family_id,
                expected: exp,
            });
        }
    }
    if let Some(exp) = req.expected_image_id {
        if report.image_id != exp {
            return Err(PolicyError::ImageIdMismatch {
                actual: report.image_id,
                expected: exp,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_report() -> SnpReport {
        // The sev crate's Default impl gives us a report with all
        // fields zeroed. That happens to satisfy the strict default
        // policy (vmpl 0, all flag bits cleared) — so we use it as a
        // baseline and tamper specific fields per test.
        SnpReport::default()
    }

    #[test]
    fn default_policy_accepts_default_report() {
        // A zero-filled report has VMPL 0, no debug, no migrate, etc.
        // The strict default policy accepts it.
        verify_policy(&base_report(), &PolicyRequirements::default()).unwrap();
    }

    #[test]
    fn vmpl_too_high_rejected() {
        let mut r = base_report();
        r.vmpl = 1;
        let err = verify_policy(&r, &PolicyRequirements::default()).unwrap_err();
        assert!(
            matches!(err, PolicyError::VmplTooHigh { actual: 1, max: 0 }),
            "{:?}",
            err
        );
    }

    #[test]
    fn vmpl_within_allowance_accepted() {
        let mut r = base_report();
        r.vmpl = 2;
        let req = PolicyRequirements {
            max_vmpl: 3,
            ..PolicyRequirements::default()
        };
        verify_policy(&r, &req).unwrap();
    }

    #[test]
    fn debug_bit_rejected_by_default() {
        let mut r = base_report();
        r.policy.set_debug_allowed(true);
        let err = verify_policy(&r, &PolicyRequirements::default()).unwrap_err();
        assert!(matches!(err, PolicyError::DebugNotAllowed), "{:?}", err);
    }

    #[test]
    fn debug_bit_accepted_when_policy_relaxed() {
        let mut r = base_report();
        r.policy.set_debug_allowed(true);
        let req = PolicyRequirements {
            allow_debug: true,
            ..PolicyRequirements::default()
        };
        verify_policy(&r, &req).unwrap();
    }

    #[test]
    fn migrate_ma_bit_rejected_by_default() {
        let mut r = base_report();
        r.policy.set_migrate_ma_allowed(true);
        let err = verify_policy(&r, &PolicyRequirements::default()).unwrap_err();
        assert!(matches!(err, PolicyError::MigrateMaNotAllowed), "{:?}", err);
    }

    #[test]
    fn single_socket_required_when_policy_demands() {
        // Default report has single_socket clear → require=true rejects.
        let req = PolicyRequirements {
            require_single_socket: true,
            ..PolicyRequirements::default()
        };
        let err = verify_policy(&base_report(), &req).unwrap_err();
        assert!(matches!(err, PolicyError::NotSingleSocket), "{:?}", err);
    }

    #[test]
    fn reported_tcb_above_committed_is_rejected() {
        let mut r = base_report();
        r.reported_tcb = TcbVersion {
            fmc: None,
            bootloader: 5,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        r.committed_tcb = TcbVersion {
            fmc: None,
            bootloader: 3,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        let err = verify_policy(&r, &PolicyRequirements::default()).unwrap_err();
        assert!(
            matches!(err, PolicyError::ReportedTcbExceedsCommitted { .. }),
            "{:?}",
            err
        );
    }

    #[test]
    fn tcb_below_minimum_is_rejected() {
        let mut r = base_report();
        r.reported_tcb = TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        r.committed_tcb = r.reported_tcb;
        let req = PolicyRequirements {
            min_tcb: Some(TcbVersion {
                fmc: None,
                bootloader: 5,
                tee: 0,
                snp: 0,
                microcode: 0,
            }),
            ..PolicyRequirements::default()
        };
        let err = verify_policy(&r, &req).unwrap_err();
        assert!(matches!(err, PolicyError::TcbBelowMinimum { .. }), "{:?}", err);
    }

    #[test]
    fn tcb_at_minimum_is_accepted() {
        let mut r = base_report();
        r.reported_tcb = TcbVersion {
            fmc: None,
            bootloader: 5,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        r.committed_tcb = r.reported_tcb;
        let req = PolicyRequirements {
            min_tcb: Some(r.reported_tcb),
            ..PolicyRequirements::default()
        };
        verify_policy(&r, &req).unwrap();
    }

    #[test]
    fn measurement_mismatch_rejected() {
        let mut r = base_report();
        r.measurement = [0xAAu8; 48];
        let req = PolicyRequirements {
            expected_measurement: Some([0xBBu8; 48]),
            ..PolicyRequirements::default()
        };
        let err = verify_policy(&r, &req).unwrap_err();
        assert!(
            matches!(err, PolicyError::MeasurementMismatch { .. }),
            "{:?}",
            err
        );
    }

    #[test]
    fn measurement_match_accepted() {
        let mut r = base_report();
        r.measurement = [0xCCu8; 48];
        let req = PolicyRequirements {
            expected_measurement: Some([0xCCu8; 48]),
            ..PolicyRequirements::default()
        };
        verify_policy(&r, &req).unwrap();
    }

    #[test]
    fn family_id_mismatch_rejected() {
        let mut r = base_report();
        r.family_id = [0x11u8; 16];
        let req = PolicyRequirements {
            expected_family_id: Some([0x22u8; 16]),
            ..PolicyRequirements::default()
        };
        let err = verify_policy(&r, &req).unwrap_err();
        assert!(matches!(err, PolicyError::FamilyIdMismatch { .. }), "{:?}", err);
    }

    #[test]
    fn image_id_mismatch_rejected() {
        let mut r = base_report();
        r.image_id = [0x33u8; 16];
        let req = PolicyRequirements {
            expected_image_id: Some([0x44u8; 16]),
            ..PolicyRequirements::default()
        };
        let err = verify_policy(&r, &req).unwrap_err();
        assert!(matches!(err, PolicyError::ImageIdMismatch { .. }), "{:?}", err);
    }

    #[test]
    fn policy_short_circuits_on_first_failure() {
        // VMPL fails first → we don't get a TCB error even though
        // TCB would also fail.
        let mut r = base_report();
        r.vmpl = 99;
        r.reported_tcb = TcbVersion {
            fmc: None,
            bootloader: 200,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        r.committed_tcb = TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        let err = verify_policy(&r, &PolicyRequirements::default()).unwrap_err();
        assert!(matches!(err, PolicyError::VmplTooHigh { .. }), "{:?}", err);
    }

    #[test]
    fn display_includes_hex_for_pinned_fields() {
        let e = PolicyError::MeasurementMismatch {
            actual: [0xAA; 48],
            expected: [0xBB; 48],
        };
        let s = e.to_string();
        assert!(s.contains("MEASUREMENT mismatch"));
        assert!(s.contains(&"aa".repeat(48)));
        assert!(s.contains(&"bb".repeat(48)));
    }
}
