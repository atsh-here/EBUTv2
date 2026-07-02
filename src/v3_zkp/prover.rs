use ff::Field; // FIX: Gives access to BlsScalar::random()
use crate::v3_zkp::batched_eq::BatchedEqualityProof;
use crate::v3_zkp::gap::{GapProof, ServerPublicKey};
use crate::v3_zkp::generators::{bls_g1_affine, bls_h1_affine, ristretto_g1, ristretto_gv};

use blstrs::{G1Projective, Scalar as BlsScalar};
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as RistrettoScalar;
use curve25519_dalek_ng::traits::VartimeMultiscalarMul;
use merlin::Transcript;
use rand::rngs::OsRng;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use crate::error::{ActError, Result};

static REV_BP_GENS_32: OnceLock<BulletproofGens> = OnceLock::new();
static REV_BP_GENS_64: OnceLock<BulletproofGens> = OnceLock::new();
static REV_PC_GENS: OnceLock<PedersenGens> = OnceLock::new();

fn rev_bp_gens(bits: usize) -> &'static BulletproofGens {
    match bits {
        32 => REV_BP_GENS_32.get_or_init(|| BulletproofGens::new(32, 2)),
        64 => REV_BP_GENS_64.get_or_init(|| BulletproofGens::new(64, 2)),
        _ => REV_BP_GENS_64.get_or_init(|| BulletproofGens::new(64, 2)),
    }
}

#[inline]
fn rev_range_bits(diff1: u64, diff2: u64) -> usize {
    if diff1 <= u32::MAX as u64 && diff2 <= u32::MAX as u64 { 32 } else { 64 }
}

fn rev_pc_gens() -> &'static PedersenGens {
    REV_PC_GENS.get_or_init(PedersenGens::default)
}


#[derive(Clone)]
pub struct NonMembershipProof {
    pub com_ea_rist: RistrettoPoint,
    pub com_eb_rist: RistrettoPoint,
    pub batched_eq_proof: BatchedEqualityProof,
    pub gap_proof: GapProof,
    pub aggregated_range_proof: RangeProof,
    pub com_diff1: RistrettoPoint,
    pub com_diff2: RistrettoPoint,
    pub range_bits: usize,
}

#[derive(Clone)]
pub struct TimedProof {
    pub proof: NonMembershipProof,
    pub times: ProverTiming,
    pub sizes: ProofSizes,
}

#[derive(Default, Clone)]
pub struct ProverTiming { 
    pub eq_batched: Duration, 
    pub gap: Duration, 
    pub range: Duration, 
    pub total: Duration 
}

#[derive(Default, Clone)]
pub struct VerifierTiming {
    pub eq_batched: Duration, pub gap: Duration, pub external: Duration, pub range: Duration, pub total: Duration,
}

#[derive(Clone)]
pub struct ProofSizes {
    pub eq_batched: usize, pub gap: usize, pub range: usize, pub total: usize,
}

pub fn create_non_membership_proof_timed(
    secret_e: u64, r1_e: RistrettoScalar, r2_e: BlsScalar, server_pk: &ServerPublicKey,
    interval: (u64, u64), sigma: (G1Projective, G1Projective),
    r2_ea: BlsScalar, r2_eb: BlsScalar, r1_ea: RistrettoScalar, r1_eb: RistrettoScalar,
) -> Result<TimedProof> {
    create_non_membership_proof_timed_with_context(
        secret_e, r1_e, r2_e, server_pk, interval, sigma, r2_ea, r2_eb, r1_ea, r1_eb, BlsScalar::ZERO,
    )
}

pub fn create_non_membership_proof_timed_with_context(
    secret_e: u64, r1_e: RistrettoScalar, r2_e: BlsScalar, server_pk: &ServerPublicKey,
    interval: (u64, u64), sigma: (G1Projective, G1Projective),
    r2_ea: BlsScalar, r2_eb: BlsScalar, r1_ea: RistrettoScalar, r1_eb: RistrettoScalar,
    gap_ctx: BlsScalar,
) -> Result<TimedProof> {
    create_non_membership_proof_timed_with_context_and_bases(
        secret_e, r1_e, r2_e, server_pk, interval, sigma, r2_ea, r2_eb, r1_ea, r1_eb, gap_ctx,
        G1Projective::from(bls_g1_affine()),
        G1Projective::from(bls_h1_affine()),
    )
}

/// Create a signed-gap non-membership proof when the BLS-side commitments use
/// caller-supplied bases `value_base` and `blind_base`:
/// `C_B = value * value_base + blinder * blind_base`.
pub fn create_non_membership_proof_timed_with_context_and_bases(
    secret_e: u64, r1_e: RistrettoScalar, r2_e: BlsScalar, server_pk: &ServerPublicKey,
    interval: (u64, u64), sigma: (G1Projective, G1Projective),
    r2_ea: BlsScalar, r2_eb: BlsScalar, r1_ea: RistrettoScalar, r1_eb: RistrettoScalar,
    gap_ctx: BlsScalar,
    bls_value_base: G1Projective,
    bls_blind_base: G1Projective,
) -> Result<TimedProof> {
    let start_total = Instant::now();
    let (ea, eb) = interval;
    
    let com_e_rist = RistrettoPoint::vartime_multiscalar_mul(&[RistrettoScalar::from(secret_e), r1_e], &[ristretto_gv(), ristretto_g1()]);
    let com_e_bls = bls_value_base * BlsScalar::from(secret_e) + bls_blind_base * r2_e;
    let com_ea_rist = RistrettoPoint::vartime_multiscalar_mul(&[RistrettoScalar::from(ea), r1_ea], &[ristretto_gv(), ristretto_g1()]);
    let com_eb_rist = RistrettoPoint::vartime_multiscalar_mul(&[RistrettoScalar::from(eb), r1_eb], &[ristretto_gv(), ristretto_g1()]);

    let ((gap_proof, gap_time), range_result) = rayon::join(
        || {
            let s = Instant::now();
            let p = GapProof::prove_with_context_and_bases(
                ea, eb, r2_ea, r2_eb, sigma.0, sigma.1,
                BlsScalar::random(&mut OsRng), gap_ctx, server_pk,
                bls_value_base, bls_blind_base,
            );
            (p, s.elapsed())
        },
        || -> Result<((RangeProof, RistrettoPoint, RistrettoPoint, usize), Duration)> {
            let s = Instant::now();
            let diff1 = secret_e
                .checked_sub(ea)
                .and_then(|d| d.checked_sub(1))
                .ok_or_else(|| ActError::ProtocolError("invalid revocation lower gap".into()))?;
            let diff2 = eb
                .checked_sub(secret_e)
                .and_then(|d| d.checked_sub(1))
                .ok_or_else(|| ActError::ProtocolError("invalid revocation upper gap".into()))?;
            let range_bits = rev_range_bits(diff1, diff2);
            let blinding_diff1 = r1_e - r1_ea;
            let blinding_diff2 = r1_eb - r1_e;
            let com1 = RistrettoPoint::vartime_multiscalar_mul(&[RistrettoScalar::from(diff1), blinding_diff1], &[ristretto_gv(), ristretto_g1()]);
            let com2 = RistrettoPoint::vartime_multiscalar_mul(&[RistrettoScalar::from(diff2), blinding_diff2], &[ristretto_gv(), ristretto_g1()]);
            let (proof, _) = RangeProof::prove_multiple(
                rev_bp_gens(range_bits), rev_pc_gens(), &mut Transcript::new(b"aggregated_diffs"),
                &[diff1, diff2], &[blinding_diff1, blinding_diff2], range_bits,
            ).map_err(|_| ActError::ProtocolError("revocation range proof generation failed".into()))?;
            Ok(((proof, com1, com2, range_bits), s.elapsed()))
        }
    );
    let ((range_proof, com_diff1, com_diff2, range_bits), range_time) = range_result?;

    let s_eq = Instant::now();
    let batched_eq_proof = BatchedEqualityProof::prove_with_bls_bases(
        secret_e, ea, eb, r1_e, r2_e, r1_ea, r2_ea, r1_eb, r2_eb,
        com_e_rist, com_e_bls, com_ea_rist, gap_proof.com_ea, com_eb_rist, gap_proof.com_eb,
        bls_value_base, bls_blind_base,
    );
    let eq_time = s_eq.elapsed();

    let sz_eq = batched_eq_proof.size_in_bytes();
    let sz_gap = gap_proof.size_in_bytes();
    let sz_range = range_proof.to_bytes().len();

    Ok(TimedProof {
        proof: NonMembershipProof { com_ea_rist, com_eb_rist, batched_eq_proof, gap_proof, aggregated_range_proof: range_proof, com_diff1, com_diff2, range_bits },
        times: ProverTiming { eq_batched: eq_time, gap: gap_time, range: range_time, total: start_total.elapsed() }, 
        sizes: ProofSizes { eq_batched: sz_eq, gap: sz_gap, range: sz_range, total: sz_eq + sz_gap + sz_range + 128 },
    })
}

pub fn verify_non_membership_proof_timed(
    timed: &TimedProof, server_pk: &ServerPublicKey, user_com_rist: RistrettoPoint, user_com_bls: G1Projective,
) -> (bool, VerifierTiming) {
    verify_non_membership_proof_timed_with_context(timed, server_pk, user_com_rist, user_com_bls, BlsScalar::ZERO)
}

pub fn verify_non_membership_proof_timed_with_context(
    timed: &TimedProof, server_pk: &ServerPublicKey, user_com_rist: RistrettoPoint, user_com_bls: G1Projective, gap_ctx: BlsScalar,
) -> (bool, VerifierTiming) {
    verify_non_membership_proof_timed_with_context_and_bases(
        timed, server_pk, user_com_rist, user_com_bls, gap_ctx,
        G1Projective::from(bls_g1_affine()),
        G1Projective::from(bls_h1_affine()),
    )
}

/// Verify a signed-gap non-membership proof whose BLS-side commitments use
/// caller-supplied bases `value_base` and `blind_base`.
pub fn verify_non_membership_proof_timed_with_context_and_bases(
    timed: &TimedProof, server_pk: &ServerPublicKey, user_com_rist: RistrettoPoint, user_com_bls: G1Projective, gap_ctx: BlsScalar,
    bls_value_base: G1Projective,
    bls_blind_base: G1Projective,
) -> (bool, VerifierTiming) {
    let proof = &timed.proof;
    let start_total = Instant::now();

    let ((eq_ok, eq_time), ((gap_ok, gap_time), (range_ok, range_time))) = rayon::join(
        || {
            let s = Instant::now();
            let ok = proof.batched_eq_proof.verify_with_bls_bases(
                user_com_rist, user_com_bls,
                proof.com_ea_rist, proof.gap_proof.com_ea,
                proof.com_eb_rist, proof.gap_proof.com_eb,
                bls_value_base, bls_blind_base,
            );
            (ok, s.elapsed())
        },
        || {
            rayon::join(
                || { let s = Instant::now(); (proof.gap_proof.verify_with_context_and_bases(server_pk, gap_ctx, bls_value_base, bls_blind_base), s.elapsed()) },
                || {
                    let s = Instant::now();
                    let ok = proof.aggregated_range_proof.verify_multiple(
                        rev_bp_gens(proof.range_bits), rev_pc_gens(), &mut Transcript::new(b"aggregated_diffs"),
                        &[proof.com_diff1.compress(), proof.com_diff2.compress()], proof.range_bits,
                    ).is_ok();
                    (ok, s.elapsed())
                }
            )
        }
    );

    let s_ext = Instant::now();
    let gv = ristretto_gv();
    let expected_diff1 = user_com_rist - proof.com_ea_rist - gv;
    let expected_diff2 = proof.com_eb_rist - user_com_rist - gv;
    let ext_ok = (expected_diff1 == proof.com_diff1) && (expected_diff2 == proof.com_diff2);
    let ext_time = s_ext.elapsed();

    (
        eq_ok && gap_ok && ext_ok && range_ok,
        VerifierTiming { eq_batched: eq_time, gap: gap_time, external: ext_time, range: range_time, total: start_total.elapsed() },
    )
}
