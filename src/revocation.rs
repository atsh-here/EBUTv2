//! Revocation wrapper around signed-gap non-membership.
//!
//! In this design the hidden `Emax` is both the Unix expiry timestamp and the
//! blacklist handle. Revocation succeeds by proving that hidden `Emax` lies in a
//! server-signed open interval `(ea, eb)` of non-revoked values.
//!
//! The integrated v3 gap proof uses 32-bit Bulletproofs whenever both gap
//! differences fit in u32 and falls back to 64-bit only for wider gaps.

use blstrs::{G1Projective, Scalar as BlsScalar};
use ff::Field;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as RistrettoScalar;
use curve25519_dalek_ng::traits::VartimeMultiscalarMul;

use crate::error::{ActError, Result};
use crate::v3_zkp::gap::ServerPublicKey;
use crate::v3_zkp::prover::{
    TimedProof,
    create_non_membership_proof_timed_with_context,
    create_non_membership_proof_timed_with_context_and_bases,
    verify_non_membership_proof_timed_with_context,
    verify_non_membership_proof_timed_with_context_and_bases,
};
use crate::setup::Generators;
use crate::epoch_refresh::{RefreshProof, refresh_emax_bls_commitment};
use crate::spend::{SpendProof, spend_emax_bls_commitment};
use crate::hash::scalar_from_le_bytes_mod_order;
use sha2::{Digest, Sha256};

/// Maximum width supported by the current 64-bit gap range proof.
pub const MAX_GAP_WIDTH_V1: u64 = u32::MAX as u64 - 1;
/// Current signed-gap revocation domain. The integrated v3 gap proof is a
/// 32-bit construction, which is enough for Unix-second expiries until 2106.
pub const REVOCATION_DOMAIN_MAX_V1: u64 = u32::MAX as u64;

/// Public revocation context. Bind this into outer EBUT transcripts too.
#[derive(Clone, Debug)]
pub struct RevocationContext {
    pub app_id: Vec<u8>,
    pub policy_id: Vec<u8>,
    pub server_key_id: [u8; 32],
    pub revocation_list_version: u64,
    pub now_unix: u64,
}


/// Derive the public scalar used to bind signed revocation gaps to a concrete
/// app/policy/server/revocation-list version. Without this, an old signed gap
/// could be replayed after a user is later blacklisted.
pub fn gap_context_scalar(ctx: &RevocationContext) -> BlsScalar {
    let mut h = Sha256::new();
    h.update(b"EBUT:REVOCATION:GAP-CONTEXT:V1");
    h.update((ctx.app_id.len() as u64).to_le_bytes());
    h.update(&ctx.app_id);
    h.update((ctx.policy_id.len() as u64).to_le_bytes());
    h.update(&ctx.policy_id);
    h.update(ctx.server_key_id);
    h.update(ctx.revocation_list_version.to_le_bytes());
    let d = h.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&d[..32]);
    scalar_from_le_bytes_mod_order(&b)
}

/// Signed gap and its blindings/commitments.
///
/// The current v3 prototype expects the caller to provide the interval
/// signature `(sigma1, sigma2)` and the BLS/Ristretto blindings used in the
/// equality proof. A production implementation should package these in a
/// canonical wire format.
#[derive(Clone, Debug)]
pub struct GapWitnessInputs {
    pub emax: u64,
    pub r1_emax: RistrettoScalar,
    pub r2_emax: BlsScalar,
    pub interval: (u64, u64),
    pub signature: (G1Projective, G1Projective),
    pub r2_ea: BlsScalar,
    pub r2_eb: BlsScalar,
    pub r1_ea: RistrettoScalar,
    pub r1_eb: RistrettoScalar,
}

/// Verify static gap constraints before proving or verifying.
pub fn validate_gap_interval(emax: u64, interval: (u64, u64), now_unix: u64) -> Result<()> {
    let (ea, eb) = interval;
    if emax > REVOCATION_DOMAIN_MAX_V1 || ea > REVOCATION_DOMAIN_MAX_V1 || eb > REVOCATION_DOMAIN_MAX_V1 {
        return Err(ActError::ProtocolError("revocation proof v1 supports Emax/gap endpoints <= u32::MAX".into()));
    }
    if !(ea < emax && emax < eb) {
        return Err(ActError::ProtocolError("Emax not inside revocation gap".into()));
    }
    if eb <= ea {
        return Err(ActError::ProtocolError("invalid revocation gap".into()));
    }
    if now_unix > emax {
        return Err(ActError::ProtocolError("Emax expired".into()));
    }
    Ok(())
}

/// Create the current v1 non-membership proof for `Emax`.
pub fn prove_emax_not_revoked(
    ctx: &RevocationContext,
    server_pk: &ServerPublicKey,
    inputs: GapWitnessInputs,
) -> Result<TimedProof> {
    prove_emax_not_revoked_with_bases(
        ctx, server_pk, inputs,
        G1Projective::from(crate::v3_zkp::generators::bls_g1_affine()),
        G1Projective::from(crate::v3_zkp::generators::bls_h1_affine()),
    )
}

/// Create a hidden-gap non-membership proof using explicit BLS commitment bases.
/// For refresh/spend binding these must be the EBUT expiry bases `(h5, h0)`,
/// because the public EBUT commitment is `Emax*h5 + r_delta*h0`.
pub fn prove_emax_not_revoked_with_bases(
    ctx: &RevocationContext,
    server_pk: &ServerPublicKey,
    inputs: GapWitnessInputs,
    bls_value_base: G1Projective,
    bls_blind_base: G1Projective,
) -> Result<TimedProof> {
    validate_gap_interval(inputs.emax, inputs.interval, ctx.now_unix)?;
    create_non_membership_proof_timed_with_context_and_bases(
        inputs.emax,
        inputs.r1_emax,
        inputs.r2_emax,
        server_pk,
        inputs.interval,
        inputs.signature,
        inputs.r2_ea,
        inputs.r2_eb,
        inputs.r1_ea,
        inputs.r1_eb,
        gap_context_scalar(ctx),
        bls_value_base,
        bls_blind_base,
    )
}

/// Verify v1 non-membership proof. This verifies the proof equations and also
/// requires the caller-provided public commitments to the hidden Emax.
pub fn verify_emax_not_revoked(
    ctx: &RevocationContext,
    proof: &TimedProof,
    server_pk: &ServerPublicKey,
    user_com_rist: RistrettoPoint,
    user_com_bls: G1Projective,
) -> Result<()> {
    verify_emax_not_revoked_with_bases(
        ctx, proof, server_pk, user_com_rist, user_com_bls,
        G1Projective::from(crate::v3_zkp::generators::bls_g1_affine()),
        G1Projective::from(crate::v3_zkp::generators::bls_h1_affine()),
    )
}

/// Verify hidden-gap non-membership against explicit BLS commitment bases.
pub fn verify_emax_not_revoked_with_bases(
    ctx: &RevocationContext,
    proof: &TimedProof,
    server_pk: &ServerPublicKey,
    user_com_rist: RistrettoPoint,
    user_com_bls: G1Projective,
    bls_value_base: G1Projective,
    bls_blind_base: G1Projective,
) -> Result<()> {
    let (ok, _timing) = verify_non_membership_proof_timed_with_context_and_bases(
        proof,
        server_pk,
        user_com_rist,
        user_com_bls,
        gap_context_scalar(ctx),
        bls_value_base,
        bls_blind_base,
    );
    if ok { Ok(()) } else { Err(ActError::VerificationFailed("revocation non-membership proof failed".into())) }
}


/// Verify that the hidden `Emax` proven by a refresh proof is not revoked.
///
/// This ties revocation to EBUT by using the BLS commitment to `Emax` already
/// proven inside [`RefreshProof`]: `C_Emax = proof.c_delta + now_unix*h5`.
pub fn verify_refresh_not_revoked(
    ctx: &RevocationContext,
    revocation_proof: &TimedProof,
    server_pk: &ServerPublicKey,
    refresh_proof: &RefreshProof,
    generators: &Generators,
    user_com_rist: RistrettoPoint,
) -> Result<()> {
    let user_com_bls = refresh_emax_bls_commitment(refresh_proof, ctx.now_unix, generators);
    verify_emax_not_revoked_with_bases(
        ctx, revocation_proof, server_pk, user_com_rist, user_com_bls,
        generators.h[5], generators.h[0],
    )
}

/// Verify that the hidden `Emax` proven by a spend proof is not revoked.
///
/// This ties revocation to EBUT by using the BLS commitment to `Emax` already
/// proven inside [`SpendProof`]: `C_Emax = proof.c_delta + now_unix*h5`.
pub fn verify_spend_not_revoked(
    ctx: &RevocationContext,
    revocation_proof: &TimedProof,
    server_pk: &ServerPublicKey,
    spend_proof: &SpendProof,
    generators: &Generators,
    user_com_rist: RistrettoPoint,
) -> Result<()> {
    let user_com_bls = spend_emax_bls_commitment(spend_proof, ctx.now_unix, generators);
    verify_emax_not_revoked_with_bases(
        ctx, revocation_proof, server_pk, user_com_rist, user_com_bls,
        generators.h[5], generators.h[0],
    )
}

/// One server-signed open interval `(left, right)` proving that values strictly
/// inside it are absent from the blacklist for the bound revocation-list context.
#[derive(Clone, Debug)]
pub struct SignedRevocationGap {
    /// Left blacklisted boundary/sentinel. The proven Emax must be strictly greater.
    pub left: u64,
    /// Right blacklisted boundary/sentinel. The proven Emax must be strictly smaller.
    pub right: u64,
    /// Server signature on `(left, right, revocation_context)`.
    pub signature: (G1Projective, G1Projective),
}

/// Sorted, context-bound signed revocation list.
///
/// The server starts from a blacklist of revoked `Emax` handles, sorts and
/// deduplicates it, then signs every non-empty open gap between adjacent
/// blacklisted handles. A client proves non-membership by finding the unique
/// signed gap containing its hidden `Emax` and proving `left < Emax < right`.
#[derive(Clone, Debug)]
pub struct SignedRevocationList {
    /// Public revocation context bound into every gap signature.
    pub ctx: RevocationContext,
    /// Sorted unique revoked Emax values.
    pub blacklisted_emax: Vec<u64>,
    /// Signed non-empty open gaps.
    pub gaps: Vec<SignedRevocationGap>,
}

/// A client-side revocation proof plus the Ristretto commitment needed by the verifier.
///
/// The containing gap `(E_a,E_b)` is deliberately **not** exposed here. Revealing
/// it leaks where the user's hidden expiry lies in the revocation list. The gap
/// is instead hidden inside the signed-gap proof via BLS commitments, blinded
/// signatures, cross-curve equality, and Bulletproof range constraints.
#[derive(Clone)]
pub struct ClientRevocationProof {
    /// Zero-knowledge non-membership proof for the hidden Emax.
    pub proof: TimedProof,
    /// Ristretto commitment to the same hidden Emax, consumed by the cross-curve equality proof.
    pub user_com_rist: RistrettoPoint,
}

fn random_ristretto_scalar(rng: &mut impl rand_core::RngCore) -> RistrettoScalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    RistrettoScalar::from_bytes_mod_order_wide(&wide)
}

impl SignedRevocationList {
    /// Build a sorted signed-gap revocation list from a raw blacklist.
    pub fn sign_blacklist(
        ctx: RevocationContext,
        server_sk: &crate::v3_zkp::gap::ServerSecretKey,
        mut blacklisted: Vec<u64>,
    ) -> Self {
        blacklisted.sort_unstable();
        blacklisted.dedup();
        let mut gaps = Vec::new();
        let mut left = 0u64;
        for &right in &blacklisted {
            if right > left.saturating_add(1) {
                gaps.push(SignedRevocationGap {
                    left,
                    right,
                    signature: server_sk.sign_interval_with_context(left, right, gap_context_scalar(&ctx)),
                });
            }
            left = right;
        }
        let right = REVOCATION_DOMAIN_MAX_V1;
        if left < right && right > left.saturating_add(1) {
            gaps.push(SignedRevocationGap {
                left,
                right,
                signature: server_sk.sign_interval_with_context(left, right, gap_context_scalar(&ctx)),
            });
        }
        Self { ctx, blacklisted_emax: blacklisted, gaps }
    }

    /// Return true iff `emax` is explicitly revoked.
    pub fn is_blacklisted(&self, emax: u64) -> bool {
        self.blacklisted_emax.binary_search(&emax).is_ok()
    }

    /// Find the unique signed open gap containing `emax`.
    pub fn find_gap(&self, emax: u64) -> Result<&SignedRevocationGap> {
        if self.is_blacklisted(emax) {
            return Err(ActError::VerificationFailed("Emax is blacklisted".into()));
        }
        self.gaps
            .iter()
            .find(|gap| gap.left < emax && emax < gap.right)
            .ok_or_else(|| ActError::VerificationFailed("no signed revocation gap contains Emax".into()))
    }

    /// Internal/debug helper: returns true iff this exact open interval is one
    /// of the current list's adjacent signed gaps. This must not be required
    /// from the client during redemption, because revealing the containing gap
    /// is a privacy leak. Production verification relies on context-bound
    /// signed-gap proofs instead.
    pub fn contains_current_gap_for_debug_only(&self, interval: (u64, u64)) -> bool {
        self.gaps.iter().any(|gap| (gap.left, gap.right) == interval)
    }

    /// Build low-level witness inputs for the hidden Emax proof.
    pub fn witness_inputs(
        &self,
        rng: &mut impl rand_core::RngCore,
        emax: u64,
        r1_emax: RistrettoScalar,
        r2_emax: BlsScalar,
    ) -> Result<GapWitnessInputs> {
        validate_gap_interval(emax, self.find_gap(emax).map(|g| (g.left, g.right))?, self.ctx.now_unix)?;
        let gap = self.find_gap(emax)?;
        Ok(GapWitnessInputs {
            emax,
            r1_emax,
            r2_emax,
            interval: (gap.left, gap.right),
            signature: gap.signature,
            r2_ea: BlsScalar::random(&mut *rng),
            r2_eb: BlsScalar::random(&mut *rng),
            r1_ea: random_ristretto_scalar(&mut *rng),
            r1_eb: random_ristretto_scalar(&mut *rng),
        })
    }

    /// Prove that `emax` is not blacklisted, using an existing BLS commitment blinder.
    ///
    /// `r2_emax` must be the blinder in the EBUT-side commitment
    /// `Emax*h5 + r2_emax*h0`, e.g. `RefreshClient::r_delta` or
    /// `SpendClient::r_delta` after adding `now*h5` to the expiry-delta commitment.
    pub fn prove_emax(
        &self,
        rng: &mut impl rand_core::RngCore,
        server_pk: &ServerPublicKey,
        emax: u64,
        r2_emax: BlsScalar,
    ) -> Result<ClientRevocationProof> {
        self.prove_emax_with_bases(
            rng, server_pk, emax, r2_emax,
            G1Projective::from(crate::v3_zkp::generators::bls_g1_affine()),
            G1Projective::from(crate::v3_zkp::generators::bls_h1_affine()),
        )
    }

    /// Prove that `emax` is not revoked using the same BLS bases as the
    /// commitment that the verifier will check. For EBUT refresh/spend this is
    /// exactly `(generators.h[5], generators.h[0])`.
    pub fn prove_emax_with_bases(
        &self,
        rng: &mut impl rand_core::RngCore,
        server_pk: &ServerPublicKey,
        emax: u64,
        r2_emax: BlsScalar,
        bls_value_base: G1Projective,
        bls_blind_base: G1Projective,
    ) -> Result<ClientRevocationProof> {
        let r1_emax = random_ristretto_scalar(rng);
        let inputs = self.witness_inputs(rng, emax, r1_emax, r2_emax)?;
        let proof = prove_emax_not_revoked_with_bases(
            &self.ctx, server_pk, inputs, bls_value_base, bls_blind_base,
        )?;
        let user_com_rist = RistrettoPoint::vartime_multiscalar_mul(
            &[RistrettoScalar::from(emax), r1_emax],
            &[crate::v3_zkp::generators::ristretto_gv(), crate::v3_zkp::generators::ristretto_g1()],
        );
        Ok(ClientRevocationProof { proof, user_com_rist })
    }

    /// Convenience helper for a refresh proof. The client must pass the
    /// corresponding [`RefreshClient`] because it contains the hidden Emax and
    /// the expiry-commitment blinder.
    pub fn prove_refresh_client(
        &self,
        rng: &mut impl rand_core::RngCore,
        server_pk: &ServerPublicKey,
        client: &crate::epoch_refresh::RefreshClient,
        generators: &Generators,
    ) -> Result<ClientRevocationProof> {
        self.prove_emax_with_bases(
            rng, server_pk, client.e_max, client.r_delta.0,
            generators.h[5], generators.h[0],
        )
    }

    /// Convenience helper for a spend proof. The client must pass the
    /// corresponding [`SpendClient`] because it contains the hidden Emax and
    /// the spend-time expiry-commitment blinder.
    pub fn prove_spend_client(
        &self,
        rng: &mut impl rand_core::RngCore,
        server_pk: &ServerPublicKey,
        client: &crate::spend::SpendClient,
        generators: &Generators,
    ) -> Result<ClientRevocationProof> {
        self.prove_emax_with_bases(
            rng, server_pk, client.e_max, client.r_delta.0,
            generators.h[5], generators.h[0],
        )
    }
}

/// Verify refresh plus revocation in one call.
pub fn verify_refresh_not_revoked_from_client_proof(
    signed_list: &SignedRevocationList,
    revocation_proof: &ClientRevocationProof,
    server_pk: &ServerPublicKey,
    refresh_proof: &RefreshProof,
    generators: &Generators,
) -> Result<()> {
    // Do not ask the prover to reveal the containing gap. Current-list freshness
    // and adjacency are enforced by the context-bound signed-gap proof itself.
    // The server signs only adjacent gaps for this list context; old or broad
    // gap signatures verify under a different context and fail here.
    verify_refresh_not_revoked(
        &signed_list.ctx,
        &revocation_proof.proof,
        server_pk,
        refresh_proof,
        generators,
        revocation_proof.user_com_rist,
    )
}

/// Verify spend plus revocation in one call.
pub fn verify_spend_not_revoked_from_client_proof(
    signed_list: &SignedRevocationList,
    revocation_proof: &ClientRevocationProof,
    server_pk: &ServerPublicKey,
    spend_proof: &SpendProof,
    generators: &Generators,
) -> Result<()> {
    // Do not ask the prover to reveal the containing gap. Current-list freshness
    // and adjacency are enforced by the context-bound signed-gap proof itself.
    verify_spend_not_revoked(
        &signed_list.ctx,
        &revocation_proof.proof,
        server_pk,
        spend_proof,
        generators,
        revocation_proof.user_com_rist,
    )
}

#[cfg(test)]
mod signed_list_tests {
    use super::*;
    use crate::v3_zkp::gap::ServerSecretKey;
    use crate::setup::{Generators, ServerKeys};
    use crate::hash::compute_h_ctx;
    use crate::epoch_refresh::RefreshProver;
    use crate::spend::SpendProver;
    use crate::bbs_proof::BbsSignature;
    use crate::commitments::commit;
    use crate::msm::g1_msm;
    use crate::types::Scalar;
    use blstrs::G1Affine;
    use group::Group as _;
    use rand::thread_rng;

    fn ctx(now_unix: u64, version: u64) -> RevocationContext {
        RevocationContext {
            app_id: b"test-app".to_vec(),
            policy_id: b"test-policy".to_vec(),
            server_key_id: [7u8; 32],
            revocation_list_version: version,
            now_unix,
        }
    }

    #[test]
    fn signed_revocation_list_sorts_and_rejects_blacklisted_emax() {
        let mut rng = thread_rng();
        let (sk, pk) = ServerSecretKey::generate();
        let now = 1_700_000_000u64;
        let list = SignedRevocationList::sign_blacklist(ctx(now, 1), &sk, vec![3000, 1000, 3000, 2000]);
        assert_eq!(list.blacklisted_emax, vec![1000, 2000, 3000]);
        assert!(list.find_gap(2500).is_ok());
        assert!(list.find_gap(2000).is_err());
        // Use Unix-like values above `now` for the actual non-expiry proof.
        let emax = 2_000_000_000u64;
        let list = SignedRevocationList::sign_blacklist(ctx(now, 2), &sk, vec![1_900_000_000, 2_100_000_000]);
        let r2 = BlsScalar::random(&mut rng);
        let cp = list.prove_emax(&mut rng, &pk, emax, r2).unwrap();
        let user_com_bls = G1Projective::from(crate::v3_zkp::generators::bls_g1_affine()) * BlsScalar::from(emax)
            + G1Projective::from(crate::v3_zkp::generators::bls_h1_affine()) * r2;
        verify_emax_not_revoked(&list.ctx, &cp.proof, &pk, cp.user_com_rist, user_com_bls).unwrap();

        // A broad gap from an old list must not verify against the current list
        // context, even though it contains the same Emax. This prevents stale
        // broad-gap replay without revealing the containing current gap.
        let old_broad = SignedRevocationList::sign_blacklist(ctx(now, 1), &sk, vec![]);
        let old_cp = old_broad.prove_emax(&mut rng, &pk, emax, r2).unwrap();
        assert!(verify_emax_not_revoked(&list.ctx, &old_cp.proof, &pk, old_cp.user_com_rist, user_com_bls).is_err());

        let revoked = SignedRevocationList::sign_blacklist(ctx(now, 3), &sk, vec![emax]);
        assert!(revoked.prove_emax(&mut rng, &pk, emax, r2).is_err());
    }

    fn master_sig(
        rng: &mut impl rand_core::RngCore,
        k_sub: Scalar,
        c_max: u32,
        e_max: u64,
        generators: &Generators,
        keys: &ServerKeys,
    ) -> BbsSignature {
        let r_sub = Scalar::rand(rng);
        let k_sub_commit = commit(k_sub, r_sub, generators.h[1], generators.h[0]);
        let e_sub = Scalar::rand(rng);
        let s_prime = Scalar::rand(rng);
        let msg_part = g1_msm(
            &[generators.g1_affine, G1Affine::from(k_sub_commit), generators.h_affine[0], generators.h_affine[3], generators.h_affine[5]],
            &[BlsScalar::ONE, BlsScalar::ONE, s_prime.0, BlsScalar::from(c_max as u64), BlsScalar::from(e_max)],
        );
        let a_sub = &msg_part * &(e_sub + keys.sk_master).inverse().0;
        BbsSignature { a: a_sub, e: e_sub, s: r_sub + s_prime }
    }

    fn daily_sig(
        rng: &mut impl rand_core::RngCore,
        k_sub: Scalar,
        k_cur: Scalar,
        c_bal: u32,
        t_issue: u32,
        e_max: u64,
        generators: &Generators,
        keys: &ServerKeys,
    ) -> BbsSignature {
        let r_daily = Scalar::rand(rng);
        let k_daily_commit = &(&(&(&(&generators.h[1] * &k_sub.0)
            + &(&generators.h[2] * &k_cur.0))
            + &(&generators.h[3] * &Scalar::from(c_bal).0))
            + &(&generators.h[4] * &Scalar::from(t_issue).0))
            + &(&(&generators.h[5] * &Scalar::from(e_max).0)
            + &(&generators.h[0] * &r_daily.0));
        let e_d = Scalar::rand(rng);
        let s_p = Scalar::rand(rng);
        let msg_part = &(&generators.g1 + &k_daily_commit) + &(&generators.h[0] * &s_p.0);
        let a_d = &msg_part * &(e_d + keys.sk_daily).inverse().0;
        BbsSignature { a: a_d, e: e_d, s: r_daily + s_p }
    }

    #[test]
    fn refresh_and_spend_revocation_bind_to_token_emax() {
        let mut rng = thread_rng();
        let generators = Generators::new();
        let keys = ServerKeys::generate(&mut rng);
        let h_ctx = compute_h_ctx("test-app", &keys.pk_master, &keys.pk_daily, &generators);
        let (rev_sk, rev_pk) = ServerSecretKey::generate();
        let now = 1_700_000_000u64;
        let emax = 2_000_000_000u64;
        let rev_list = SignedRevocationList::sign_blacklist(ctx(now, 44), &rev_sk, vec![1_900_000_000, 2_100_000_000]);

        let k_sub = Scalar::rand_nonzero(&mut rng);
        let c_max = 100u32;
        let epoch = 42u32;
        let master = master_sig(&mut rng, k_sub, c_max, emax, &generators, &keys);
        let (refresh_client, refresh_proof) = RefreshProver::prove(
            &mut rng, &master, k_sub, c_max, emax, epoch, now, &generators, &keys.pk_master, h_ctx,
        ).unwrap();
        let refresh_rev = rev_list.prove_refresh_client(&mut rng, &rev_pk, &refresh_client, &generators).unwrap();
        verify_refresh_not_revoked_from_client_proof(&rev_list, &refresh_rev, &rev_pk, &refresh_proof, &generators).unwrap();
        // A proof made against an older broad list must fail against the current
        // list context. This gives anti-stale/anti-broad-gap security without
        // revealing the current containing gap.
        let old_broad = SignedRevocationList::sign_blacklist(ctx(now, 43), &rev_sk, vec![]);
        let old_refresh_rev = old_broad.prove_refresh_client(&mut rng, &rev_pk, &refresh_client, &generators).unwrap();
        assert!(verify_refresh_not_revoked_from_client_proof(&rev_list, &old_refresh_rev, &rev_pk, &refresh_proof, &generators).is_err());

        let k_cur = Scalar::rand_nonzero(&mut rng);
        let daily = daily_sig(&mut rng, k_sub, k_cur, c_max, epoch, emax, &generators, &keys);
        let (spend_client, spend_proof) = SpendProver::prove(
            &mut rng, &daily, k_sub, k_cur, c_max, epoch, emax, now, 10, &[9u8; 16], &generators, &keys.pk_daily, h_ctx,
        ).unwrap();
        let spend_rev = rev_list.prove_spend_client(&mut rng, &rev_pk, &spend_client, &generators).unwrap();
        verify_spend_not_revoked_from_client_proof(&rev_list, &spend_rev, &rev_pk, &spend_proof, &generators).unwrap();

        let revoked_list = SignedRevocationList::sign_blacklist(ctx(now, 45), &rev_sk, vec![emax]);
        assert!(revoked_list.prove_refresh_client(&mut rng, &rev_pk, &refresh_client, &generators).is_err());
        assert!(revoked_list.prove_spend_client(&mut rng, &rev_pk, &spend_client, &generators).is_err());
    }
}
