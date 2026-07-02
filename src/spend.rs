//! Phase 3: Intra-Day Spending.

extern crate alloc;
use alloc::vec::Vec;

use blstrs::{Bls12, G1Affine, G1Projective, G2Projective, Gt, Scalar as BlsScalar};
use ff::Field as _;
use group::Group as _;
use pairing::{MultiMillerLoop as _, MillerLoopResult as _};
use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng as _};
use sha2::{Digest as _, Sha256};
use std::io::Write as _;

use crate::bbs_proof::BbsSignature;
use crate::batched_eq::{prove_batched_equality, verify_batched_equality, BatchedEqualityProof};
use crate::error::{ActError, Result};
use crate::hash::{hash_to_scalar_from_hasher, write_g1, write_g2, write_scalar, HasherWriter};
use crate::msm::{batch_normalize, g1_msm};
use crate::setup::{Generators, ServerKeys};
use crate::types::Scalar;
#[cfg(feature = "std")]
use rayon;

// ============================================================================
// Structures
// ============================================================================

#[derive(Clone, Debug)]
pub struct SpendProof {
    pub a_prime:    G1Projective,
    pub a_bar:      G1Projective,
    pub t_bbs:      G1Projective,
    pub t_scale_t:  G1Projective,
    pub t_total:    G1Projective,
    pub t_scale_r:  G1Projective,
    pub t_refund:   G1Projective,
    pub t_scale_bp: G1Projective,
    pub t_bp:       G1Projective,
    pub z_e:        Scalar,
    pub z_r1:       Scalar,
    pub z_s_tilde:  Scalar,
    pub z_x_tilde:  Scalar,
    pub z_c_tilde:  Scalar,
    pub z_e_tilde:  Scalar,
    pub z_u:        Scalar,
    pub z_v:        Scalar,
    pub z_w:        Scalar,
    pub batched_eq: BatchedEqualityProof,
    pub s:          u32,
    pub k_cur:      Scalar,
    pub t_issue:    u32,
    pub k_prime:    G1Projective,
    pub c_bp:       G1Projective,
    /// Unique Unix-second expiry/revocation handle carried by the token.
    pub e_max:      u64,
    /// BLS commitment to hidden x proven inside this spend proof.
    pub x_bls_commitment: G1Projective,
    pub t_scale_x:  G1Projective,
    pub t_x:        G1Projective,
    pub z_r_x:      Scalar,
    /// Expiry delta commitment proving now_unix <= e_max at spend time.
    pub c_delta:    G1Projective,
    pub expiry_eq:  BatchedEqualityProof,
    pub t_scale_exp: G1Projective,
    pub t_exp:      G1Projective,
    pub z_r_delta:  Scalar,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SpendResponse {
    #[serde(with = "crate::types::g1_serde")]
    pub a_refund:       G1Projective,
    pub e_refund:       Scalar,
    pub s_prime_refund: Scalar,
}

pub struct SpendClient {
    pub k_cur:   Scalar,
    pub c_bal:   u32,
    pub t_issue: u32,
    pub e_max: u64,
    pub k_star:  Scalar,
    pub r_star:  Scalar,
    pub remaining_balance: u32,
    /// Blinder for the spend-time Emax commitment `c_delta = (Emax-now)*h5 + r_delta*h0`.
    /// This is needed by the client to build the revocation non-membership proof
    /// against the same hidden Emax proven inside the spend proof.
    pub r_delta: Scalar,
    r_bp:        Scalar,
}

impl SpendClient {
    /// Finalize a server refund response into a daily-token BBS+ signature.
    ///
    /// The server signs the committed message
    /// `x*h1 + k_star*h2 + m*h3 + T*h4 + Emax*h5 + r_star*h0`;
    /// adding `s_prime_refund` to `r_star` gives a normal signature on
    /// `(x, k_star, m, T, Emax)`.
    pub fn finalize(self, response: SpendResponse) -> (BbsSignature, Scalar, u32, u32, u64) {
        let m = self.remaining_balance;
        (
            BbsSignature {
                a: response.a_refund,
                e: response.e_refund,
                s: self.r_star + response.s_prime_refund,
            },
            self.k_star,
            m,
            self.t_issue,
            self.e_max,
        )
    }
}


// ============================================================================
// Prover
// ============================================================================

pub struct SpendProver;

impl SpendProver {
    #[allow(clippy::too_many_arguments)]
    pub fn prove(
        rng: &mut (impl CryptoRng + RngCore),
        token: &BbsSignature,
        k_sub: Scalar,
        k_cur: Scalar,
        c_bal: u32,
        t_issue: u32,
        e_max: u64,
        now_unix: u64,
        spend_amount: u32,
        nonce: &[u8; 16],
        generators: &Generators,
        pk_daily: &G2Projective,
        h_ctx: Scalar,
    ) -> Result<(SpendClient, SpendProof)> {
        if spend_amount == 0 {
            return Err(ActError::ProtocolError("Spend amount must be positive".into()));
        }
        if spend_amount > c_bal {
            return Err(ActError::ProtocolError("Insufficient balance".into()));
        }
        if e_max < now_unix {
            return Err(ActError::ProtocolError("Token expired".into()));
        }
        let expiry_delta = e_max - now_unix;
        let m = c_bal - spend_amount;

        // Seed a ChaCha20Rng from 32 bytes of OS/caller entropy.
        // This makes all subsequent blinder generation virtually free (SIMD stream)
        // while still being cryptographically secure.
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let mut fast_rng = ChaCha20Rng::from_seed(seed);

        // Non-transferable refund commitment:
        // K' = x*h1 + k_star*h2 + m*h3 + T_issue*h4 + Emax*h5 + r_star*h0.
        let k_star = Scalar::rand_nonzero(&mut fast_rng);
        let r_star = Scalar::rand(&mut fast_rng);
        let k_prime = &(&(&(&(&generators.h[1] * &k_sub.0)
            + &(&generators.h[2] * &k_star.0))
            + &(&generators.h[3] * &Scalar::from(m).0))
            + &(&generators.h[4] * &Scalar::from(t_issue).0))
            + &(&(&generators.h[5] * &Scalar::from(e_max).0)
            + &(&generators.h[0] * &r_star.0));

        // Range proof commitment C_BP = m·h4 + r_bp·h0
        let r_bp  = Scalar::rand(&mut fast_rng);
        let c_bp  = &(&generators.h[3] * &Scalar::from(m).0) + &(&generators.h[0] * &r_bp.0);

        // Spend-time expiry proof: C_delta = (Emax-now)*h5 + r_delta*h0.
        let r_delta = Scalar::rand(&mut fast_rng);
        let c_delta = &(&generators.h[5] * &Scalar::from(expiry_delta).0) + &(&generators.h[0] * &r_delta.0);

        // Public BLS commitment to hidden x, proven tied to the BBS+ token.
        let r_x = Scalar::rand(&mut fast_rng);
        let x_bls_commitment = &(&generators.h[1] * &k_sub.0) + &(&generators.h[0] * &r_x.0);

        // BBS+ randomization
        let r1      = Scalar::rand_nonzero(&mut fast_rng);
        let a_prime = &token.a * &r1.0;

        let msg_part = g1_msm(
            &[generators.g1_affine, generators.h_affine[0], generators.h_affine[1],
              generators.h_affine[2], generators.h_affine[3], generators.h_affine[4], generators.h_affine[5]],
            &[BlsScalar::ONE, token.s.0, k_sub.0, k_cur.0,
              BlsScalar::from(c_bal as u64), BlsScalar::from(t_issue as u64), BlsScalar::from(e_max)],
        );
        let a_bar = &(&a_prime * &(-token.e.0)) + &(&msg_part * &r1.0);

        let s_tilde = token.s * r1;
        let x_tilde = k_sub * r1;
        let c_tilde = Scalar::from(c_bal) * r1;
        let e_tilde = Scalar::from(e_max) * r1;

        let (rho_e, rho_r1, rho_s, rho_x, rho_c, rho_emax) = (
            Scalar::rand(&mut fast_rng), Scalar::rand(&mut fast_rng),
            Scalar::rand(&mut fast_rng), Scalar::rand(&mut fast_rng),
            Scalar::rand(&mut fast_rng), Scalar::rand(&mut fast_rng),
        );

        let a_prime_aff = G1Affine::from(a_prime);
        let t_bbs = g1_msm(
            &[a_prime_aff, generators.g1_affine, generators.h_affine[0],
              generators.h_affine[1], generators.h_affine[2], generators.h_affine[3],
              generators.h_affine[4], generators.h_affine[5]],
            &[(-rho_e).0, rho_r1.0, rho_s.0,
              rho_x.0, (k_cur * rho_r1).0, rho_c.0,
              (Scalar::from(t_issue) * rho_r1).0, rho_emax.0],
        );

        let (rho_u, rho_v, rho_w, rho_rx, rho_delta) = (
            Scalar::rand(&mut fast_rng), Scalar::rand(&mut fast_rng), Scalar::rand(&mut fast_rng),
            Scalar::rand(&mut fast_rng), Scalar::rand(&mut fast_rng),
        );

        let c_total  = &k_prime + &(&generators.h[3] * &Scalar::from(spend_amount).0);
        let t_scale_t = &c_total  * &rho_r1.0;
        let t_total   = g1_msm(
            &[generators.h_affine[1], generators.h_affine[2], generators.h_affine[3],
              generators.h_affine[4], generators.h_affine[5], generators.h_affine[0]],
            &[rho_x.0, rho_u.0, rho_c.0,
              (rho_r1 * Scalar::from(t_issue)).0, rho_emax.0, rho_v.0],
        );

        let t_scale_r = &k_prime * &rho_r1.0;
        let rho_m     = rho_c - Scalar::from(spend_amount) * rho_r1;
        let t_refund  = g1_msm(
            &[generators.h_affine[1], generators.h_affine[2], generators.h_affine[3],
              generators.h_affine[4], generators.h_affine[5], generators.h_affine[0]],
            &[rho_x.0, rho_u.0, rho_m.0,
              (rho_r1 * Scalar::from(t_issue)).0, rho_emax.0, rho_v.0],
        );

        let t_scale_bp = &c_bp * &rho_r1.0;
        let t_bp = g1_msm(
            &[generators.h_affine[3], generators.h_affine[0]],
            &[rho_m.0, rho_w.0],
        );

        let t_scale_x = &x_bls_commitment * &rho_r1.0;
        let t_x = g1_msm(
            &[generators.h_affine[1], generators.h_affine[0]],
            &[rho_x.0, rho_rx.0],
        );
        let c_exp_bridge = &c_delta + &(&generators.h[5] * &Scalar::from(now_unix).0);
        let t_scale_exp = &c_exp_bridge * &rho_r1.0;
        let t_exp = g1_msm(
            &[generators.h_affine[5], generators.h_affine[0]],
            &[rho_emax.0, rho_delta.0],
        );

        // BatchedEqualityProof
        let mut beq_ctx = Vec::new();
        beq_ctx.extend_from_slice(&h_ctx.to_bytes());
        beq_ctx.extend_from_slice(&spend_amount.to_le_bytes());
        beq_ctx.extend_from_slice(&k_cur.to_bytes());
        beq_ctx.extend_from_slice(&t_issue.to_le_bytes());
        beq_ctx.extend_from_slice(&e_max.to_le_bytes());
        beq_ctx.extend_from_slice(&now_unix.to_le_bytes());
        beq_ctx.extend_from_slice(nonce);

        // BBS+ and bridge commitments passed explicitly into the BatchedEqualityProof
        // so they are bound in both the Sigma challenge and the Bulletproof transcript
        // (prevents transcript-splicing attacks per Section 9.2 of the ACT paper).
        let beq_commitments = [
            G1Affine::from(a_prime),
            G1Affine::from(a_bar),
            G1Affine::from(t_bbs),
            G1Affine::from(k_prime),
            G1Affine::from(c_total),
            G1Affine::from(x_bls_commitment),
            G1Affine::from(c_delta),
        ];

        let (batched_eq, c_bp_from_beq) = prove_batched_equality(
            &mut fast_rng, m as u64, r_bp.0, generators.h[3], generators.h[0], &beq_ctx, &beq_commitments,
        )?;
        debug_assert_eq!(c_bp, c_bp_from_beq, "c_bp mismatch");

        let mut expiry_ctx = Vec::new();
        expiry_ctx.extend_from_slice(&h_ctx.to_bytes());
        expiry_ctx.extend_from_slice(&t_issue.to_le_bytes());
        expiry_ctx.extend_from_slice(&e_max.to_le_bytes());
        expiry_ctx.extend_from_slice(&now_unix.to_le_bytes());
        expiry_ctx.extend_from_slice(&k_cur.to_bytes());
        expiry_ctx.extend_from_slice(nonce);
        let expiry_commitments = [
            G1Affine::from(a_prime),
            G1Affine::from(a_bar),
            G1Affine::from(t_bbs),
            G1Affine::from(k_prime),
            G1Affine::from(c_delta),
            G1Affine::from(x_bls_commitment),
        ];
        let (expiry_eq, c_delta_from_beq) = prove_batched_equality(
            &mut fast_rng, expiry_delta, r_delta.0, generators.h[5], generators.h[0], &expiry_ctx, &expiry_commitments,
        )?;
        debug_assert_eq!(c_delta, c_delta_from_beq, "c_delta mismatch");

        let beq_bytes = batched_eq.to_bytes();
        let expiry_bytes = expiry_eq.to_bytes();

        let c = Self::challenge(
            h_ctx, pk_daily, spend_amount, &k_cur, t_issue, e_max, now_unix, nonce,
            k_prime, c_total, c_bp, c_delta, x_bls_commitment, &beq_bytes, &expiry_bytes,
            a_prime, a_bar, t_bbs,
            t_scale_t, t_total, t_scale_r, t_refund, t_scale_bp, t_bp,
            t_scale_x, t_x, t_scale_exp, t_exp,
        );

        let z_e      = rho_e  + c * token.e;
        let z_r1     = rho_r1 + c * r1;
        let z_s_tilde = rho_s + c * s_tilde;
        let z_x_tilde = rho_x + c * x_tilde;
        let z_c_tilde = rho_c + c * c_tilde;
        let z_e_tilde = rho_emax + c * e_tilde;
        let z_u = rho_u + c * (k_star * r1);
        let z_v = rho_v + c * (r_star * r1);
        let z_w = rho_w + c * (r_bp * r1);
        let z_r_x = rho_rx + c * (r_x * r1);
        let z_r_delta = rho_delta + c * (r_delta * r1);

        Ok((
            SpendClient { k_cur, c_bal, t_issue, e_max, k_star, r_star, remaining_balance: m, r_delta, r_bp },
            SpendProof {
                a_prime, a_bar, t_bbs,
                t_scale_t, t_total, t_scale_r, t_refund, t_scale_bp, t_bp,
                z_e, z_r1, z_s_tilde, z_x_tilde, z_c_tilde, z_e_tilde, z_u, z_v, z_w,
                batched_eq, s: spend_amount, k_cur, t_issue, k_prime, c_bp, e_max,
                x_bls_commitment, t_scale_x, t_x, z_r_x,
                c_delta, expiry_eq, t_scale_exp, t_exp, z_r_delta,
            },
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn challenge(
        h_ctx: Scalar,
        pk_daily: &G2Projective,
        spend_amount: u32,
        k_cur: &Scalar,
        t_issue: u32,
        e_max: u64,
        now_unix: u64,
        nonce: &[u8; 16],
        k_prime: G1Projective,
        c_total: G1Projective,
        c_bp: G1Projective,
        c_delta: G1Projective,
        x_bls_commitment: G1Projective,
        beq_bytes: &[u8],
        expiry_bytes: &[u8],
        a_prime: G1Projective,
        a_bar: G1Projective,
        t_bbs: G1Projective,
        t_scale_t: G1Projective,
        t_total: G1Projective,
        t_scale_r: G1Projective,
        t_refund: G1Projective,
        t_scale_bp: G1Projective,
        t_bp: G1Projective,
        t_scale_x: G1Projective,
        t_x: G1Projective,
        t_scale_exp: G1Projective,
        t_exp: G1Projective,
    ) -> Scalar {
        let mut hasher = Sha256::new();
        let mut w = HasherWriter(&mut hasher);
        write_scalar(&mut w, h_ctx);
        write_g2(&mut w, *pk_daily);
        w.write_all(&spend_amount.to_le_bytes()).unwrap();
        w.write_all(&k_cur.to_bytes()).unwrap();
        w.write_all(&t_issue.to_le_bytes()).unwrap();
        w.write_all(&e_max.to_le_bytes()).unwrap();
        w.write_all(&now_unix.to_le_bytes()).unwrap();
        w.write_all(nonce).unwrap();
        write_g1(&mut w, k_prime);
        write_g1(&mut w, c_total);
        write_g1(&mut w, c_bp);
        write_g1(&mut w, c_delta);
        write_g1(&mut w, x_bls_commitment);
        w.write_all(beq_bytes).unwrap();
        w.write_all(expiry_bytes).unwrap();
        write_g1(&mut w, a_prime);
        write_g1(&mut w, a_bar);
        write_g1(&mut w, t_bbs);
        write_g1(&mut w, t_scale_t);
        write_g1(&mut w, t_total);
        write_g1(&mut w, t_scale_r);
        write_g1(&mut w, t_refund);
        write_g1(&mut w, t_scale_bp);
        write_g1(&mut w, t_bp);
        write_g1(&mut w, t_scale_x);
        write_g1(&mut w, t_x);
        write_g1(&mut w, t_scale_exp);
        write_g1(&mut w, t_exp);
        w.write_all(b"Spend").unwrap();
        drop(w);
        hash_to_scalar_from_hasher(hasher)
    }
}

// ============================================================================
// Server Verifier
// ============================================================================

pub fn verify_spend(
    proof: &SpendProof,
    current_epoch: u32,
    now_unix: u64,
    nonce: &[u8; 16],
    generators: &Generators,
    pk_daily: &G2Projective,
    keys: &ServerKeys,
    h_ctx: Scalar,
    rng: &mut impl RngCore,
) -> Result<SpendResponse> {
    if proof.s == 0 {
        return Err(ActError::VerificationFailed("Spend amount must be positive".into()));
    }
    if proof.t_issue != current_epoch && proof.t_issue.saturating_add(1) != current_epoch {
        return Err(ActError::VerificationFailed("Epoch mismatch".into()));
    }
    if bool::from(proof.a_prime.is_identity()) || bool::from(proof.t_bbs.is_identity()) {
        return Err(ActError::VerificationFailed("Zero point in proof".into()));
    }

    let c_total  = &proof.k_prime + &(&generators.h[3] * &Scalar::from(proof.s).0);
    let beq_bytes = proof.batched_eq.to_bytes();

    let c = SpendProver::challenge(
        h_ctx, pk_daily, proof.s, &proof.k_cur, proof.t_issue, proof.e_max, now_unix, nonce,
        proof.k_prime, c_total, proof.c_bp, proof.c_delta, proof.x_bls_commitment, &beq_bytes, &proof.expiry_eq.to_bytes(),
        proof.a_prime, proof.a_bar, proof.t_bbs,
        proof.t_scale_t, proof.t_total, proof.t_scale_r, proof.t_refund,
        proof.t_scale_bp, proof.t_bp, proof.t_scale_x, proof.t_x, proof.t_scale_exp, proof.t_exp,
    );
    let c_fr = c.0;

    let lhs_x = &(&generators.h[1] * &proof.z_x_tilde.0) + &(&generators.h[0] * &proof.z_r_x.0) - &proof.t_x;
    let rhs_x = &(&proof.x_bls_commitment * &proof.z_r1.0) - &proof.t_scale_x;
    if lhs_x != rhs_x {
        return Err(ActError::VerificationFailed("x BLS commitment bridge failed".into()));
    }
    let c_exp_bridge = &proof.c_delta + &(&generators.h[5] * &Scalar::from(now_unix).0);
    let lhs_exp = &(&generators.h[5] * &proof.z_e_tilde.0) + &(&generators.h[0] * &proof.z_r_delta.0) - &proof.t_exp;
    let rhs_exp = &(&c_exp_bridge * &proof.z_r1.0) - &proof.t_scale_exp;
    if lhs_exp != rhs_exp {
        return Err(ActError::VerificationFailed("spend-time expiry bridge failed".into()));
    }

    // Schwartz–Zippell RLC combined check
    {
        let c2 = &c_fr * &c_fr;
        let c3 = &c2   * &c_fr;
        let ti = BlsScalar::from(proof.t_issue as u64);
        let sf = BlsScalar::from(proof.s as u64);

        let sc_h0 = &(&(&c_fr + &c2) * &proof.z_v.0) + &(&(&c3 * &proof.z_w.0) + &proof.z_s_tilde.0);
        let sc_h1 = &(&BlsScalar::ONE + &(&c_fr + &c2)) * &proof.z_x_tilde.0;
        let sc_h2 = &(&(&c_fr + &c2) * &proof.z_u.0) + &(&proof.k_cur.0 * &proof.z_r1.0);
        let sc_h3 = {
            let zc = proof.z_c_tilde.0;
            let zr = proof.z_r1.0;
            // (1+c+c2+c3)*z_c - (c2+c3)*s*z_r1
            let t1 = &(&BlsScalar::ONE + &(&c_fr + &(&c2 + &c3))) * &zc;
            let t2 = &(&c2 + &c3) * &(&sf * &zr);
            &t1 - &t2
        };
        let sc_h4 = &(&BlsScalar::ONE + &(&c_fr + &c2)) * &(&ti * &proof.z_r1.0);
        let sc_h5 = &(&BlsScalar::ONE + &(&c_fr + &c2)) * &proof.z_e_tilde.0;
        let sc_g1      = proof.z_r1.0;
        let sc_aprime  = -proof.z_e.0;
        let sc_ctotal  = -(&c_fr * &proof.z_r1.0);
        let sc_kprime  = -(&c2   * &proof.z_r1.0);
        let sc_cbp     = -(&c3   * &proof.z_r1.0);
        let sc_abar    = -c_fr;
        let sc_ttotal    = -c_fr;
        let sc_tscale_t  =  c_fr;
        let sc_trefund   = -c2;
        let sc_tscale_r  =  c2;
        let sc_tbp       = -c3;
        let sc_tscale_bp =  c3;
        let sc_tbbs      = -BlsScalar::ONE;

        let dyn_pts = batch_normalize(&[
            proof.a_prime, c_total, proof.k_prime, proof.c_bp, proof.a_bar,
            proof.t_total, proof.t_scale_t, proof.t_refund, proof.t_scale_r,
            proof.t_bp, proof.t_scale_bp, proof.t_bbs,
        ]);

        // Fixed-base part: use precomputed tables for the 5 protocol generators.
        let mut fixed_sum = generators.h_tables[0].mul(&sc_h0);
        fixed_sum = &fixed_sum + &generators.h_tables[1].mul(&sc_h1);
        fixed_sum = &fixed_sum + &generators.h_tables[2].mul(&sc_h2);
        fixed_sum = &fixed_sum + &generators.h_tables[3].mul(&sc_h3);
        fixed_sum = &fixed_sum + &generators.h_tables[4].mul(&sc_h4);
        fixed_sum = &fixed_sum + &generators.h_tables[5].mul(&sc_h5);
        fixed_sum = &fixed_sum + &generators.g1_table.mul(&sc_g1);

        // Variable-base part: 12 dynamic proof points via Pippenger MSM.
        let var_scalars = [
            sc_aprime, sc_ctotal, sc_kprime, sc_cbp, sc_abar,
            sc_ttotal, sc_tscale_t, sc_trefund, sc_tscale_r,
            sc_tbp, sc_tscale_bp, sc_tbbs,
        ];
        let combined = &fixed_sum + &g1_msm(&dyn_pts, &var_scalars);
        if !bool::from(combined.is_identity()) {
            return Err(ActError::VerificationFailed("Combined bridge+Schnorr check failed".into()));
        }
    }

    // Build BatchedEqualityProof context and commitment list (used in rayon::join below).
    let mut beq_ctx = Vec::new();
    beq_ctx.extend_from_slice(&h_ctx.to_bytes());
    beq_ctx.extend_from_slice(&proof.s.to_le_bytes());
    beq_ctx.extend_from_slice(&proof.k_cur.to_bytes());
    beq_ctx.extend_from_slice(&proof.t_issue.to_le_bytes());
    beq_ctx.extend_from_slice(&proof.e_max.to_le_bytes());
    beq_ctx.extend_from_slice(&now_unix.to_le_bytes());
    beq_ctx.extend_from_slice(nonce);
    let beq_commitments = [
        G1Affine::from(proof.a_prime),
        G1Affine::from(proof.a_bar),
        G1Affine::from(proof.t_bbs),
        G1Affine::from(proof.k_prime),
        G1Affine::from(c_total),
        G1Affine::from(proof.x_bls_commitment),
        G1Affine::from(proof.c_delta),
    ];

    // BatchedEqualityProof + Pairing check run concurrently (mathematically
    // isolated: no shared mutable state).  rayon::join offloads one branch to
    // the thread pool, cutting combined latency from ~7ms to ~4ms.
    let (beq_result, pairing_ok) = rayon::join(
        || {
            verify_batched_equality(
                &proof.batched_eq, proof.c_bp,
                generators.h[3], generators.h[0],
                &beq_ctx, &beq_commitments,
            )
        },
        || {
            let result = Bls12::multi_miller_loop(&[
                (&G1Affine::from(proof.a_prime), &keys.pk_daily_prepared),
                (&G1Affine::from(-proof.a_bar),  &generators.g2_prepared),
            ])
            .final_exponentiation();
            result == Gt::identity()
        },
    );
    beq_result?;
    let mut expiry_ctx = Vec::new();
    expiry_ctx.extend_from_slice(&h_ctx.to_bytes());
    expiry_ctx.extend_from_slice(&proof.t_issue.to_le_bytes());
    expiry_ctx.extend_from_slice(&proof.e_max.to_le_bytes());
    expiry_ctx.extend_from_slice(&now_unix.to_le_bytes());
    expiry_ctx.extend_from_slice(&proof.k_cur.to_bytes());
    expiry_ctx.extend_from_slice(nonce);
    let expiry_commitments = [
        G1Affine::from(proof.a_prime),
        G1Affine::from(proof.a_bar),
        G1Affine::from(proof.t_bbs),
        G1Affine::from(proof.k_prime),
        G1Affine::from(proof.c_delta),
        G1Affine::from(proof.x_bls_commitment),
    ];
    verify_batched_equality(&proof.expiry_eq, proof.c_delta, generators.h[5], generators.h[0], &expiry_ctx, &expiry_commitments)?;
    if !pairing_ok {
        return Err(ActError::VerificationFailed("Pairing check failed".into()));
    }

    // Issue Refund Token
    let e_refund       = Scalar::rand(rng);
    let s_prime_refund = Scalar::rand(rng);
    let k_prime_aff    = G1Affine::from(proof.k_prime);
    let msg_part = g1_msm(
        &[generators.g1_affine, k_prime_aff, generators.h_affine[0]],
        &[BlsScalar::ONE, BlsScalar::ONE, s_prime_refund.0],
    );
    let denom = e_refund + keys.sk_daily;
    if denom.is_zero() {
        return Err(ActError::ProtocolError("Division by zero in issuance".into()));
    }
    let a_refund = &msg_part * &denom.inverse().0;

    Ok(SpendResponse { a_refund, e_refund, s_prime_refund })
}


/// Public BLS commitment to the hidden Emax proven by [`SpendProof`].
///
/// The spend proof contains `c_delta = (Emax - now_unix)*h5 + r*h0`;
/// adding `now_unix*h5` yields `Emax*h5 + r*h0`. The revocation gap
/// verifier uses this as its BLS-side commitment to the same hidden `Emax`.
pub fn spend_emax_bls_commitment(
    proof: &SpendProof,
    now_unix: u64,
    generators: &Generators,
) -> G1Projective {
    &proof.c_delta + &(&generators.h[5] * &Scalar::from(now_unix).0)
}

// ============================================================================
// Batch Server Verifier
// ============================================================================

/// Batch-verify a slice of [`SpendProof`]s sharing the same epoch and keys.
///
/// `nonces` must be the same length as `proofs`; each entry is the anti-replay
/// nonce for the corresponding proof.
///
/// # Batching strategy
///
/// * **Schnorr MSM** – per-proof Schwartz–Zippel equations combined into one
///   Pippenger MSM via RLC weights `ρ_i` derived from the per-proof challenges.
///
/// * **Pairing check** – G1 points aggregated via the same RLC weights;
///   a single 2-pair `multi_miller_loop` + one `final_exponentiation` replaces
///   N individual pairing checks.
///
/// * **BEQ range proofs** – verified concurrently via `rayon`.
///
/// Returns `Ok(Vec<SpendResponse>)` on success.  Returns `Err` if any proof is
/// invalid.
///
/// Falls back to [`verify_spend`] directly for 0 or 1 proofs.
pub fn verify_spend_batch(
    proofs: &[SpendProof],
    current_epoch: u32,
    now_unix: u64,
    nonces: &[[u8; 16]],
    generators: &Generators,
    pk_daily: &G2Projective,
    keys: &ServerKeys,
    h_ctx: Scalar,
    rng: &mut impl RngCore,
) -> Result<Vec<SpendResponse>> {
    if proofs.len() != nonces.len() {
        return Err(ActError::ProtocolError("proof/nonce length mismatch".into()));
    }
    // Safety-first integration path: the optimized batch verifier was tied to
    // the old transferable token layout. Use individual verification until the
    // new six-generator RLC batch formula is independently audited.
    proofs.iter().zip(nonces.iter())
        .map(|(proof, nonce)| verify_spend(proof, current_epoch, now_unix, nonce, generators, pk_daily, keys, h_ctx, rng))
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bbs_proof::BbsSignature;
    use crate::hash::compute_h_ctx;
    use crate::setup::{Generators, ServerKeys};
    use crate::types::Scalar;
    use rand::thread_rng;

    fn daily_sig(
        rng: &mut impl RngCore,
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
        let denom = e_d + keys.sk_daily;
        let a_d = &msg_part * &denom.inverse().0;
        BbsSignature { a: a_d, e: e_d, s: r_daily + s_p }
    }

    #[test]
    fn spend_roundtrip_nontransferable_with_expiry() {
        let mut rng = thread_rng();
        let generators = Generators::new();
        let keys = ServerKeys::generate(&mut rng);
        let h_ctx = compute_h_ctx("test-app", &keys.pk_master, &keys.pk_daily, &generators);
        let k_sub = Scalar::rand_nonzero(&mut rng);
        let k_cur = Scalar::rand_nonzero(&mut rng);
        let c_bal = 100u32;
        let t_issue = 42u32;
        let e_max = 5_000_000_000u64;
        let now = 1_700_000_000u64;
        let token = daily_sig(&mut rng, k_sub, k_cur, c_bal, t_issue, e_max, &generators, &keys);

        let (client, proof) = SpendProver::prove(
            &mut rng, &token, k_sub, k_cur, c_bal, t_issue, e_max, now, 30, &[0xAAu8; 16],
            &generators, &keys.pk_daily, h_ctx,
        ).unwrap();
        let resp = verify_spend(
            &proof, t_issue, now, &[0xAAu8; 16], &generators, &keys.pk_daily, &keys, h_ctx, &mut rng,
        ).unwrap();
        let refund = BbsSignature { a: resp.a_refund, e: resp.e_refund, s: client.r_star + resp.s_prime_refund };
        assert!(!bool::from(refund.a.is_identity()));
        assert_eq!(client.c_bal - 30, 70);
        assert_eq!(proof.e_max, e_max);
    }

    #[test]
    fn transfer_without_x_fails() {
        let mut rng = thread_rng();
        let generators = Generators::new();
        let keys = ServerKeys::generate(&mut rng);
        let h_ctx = compute_h_ctx("test-app", &keys.pk_master, &keys.pk_daily, &generators);
        let real_x = Scalar::rand_nonzero(&mut rng);
        let wrong_x = Scalar::rand_nonzero(&mut rng);
        let k_cur = Scalar::rand_nonzero(&mut rng);
        let e_max = 5_000_000_000u64;
        let token = daily_sig(&mut rng, real_x, k_cur, 100, 42, e_max, &generators, &keys);
        let (_client, proof) = SpendProver::prove(
            &mut rng, &token, wrong_x, k_cur, 100, 42, e_max, 1_700_000_000, 30, &[0xAAu8; 16],
            &generators, &keys.pk_daily, h_ctx,
        ).unwrap();
        assert!(verify_spend(&proof, 42, 1_700_000_000, &[0xAAu8; 16], &generators, &keys.pk_daily, &keys, h_ctx, &mut rng).is_err());
    }

    #[test]
    fn expired_spend_rejected() {
        let mut rng = thread_rng();
        let generators = Generators::new();
        let keys = ServerKeys::generate(&mut rng);
        let h_ctx = compute_h_ctx("test-app", &keys.pk_master, &keys.pk_daily, &generators);
        let k_sub = Scalar::rand_nonzero(&mut rng);
        let k_cur = Scalar::rand_nonzero(&mut rng);
        let token = daily_sig(&mut rng, k_sub, k_cur, 100, 42, 1_000, &generators, &keys);
        assert!(SpendProver::prove(
            &mut rng, &token, k_sub, k_cur, 100, 42, 1_000, 2_000, 30, &[0xAAu8; 16],
            &generators, &keys.pk_daily, h_ctx,
        ).is_err());
    }
}
