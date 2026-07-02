use ff::Field; // FIX: Gives access to BlsScalar::random()
use pairing::MillerLoopResult; // FIX: Gives access to final_exponentiation()

use crate::v3_zkp::generators::{bls_g1_affine, bls_h1_affine, neg_g2_prepared};
use crate::v3_zkp::utils::biguint_to_bls_scalar;

use blstrs::{Bls12, G1Projective, G2Prepared, G2Projective, Gt, Scalar as BlsScalar};
use group::{Curve, Group};
use num_bigint::BigUint;
use pairing::{Engine, MultiMillerLoop};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct ServerPublicKey {
    pub x_g2: G2Projective,
    pub y1_g2: G2Projective,
    pub y2_g2: G2Projective,
    /// Public key component binding signed gaps to a revocation context.
    pub yctx_g2: G2Projective,
}

pub struct ServerSecretKey {
    pub x: BlsScalar, pub y1: BlsScalar, pub y2: BlsScalar, pub yctx: BlsScalar,
}

impl ServerSecretKey {
    pub fn generate() -> (Self, ServerPublicKey) {
        let mut rng = OsRng;
        let x = BlsScalar::random(&mut rng);
        let y1 = BlsScalar::random(&mut rng);
        let y2 = BlsScalar::random(&mut rng);
        let yctx = BlsScalar::random(&mut rng);
        let g2 = G2Projective::generator();
        (Self { x, y1, y2, yctx }, ServerPublicKey { x_g2: g2 * x, y1_g2: g2 * y1, y2_g2: g2 * y2, yctx_g2: g2 * yctx })
    }
    pub fn sign_interval(&self, ea: u64, eb: u64) -> (G1Projective, G1Projective) {
        self.sign_interval_with_context(ea, eb, BlsScalar::ZERO)
    }

    /// Sign an open revocation gap for a specific public context.
    /// The context scalar must be derived from app_id, policy_id, server key id,
    /// and revocation_list_version. This prevents rollback/replay of old gap signatures.
    pub fn sign_interval_with_context(&self, ea: u64, eb: u64, gap_ctx: BlsScalar) -> (G1Projective, G1Projective) {
        let h = G1Projective::random(&mut OsRng);
        let exp = self.x + self.y1 * BlsScalar::from(ea) + self.y2 * BlsScalar::from(eb) + self.yctx * gap_ctx;
        (h, h * exp)
    }
}


fn gt_bytes(gt: &Gt) -> Vec<u8> {
    // blstrs::Gt in this dependency set does not expose canonical bytes.
    // This keeps the prototype compiling; production must replace this with
    // stable canonical serialization from a pairing library that exposes it.
    format!("{:?}", gt).into_bytes()
}

fn hash_gap_transcript(
    pk: &ServerPublicKey,
    gap_ctx: BlsScalar,
    bls_value_base: G1Projective,
    bls_blind_base: G1Projective,
    com_ea: G1Projective,
    com_eb: G1Projective,
    sigma1_blind: G1Projective,
    sigma2_blind: G1Projective,
    a1: G1Projective,
    a2: G1Projective,
    a_pair: &Gt,
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"gap_proof_v3_ctx_bound");
    hasher.update(pk.x_g2.to_affine().to_compressed().as_ref());
    hasher.update(pk.y1_g2.to_affine().to_compressed().as_ref());
    hasher.update(pk.y2_g2.to_affine().to_compressed().as_ref());
    hasher.update(pk.yctx_g2.to_affine().to_compressed().as_ref());
    hasher.update(gap_ctx.to_bytes_le());
    hasher.update(bls_value_base.to_affine().to_compressed().as_ref());
    hasher.update(bls_blind_base.to_affine().to_compressed().as_ref());
    hasher.update(com_ea.to_affine().to_compressed().as_ref());
    hasher.update(com_eb.to_affine().to_compressed().as_ref());
    hasher.update(sigma1_blind.to_affine().to_compressed().as_ref());
    hasher.update(sigma2_blind.to_affine().to_compressed().as_ref());
    hasher.update(a1.to_affine().to_compressed().as_ref());
    hasher.update(a2.to_affine().to_compressed().as_ref());
    hasher.update(gt_bytes(a_pair));
    BigUint::from_bytes_be(&hasher.finalize())
}

#[derive(Clone, Debug)]
pub struct GapProof {
    pub com_ea: G1Projective, pub com_eb: G1Projective,
    pub sigma1_blind: G1Projective, pub sigma2_blind: G1Projective,
    pub a1: G1Projective, pub a2: G1Projective, pub a_pair: Gt,
    pub challenge: BigUint,
    pub s_ea: BlsScalar, pub s_ra: BlsScalar, pub s_eb: BlsScalar, pub s_rb: BlsScalar,
}

impl GapProof {
    pub fn size_in_bytes(&self) -> usize {
        48 * 6 + 576 + self.challenge.to_bytes_le().len() + 32 * 4
    }

    pub fn prove(
        ea: u64, eb: u64, ra: BlsScalar, rb: BlsScalar,
        sigma1: G1Projective, sigma2: G1Projective,
        t: BlsScalar, pk: &ServerPublicKey,
    ) -> Self {
        Self::prove_with_context(ea, eb, ra, rb, sigma1, sigma2, t, BlsScalar::ZERO, pk)
    }

    pub fn prove_with_context(
        ea: u64, eb: u64, ra: BlsScalar, rb: BlsScalar,
        sigma1: G1Projective, sigma2: G1Projective,
        t: BlsScalar, gap_ctx: BlsScalar, pk: &ServerPublicKey,
    ) -> Self {
        Self::prove_with_context_and_bases(
            ea, eb, ra, rb, sigma1, sigma2, t, gap_ctx, pk,
            G1Projective::from(bls_g1_affine()),
            G1Projective::from(bls_h1_affine()),
        )
    }

    /// Prove a context-bound signed gap while committing to endpoints using
    /// caller-supplied BLS Pedersen bases.
    pub fn prove_with_context_and_bases(
        ea: u64, eb: u64, ra: BlsScalar, rb: BlsScalar,
        sigma1: G1Projective, sigma2: G1Projective,
        t: BlsScalar, gap_ctx: BlsScalar, pk: &ServerPublicKey,
        bls_value_base: G1Projective,
        bls_blind_base: G1Projective,
    ) -> Self {
        let mut rng = OsRng;
        let g1 = bls_value_base;
        let h1 = bls_blind_base;
        let ea_scalar = BlsScalar::from(ea);
        let eb_scalar = BlsScalar::from(eb);

        let com_ea = g1 * ea_scalar + h1 * ra;
        let com_eb = g1 * eb_scalar + h1 * rb;
        let sigma1_blind = sigma1 * t;
        let sigma2_blind = sigma2 * t;

        let r_ea = BlsScalar::random(&mut rng); let r_ra = BlsScalar::random(&mut rng);
        let r_eb = BlsScalar::random(&mut rng); let r_rb = BlsScalar::random(&mut rng);

        let a1 = g1 * r_ea + h1 * r_ra;
        let a2 = g1 * r_eb + h1 * r_rb;

        let combined_pk_g2 = pk.y1_g2 * r_ea + pk.y2_g2 * r_eb;
        let a_pair = Bls12::pairing(&sigma1_blind.to_affine(), &combined_pk_g2.to_affine());

        let challenge = hash_gap_transcript(pk, gap_ctx, bls_value_base, bls_blind_base, com_ea, com_eb, sigma1_blind, sigma2_blind, a1, a2, &a_pair);
        let c = biguint_to_bls_scalar(&challenge);

        GapProof {
            com_ea, com_eb, sigma1_blind, sigma2_blind, a1, a2, a_pair, challenge,
            s_ea: r_ea + c * ea_scalar, s_ra: r_ra + c * ra,
            s_eb: r_eb + c * eb_scalar, s_rb: r_rb + c * rb,
        }
    }

    pub fn verify(&self, pk: &ServerPublicKey) -> bool {
        self.verify_with_context(pk, BlsScalar::ZERO)
    }

    pub fn verify_with_context(&self, pk: &ServerPublicKey, gap_ctx: BlsScalar) -> bool {
        self.verify_with_context_and_bases(
            pk, gap_ctx,
            G1Projective::from(bls_g1_affine()),
            G1Projective::from(bls_h1_affine()),
        )
    }

    /// Verify a context-bound signed gap whose endpoint commitments use
    /// caller-supplied BLS Pedersen bases.
    pub fn verify_with_context_and_bases(
        &self, pk: &ServerPublicKey, gap_ctx: BlsScalar,
        bls_value_base: G1Projective,
        bls_blind_base: G1Projective,
    ) -> bool {
        let challenge_recomputed = hash_gap_transcript(
            pk, gap_ctx, bls_value_base, bls_blind_base, self.com_ea, self.com_eb, self.sigma1_blind,
            self.sigma2_blind, self.a1, self.a2, &self.a_pair,
        );
        if self.challenge != challenge_recomputed { return false; }

        let c = biguint_to_bls_scalar(&self.challenge);
        let g1 = bls_value_base;
        let h1 = bls_blind_base;
        
        if self.a1 != g1 * self.s_ea + h1 * self.s_ra - (self.com_ea * c) { return false; }
        if self.a2 != g1 * self.s_eb + h1 * self.s_rb - (self.com_eb * c) { return false; }

        let combined_pk_g2 = pk.y1_g2 * self.s_ea + pk.y2_g2 * self.s_eb + (pk.x_g2 + pk.yctx_g2 * gap_ctx) * c;
        let terms = [
            (&self.sigma1_blind.to_affine(), &G2Prepared::from(combined_pk_g2.to_affine())),
            (&(self.sigma2_blind * c).to_affine(), neg_g2_prepared()),
        ];
        self.a_pair == Bls12::multi_miller_loop(&terms).final_exponentiation()
    }
}
