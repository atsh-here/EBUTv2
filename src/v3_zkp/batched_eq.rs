use ff::Field; // FIX: Gives access to BlsScalar::random()
use group::Curve; // FIX: Gives access to G1Projective::to_affine()

use crate::v3_zkp::generators::{bls_g1_affine, bls_h1_affine, ristretto_g1, ristretto_gv};
use crate::v3_zkp::utils::{biguint_to_bls_scalar, biguint_to_ristretto_scalar};

use blstrs::{G1Projective, Scalar as BlsScalar};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as RistrettoScalar;
use curve25519_dalek_ng::traits::VartimeMultiscalarMul;

use num_bigint::BigUint;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct BatchedEqualityProof {
    pub r1_comb: RistrettoPoint,
    pub r2_comb: G1Projective,
    pub z_e: BigUint,
    pub z_r1: RistrettoScalar,
    pub z_r2: BlsScalar,
}


fn write_public_statement(hasher: &mut Sha256,
    com_e_rist: &RistrettoPoint, com_e_bls: &G1Projective,
    com_ea_rist: &RistrettoPoint, com_ea_bls: &G1Projective,
    com_eb_rist: &RistrettoPoint, com_eb_bls: &G1Projective,
) {
    hasher.update(com_e_rist.compress().as_bytes());
    hasher.update(com_e_bls.to_affine().to_compressed().as_ref());
    hasher.update(com_ea_rist.compress().as_bytes());
    hasher.update(com_ea_bls.to_affine().to_compressed().as_ref());
    hasher.update(com_eb_rist.compress().as_bytes());
    hasher.update(com_eb_bls.to_affine().to_compressed().as_ref());
}

fn equality_challenge(
    r1_point: &RistrettoPoint,
    r2_point: &G1Projective,
    com_e_rist: &RistrettoPoint, com_e_bls: &G1Projective,
    com_ea_rist: &RistrettoPoint, com_ea_bls: &G1Projective,
    com_eb_rist: &RistrettoPoint, com_eb_bls: &G1Projective,
) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"cross_curve_batched_proof_v2");
    write_public_statement(&mut hasher, com_e_rist, com_e_bls, com_ea_rist, com_ea_bls, com_eb_rist, com_eb_bls);
    hasher.update(r1_point.compress().as_bytes());
    hasher.update(r2_point.to_affine().to_compressed().as_ref());
    BigUint::from_bytes_be(&hasher.finalize()[0..16])
}

impl BatchedEqualityProof {
    pub fn size_in_bytes(&self) -> usize {
        32 + 48 + self.z_e.to_bytes_le().len() + 32 + 32
    }

    pub fn prove(
        e: u64, ea: u64, eb: u64,
        r1_e: RistrettoScalar, r2_e: BlsScalar,
        r1_ea: RistrettoScalar, r2_ea: BlsScalar,
        r1_eb: RistrettoScalar, r2_eb: BlsScalar,
        com_e_rist: RistrettoPoint, com_e_bls: G1Projective,
        com_ea_rist: RistrettoPoint, com_ea_bls: G1Projective,
        com_eb_rist: RistrettoPoint, com_eb_bls: G1Projective,
    ) -> Self {
        Self::prove_with_bls_bases(
            e, ea, eb,
            r1_e, r2_e, r1_ea, r2_ea, r1_eb, r2_eb,
            com_e_rist, com_e_bls, com_ea_rist, com_ea_bls, com_eb_rist, com_eb_bls,
            G1Projective::from(bls_g1_affine()),
            G1Projective::from(bls_h1_affine()),
        )
    }

    /// Prove batched equality when the BLS commitment uses caller-supplied
    /// bases `value_base` and `blind_base`:
    /// `C_B = value * value_base + blinder * blind_base`.
    pub fn prove_with_bls_bases(
        e: u64, ea: u64, eb: u64,
        r1_e: RistrettoScalar, r2_e: BlsScalar,
        r1_ea: RistrettoScalar, r2_ea: BlsScalar,
        r1_eb: RistrettoScalar, r2_eb: BlsScalar,
        com_e_rist: RistrettoPoint, com_e_bls: G1Projective,
        com_ea_rist: RistrettoPoint, com_ea_bls: G1Projective,
        com_eb_rist: RistrettoPoint, com_eb_bls: G1Projective,
        bls_value_base: G1Projective,
        bls_blind_base: G1Projective,
    ) -> Self {
        let mut rng = OsRng;

        let mut hasher = Sha256::new();
        hasher.update(b"batch_gamma_v1");
        hasher.update(com_e_rist.compress().as_bytes());
        hasher.update(com_e_bls.to_affine().to_compressed().as_ref());
        hasher.update(com_ea_rist.compress().as_bytes());
        hasher.update(com_ea_bls.to_affine().to_compressed().as_ref());
        hasher.update(com_eb_rist.compress().as_bytes());
        hasher.update(com_eb_bls.to_affine().to_compressed().as_ref());
        let hash_out = hasher.finalize();
        
        let gamma = BigUint::from_bytes_be(&hash_out[0..10]);
        let gamma2 = &gamma * &gamma;

        let e_comb = BigUint::from(e) + &gamma * BigUint::from(ea) + &gamma2 * BigUint::from(eb);
        
        let gamma_rist = biguint_to_ristretto_scalar(&gamma);
        let gamma2_rist = biguint_to_ristretto_scalar(&gamma2);
        let r1_comb = r1_e + gamma_rist * r1_ea + gamma2_rist * r1_eb;

        let gamma_bls = biguint_to_bls_scalar(&gamma);
        let gamma2_bls = biguint_to_bls_scalar(&gamma2);
        let r2_comb = r2_e + gamma_bls * r2_ea + gamma2_bls * r2_eb;

        let mut k_bytes = [0u8; 54];
        rng.fill_bytes(&mut k_bytes);
        let k = BigUint::from_bytes_le(&k_bytes);

        let mut u1_bytes = [0u8; 32];
        rng.fill_bytes(&mut u1_bytes);
        let u1 = RistrettoScalar::from_bytes_mod_order(u1_bytes);
        let u2 = BlsScalar::random(&mut rng);

        let k_mod_q = biguint_to_ristretto_scalar(&k);
        let k_mod_r = biguint_to_bls_scalar(&k);

        let r1_point = RistrettoPoint::vartime_multiscalar_mul(&[k_mod_q, u1], &[ristretto_gv(), ristretto_g1()]);
        let r2_point = bls_value_base * k_mod_r + bls_blind_base * u2;

        let c = equality_challenge(
            &r1_point, &r2_point,
            &com_e_rist, &com_e_bls,
            &com_ea_rist, &com_ea_bls,
            &com_eb_rist, &com_eb_bls,
        );

        let z_e = k + &c * &e_comb;
        let z_r1 = u1 + biguint_to_ristretto_scalar(&c) * r1_comb;
        let z_r2 = u2 + biguint_to_bls_scalar(&c) * r2_comb;

        BatchedEqualityProof { r1_comb: r1_point, r2_comb: r2_point, z_e, z_r1, z_r2 }
    }

    pub fn verify(
        &self,
        com_e_rist: RistrettoPoint, com_e_bls: G1Projective,
        com_ea_rist: RistrettoPoint, com_ea_bls: G1Projective,
        com_eb_rist: RistrettoPoint, com_eb_bls: G1Projective,
    ) -> bool {
        self.verify_with_bls_bases(
            com_e_rist, com_e_bls, com_ea_rist, com_ea_bls, com_eb_rist, com_eb_bls,
            G1Projective::from(bls_g1_affine()),
            G1Projective::from(bls_h1_affine()),
        )
    }

    /// Verify batched equality against BLS commitments in the form
    /// `C_B = value * value_base + blinder * blind_base`.
    pub fn verify_with_bls_bases(
        &self,
        com_e_rist: RistrettoPoint, com_e_bls: G1Projective,
        com_ea_rist: RistrettoPoint, com_ea_bls: G1Projective,
        com_eb_rist: RistrettoPoint, com_eb_bls: G1Projective,
        bls_value_base: G1Projective,
        bls_blind_base: G1Projective,
    ) -> bool {
        let limit = BigUint::from(1u32) << 433;
        if self.z_e >= limit {
            println!("❌ Batched z_e too large (CRT forgery attempt)");
            return false;
        }

        let mut hasher = Sha256::new();
        hasher.update(b"batch_gamma_v1");
        hasher.update(com_e_rist.compress().as_bytes());
        hasher.update(com_e_bls.to_affine().to_compressed().as_ref());
        hasher.update(com_ea_rist.compress().as_bytes());
        hasher.update(com_ea_bls.to_affine().to_compressed().as_ref());
        hasher.update(com_eb_rist.compress().as_bytes());
        hasher.update(com_eb_bls.to_affine().to_compressed().as_ref());
        let hash_out = hasher.finalize();
        
        let gamma = BigUint::from_bytes_be(&hash_out[0..10]);
        let gamma2 = &gamma * &gamma;

        let gamma_rist = biguint_to_ristretto_scalar(&gamma);
        let gamma2_rist = biguint_to_ristretto_scalar(&gamma2);
        let com_comb_rist = com_e_rist + com_ea_rist * gamma_rist + com_eb_rist * gamma2_rist;

        let gamma_bls = biguint_to_bls_scalar(&gamma);
        let gamma2_bls = biguint_to_bls_scalar(&gamma2);
        let com_comb_bls = com_e_bls + com_ea_bls * gamma_bls + com_eb_bls * gamma2_bls;

        let c = equality_challenge(
            &self.r1_comb, &self.r2_comb,
            &com_e_rist, &com_e_bls,
            &com_ea_rist, &com_ea_bls,
            &com_eb_rist, &com_eb_bls,
        );

        let z_q = biguint_to_ristretto_scalar(&self.z_e);
        let z_r = biguint_to_bls_scalar(&self.z_e);
        let c_q = biguint_to_ristretto_scalar(&c);
        let c_r = biguint_to_bls_scalar(&c);

        let lhs_rist = RistrettoPoint::vartime_multiscalar_mul(&[z_q, self.z_r1], &[ristretto_gv(), ristretto_g1()]);
        if lhs_rist != self.r1_comb + com_comb_rist * c_q { return false; }
        
        let lhs_bls = bls_value_base * z_r + bls_blind_base * self.z_r2;
        if lhs_bls != self.r2_comb + com_comb_bls * c_r { return false; }
        
        true
    }
}
