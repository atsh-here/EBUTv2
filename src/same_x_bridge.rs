//! Cross-curve equality proof for the EBUT ownership secret `x`.
//!
//! This module implements the missing bridge that the old NTAT file-binding
//! layer did not have: a proof that the same canonical integer `x` is used in a
//! BLS12-381 commitment and a Ristretto commitment/tag.
//!
//! Important scope boundary:
//! - This proves equality between *commitments* to `x` across the two curves.
//! - The EBUT spend/refresh proof must also prove that the BLS commitment used
//!   here contains the same hidden `x` signed inside the BBS+ token. That hook is
//!   represented by `bls_x_commitment` in the upload proof.
//!
//! The canonical secret is intentionally limited to 248 bits (31 bytes). This
//! keeps it below both scalar moduli and makes the integer-response Sigma proof
//! safe from modular wrap/CRT ambiguity when combined with a 128-bit challenge.

use blstrs::{G1Projective, Scalar as BlsScalar};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as RistrettoScalar;
use ff::Field;
use group::{Curve, Group};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::error::{ActError, Result};
use crate::types::Scalar as EbutScalar;

/// Maximum bit length for the canonical ownership secret `x`.
pub const CANONICAL_X_BITS: usize = 248;
/// Fiat-Shamir challenge length in bits.
pub const X_BRIDGE_CHALLENGE_BITS: usize = 128;
/// Integer blinding length. 384 bits gives statistical hiding with a 248-bit witness.
pub const X_BRIDGE_BLINDING_BYTES: usize = 48;
/// Bound on `z_x = u + c*x`. 384 + 1 bits is enough and far below q_BLS*q_Ristretto.
pub const X_BRIDGE_Z_BOUND_BITS: usize = 385;

/// A canonical cross-curve ownership secret.
///
/// Store the user master secret as this 31-byte integer, then embed it into both
/// BLS12-381 and Ristretto scalar fields. Do **not** generate unrelated BLS and
/// Ristretto scalars independently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalX(pub [u8; 31]);

impl CanonicalX {
    /// Generate a random 248-bit ownership secret.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut b = [0u8; 31];
        rng.fill_bytes(&mut b);
        // Avoid zero because x=0 would create identity nullifiers/tags.
        if b.iter().all(|x| *x == 0) { b[0] = 1; }
        Self(b)
    }

    /// Interpret as little-endian integer.
    pub fn to_biguint(self) -> BigUint { BigUint::from_bytes_le(&self.0) }


    /// Embed into the EBUT/BLS scalar wrapper used by BBS+ messages.
    pub fn to_ebut_scalar(self) -> EbutScalar { EbutScalar(self.to_bls_scalar()) }

    /// Embed into BLS12-381 scalar field.
    pub fn to_bls_scalar(self) -> BlsScalar {
        let mut b = [0u8; 32];
        b[..31].copy_from_slice(&self.0);
        // 248-bit value is strictly below the BLS12-381 scalar modulus.
        Option::<BlsScalar>::from(BlsScalar::from_bytes_le(&b))
            .expect("248-bit CanonicalX must fit in BLS scalar")
    }

    /// Embed into Ristretto/Curve25519 scalar field.
    pub fn to_ristretto_scalar(self) -> RistrettoScalar {
        let mut b = [0u8; 32];
        b[..31].copy_from_slice(&self.0);
        // 248-bit value is strictly below the Ristretto scalar modulus.
        RistrettoScalar::from_canonical_bytes(b).expect("248-bit CanonicalX must fit in Ristretto scalar")
    }
}

/// Public statement for equality of `x` in a BLS commitment and a Ristretto commitment.
#[derive(Clone, Debug)]
pub struct SameXStatement {
    /// BLS value base for x.
    pub bls_x_base: G1Projective,
    /// BLS blinding base.
    pub bls_blind_base: G1Projective,
    /// `C_bls = x*bls_x_base + r_bls*bls_blind_base`.
    pub bls_x_commitment: G1Projective,

    /// Ristretto value base. For file binding this is usually `H_file`.
    pub ristretto_x_base: RistrettoPoint,
    /// Ristretto blinding base. For a plain file tag use `RistrettoPoint::default()` and blinding zero.
    pub ristretto_blind_base: RistrettoPoint,
    /// `C_rist = x*ristretto_x_base + r_rist*ristretto_blind_base`.
    pub ristretto_x_commitment: RistrettoPoint,
}

/// Proof that the same canonical integer `x` opens both commitments.
#[derive(Clone, Debug)]
pub struct SameXProof {
    pub t_bls: G1Projective,
    pub t_ristretto: RistrettoPoint,
    pub c_bytes: [u8; 16],
    /// Integer response `z_x = u + c*x`, little-endian.
    pub z_x_le: Vec<u8>,
    pub z_r_bls: BlsScalar,
    pub z_r_ristretto: RistrettoScalar,
}

fn biguint_to_bls_scalar(x: &BigUint) -> BlsScalar {
    // blstrs 0.7 does not expose from_bytes_wide; reduce explicitly.
    let r = BigUint::parse_bytes(
        b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001",
        16,
    ).expect("valid BLS scalar modulus");
    let reduced = x % r;
    let mut b = [0u8; 32];
    let le = reduced.to_bytes_le();
    let n = le.len().min(32);
    b[..n].copy_from_slice(&le[..n]);
    Option::<BlsScalar>::from(BlsScalar::from_bytes_le(&b))
        .expect("reduced value is canonical BLS scalar")
}

fn biguint_to_ristretto_scalar(x: &BigUint) -> RistrettoScalar {
    let mut b = [0u8; 64];
    let le = x.to_bytes_le();
    let n = le.len().min(64);
    b[..n].copy_from_slice(&le[..n]);
    RistrettoScalar::from_bytes_mod_order_wide(&b)
}

fn write_g1(buf: &mut Vec<u8>, p: G1Projective) {
    buf.extend_from_slice(p.to_affine().to_compressed().as_ref());
}

fn write_rist(buf: &mut Vec<u8>, p: RistrettoPoint) {
    buf.extend_from_slice(p.compress().as_bytes());
}

fn challenge(ctx: &[u8], st: &SameXStatement, t_bls: G1Projective, t_rist: RistrettoPoint) -> [u8; 16] {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"EBUT:SAME-X-BRIDGE:V1");
    bytes.extend_from_slice(&(ctx.len() as u64).to_le_bytes());
    bytes.extend_from_slice(ctx);
    write_g1(&mut bytes, st.bls_x_base);
    write_g1(&mut bytes, st.bls_blind_base);
    write_g1(&mut bytes, st.bls_x_commitment);
    write_rist(&mut bytes, st.ristretto_x_base);
    write_rist(&mut bytes, st.ristretto_blind_base);
    write_rist(&mut bytes, st.ristretto_x_commitment);
    write_g1(&mut bytes, t_bls);
    write_rist(&mut bytes, t_rist);
    let h = Sha256::digest(&bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h[..16]);
    out
}


fn validate_statement(statement: &SameXStatement) -> Result<()> {
    if bool::from(statement.bls_x_base.is_identity())
        || bool::from(statement.bls_blind_base.is_identity())
        || bool::from(statement.bls_x_commitment.is_identity())
        || statement.ristretto_x_base == RistrettoPoint::default()
        || statement.ristretto_x_commitment == RistrettoPoint::default()
    {
        return Err(ActError::VerificationFailed("same-x statement contains an identity point".into()));
    }
    Ok(())
}

fn canonical_biguint_le(bytes: &[u8]) -> bool {
    bytes.len() <= X_BRIDGE_BLINDING_BYTES + 1
        && (bytes.len() <= 1 || *bytes.last().unwrap_or(&0) != 0)
}

impl SameXProof {
    /// Prove equality of x across the two commitments.
    pub fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        ctx: &[u8],
        x: CanonicalX,
        r_bls: BlsScalar,
        r_ristretto: RistrettoScalar,
        statement: &SameXStatement,
    ) -> Result<Self> {
        validate_statement(statement)?;
        let mut u_bytes = [0u8; X_BRIDGE_BLINDING_BYTES];
        rng.fill_bytes(&mut u_bytes);
        let u = BigUint::from_bytes_le(&u_bytes);
        let u_bls = biguint_to_bls_scalar(&u);
        let u_rist = biguint_to_ristretto_scalar(&u);

        let alpha_bls = BlsScalar::random(&mut *rng);
        let alpha_rist = RistrettoScalar::random(&mut *rng);

        let t_bls = statement.bls_x_base * u_bls + statement.bls_blind_base * alpha_bls;
        let t_ristretto = statement.ristretto_x_base * u_rist + statement.ristretto_blind_base * alpha_rist;

        let c_bytes = challenge(ctx, statement, t_bls, t_ristretto);
        let c = BigUint::from_bytes_le(&c_bytes);
        let c_bls = biguint_to_bls_scalar(&c);
        let c_rist = biguint_to_ristretto_scalar(&c);

        let z_x = u + c * x.to_biguint();
        if z_x.bits() > X_BRIDGE_Z_BOUND_BITS as u64 {
            return Err(ActError::ProtocolError("same-x response bound exceeded".into()));
        }

        Ok(Self {
            t_bls,
            t_ristretto,
            c_bytes,
            z_x_le: z_x.to_bytes_le(),
            z_r_bls: alpha_bls + c_bls * r_bls,
            z_r_ristretto: alpha_rist + c_rist * r_ristretto,
        })
    }

    /// Verify equality of x across both commitments.
    pub fn verify(&self, ctx: &[u8], statement: &SameXStatement) -> Result<()> {
        validate_statement(statement)?;
        if !canonical_biguint_le(&self.z_x_le) {
            return Err(ActError::VerificationFailed("same-x z_x is not canonical".into()));
        }
        let expected_c = challenge(ctx, statement, self.t_bls, self.t_ristretto);
        if expected_c != self.c_bytes {
            return Err(ActError::VerificationFailed("same-x challenge mismatch".into()));
        }
        let z_x = BigUint::from_bytes_le(&self.z_x_le);
        if z_x.bits() > X_BRIDGE_Z_BOUND_BITS as u64 {
            return Err(ActError::VerificationFailed("same-x z_x bound exceeded".into()));
        }
        let z_bls = biguint_to_bls_scalar(&z_x);
        let z_rist = biguint_to_ristretto_scalar(&z_x);
        let c = BigUint::from_bytes_le(&self.c_bytes);
        let c_bls = biguint_to_bls_scalar(&c);
        let c_rist = biguint_to_ristretto_scalar(&c);

        let lhs_bls = statement.bls_x_base * z_bls + statement.bls_blind_base * self.z_r_bls;
        let rhs_bls = self.t_bls + statement.bls_x_commitment * c_bls;
        if lhs_bls != rhs_bls {
            return Err(ActError::VerificationFailed("same-x BLS equation failed".into()));
        }

        let lhs_rist = statement.ristretto_x_base * z_rist + statement.ristretto_blind_base * self.z_r_ristretto;
        let rhs_rist = self.t_ristretto + statement.ristretto_x_commitment * c_rist;
        if lhs_rist != rhs_rist {
            return Err(ActError::VerificationFailed("same-x Ristretto equation failed".into()));
        }
        Ok(())
    }
}

/// Build the Ristretto side of the same-x statement for an unblinded file tag.
///
/// The tag is `binding_tag = x * binding_generator`, so the Ristretto blinding
/// base and blinding scalar are zero.
pub fn file_tag_statement(
    bls_x_base: G1Projective,
    bls_blind_base: G1Projective,
    bls_x_commitment: G1Projective,
    binding_generator: RistrettoPoint,
    binding_tag: RistrettoPoint,
) -> SameXStatement {
    SameXStatement {
        bls_x_base,
        bls_blind_base,
        bls_x_commitment,
        ristretto_x_base: binding_generator,
        ristretto_blind_base: RistrettoPoint::default(),
        ristretto_x_commitment: binding_tag,
    }
}
