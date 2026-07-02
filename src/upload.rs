//! Upload-level composition for EBUT spend + reversible file binding.
//!
//! The verifier performs three independent checks:
//! 1. EBUT spend/refund proof for rate limiting and balance.
//! 2. Reversible Ristretto ElGamal file-binding proof.
//! 3. Cross-curve same-`x` proof linking an EBUT/BLS commitment to the
//!    Ristretto file-binding tag.

use blstrs::G2Projective;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

use crate::error::{ActError, Result};
use crate::file_binding::{FileCommitment, AccountableFileProof, verify_accountable_file_proof_with_confidence};
use crate::same_x_bridge::{SameXProof, SameXStatement};
use crate::revocation::{RevocationContext, verify_spend_not_revoked};
use crate::v3_zkp::gap::ServerPublicKey as RevocationServerPublicKey;
use crate::v3_zkp::prover::TimedProof as RevocationProof;
use crate::setup::{Generators, ServerKeys};
use crate::spend::{SpendProof, SpendResponse, verify_spend};
use crate::types::Scalar;

/// Default audit confidence for upload spot-checks.
/// The verifier enforces this count; clients cannot choose a cheaper proof.
pub const DEFAULT_FILE_AUDIT_CONFIDENCE: f64 = 0.90;

/// Derive the Ristretto generator that binds a file proof to a concrete EBUT
/// context. The verifier recomputes this value, so clients cannot choose a free
/// generator unrelated to the file, epoch, expiry, or revocation list.
pub fn derive_file_binding_generator(
    h_ctx: Scalar,
    current_epoch: u32,
    now_unix: u64,
    e_max: u64,
    file_commitment: &FileCommitment,
    revocation_list_version: u64,
) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(b"EBUT:FILE:BINDING-GENERATOR:V1");
    h.update(h_ctx.to_bytes());
    h.update(current_epoch.to_le_bytes());
    h.update(now_unix.to_le_bytes());
    h.update(e_max.to_le_bytes());
    h.update(revocation_list_version.to_le_bytes());
    h.update(file_commitment.file_id);
    h.update(file_commitment.root_hash);
    h.update(file_commitment.num_blocks.to_le_bytes());
    h.update((file_commitment.block_size as u64).to_le_bytes());
    h.update(file_commitment.file_size.to_le_bytes());
    h.update(file_commitment.encoding_version.to_le_bytes());
    RistrettoPoint::from_uniform_bytes(&h.finalize().into())
}

/// Public tag used by the Ristretto file-binding proof.
/// `binding_tag = x_ristretto * binding_generator`.
#[derive(Clone, Debug)]
pub struct FileBindingTag {
    pub binding_generator: RistrettoPoint,
    pub binding_tag: RistrettoPoint,
    /// Public ElGamal key `X_file = x * G` used to encrypt file blocks.
    pub encryption_public_key: RistrettoPoint,
}

/// Full upload proof object.
#[derive(Clone, Debug)]
pub struct UploadSpendProof {
    pub spend_proof: SpendProof,
    pub nonce: [u8; 16],
    pub file_commitment: FileCommitment,
    /// Server-provided unpredictable challenge nonce, issued only after the
    /// verifier has seen/bound the file commitment/root. This prevents the
    /// uploader from choosing indices that avoid corrupted blocks.
    pub file_challenge_nonce: [u8; 32],
    pub file_proof: AccountableFileProof,
    pub file_binding: FileBindingTag,
    pub same_x_statement: SameXStatement,
    pub same_x_proof: SameXProof,
    /// Context bytes bound into the same-x proof. Must include h_ctx, epoch/time,
    /// Emax, file_id/root, and revocation-list version. The verifier does not parse
    /// these bytes, but it separately recomputes the file-binding generator above.
    pub same_x_context: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
fn verify_upload_spend_inner<R: RngCore + CryptoRng>(
    proof: &UploadSpendProof,
    current_epoch: u32,
    now_unix: u64,
    revocation_list_version: u64,
    generators: &Generators,
    pk_daily: &G2Projective,
    keys: &ServerKeys,
    h_ctx: Scalar,
    rng: &mut R,
) -> Result<SpendResponse> {
    // 1. EBUT spend/rate-limit/balance proof.
    let response = verify_spend(
        &proof.spend_proof,
        current_epoch,
        now_unix,
        &proof.nonce,
        generators,
        pk_daily,
        keys,
        h_ctx,
        rng,
    )?;

    // 2. Recompute the file-binding generator from public EBUT/file context.
    let expected_generator = derive_file_binding_generator(
        h_ctx,
        current_epoch,
        now_unix,
        proof.spend_proof.e_max,
        &proof.file_commitment,
        revocation_list_version,
    );
    if proof.file_binding.binding_generator != expected_generator {
        return Err(ActError::VerificationFailed("file-binding generator is not bound to EBUT/file context".into()));
    }

    // 3. The same-x BLS commitment must be the one proven inside the EBUT spend proof.
    if proof.same_x_statement.bls_x_base != generators.h[1]
        || proof.same_x_statement.bls_blind_base != generators.h[0]
        || proof.same_x_statement.bls_x_commitment != proof.spend_proof.x_bls_commitment
    {
        return Err(ActError::VerificationFailed("same-x BLS statement does not match EBUT spend proof".into()));
    }

    // 4. The same-x proof now links EBUT's hidden x to the file ElGamal
    //    public key X_file = x*G. The context-derived binding tag may still be
    //    carried for application policy binding, but ciphertext privacy relies
    //    on X_file, not on revealing decrypted chunks.
    if proof.same_x_statement.ristretto_x_base != RISTRETTO_BASEPOINT_POINT
        || proof.same_x_statement.ristretto_x_commitment != proof.file_binding.encryption_public_key
    {
        return Err(ActError::VerificationFailed("same-x statement does not match file encryption public key".into()));
    }

    // 5. Hidden-plaintext ElGamal file proof. This verifies sampled blocks via
    //    K_i = M_i+s_iH and C2_i-K_i = r_iX-s_iH without revealing M_i.
    if !verify_accountable_file_proof_with_confidence(
        &proof.file_proof,
        &proof.file_commitment,
        &proof.file_challenge_nonce,
        &proof.file_binding.encryption_public_key,
        &proof.same_x_context,
        DEFAULT_FILE_AUDIT_CONFIDENCE,
    ) {
        return Err(ActError::VerificationFailed("private file-binding proof failed".into()));
    }

    // 6. Cross-curve bridge: BLS commitment to x equals Ristretto X_file=xG.
    proof.same_x_proof.verify(&proof.same_x_context, &proof.same_x_statement)?;

    Ok(response)
}

/// Verify an EBUT spend and a reversible ElGamal file proof without revocation.
#[allow(clippy::too_many_arguments)]
pub fn verify_upload_spend<R: RngCore + CryptoRng>(
    proof: &UploadSpendProof,
    current_epoch: u32,
    now_unix: u64,
    generators: &Generators,
    pk_daily: &G2Projective,
    keys: &ServerKeys,
    h_ctx: Scalar,
    rng: &mut R,
) -> Result<SpendResponse> {
    verify_upload_spend_inner(proof, current_epoch, now_unix, 0, generators, pk_daily, keys, h_ctx, rng)
}

/// Verify upload spend and also require revocation non-membership for the same
/// hidden `Emax` carried inside the EBUT spend proof.
#[allow(clippy::too_many_arguments)]
pub fn verify_upload_spend_with_revocation<R: RngCore + CryptoRng>(
    proof: &UploadSpendProof,
    current_epoch: u32,
    now_unix: u64,
    generators: &Generators,
    pk_daily: &G2Projective,
    keys: &ServerKeys,
    h_ctx: Scalar,
    revocation_ctx: &RevocationContext,
    revocation_proof: &RevocationProof,
    revocation_pk: &RevocationServerPublicKey,
    emax_ristretto_commitment: RistrettoPoint,
    rng: &mut R,
) -> Result<SpendResponse> {
    if revocation_ctx.now_unix != now_unix {
        return Err(ActError::VerificationFailed("revocation context time does not match upload time".into()));
    }
    let response = verify_upload_spend_inner(
        proof,
        current_epoch,
        now_unix,
        revocation_ctx.revocation_list_version,
        generators,
        pk_daily,
        keys,
        h_ctx,
        rng,
    )?;
    verify_spend_not_revoked(
        revocation_ctx, revocation_proof, revocation_pk, &proof.spend_proof, generators, emax_ristretto_commitment,
    )?;
    Ok(response)
}
