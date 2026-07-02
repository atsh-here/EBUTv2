//! Option 1 accountable file binding using a cache-free Ristretto/Elligator codec.
//!
//! This module is the replacement path for the old compressed-point suffix search.
//! It uses a fresh per-file base `B_f`, an unlinkable file public key
//! `X_f = x B_f`, packed accountable ElGamal blocks, and hidden 3-bit
//! Elligator inverse selectors encrypted under the same block shared secret.
//!
//! Public encrypted block equation:
//!
//! ```text
//! C1_b      = r_b B_f
//! C2_bj     = M_bj + r_b X_f
//! K_bj      = M_bj + s_bj H_f
//! selector  = Enc_{H(r_b X_f)}(tau_bj)
//! ```
//!
//! Challenge proof equation:
//!
//! ```text
//! C2_bj - K_bj = r_b X_f - s_bj H_f
//! ```
//!
//! Decryption:
//!
//! ```text
//! M_bj = C2_bj - x C1_b
//! tau  = Dec_{H(x C1_b)}(selector)
//! m    = ElligatorDecode(M_bj, tau)
//! ```

use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use std::collections::BTreeSet;

use crate::ristretto_elligator_codec::{
    decode_chunk, encode_chunk, pack_selectors, unpack_selectors, ElligatorCodecError,
    ELLIGATOR_CODEC_VERSION, ELLIGATOR_PAYLOAD_BYTES,
};
use crate::serde_utils::ristretto_serde;

pub const OPTION1_FILE_ENCODING_V3: u32 = ELLIGATOR_CODEC_VERSION;
pub const OPTION1_POINT_PAYLOAD_SIZE: usize = ELLIGATOR_PAYLOAD_BYTES;
pub const OPTION1_POINTS_PER_BLOCK: usize = 16;
pub const OPTION1_BLOCK_PAYLOAD_SIZE: usize = OPTION1_POINT_PAYLOAD_SIZE * OPTION1_POINTS_PER_BLOCK;
pub const OPTION1_FULL_AUDIT_FILE_BYTES: u64 = 100 * 1024;
pub const OPTION1_MAX_AUDIT_CHALLENGES: usize = 100;
pub const OPTION1_DEFAULT_BAD_FRACTION: f64 = 0.10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Option1FileBindingError {
    Codec(ElligatorCodecError),
    InvalidCiphertext,
    InvalidCommitment,
}

impl From<ElligatorCodecError> for Option1FileBindingError {
    fn from(e: ElligatorCodecError) -> Self { Self::Codec(e) }
}

fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    Scalar::from_bytes_mod_order_wide(&wide)
}

fn hash_point(domain: &[u8], inputs: &[&[u8]]) -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(domain);
    for input in inputs { h.update((*input).len().to_le_bytes()); h.update(input); }
    RistrettoPoint::from_uniform_bytes(&h.finalize().into())
}

/// Derive fresh unlinkable file base `B_f`.
pub fn derive_option1_file_base(
    app_id: &[u8],
    policy_id: &[u8],
    server_nonce: &[u8; 32],
    file_salt: &[u8; 32],
    file_id: &[u8; 32],
) -> RistrettoPoint {
    hash_point(
        b"EBUT:OPTION1:FILE-BASE:V3",
        &[app_id, policy_id, server_nonce, file_salt, file_id],
    )
}

/// Derive file-specific Pedersen base `H_f`.
pub fn derive_option1_commitment_base(file_id: &[u8; 32], file_base: &RistrettoPoint, file_public_key: &RistrettoPoint) -> RistrettoPoint {
    hash_point(
        b"EBUT:OPTION1:FILE-COMMIT-BASE:V3",
        &[file_id, file_base.compress().as_bytes(), file_public_key.compress().as_bytes()],
    )
}

fn merkle_hash(leaf: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"EBUT:OPTION1:MERKLE-LEAF:V3");
    h.update(leaf);
    h.finalize()[..32].try_into().unwrap()
}

fn merkle_combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"EBUT:OPTION1:MERKLE-NODE:V3");
    h.update(left);
    h.update(right);
    h.finalize()[..32].try_into().unwrap()
}

fn build_merkle_tree(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() { return vec![vec![[0u8; 32]]]; }
    let mut tree = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.iter().map(merkle_hash).collect();
    tree.push(level.clone());
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            if chunk.len() == 2 { next.push(merkle_combine(&chunk[0], &chunk[1])); } else { next.push(chunk[0]); }
        }
        tree.push(next.clone());
        level = next;
    }
    tree
}

fn merkle_path_from_tree(tree: &[Vec<[u8; 32]>], index: usize) -> Vec<(bool, [u8; 32])> {
    let mut path = Vec::new();
    let mut idx = index;
    for level in tree.iter().take(tree.len().saturating_sub(1)) {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() { path.push((sibling_idx < idx, level[sibling_idx])); }
        idx /= 2;
    }
    path
}

fn verify_merkle_path(leaf: &[u8; 32], path: &[(bool, [u8; 32])], root: &[u8; 32]) -> bool {
    let mut cur = merkle_hash(leaf);
    for (is_left, sibling) in path {
        cur = if *is_left { merkle_combine(sibling, &cur) } else { merkle_combine(&cur, sibling) };
    }
    &cur == root
}

fn stream_xor_mask(shared: &RistrettoPoint, file_id: &[u8; 32], block_index: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        let mut h = Sha512::new();
        h.update(b"EBUT:OPTION1:SELECTOR-STREAM:V3");
        h.update(shared.compress().as_bytes());
        h.update(file_id);
        h.update(block_index.to_le_bytes());
        h.update(counter.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> { a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect() }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Option1FileCommitment {
    pub file_id: [u8; 32],
    pub root_hash: [u8; 32],
    pub num_blocks: u64,
    pub file_size: u64,
    pub point_payload_size: usize,
    pub points_per_block: usize,
    pub encoding_version: u32,
    #[serde(with = "ristretto_serde")]
    pub file_base: RistrettoPoint,
    #[serde(with = "ristretto_serde")]
    pub file_public_key: RistrettoPoint,
    #[serde(with = "ristretto_serde")]
    pub commitment_base: RistrettoPoint,
    pub file_salt: [u8; 32],
    pub server_nonce: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Option1CiphertextBlock {
    #[serde(with = "ristretto_serde")]
    pub c1: RistrettoPoint,
    #[serde(with = "ristretto_vec_serde")]
    pub c2_points: Vec<RistrettoPoint>,
    #[serde(with = "ristretto_vec_serde")]
    pub plaintext_commitments: Vec<RistrettoPoint>,
    pub point_lengths: Vec<u8>,
    /// Encrypted packed 3-bit selectors.  This is the hidden `tau` metadata.
    pub selector_ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Option1WitnessBlock {
    pub encryption_randomness: Scalar,
    pub commitment_blindings: Vec<Scalar>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Option1BlockProof {
    pub index: u64,
    pub block: Option1CiphertextBlock,
    pub merkle_path: Vec<(bool, [u8; 32])>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Option1BatchProof {
    #[serde(with = "ristretto_serde")]
    pub a1: RistrettoPoint,
    #[serde(with = "ristretto_serde")]
    pub a2: RistrettoPoint,
    pub z_r: Scalar,
    pub z_minus_s: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Option1FileProof {
    pub file_id: [u8; 32],
    pub root_hash: [u8; 32],
    pub blocks: Vec<Option1BlockProof>,
    pub batch_proof: Option1BatchProof,
}

mod ristretto_vec_serde {
    use super::*;
    use curve25519_dalek_ng::ristretto::CompressedRistretto;
    use serde::{Deserializer, Serializer};
    use serde::de::{SeqAccess, Visitor};
    use core::fmt;

    pub fn serialize<S>(points: &Vec<RistrettoPoint>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let bytes: Vec<[u8; 32]> = points.iter().map(|p| p.compress().to_bytes()).collect();
        bytes.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<RistrettoPoint>, D::Error>
    where D: Deserializer<'de> {
        struct PointsVisitor;
        impl<'de> Visitor<'de> for PointsVisitor {
            type Value = Vec<RistrettoPoint>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("compressed Ristretto point list") }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where A: SeqAccess<'de> {
                let mut out = Vec::new();
                while let Some(bytes) = seq.next_element::<[u8; 32]>()? {
                    let p = CompressedRistretto(bytes).decompress().ok_or_else(|| serde::de::Error::custom("invalid compressed Ristretto point"))?;
                    out.push(p);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_seq(PointsVisitor)
    }
}

fn option1_cipher_leaf(block: &Option1CiphertextBlock) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"EBUT:OPTION1:CIPHER-LEAF:V3");
    h.update(block.c1.compress().as_bytes());
    h.update((block.c2_points.len() as u64).to_le_bytes());
    for ((c2, k), len) in block.c2_points.iter().zip(block.plaintext_commitments.iter()).zip(block.point_lengths.iter()) {
        h.update(c2.compress().as_bytes());
        h.update(k.compress().as_bytes());
        h.update([*len]);
    }
    h.update((block.selector_ciphertext.len() as u64).to_le_bytes());
    h.update(&block.selector_ciphertext);
    h.finalize()[..32].try_into().unwrap()
}

fn derive_challenge_indices(challenge_nonce: &[u8; 32], num_blocks: u64, count: usize) -> Vec<u64> {
    if num_blocks == 0 || count == 0 { return Vec::new(); }
    let target = count.min(num_blocks as usize);
    if target == num_blocks as usize { return (0..num_blocks).collect(); }
    let mut out = BTreeSet::new();
    let mut counter = 0u64;
    while out.len() < target {
        let mut h = Sha512::new();
        h.update(b"EBUT:OPTION1:CHALLENGE-INDEX:V3");
        h.update(challenge_nonce);
        h.update(num_blocks.to_le_bytes());
        h.update((target as u64).to_le_bytes());
        h.update(counter.to_le_bytes());
        let digest = h.finalize();
        let mut wide = [0u8; 16]; wide.copy_from_slice(&digest[..16]);
        out.insert((u128::from_le_bytes(wide) % (num_blocks as u128)) as u64);
        counter = counter.wrapping_add(1);
    }
    out.into_iter().collect()
}

fn option1_batch_coefficients(blocks: &[Option1BlockProof], context: &[u8], commitment: &Option1FileCommitment) -> Vec<Vec<Scalar>> {
    let mut transcript = Sha512::new();
    transcript.update(b"EBUT:OPTION1:BATCH-TRANSCRIPT:V3");
    transcript.update(context);
    transcript.update(commitment.file_id);
    transcript.update(commitment.root_hash);
    transcript.update(commitment.file_base.compress().as_bytes());
    transcript.update(commitment.file_public_key.compress().as_bytes());
    transcript.update(commitment.commitment_base.compress().as_bytes());
    for block in blocks {
        transcript.update(block.index.to_le_bytes());
        transcript.update(block.block.c1.compress().as_bytes());
        for ((c2, k), len) in block.block.c2_points.iter().zip(block.block.plaintext_commitments.iter()).zip(block.block.point_lengths.iter()) {
            transcript.update(c2.compress().as_bytes()); transcript.update(k.compress().as_bytes()); transcript.update([*len]);
        }
        transcript.update(&block.block.selector_ciphertext);
    }
    let digest = transcript.finalize();
    let mut coeffs = Vec::with_capacity(blocks.len());
    for (bi, block) in blocks.iter().enumerate() {
        let mut row = Vec::with_capacity(block.block.c2_points.len());
        for j in 0..block.block.c2_points.len() {
            let mut h = Sha512::new();
            h.update(b"EBUT:OPTION1:RHO:V3");
            h.update(&digest);
            h.update((bi as u64).to_le_bytes());
            h.update((j as u64).to_le_bytes());
            row.push(Scalar::from_bytes_mod_order_wide(&h.finalize().into()));
        }
        coeffs.push(row);
    }
    coeffs
}

fn aggregate_statement(blocks: &[Option1BlockProof], coeffs: &[Vec<Scalar>]) -> (RistrettoPoint, RistrettoPoint) {
    let mut c1_bar = RistrettoPoint::default();
    let mut d_bar = RistrettoPoint::default();
    for (block, row) in blocks.iter().zip(coeffs.iter()) {
        let mut rho_sum = Scalar::zero();
        for ((rho, c2), k) in row.iter().zip(block.block.c2_points.iter()).zip(block.block.plaintext_commitments.iter()) {
            rho_sum += rho;
            d_bar += rho * (*c2 - *k);
        }
        c1_bar += rho_sum * block.block.c1;
    }
    (c1_bar, d_bar)
}

fn proof_challenge(context: &[u8], commitment: &Option1FileCommitment, c1_bar: &RistrettoPoint, d_bar: &RistrettoPoint, a1: &RistrettoPoint, a2: &RistrettoPoint) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"EBUT:OPTION1:SCHNORR:V3");
    h.update(context);
    h.update(commitment.file_id);
    h.update(commitment.root_hash);
    h.update(commitment.file_base.compress().as_bytes());
    h.update(commitment.file_public_key.compress().as_bytes());
    h.update(commitment.commitment_base.compress().as_bytes());
    h.update(c1_bar.compress().as_bytes());
    h.update(d_bar.compress().as_bytes());
    h.update(a1.compress().as_bytes());
    h.update(a2.compress().as_bytes());
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

impl Option1BatchProof {
    fn prove<R: RngCore + CryptoRng>(rng: &mut R, context: &[u8], commitment: &Option1FileCommitment, blocks: &[Option1BlockProof], witnesses: &[Option1WitnessBlock]) -> Self {
        let coeffs = option1_batch_coefficients(blocks, context, commitment);
        let (c1_bar, d_bar) = aggregate_statement(blocks, &coeffs);
        let mut r_bar = Scalar::zero();
        let mut minus_s_bar = Scalar::zero();
        for ((row, _block), wit) in coeffs.iter().zip(blocks.iter()).zip(witnesses.iter()) {
            let mut rho_sum = Scalar::zero();
            for (rho, s) in row.iter().zip(wit.commitment_blindings.iter()) {
                rho_sum += rho;
                minus_s_bar -= rho * s;
            }
            r_bar += rho_sum * wit.encryption_randomness;
        }
        let ar = random_scalar(rng);
        let as_ = random_scalar(rng);
        let a1 = ar * commitment.file_base;
        let a2 = ar * commitment.file_public_key + as_ * commitment.commitment_base;
        let c = proof_challenge(context, commitment, &c1_bar, &d_bar, &a1, &a2);
        Self { a1, a2, z_r: ar + c * r_bar, z_minus_s: as_ + c * minus_s_bar }
    }

    fn verify(&self, context: &[u8], commitment: &Option1FileCommitment, blocks: &[Option1BlockProof]) -> bool {
        if blocks.is_empty() || commitment.file_base == RistrettoPoint::default() || commitment.file_public_key == RistrettoPoint::default() || commitment.commitment_base == RistrettoPoint::default() { return false; }
        for block in blocks {
            if block.block.c2_points.is_empty()
                || block.block.c2_points.len() != block.block.plaintext_commitments.len()
                || block.block.c2_points.len() != block.block.point_lengths.len()
                || block.block.c2_points.len() > OPTION1_POINTS_PER_BLOCK
            { return false; }
            if block.block.point_lengths.iter().any(|&l| l == 0 || (l as usize) > OPTION1_POINT_PAYLOAD_SIZE) { return false; }
        }
        let coeffs = option1_batch_coefficients(blocks, context, commitment);
        let (c1_bar, d_bar) = aggregate_statement(blocks, &coeffs);
        let c = proof_challenge(context, commitment, &c1_bar, &d_bar, &self.a1, &self.a2);
        if self.z_r * commitment.file_base != self.a1 + c * c1_bar { return false; }
        self.z_r * commitment.file_public_key + self.z_minus_s * commitment.commitment_base == self.a2 + c * d_bar
    }
}

#[allow(clippy::too_many_arguments)]
pub fn create_option1_file_commitment_auto<R: RngCore + CryptoRng>(
    rng: &mut R,
    file_id: [u8; 32],
    file_data: &[u8],
    file_base: RistrettoPoint,
    file_public_key: RistrettoPoint,
    server_nonce: [u8; 32],
    file_salt: [u8; 32],
) -> Result<(Option1FileCommitment, Vec<Option1CiphertextBlock>, Vec<[u8; 32]>, Vec<Option1WitnessBlock>), Option1FileBindingError> {
    let commitment_base = derive_option1_commitment_base(&file_id, &file_base, &file_public_key);
    let mut public_blocks = Vec::new();
    let mut leaves = Vec::new();
    let mut witnesses = Vec::new();

    for (block_index, group) in file_data.chunks(OPTION1_BLOCK_PAYLOAD_SIZE).enumerate() {
        let r = random_scalar(rng);
        let c1 = r * file_base;
        let shared = r * file_public_key;
        let mut c2_points = Vec::new();
        let mut plaintext_commitments = Vec::new();
        let mut point_lengths = Vec::new();
        let mut selectors = Vec::new();
        let mut blindings = Vec::new();
        for chunk in group.chunks(OPTION1_POINT_PAYLOAD_SIZE) {
            let enc = encode_chunk(chunk)?;
            let s = random_scalar(rng);
            c2_points.push(enc.point + shared);
            plaintext_commitments.push(enc.point + s * commitment_base);
            point_lengths.push(enc.len);
            selectors.push(enc.selector);
            blindings.push(s);
        }
        let selector_plain = pack_selectors(&selectors)?;
        let selector_mask = stream_xor_mask(&shared, &file_id, block_index as u64, selector_plain.len());
        let selector_ciphertext = xor_bytes(&selector_plain, &selector_mask);
        let block = Option1CiphertextBlock { c1, c2_points, plaintext_commitments, point_lengths, selector_ciphertext };
        leaves.push(option1_cipher_leaf(&block));
        public_blocks.push(block);
        witnesses.push(Option1WitnessBlock { encryption_randomness: r, commitment_blindings: blindings });
    }
    let tree = build_merkle_tree(&leaves);
    let root = *tree.last().unwrap().first().unwrap();
    let commitment = Option1FileCommitment { file_id, root_hash: root, num_blocks: public_blocks.len() as u64, file_size: file_data.len() as u64, point_payload_size: OPTION1_POINT_PAYLOAD_SIZE, points_per_block: OPTION1_POINTS_PER_BLOCK, encoding_version: OPTION1_FILE_ENCODING_V3, file_base, file_public_key, commitment_base, file_salt, server_nonce };
    Ok((commitment, public_blocks, leaves, witnesses))
}

pub fn create_option1_file_proof<R: RngCore + CryptoRng>(
    rng: &mut R,
    commitment: &Option1FileCommitment,
    public_blocks: &[Option1CiphertextBlock],
    leaves: &[[u8; 32]],
    challenge_nonce: &[u8; 32],
    num_challenges: usize,
    witnesses: &[Option1WitnessBlock],
    proof_context: &[u8],
) -> Option1FileProof {
    let indices = derive_challenge_indices(challenge_nonce, public_blocks.len() as u64, num_challenges);
    let tree = build_merkle_tree(leaves);
    let mut blocks = Vec::with_capacity(indices.len());
    let mut selected_witnesses = Vec::with_capacity(indices.len());
    for idx in indices {
        let i = idx as usize;
        blocks.push(Option1BlockProof { index: idx, block: public_blocks[i].clone(), merkle_path: merkle_path_from_tree(&tree, i) });
        selected_witnesses.push(witnesses[i].clone());
    }
    let batch_proof = Option1BatchProof::prove(rng, proof_context, commitment, &blocks, &selected_witnesses);
    Option1FileProof { file_id: commitment.file_id, root_hash: commitment.root_hash, blocks, batch_proof }
}

pub fn verify_option1_file_proof(proof: &Option1FileProof, commitment: &Option1FileCommitment, challenge_nonce: &[u8; 32], proof_context: &[u8]) -> bool {
    if commitment.encoding_version != OPTION1_FILE_ENCODING_V3 { return false; }
    if commitment.point_payload_size != OPTION1_POINT_PAYLOAD_SIZE || commitment.points_per_block != OPTION1_POINTS_PER_BLOCK { return false; }
    if proof.file_id != commitment.file_id || proof.root_hash != commitment.root_hash { return false; }
    if proof.blocks.len() as u64 > commitment.num_blocks { return false; }
    if commitment.num_blocks > 0 && proof.blocks.is_empty() { return false; }
    let expected_indices = derive_challenge_indices(challenge_nonce, commitment.num_blocks, proof.blocks.len());
    for (block, expected) in proof.blocks.iter().zip(expected_indices.iter()) {
        if block.index != *expected { return false; }
        let leaf = option1_cipher_leaf(&block.block);
        if !verify_merkle_path(&leaf, &block.merkle_path, &commitment.root_hash) { return false; }
    }
    proof.batch_proof.verify(proof_context, commitment, &proof.blocks)
}

pub fn expected_option1_challenge_count(commitment: &Option1FileCommitment, confidence: f64) -> usize {
    if commitment.num_blocks == 0 { return 0; }
    if commitment.file_size <= OPTION1_FULL_AUDIT_FILE_BYTES { return commitment.num_blocks as usize; }
    audit_sample_count(commitment.num_blocks, confidence, OPTION1_DEFAULT_BAD_FRACTION)
}

fn audit_sample_count(num_blocks: u64, confidence: f64, bad_fraction: f64) -> usize {
    let confidence = if confidence.is_finite() { confidence.clamp(0.50, 0.999999) } else { 0.90 };
    let bad_fraction = if bad_fraction.is_finite() { bad_fraction.clamp(0.001, 1.0) } else { OPTION1_DEFAULT_BAD_FRACTION };
    let bad_blocks = ((num_blocks as f64) * bad_fraction).ceil().clamp(1.0, num_blocks as f64) as u64;
    let max_k = OPTION1_MAX_AUDIT_CHALLENGES.min(num_blocks as usize);
    let mut miss = 1.0f64;
    for k in 1..=max_k {
        let i = (k - 1) as u64;
        let numerator = num_blocks.saturating_sub(bad_blocks).saturating_sub(i) as f64;
        let denominator = num_blocks.saturating_sub(i) as f64;
        if denominator <= 0.0 || numerator <= 0.0 { return k; }
        miss *= numerator / denominator;
        if 1.0 - miss >= confidence { return k; }
    }
    max_k
}

pub fn verify_option1_file_proof_with_confidence(proof: &Option1FileProof, commitment: &Option1FileCommitment, challenge_nonce: &[u8; 32], proof_context: &[u8], confidence: f64) -> bool {
    if proof.blocks.len() != expected_option1_challenge_count(commitment, confidence) { return false; }
    verify_option1_file_proof(proof, commitment, challenge_nonce, proof_context)
}

pub fn decrypt_option1_file_from_ciphertexts(public_blocks: &[Option1CiphertextBlock], commitment: &Option1FileCommitment, x: &Scalar) -> Result<Vec<u8>, Option1FileBindingError> {
    if commitment.encoding_version != OPTION1_FILE_ENCODING_V3 { return Err(Option1FileBindingError::InvalidCommitment); }
    if public_blocks.len() as u64 != commitment.num_blocks { return Err(Option1FileBindingError::InvalidCiphertext); }
    let mut out = Vec::with_capacity(commitment.file_size as usize);
    for (block_index, block) in public_blocks.iter().enumerate() {
        let shared = x * block.c1;
        let selector_mask = stream_xor_mask(&shared, &commitment.file_id, block_index as u64, block.selector_ciphertext.len());
        let selector_plain = xor_bytes(&block.selector_ciphertext, &selector_mask);
        let selectors = unpack_selectors(&selector_plain, block.c2_points.len())?;
        for ((c2, len), selector) in block.c2_points.iter().zip(block.point_lengths.iter()).zip(selectors.iter()) {
            if out.len() >= commitment.file_size as usize { break; }
            let point = *c2 - shared;
            let remaining = commitment.file_size as usize - out.len();
            let chunk_len = remaining.min(*len as usize) as u8;
            let chunk = decode_chunk(&point, *selector, chunk_len)?;
            out.extend_from_slice(&chunk);
        }
    }
    out.truncate(commitment.file_size as usize);
    Ok(out)
}
