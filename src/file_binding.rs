use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use rand_core::{CryptoRng, RngCore};
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::seq::SliceRandom;
use sha2::{Sha512, Digest};
use serde::{Serialize, Deserialize};
use rayon::prelude::*;
use std::collections::BTreeSet;

use crate::file_binding::random_ristretto_scalar as random_scalar;
use crate::serde_utils::ristretto_serde;

pub const BATCH_THRESHOLD: usize = 3;

/// Large-file spot-check cap. For files above `FULL_AUDIT_FILE_BYTES`,
/// verifier challenges at most this many blocks.
pub const MAX_AUDIT_CHALLENGES: usize = 100;

/// Files at or below this size are fully challenged.
/// This makes small uploads deterministic/audit-complete while keeping large
/// uploads bounded.
pub const FULL_AUDIT_FILE_BYTES: u64 = 100 * 1024;

/// Assumed minimum cheating rate for large-file sampling. With 10%, a 90%
/// confidence audit needs about 22 random blocks; the 100-block cap gives much
/// stronger assurance for that cheating rate.
pub const DEFAULT_AUDIT_BAD_FRACTION: f64 = 0.10;

#[cfg(test)]
const TEST_FILE_SIZE_BYTES: usize = 50 * 1024;

fn random_ristretto_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    Scalar::from_bytes_mod_order_wide(&bytes)
}


fn merkle_hash(leaf: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"MERKLE_LEAF");
    hasher.update(leaf);
    hasher.finalize()[..32].try_into().unwrap()
}

fn merkle_combine(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"MERKLE_NODE");
    hasher.update(left);
    hasher.update(right);
    hasher.finalize()[..32].try_into().unwrap()
}

fn build_merkle_tree(leaves: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    if leaves.is_empty() { return vec![vec![[0u8; 32]]]; }
    let mut tree = Vec::new();
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|l| merkle_hash(l)).collect();
    tree.push(level.clone());
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        for chunk in level.chunks(2) {
            if chunk.len() == 2 { next.push(merkle_combine(&chunk[0], &chunk[1])); } else { next.push(chunk[0]); }
        }
        tree.push(next.clone()); level = next;
    }
    tree
}

pub fn merkle_path(leaves: &[[u8; 32]], index: usize) -> Vec<(bool, [u8; 32])> {
    let tree = build_merkle_tree(leaves);
    merkle_path_from_tree(&tree, index)
}

fn merkle_path_from_tree(tree: &[Vec<[u8; 32]>], index: usize) -> Vec<(bool, [u8; 32])> {
    let mut path = Vec::new();
    let mut idx = index;
    for level in tree.iter().take(tree.len().saturating_sub(1)) {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < level.len() {
            path.push((sibling_idx < idx, level[sibling_idx]));
        }
        idx /= 2;
    }
    path
}

fn verify_merkle_path(leaf: &[u8; 32], _index: usize, path: &[(bool, [u8; 32])], root: &[u8; 32]) -> bool {
    let mut current = merkle_hash(leaf);
    for (is_left, sibling) in path {
        if *is_left { current = merkle_combine(sibling, &current); } else { current = merkle_combine(&current, sibling); }
    }
    &current == root
}

/// We encode file bytes directly into compressed Ristretto encodings.
///
/// A curve point cannot carry an arbitrary large block. This encoding stores
/// 17 bytes of payload by bit-packing them into compressed encoding bits 1..136,
/// leaving bit 0 fixed to zero because Ristretto decoding rejects "negative"
/// field encodings.  The remaining high bits are searched with a hash-derived
/// suffix until the 32-byte string is a valid canonical compressed Ristretto
/// point.
///
/// This is reversible:
///   payload -> compressed bytes -> RistrettoPoint -> compressed bytes -> payload
///
/// The previous byte-prefix encoders were wrong: copying arbitrary payload into
/// byte 0 fixes the low sign bit, and any payload with that bit set can never
/// decode as a valid Ristretto point.  Bit-packing avoids that impossible class
/// and keeps accountable point-ElGamal under the 4x size target.
pub const REVERSIBLE_POINT_ENCODING_V1: u32 = 1;
pub const REVERSIBLE_POINT_PAYLOAD_SIZE: usize = 17;
pub const REVERSIBLE_POINT_COUNTER_SIZE: usize = 15;
/// Safety cap for reversible encoding search. With 17 payload bytes and 118 free
/// searched bits, valid canonical encodings are normally found quickly; the cap
/// prevents denial-of-service style unbounded encoding work.
pub const REVERSIBLE_POINT_MAX_ENCODING_ATTEMPTS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PointEncodingError {
    ChunkTooLarge { len: usize, max: usize },
    NoValidEncoding,
    InvalidDecodedLength { len: usize, max: usize },
}

fn set_bit_le(bytes: &mut [u8; 32], bit_index: usize, value: bool) {
    let byte = bit_index / 8;
    let bit = bit_index % 8;
    if value {
        bytes[byte] |= 1u8 << bit;
    } else {
        bytes[byte] &= !(1u8 << bit);
    }
}

fn get_bit_le(bytes: &[u8; 32], bit_index: usize) -> bool {
    ((bytes[bit_index / 8] >> (bit_index % 8)) & 1u8) == 1u8
}

/// Put payload bits into the compressed encoding while leaving bit 0 forced to
/// zero.  Ristretto decoding rejects encodings whose field element is
/// "negative", which for this field representation depends on the low bit.
/// The older encoder copied payload bytes directly into bytes[0..N], so any
/// payload whose first bit was 1 could never encode, regardless of the suffix.
///
/// We instead store payload bit `i` at compressed bit `i + 1` and reserve bit 0
/// as zero.  The remaining high bits are filled by the randomized suffix search.
/// Decoding reverses the same bit packing.
fn pack_payload_bits(payload: &[u8; REVERSIBLE_POINT_PAYLOAD_SIZE], candidate: &mut [u8; 32]) {
    set_bit_le(candidate, 0, false);
    for i in 0..(REVERSIBLE_POINT_PAYLOAD_SIZE * 8) {
        let value = ((payload[i / 8] >> (i % 8)) & 1u8) == 1u8;
        set_bit_le(candidate, i + 1, value);
    }
}

fn unpack_payload_bits(encoded: &[u8; 32]) -> [u8; REVERSIBLE_POINT_PAYLOAD_SIZE] {
    let mut payload = [0u8; REVERSIBLE_POINT_PAYLOAD_SIZE];
    for i in 0..(REVERSIBLE_POINT_PAYLOAD_SIZE * 8) {
        if get_bit_le(encoded, i + 1) {
            payload[i / 8] |= 1u8 << (i % 8);
        }
    }
    payload
}

pub fn encode_chunk_to_point(chunk: &[u8]) -> Result<RistrettoPoint, PointEncodingError> {
    if chunk.len() > REVERSIBLE_POINT_PAYLOAD_SIZE {
        return Err(PointEncodingError::ChunkTooLarge { len: chunk.len(), max: REVERSIBLE_POINT_PAYLOAD_SIZE });
    }

    let mut payload = [0u8; REVERSIBLE_POINT_PAYLOAD_SIZE];
    payload[..chunk.len()].copy_from_slice(chunk);

    for counter in 0..REVERSIBLE_POINT_MAX_ENCODING_ATTEMPTS {
        let mut candidate = [0u8; 32];
        pack_payload_bits(&payload, &mut candidate);

        // Fill every non-payload bit after the packed payload with a
        // domain-separated hash of (payload, counter).  This gives a large
        // random-looking completion space while preserving exact reversibility
        // of the payload bits.
        let mut suffix_hasher = Sha512::new();
        suffix_hasher.update(b"EBUT:REVERSIBLE-POINT-BITPACK-SUFFIX:V3");
        suffix_hasher.update(&payload);
        suffix_hasher.update(counter.to_le_bytes());
        let suffix = suffix_hasher.finalize();

        let first_free_bit = 1 + REVERSIBLE_POINT_PAYLOAD_SIZE * 8;
        let mut suffix_bit = 0usize;
        for bit_index in first_free_bit..255 {
            let value = ((suffix[suffix_bit / 8] >> (suffix_bit % 8)) & 1u8) == 1u8;
            set_bit_le(&mut candidate, bit_index, value);
            suffix_bit += 1;
            if suffix_bit == suffix.len() * 8 {
                suffix_bit = 0;
            }
        }
        // Keep the top bit clear for canonical field-element encodings.
        set_bit_le(&mut candidate, 255, false);

        if let Some(point) = CompressedRistretto(candidate).decompress() {
            // Canonical round-trip check. This prevents accepting a point whose
            // canonical encoding is not exactly the bytes carrying our payload.
            if point.compress().to_bytes() == candidate {
                return Ok(point);
            }
        }
    }

    Err(PointEncodingError::NoValidEncoding)
}

pub fn decode_point_to_chunk(point: &RistrettoPoint, chunk_len: usize) -> Result<Vec<u8>, PointEncodingError> {
    if chunk_len > REVERSIBLE_POINT_PAYLOAD_SIZE {
        return Err(PointEncodingError::InvalidDecodedLength { len: chunk_len, max: REVERSIBLE_POINT_PAYLOAD_SIZE });
    }
    let bytes = point.compress().to_bytes();
    let payload = unpack_payload_bits(&bytes);
    Ok(payload[..chunk_len].to_vec())
}

fn elgamal_encrypt_block<R: RngCore + CryptoRng>(rng: &mut R, m: &RistrettoPoint, pk: &RistrettoPoint) -> (RistrettoPoint, RistrettoPoint) {
    let r = random_scalar(rng);
    let c1 = r * RISTRETTO_BASEPOINT_POINT;
    let c2 = *m + r * pk;
    (c1, c2)
}

fn elgamal_decrypt_block(x: &Scalar, c1: &RistrettoPoint, c2: &RistrettoPoint) -> RistrettoPoint { *c2 - x * c1 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLEQProof {
    #[serde(with = "ristretto_serde")] pub t1: RistrettoPoint,
    #[serde(with = "ristretto_serde")] pub t2: RistrettoPoint,
    pub s: Scalar,
}

impl DLEQProof {
    pub fn prove<R: RngCore + CryptoRng>(rng: &mut R, x: &Scalar, a: &RistrettoPoint, b: &RistrettoPoint, c: &RistrettoPoint, d: &RistrettoPoint) -> Self {
        let r = random_scalar(rng);
        let t1 = r * a; let t2 = r * c;
        let mut hasher = Sha512::new();
        hasher.update(b"DLEQ_PROOF");
        hasher.update(a.compress().as_bytes()); hasher.update(b.compress().as_bytes());
        hasher.update(c.compress().as_bytes()); hasher.update(d.compress().as_bytes());
        hasher.update(t1.compress().as_bytes()); hasher.update(t2.compress().as_bytes());
        let challenge = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        let s = r + challenge * x;
        DLEQProof { t1, t2, s }
    }

    pub fn verify(&self, a: &RistrettoPoint, b: &RistrettoPoint, c: &RistrettoPoint, d: &RistrettoPoint) -> bool {
        let mut hasher = Sha512::new();
        hasher.update(b"DLEQ_PROOF");
        hasher.update(a.compress().as_bytes()); hasher.update(b.compress().as_bytes());
        hasher.update(c.compress().as_bytes()); hasher.update(d.compress().as_bytes());
        hasher.update(self.t1.compress().as_bytes()); hasher.update(self.t2.compress().as_bytes());
        let challenge = Scalar::from_bytes_mod_order_wide(&hasher.finalize().into());
        let left1 = self.s * a - challenge * b; let left2 = self.s * c - challenge * d;
        left1 == self.t1 && left2 == self.t2
    }
}

pub type BatchDLEQProof = DLEQProof;

fn derive_batch_coefficients(pairs: &[(RistrettoPoint, RistrettoPoint)]) -> Vec<Scalar> {
    let mut coeffs = Vec::with_capacity(pairs.len());
    for i in 0..pairs.len() {
        let mut hasher = Sha512::new();
        hasher.update(b"NTAT:BATCH:DLEQ");
        for (a, b) in pairs.iter() {
            let a_pt: &RistrettoPoint = a; // Fix for E0282
            let b_pt: &RistrettoPoint = b;
            hasher.update(a_pt.compress().as_bytes());
            hasher.update(b_pt.compress().as_bytes());
        }
        hasher.update(&(i as u64).to_le_bytes());
        coeffs.push(Scalar::from_bytes_mod_order_wide(&hasher.finalize().into()));
    }
    coeffs
}

fn combine_pairs(pairs: &[(RistrettoPoint, RistrettoPoint)], coeffs: &[Scalar]) -> (RistrettoPoint, RistrettoPoint) {
    let mut a_sum = RistrettoPoint::default(); let mut b_sum = RistrettoPoint::default();
    for ((a, b), rho) in pairs.iter().zip(coeffs) { a_sum += rho * a; b_sum += rho * b; }
    (a_sum, b_sum)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileCommitment {
    pub file_id: [u8; 32],
    pub root_hash: [u8; 32],
    pub num_blocks: u64,
    /// Maximum plaintext bytes encoded into one Ristretto point.
    pub block_size: usize,
    /// Exact original file size in bytes. Needed to decode the final padded point.
    pub file_size: u64,
    /// Encoding version for reversible point encoding.
    pub encoding_version: u32,
    pub nonce: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CiphertextBlock {
    #[serde(with = "ristretto_serde")] pub c1: RistrettoPoint,
    #[serde(with = "ristretto_serde")] pub c2: RistrettoPoint,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockProof {
    pub index: u64, pub ciphertext: CiphertextBlock,
    #[serde(with = "ristretto_serde")] pub decrypted_point: RistrettoPoint,
    pub merkle_path: Vec<(bool, [u8; 32])>, pub dleq_proof: Option<DLEQProof>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileProof {
    pub file_id: [u8; 32], pub root_hash: [u8; 32], pub blocks: Vec<BlockProof>, pub batch_proof: Option<BatchDLEQProof>,
}

fn prepare_file_blocks<R: RngCore + CryptoRng>(_rng: &mut R, pre_encrypted_blocks: &[Vec<u8>], x: &Scalar, _nonce: &[u8; 32]) -> (Vec<CiphertextBlock>, Vec<[u8; 32]>, [u8; 32]) {
    let pk = x * RISTRETTO_BASEPOINT_POINT;
    let (ciphertexts, leaves): (Vec<_>, Vec<_>) = pre_encrypted_blocks.par_iter().map(|block_bytes| {
        let mut thread_rng = rand::thread_rng();
        let m = encode_chunk_to_point(block_bytes)
            .expect("reversible point encoding failed; use smaller chunks or check encoding parameters");
        let (c1, c2) = elgamal_encrypt_block(&mut thread_rng, &m, &pk);
        let mut hasher = Sha512::new();
        hasher.update(b"CIPHER_LEAF"); hasher.update(c1.compress().as_bytes()); hasher.update(c2.compress().as_bytes());
        let leaf: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();
        (CiphertextBlock { c1, c2 }, leaf)
    }).unzip();
    let tree = build_merkle_tree(&leaves);
    let root = *tree.last().unwrap().first().unwrap();
    (ciphertexts, leaves, root)
}

pub fn create_file_commitment<R: RngCore + CryptoRng>(rng: &mut R, file_id: [u8; 32], pre_encrypted_blocks: &[Vec<u8>], x: &Scalar) -> (FileCommitment, Vec<CiphertextBlock>, Vec<[u8; 32]>) {
    for block in pre_encrypted_blocks {
        assert!(block.len() <= REVERSIBLE_POINT_PAYLOAD_SIZE, "block too large for reversible Ristretto encoding");
    }
    let nonce = random_scalar(rng).to_bytes();
    let file_size: u64 = pre_encrypted_blocks.iter().map(|b| b.len() as u64).sum();
    let (ciphertexts, leaves, root) = prepare_file_blocks(rng, pre_encrypted_blocks, x, &nonce);
    let commitment = FileCommitment {
        file_id,
        root_hash: root,
        num_blocks: pre_encrypted_blocks.len() as u64,
        block_size: REVERSIBLE_POINT_PAYLOAD_SIZE,
        file_size,
        encoding_version: REVERSIBLE_POINT_ENCODING_V1,
        nonce,
    };
    (commitment, ciphertexts, leaves)
}

fn derive_challenge_indices(nonce: &[u8; 32], num_blocks: u64, num_challenges: usize) -> Vec<u64> {
    if num_blocks == 0 || num_challenges == 0 { return Vec::new(); }
    let target = num_challenges.min(num_blocks as usize);
    if target == num_blocks as usize {
        return (0..num_blocks).collect();
    }

    // O(k) deterministic sampling instead of shuffling 0..num_blocks.  The old
    // implementation allocated and shuffled every index, which is very costly
    // for large files even when the audit challenge count is capped at ~100.
    let mut out = BTreeSet::new();
    let mut counter = 0u64;
    while out.len() < target {
        let mut hasher = Sha512::new();
        hasher.update(b"EBUT:FILE:CHALLENGE-INDEX:V2");
        hasher.update(nonce);
        hasher.update(num_blocks.to_le_bytes());
        hasher.update((target as u64).to_le_bytes());
        hasher.update(counter.to_le_bytes());
        let digest = hasher.finalize();
        let mut wide = [0u8; 16];
        wide.copy_from_slice(&digest[..16]);
        let idx = (u128::from_le_bytes(wide) % (num_blocks as u128)) as u64;
        out.insert(idx);
        counter = counter.wrapping_add(1);
    }
    out.into_iter().collect()
}
pub fn create_file_proof<R: RngCore + CryptoRng>(
    rng: &mut R, x: &Scalar, file_id: [u8; 32], ciphertexts: &[CiphertextBlock], leaves: &[[u8; 32]],
    root_hash: &[u8; 32], challenge_nonce: &[u8; 32], num_challenges: usize, slot_generator: &RistrettoPoint, tag: &RistrettoPoint,
) -> FileProof {
    let num_blocks = ciphertexts.len() as u64;
    let indices = derive_challenge_indices(challenge_nonce, num_blocks, num_challenges);
    let merkle_tree = build_merkle_tree(leaves);
    let use_batch = indices.len() >= BATCH_THRESHOLD;
    let mut blocks = Vec::new();
    let mut pairs = if use_batch { Some(Vec::with_capacity(1 + num_challenges)) } else { None };
    if use_batch { pairs.as_mut().unwrap().push((*slot_generator, *tag)); }

    for idx in indices {
        let i = idx as usize; let cipher = &ciphertexts[i];
        let m = elgamal_decrypt_block(x, &cipher.c1, &cipher.c2); let d = cipher.c2 - m;
        let path = merkle_path_from_tree(&merkle_tree, i);
        let dleq_proof = if use_batch { pairs.as_mut().unwrap().push((cipher.c1, d)); None } else {
            Some(DLEQProof::prove(rng, x, slot_generator, tag, &cipher.c1, &d))
        };
        blocks.push(BlockProof { index: idx, ciphertext: cipher.clone(), decrypted_point: m, merkle_path: path, dleq_proof });
    }

    let batch_proof = if use_batch {
        let pairs = pairs.unwrap(); let coeffs = derive_batch_coefficients(&pairs);
        let (a, b) = combine_pairs(&pairs, &coeffs);
        Some(DLEQProof::prove(rng, x, slot_generator, tag, &a, &b))
    } else { None };

    FileProof { file_id, root_hash: *root_hash, blocks, batch_proof }
}

pub fn verify_file_proof(proof: &FileProof, stored_commitment: &FileCommitment, challenge_nonce: &[u8; 32], slot_generator: &RistrettoPoint, tag: &RistrettoPoint) -> bool {
    if proof.file_id != stored_commitment.file_id || proof.root_hash != stored_commitment.root_hash { return false; }
    let num_blocks = stored_commitment.num_blocks;
    if stored_commitment.encoding_version != REVERSIBLE_POINT_ENCODING_V1 { return false; }
    if stored_commitment.block_size == 0 || stored_commitment.block_size > REVERSIBLE_POINT_PAYLOAD_SIZE { return false; }
    if proof.blocks.len() as u64 > num_blocks { return false; }
    if num_blocks > 0 && proof.blocks.is_empty() { return false; }
    let expected_indices = derive_challenge_indices(challenge_nonce, num_blocks, proof.blocks.len());
    let use_batch = proof.batch_proof.is_some();

    if use_batch {
        let mut pairs = Vec::with_capacity(1 + proof.blocks.len()); pairs.push((*slot_generator, *tag));
        for (block, &expected_idx) in proof.blocks.iter().zip(expected_indices.iter()) {
            if block.index != expected_idx || block.dleq_proof.is_some() { return false; }
            let mut hasher = Sha512::new(); hasher.update(b"CIPHER_LEAF");
            hasher.update(block.ciphertext.c1.compress().as_bytes()); hasher.update(block.ciphertext.c2.compress().as_bytes());
            let leaf: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();
            if !verify_merkle_path(&leaf, block.index as usize, &block.merkle_path, &stored_commitment.root_hash) { return false; }
            let d = block.ciphertext.c2 - block.decrypted_point; pairs.push((block.ciphertext.c1, d));
        }
        let coeffs = derive_batch_coefficients(&pairs); let (a, b) = combine_pairs(&pairs, &coeffs);
        proof.batch_proof.as_ref().unwrap().verify(slot_generator, tag, &a, &b)
    } else {
        for (block, &expected_idx) in proof.blocks.iter().zip(expected_indices.iter()) {
            if block.index != expected_idx || block.dleq_proof.is_none() { return false; }
            let mut hasher = Sha512::new(); hasher.update(b"CIPHER_LEAF");
            hasher.update(block.ciphertext.c1.compress().as_bytes()); hasher.update(block.ciphertext.c2.compress().as_bytes());
            let leaf: [u8; 32] = hasher.finalize()[..32].try_into().unwrap();
            if !verify_merkle_path(&leaf, block.index as usize, &block.merkle_path, &stored_commitment.root_hash) { return false; }
            let d = block.ciphertext.c2 - block.decrypted_point;
            if !block.dleq_proof.as_ref().unwrap().verify(slot_generator, tag, &block.ciphertext.c1, &d) { return false; }
        }
        true
    }
}

/// Verify file proof and require exactly the expected challenge count for a
/// chosen audit confidence. This prevents a malicious client from submitting
/// a syntactically valid proof with only one or zero challenged blocks.
pub fn verify_file_proof_with_confidence(
    proof: &FileProof,
    stored_commitment: &FileCommitment,
    challenge_nonce: &[u8; 32],
    slot_generator: &RistrettoPoint,
    tag: &RistrettoPoint,
    confidence: f64,
) -> bool {
    let expected = expected_challenge_count(stored_commitment, confidence);
    if proof.blocks.len() != expected {
        return false;
    }
    verify_file_proof(proof, stored_commitment, challenge_nonce, slot_generator, tag)
}

pub fn auto_block_size(_file_size_bytes: usize) -> usize {
    // Direct EC-ElGamal encrypts one group element per block. With reversible
    // compressed-Ristretto encoding, one point carries 28 plaintext bytes.
    REVERSIBLE_POINT_PAYLOAD_SIZE
}

fn audit_sample_count_for_bad_fraction(num_blocks: u64, confidence: f64, bad_fraction: f64) -> usize {
    if num_blocks == 0 { return 0; }
    if num_blocks == 1 { return 1; }

    let confidence = if confidence.is_finite() { confidence.clamp(0.50, 0.999_999) } else { 0.90 };
    let bad_fraction = if bad_fraction.is_finite() { bad_fraction.clamp(0.001, 1.0) } else { DEFAULT_AUDIT_BAD_FRACTION };
    let bad_blocks = ((num_blocks as f64) * bad_fraction).ceil().clamp(1.0, num_blocks as f64) as u64;
    let max_k = MAX_AUDIT_CHALLENGES.min(num_blocks as usize);

    // Exact hypergeometric miss probability for sampling without replacement:
    // miss(k) = Π_{i=0}^{k-1} (N-B-i)/(N-i), where B is the number of bad blocks.
    // We choose the first k whose catch probability is at least `confidence`.
    let mut miss = 1.0f64;
    for k in 1..=max_k {
        let i = (k - 1) as u64;
        if i >= num_blocks { return num_blocks as usize; }
        let numerator = num_blocks.saturating_sub(bad_blocks).saturating_sub(i) as f64;
        let denominator = num_blocks.saturating_sub(i) as f64;
        if denominator <= 0.0 || numerator <= 0.0 { return k; }
        miss *= numerator / denominator;
        if 1.0 - miss >= confidence { return k; }
    }

    max_k
}

pub fn auto_challenge_count(num_blocks: u64, confidence: f64) -> usize {
    audit_sample_count_for_bad_fraction(num_blocks, confidence, DEFAULT_AUDIT_BAD_FRACTION)
}

pub fn create_file_commitment_auto<R: RngCore + CryptoRng>(rng: &mut R, file_id: [u8; 32], file_data: &[u8], x: &Scalar) -> (FileCommitment, Vec<CiphertextBlock>, Vec<[u8; 32]>) {
    let block_size = auto_block_size(file_data.len());
    let blocks: Vec<Vec<u8>> = file_data.chunks(block_size).map(|chunk| chunk.to_vec()).collect();
    create_file_commitment(rng, file_id, &blocks, x)
}

pub fn decrypt_file_from_ciphertexts(ciphertexts: &[CiphertextBlock], commitment: &FileCommitment, x: &Scalar) -> Result<Vec<u8>, PointEncodingError> {
    if ciphertexts.len() as u64 != commitment.num_blocks { return Err(PointEncodingError::InvalidDecodedLength { len: ciphertexts.len(), max: commitment.num_blocks as usize }); }
    if commitment.encoding_version != REVERSIBLE_POINT_ENCODING_V1 { return Err(PointEncodingError::InvalidDecodedLength { len: commitment.encoding_version as usize, max: REVERSIBLE_POINT_ENCODING_V1 as usize }); }

    let mut out = Vec::with_capacity(commitment.file_size as usize);
    for (i, cipher) in ciphertexts.iter().enumerate() {
        let m = elgamal_decrypt_block(x, &cipher.c1, &cipher.c2);
        let remaining = commitment.file_size as usize - out.len();
        let chunk_len = remaining.min(commitment.block_size);
        let chunk = decode_point_to_chunk(&m, chunk_len)?;
        out.extend_from_slice(&chunk);
        if i + 1 == ciphertexts.len() { break; }
    }
    Ok(out)
}

pub fn expected_challenge_count(commitment: &FileCommitment, confidence: f64) -> usize {
    if commitment.num_blocks == 0 {
        return 0;
    }

    // Small files are fully challenged. This matches the intended policy: a
    // ~100 KiB-or-smaller upload gets complete coverage, while large files use
    // capped random spot checks.
    if commitment.file_size <= FULL_AUDIT_FILE_BYTES {
        return commitment.num_blocks as usize;
    }

    auto_challenge_count(commitment.num_blocks, confidence)
}


// ============================================================================
// Hidden-plaintext file proof
// ============================================================================
//
// The older `FileProof` above reveals `decrypted_point` for challenged blocks.
// That is useful for debugging/TEE deployments but leaks sampled plaintext.
// The private proof below replaces the reveal with a Pedersen commitment to the
// plaintext point:
//
//     K_i = M_i + s_i H
//     C1_i = r_i G
//     C2_i = M_i + r_i X
//
// The verifier sees K_i, C1_i, C2_i and verifies in zero knowledge that the
// same hidden M_i is inside both K_i and the ElGamal ciphertext:
//
//     C2_i - K_i = r_i X - s_i H
//     C1_i       = r_i G
//
// No M_i/decrypted Ristretto point is sent. A random-linear-combination batch
// proof verifies all challenged blocks with one two-scalar Schnorr proof.

/// Generator used to hide plaintext points inside file commitments.
pub fn private_plaintext_h() -> RistrettoPoint {
    let mut h = Sha512::new();
    h.update(b"EBUT:FILE:PRIVATE-PLAINTEXT-H:V1");
    RistrettoPoint::from_uniform_bytes(&h.finalize().into())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateCiphertextBlock {
    pub ciphertext: CiphertextBlock,
    #[serde(with = "ristretto_serde")]
    pub plaintext_commitment: RistrettoPoint,
}

#[derive(Clone, Debug)]
pub struct PrivateFileWitnessBlock {
    pub encryption_randomness: Scalar,
    pub commitment_blinding: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HiddenPlaintextBatchProof {
    #[serde(with = "ristretto_serde")]
    pub a1: RistrettoPoint,
    #[serde(with = "ristretto_serde")]
    pub a2: RistrettoPoint,
    pub z_r: Scalar,
    /// Response for the witness `-s`, where `s` is the plaintext commitment blinding.
    pub z_minus_s: Scalar,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateBlockProof {
    pub index: u64,
    pub block: PrivateCiphertextBlock,
    pub merkle_path: Vec<(bool, [u8; 32])>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrivateFileProof {
    pub file_id: [u8; 32],
    pub root_hash: [u8; 32],
    pub blocks: Vec<PrivateBlockProof>,
    pub batch_proof: HiddenPlaintextBatchProof,
}

fn private_cipher_leaf(block: &PrivateCiphertextBlock) -> [u8; 32] {
    let mut hasher = Sha512::new();
    hasher.update(b"PRIVATE_CIPHER_LEAF_V1");
    hasher.update(block.ciphertext.c1.compress().as_bytes());
    hasher.update(block.ciphertext.c2.compress().as_bytes());
    hasher.update(block.plaintext_commitment.compress().as_bytes());
    hasher.finalize()[..32].try_into().unwrap()
}

fn derive_private_batch_coefficients(blocks: &[PrivateBlockProof], proof_context: &[u8], file_public_key: &RistrettoPoint) -> Vec<Scalar> {
    let mut coeffs = Vec::with_capacity(blocks.len());
    for i in 0..blocks.len() {
        let mut h = Sha512::new();
        h.update(b"EBUT:FILE:HIDDEN-M:BATCH-RHO:V1");
        h.update(proof_context);
        h.update(file_public_key.compress().as_bytes());
        for block in blocks {
            h.update(block.index.to_le_bytes());
            h.update(block.block.ciphertext.c1.compress().as_bytes());
            h.update(block.block.ciphertext.c2.compress().as_bytes());
            h.update(block.block.plaintext_commitment.compress().as_bytes());
        }
        h.update((i as u64).to_le_bytes());
        coeffs.push(Scalar::from_bytes_mod_order_wide(&h.finalize().into()));
    }
    coeffs
}

fn hidden_plaintext_challenge(
    proof_context: &[u8],
    file_public_key: &RistrettoPoint,
    c1_bar: &RistrettoPoint,
    d_bar: &RistrettoPoint,
    a1: &RistrettoPoint,
    a2: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"EBUT:FILE:HIDDEN-M:SCHNORR:V1");
    h.update(proof_context);
    h.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    h.update(file_public_key.compress().as_bytes());
    h.update(private_plaintext_h().compress().as_bytes());
    h.update(c1_bar.compress().as_bytes());
    h.update(d_bar.compress().as_bytes());
    h.update(a1.compress().as_bytes());
    h.update(a2.compress().as_bytes());
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

fn aggregate_private_statement(blocks: &[PrivateBlockProof], coeffs: &[Scalar]) -> (RistrettoPoint, RistrettoPoint) {
    let mut c1_bar = RistrettoPoint::default();
    let mut d_bar = RistrettoPoint::default();
    for (block, rho) in blocks.iter().zip(coeffs.iter()) {
        c1_bar += rho * block.block.ciphertext.c1;
        d_bar += rho * (block.block.ciphertext.c2 - block.block.plaintext_commitment);
    }
    (c1_bar, d_bar)
}

impl HiddenPlaintextBatchProof {
    fn prove<R: RngCore + CryptoRng>(
        rng: &mut R,
        proof_context: &[u8],
        file_public_key: &RistrettoPoint,
        blocks: &[PrivateBlockProof],
        witnesses: &[PrivateFileWitnessBlock],
    ) -> Self {
        let coeffs = derive_private_batch_coefficients(blocks, proof_context, file_public_key);
        let (c1_bar, d_bar) = aggregate_private_statement(blocks, &coeffs);

        let mut r_bar = Scalar::zero();
        let mut minus_s_bar = Scalar::zero();
        for ((rho, _block), witness) in coeffs.iter().zip(blocks.iter()).zip(witnesses.iter()) {
            r_bar += rho * witness.encryption_randomness;
            minus_s_bar -= rho * witness.commitment_blinding;
        }

        let alpha_r = random_scalar(rng);
        let alpha_s = random_scalar(rng);
        let h = private_plaintext_h();
        let a1 = alpha_r * RISTRETTO_BASEPOINT_POINT;
        let a2 = alpha_r * file_public_key + alpha_s * h;
        let c = hidden_plaintext_challenge(proof_context, file_public_key, &c1_bar, &d_bar, &a1, &a2);
        HiddenPlaintextBatchProof {
            a1,
            a2,
            z_r: alpha_r + c * r_bar,
            z_minus_s: alpha_s + c * minus_s_bar,
        }
    }

    fn verify(&self, proof_context: &[u8], file_public_key: &RistrettoPoint, blocks: &[PrivateBlockProof]) -> bool {
        if blocks.is_empty() { return false; }
        if *file_public_key == RistrettoPoint::default() { return false; }
        let h = private_plaintext_h();
        if h == RistrettoPoint::default() { return false; }
        let coeffs = derive_private_batch_coefficients(blocks, proof_context, file_public_key);
        let (c1_bar, d_bar) = aggregate_private_statement(blocks, &coeffs);
        let c = hidden_plaintext_challenge(proof_context, file_public_key, &c1_bar, &d_bar, &self.a1, &self.a2);
        let lhs1 = self.z_r * RISTRETTO_BASEPOINT_POINT;
        let rhs1 = self.a1 + c * c1_bar;
        if lhs1 != rhs1 { return false; }
        let lhs2 = self.z_r * file_public_key + self.z_minus_s * h;
        let rhs2 = self.a2 + c * d_bar;
        lhs2 == rhs2
    }
}

fn prepare_private_file_blocks<R: RngCore + CryptoRng>(
    _rng: &mut R,
    blocks: &[Vec<u8>],
    file_public_key: &RistrettoPoint,
) -> (Vec<PrivateCiphertextBlock>, Vec<[u8; 32]>, Vec<PrivateFileWitnessBlock>, [u8; 32]) {
    let h = private_plaintext_h();
    let triples: Vec<_> = blocks.par_iter().map(|block_bytes| {
        let mut thread_rng = rand::thread_rng();
        let m = encode_chunk_to_point(block_bytes)
            .expect("reversible point encoding failed; use smaller chunks or check encoding parameters");
        let r = random_scalar(&mut thread_rng);
        let s = random_scalar(&mut thread_rng);
        let c1 = r * RISTRETTO_BASEPOINT_POINT;
        let c2 = m + r * file_public_key;
        let plaintext_commitment = m + s * h;
        let public_block = PrivateCiphertextBlock { ciphertext: CiphertextBlock { c1, c2 }, plaintext_commitment };
        let leaf = private_cipher_leaf(&public_block);
        let witness = PrivateFileWitnessBlock { encryption_randomness: r, commitment_blinding: s };
        (public_block, leaf, witness)
    }).collect();

    let mut public_blocks = Vec::with_capacity(triples.len());
    let mut leaves = Vec::with_capacity(triples.len());
    let mut witnesses = Vec::with_capacity(triples.len());
    for (b, l, w) in triples {
        public_blocks.push(b);
        leaves.push(l);
        witnesses.push(w);
    }
    let tree = build_merkle_tree(&leaves);
    let root = *tree.last().unwrap().first().unwrap();
    (public_blocks, leaves, witnesses, root)
}

pub fn create_private_file_commitment<R: RngCore + CryptoRng>(
    rng: &mut R,
    file_id: [u8; 32],
    pre_encrypted_blocks: &[Vec<u8>],
    file_public_key: &RistrettoPoint,
) -> (FileCommitment, Vec<PrivateCiphertextBlock>, Vec<[u8; 32]>, Vec<PrivateFileWitnessBlock>) {
    for block in pre_encrypted_blocks {
        assert!(block.len() <= REVERSIBLE_POINT_PAYLOAD_SIZE, "block too large for reversible Ristretto encoding");
    }
    let nonce = random_scalar(rng).to_bytes();
    let file_size: u64 = pre_encrypted_blocks.iter().map(|b| b.len() as u64).sum();
    let (blocks, leaves, witnesses, root) = prepare_private_file_blocks(rng, pre_encrypted_blocks, file_public_key);
    let commitment = FileCommitment {
        file_id,
        root_hash: root,
        num_blocks: pre_encrypted_blocks.len() as u64,
        block_size: REVERSIBLE_POINT_PAYLOAD_SIZE,
        file_size,
        encoding_version: REVERSIBLE_POINT_ENCODING_V1,
        nonce,
    };
    (commitment, blocks, leaves, witnesses)
}

pub fn create_private_file_commitment_auto<R: RngCore + CryptoRng>(
    rng: &mut R,
    file_id: [u8; 32],
    file_data: &[u8],
    file_public_key: &RistrettoPoint,
) -> (FileCommitment, Vec<PrivateCiphertextBlock>, Vec<[u8; 32]>, Vec<PrivateFileWitnessBlock>) {
    let blocks: Vec<Vec<u8>> = file_data.chunks(REVERSIBLE_POINT_PAYLOAD_SIZE).map(|chunk| chunk.to_vec()).collect();
    create_private_file_commitment(rng, file_id, &blocks, file_public_key)
}

pub fn create_private_file_proof<R: RngCore + CryptoRng>(
    rng: &mut R,
    file_id: [u8; 32],
    public_blocks: &[PrivateCiphertextBlock],
    leaves: &[[u8; 32]],
    root_hash: &[u8; 32],
    challenge_nonce: &[u8; 32],
    num_challenges: usize,
    file_public_key: &RistrettoPoint,
    witnesses: &[PrivateFileWitnessBlock],
    proof_context: &[u8],
) -> PrivateFileProof {
    let num_blocks = public_blocks.len() as u64;
    let indices = derive_challenge_indices(challenge_nonce, num_blocks, num_challenges);
    let merkle_tree = build_merkle_tree(leaves);
    let mut blocks = Vec::with_capacity(indices.len());
    let mut selected_witnesses = Vec::with_capacity(indices.len());
    for idx in indices {
        let i = idx as usize;
        blocks.push(PrivateBlockProof { index: idx, block: public_blocks[i].clone(), merkle_path: merkle_path_from_tree(&merkle_tree, i) });
        selected_witnesses.push(witnesses[i].clone());
    }
    let batch_proof = HiddenPlaintextBatchProof::prove(rng, proof_context, file_public_key, &blocks, &selected_witnesses);
    PrivateFileProof { file_id, root_hash: *root_hash, blocks, batch_proof }
}

pub fn verify_private_file_proof(
    proof: &PrivateFileProof,
    stored_commitment: &FileCommitment,
    challenge_nonce: &[u8; 32],
    file_public_key: &RistrettoPoint,
    proof_context: &[u8],
) -> bool {
    if proof.file_id != stored_commitment.file_id || proof.root_hash != stored_commitment.root_hash { return false; }
    if stored_commitment.encoding_version != REVERSIBLE_POINT_ENCODING_V1 { return false; }
    if stored_commitment.block_size == 0 || stored_commitment.block_size > REVERSIBLE_POINT_PAYLOAD_SIZE { return false; }
    if proof.blocks.len() as u64 > stored_commitment.num_blocks { return false; }
    if stored_commitment.num_blocks > 0 && proof.blocks.is_empty() { return false; }
    let expected_indices = derive_challenge_indices(challenge_nonce, stored_commitment.num_blocks, proof.blocks.len());
    for (block, &expected_idx) in proof.blocks.iter().zip(expected_indices.iter()) {
        if block.index != expected_idx { return false; }
        let leaf = private_cipher_leaf(&block.block);
        if !verify_merkle_path(&leaf, block.index as usize, &block.merkle_path, &stored_commitment.root_hash) { return false; }
    }
    proof.batch_proof.verify(proof_context, file_public_key, &proof.blocks)
}

pub fn verify_private_file_proof_with_confidence(
    proof: &PrivateFileProof,
    stored_commitment: &FileCommitment,
    challenge_nonce: &[u8; 32],
    file_public_key: &RistrettoPoint,
    proof_context: &[u8],
    confidence: f64,
) -> bool {
    let expected = expected_challenge_count(stored_commitment, confidence);
    if proof.blocks.len() != expected { return false; }
    verify_private_file_proof(proof, stored_commitment, challenge_nonce, file_public_key, proof_context)
}

pub fn decrypt_private_file_from_ciphertexts(
    private_blocks: &[PrivateCiphertextBlock],
    commitment: &FileCommitment,
    x: &Scalar,
) -> Result<Vec<u8>, PointEncodingError> {
    let ciphertexts: Vec<CiphertextBlock> = private_blocks.iter().map(|b| b.ciphertext.clone()).collect();
    decrypt_file_from_ciphertexts(&ciphertexts, commitment, x)
}


// ============================================================================
// Accountable packed point-ElGamal file proof (Option A)
// ============================================================================
//
// This is the recommended file path. It shares one ElGamal randomness/C1 across
// several plaintext points to keep audited storage/proof overhead under 4x:
//
//   X      = xG
//   C1_b   = r_b G
//   C2_bj  = M_bj + r_b X
//   K_bj   = M_bj + s_bj H
//
// Challenge proof batches all point equations without revealing M_bj:
//
//   C2_bj - K_bj = r_b X - s_bj H
//
// With 17 bytes per point and 16 points per packed block, public challenged
// data is (32 + 16*(32+32))/(16*17) = 3.88x before Merkle path overhead.

pub const ACCOUNTABLE_FILE_ENCODING_V2: u32 = 2;
pub const ACCOUNTABLE_POINT_PAYLOAD_SIZE: usize = REVERSIBLE_POINT_PAYLOAD_SIZE;
pub const ACCOUNTABLE_POINTS_PER_BLOCK: usize = 16;
pub const ACCOUNTABLE_PACKED_BLOCK_PAYLOAD_SIZE: usize = ACCOUNTABLE_POINT_PAYLOAD_SIZE * ACCOUNTABLE_POINTS_PER_BLOCK;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountableCiphertextBlock {
    #[serde(with = "ristretto_serde")]
    pub c1: RistrettoPoint,
    #[serde(with = "ristretto_vec_serde")]
    pub c2_points: Vec<RistrettoPoint>,
    #[serde(with = "ristretto_vec_serde")]
    pub plaintext_commitments: Vec<RistrettoPoint>,
    pub point_lengths: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct AccountableFileWitnessBlock {
    pub encryption_randomness: Scalar,
    pub commitment_blindings: Vec<Scalar>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountableBlockProof {
    pub index: u64,
    pub block: AccountableCiphertextBlock,
    pub merkle_path: Vec<(bool, [u8; 32])>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountableFileProof {
    pub file_id: [u8; 32],
    pub root_hash: [u8; 32],
    pub blocks: Vec<AccountableBlockProof>,
    pub batch_proof: AccountableBatchProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AccountableBatchProof {
    #[serde(with = "ristretto_serde")]
    pub a1: RistrettoPoint,
    #[serde(with = "ristretto_serde")]
    pub a2: RistrettoPoint,
    pub z_r: Scalar,
    pub z_minus_s: Scalar,
}

mod ristretto_vec_serde {
    use super::*;
    use serde::{Serializer, Deserializer};
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
                    let p = CompressedRistretto(bytes).decompress()
                        .ok_or_else(|| serde::de::Error::custom("invalid compressed Ristretto point"))?;
                    out.push(p);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_seq(PointsVisitor)
    }
}

fn accountable_cipher_leaf(block: &AccountableCiphertextBlock) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(b"EBUT:ACCOUNTABLE-PACKED-CIPHER-LEAF:V1");
    h.update(block.c1.compress().as_bytes());
    h.update((block.c2_points.len() as u64).to_le_bytes());
    for ((c2, k), len) in block.c2_points.iter().zip(block.plaintext_commitments.iter()).zip(block.point_lengths.iter()) {
        h.update(c2.compress().as_bytes());
        h.update(k.compress().as_bytes());
        h.update([*len]);
    }
    h.finalize()[..32].try_into().unwrap()
}

fn accountable_batch_transcript_digest(
    blocks: &[AccountableBlockProof],
    proof_context: &[u8],
    file_public_key: &RistrettoPoint,
) -> [u8; 64] {
    // Build the expensive transcript exactly once.  The previous implementation
    // re-hashed every challenged block for every coefficient, giving quadratic
    // behavior on fully audited small files.  This digest is still bound to the
    // same public statement: context, file key, challenged indices, C1/C2/K
    // points, and per-point lengths.
    let mut h = Sha512::new();
    h.update(b"EBUT:ACCOUNTABLE-PACKED-RHO-TRANSCRIPT:V2");
    h.update(proof_context);
    h.update(file_public_key.compress().as_bytes());
    h.update((blocks.len() as u64).to_le_bytes());
    for b in blocks {
        h.update(b.index.to_le_bytes());
        h.update(b.block.c1.compress().as_bytes());
        h.update((b.block.c2_points.len() as u64).to_le_bytes());
        for ((c2, k), len) in b.block.c2_points.iter().zip(b.block.plaintext_commitments.iter()).zip(b.block.point_lengths.iter()) {
            h.update(c2.compress().as_bytes());
            h.update(k.compress().as_bytes());
            h.update([*len]);
        }
    }
    let digest = h.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    out
}

fn derive_accountable_batch_coefficients(blocks: &[AccountableBlockProof], proof_context: &[u8], file_public_key: &RistrettoPoint) -> Vec<Vec<Scalar>> {
    let transcript_digest = accountable_batch_transcript_digest(blocks, proof_context, file_public_key);
    let mut coeffs = Vec::with_capacity(blocks.len());
    for (bi, block) in blocks.iter().enumerate() {
        let mut row = Vec::with_capacity(block.block.c2_points.len());
        for j in 0..block.block.c2_points.len() {
            let mut h = Sha512::new();
            h.update(b"EBUT:ACCOUNTABLE-PACKED-RHO-COEFF:V2");
            h.update(transcript_digest);
            h.update((bi as u64).to_le_bytes());
            h.update((block.index).to_le_bytes());
            h.update((j as u64).to_le_bytes());
            row.push(Scalar::from_bytes_mod_order_wide(&h.finalize().into()));
        }
        coeffs.push(row);
    }
    coeffs
}

fn aggregate_accountable_statement(blocks: &[AccountableBlockProof], coeffs: &[Vec<Scalar>]) -> (RistrettoPoint, RistrettoPoint) {
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

fn accountable_challenge(
    proof_context: &[u8], file_public_key: &RistrettoPoint,
    c1_bar: &RistrettoPoint, d_bar: &RistrettoPoint,
    a1: &RistrettoPoint, a2: &RistrettoPoint,
) -> Scalar {
    let mut h = Sha512::new();
    h.update(b"EBUT:ACCOUNTABLE-PACKED-SCHNORR:V1");
    h.update(proof_context);
    h.update(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    h.update(file_public_key.compress().as_bytes());
    h.update(private_plaintext_h().compress().as_bytes());
    h.update(c1_bar.compress().as_bytes());
    h.update(d_bar.compress().as_bytes());
    h.update(a1.compress().as_bytes());
    h.update(a2.compress().as_bytes());
    Scalar::from_bytes_mod_order_wide(&h.finalize().into())
}

impl AccountableBatchProof {
    fn prove<R: RngCore + CryptoRng>(rng: &mut R, proof_context: &[u8], file_public_key: &RistrettoPoint, blocks: &[AccountableBlockProof], witnesses: &[AccountableFileWitnessBlock]) -> Self {
        let coeffs = derive_accountable_batch_coefficients(blocks, proof_context, file_public_key);
        let (c1_bar, d_bar) = aggregate_accountable_statement(blocks, &coeffs);
        let mut r_bar = Scalar::zero();
        let mut minus_s_bar = Scalar::zero();
        for ((row, _block), witness) in coeffs.iter().zip(blocks.iter()).zip(witnesses.iter()) {
            let mut rho_sum = Scalar::zero();
            for (rho, s) in row.iter().zip(witness.commitment_blindings.iter()) {
                rho_sum += rho;
                minus_s_bar -= rho * s;
            }
            r_bar += rho_sum * witness.encryption_randomness;
        }
        let alpha_r = random_scalar(rng);
        let alpha_s = random_scalar(rng);
        let h = private_plaintext_h();
        let a1 = alpha_r * RISTRETTO_BASEPOINT_POINT;
        let a2 = alpha_r * file_public_key + alpha_s * h;
        let c = accountable_challenge(proof_context, file_public_key, &c1_bar, &d_bar, &a1, &a2);
        AccountableBatchProof { a1, a2, z_r: alpha_r + c * r_bar, z_minus_s: alpha_s + c * minus_s_bar }
    }

    fn verify(&self, proof_context: &[u8], file_public_key: &RistrettoPoint, blocks: &[AccountableBlockProof]) -> bool {
        if blocks.is_empty() || *file_public_key == RistrettoPoint::default() { return false; }
        let h = private_plaintext_h();
        if h == RistrettoPoint::default() { return false; }
        for block in blocks {
            if block.block.c2_points.is_empty()
                || block.block.c2_points.len() != block.block.plaintext_commitments.len()
                || block.block.c2_points.len() != block.block.point_lengths.len()
                || block.block.c2_points.len() > ACCOUNTABLE_POINTS_PER_BLOCK
            { return false; }
            if block.block.point_lengths.iter().any(|&l| l == 0 || (l as usize) > ACCOUNTABLE_POINT_PAYLOAD_SIZE) { return false; }
        }
        let coeffs = derive_accountable_batch_coefficients(blocks, proof_context, file_public_key);
        let (c1_bar, d_bar) = aggregate_accountable_statement(blocks, &coeffs);
        let c = accountable_challenge(proof_context, file_public_key, &c1_bar, &d_bar, &self.a1, &self.a2);
        if self.z_r * RISTRETTO_BASEPOINT_POINT != self.a1 + c * c1_bar { return false; }
        self.z_r * file_public_key + self.z_minus_s * h == self.a2 + c * d_bar
    }
}

pub fn create_accountable_file_commitment_auto<R: RngCore + CryptoRng>(rng: &mut R, file_id: [u8; 32], file_data: &[u8], file_public_key: &RistrettoPoint) -> (FileCommitment, Vec<AccountableCiphertextBlock>, Vec<[u8; 32]>, Vec<AccountableFileWitnessBlock>) {
    let h = private_plaintext_h();
    let mut public_blocks = Vec::new();
    let mut leaves = Vec::new();
    let mut witnesses = Vec::new();
    for group in file_data.chunks(ACCOUNTABLE_PACKED_BLOCK_PAYLOAD_SIZE) {
        let r = random_scalar(rng);
        let c1 = r * RISTRETTO_BASEPOINT_POINT;
        let shared = r * file_public_key;
        let mut c2_points = Vec::new();
        let mut plaintext_commitments = Vec::new();
        let mut point_lengths = Vec::new();
        let mut blindings = Vec::new();
        for chunk in group.chunks(ACCOUNTABLE_POINT_PAYLOAD_SIZE) {
            let m = encode_chunk_to_point(chunk).expect("accountable point encoding failed; lower ACCOUNTABLE_POINT_PAYLOAD_SIZE");
            let s = random_scalar(rng);
            c2_points.push(m + shared);
            plaintext_commitments.push(m + s * h);
            point_lengths.push(chunk.len() as u8);
            blindings.push(s);
        }
        let block = AccountableCiphertextBlock { c1, c2_points, plaintext_commitments, point_lengths };
        leaves.push(accountable_cipher_leaf(&block));
        public_blocks.push(block);
        witnesses.push(AccountableFileWitnessBlock { encryption_randomness: r, commitment_blindings: blindings });
    }
    let tree = build_merkle_tree(&leaves);
    let root = *tree.last().unwrap().first().unwrap();
    let nonce = random_scalar(rng).to_bytes();
    let commitment = FileCommitment { file_id, root_hash: root, num_blocks: public_blocks.len() as u64, block_size: ACCOUNTABLE_PACKED_BLOCK_PAYLOAD_SIZE, file_size: file_data.len() as u64, encoding_version: ACCOUNTABLE_FILE_ENCODING_V2, nonce };
    (commitment, public_blocks, leaves, witnesses)
}

pub fn create_accountable_file_proof<R: RngCore + CryptoRng>(rng: &mut R, file_id: [u8; 32], public_blocks: &[AccountableCiphertextBlock], leaves: &[[u8; 32]], root_hash: &[u8; 32], challenge_nonce: &[u8; 32], num_challenges: usize, file_public_key: &RistrettoPoint, witnesses: &[AccountableFileWitnessBlock], proof_context: &[u8]) -> AccountableFileProof {
    let indices = derive_challenge_indices(challenge_nonce, public_blocks.len() as u64, num_challenges);
    let merkle_tree = build_merkle_tree(leaves);
    let mut blocks = Vec::with_capacity(indices.len());
    let mut proof_witnesses = Vec::with_capacity(indices.len());
    for idx in indices {
        let i = idx as usize;
        blocks.push(AccountableBlockProof { index: idx, block: public_blocks[i].clone(), merkle_path: merkle_path_from_tree(&merkle_tree, i) });
        proof_witnesses.push(witnesses[i].clone());
    }
    let batch_proof = AccountableBatchProof::prove(rng, proof_context, file_public_key, &blocks, &proof_witnesses);
    AccountableFileProof { file_id, root_hash: *root_hash, blocks, batch_proof }
}

pub fn verify_accountable_file_proof(proof: &AccountableFileProof, stored_commitment: &FileCommitment, challenge_nonce: &[u8; 32], file_public_key: &RistrettoPoint, proof_context: &[u8]) -> bool {
    if stored_commitment.encoding_version != ACCOUNTABLE_FILE_ENCODING_V2 { return false; }
    if proof.file_id != stored_commitment.file_id || proof.root_hash != stored_commitment.root_hash { return false; }
    if proof.blocks.len() as u64 > stored_commitment.num_blocks { return false; }
    if stored_commitment.num_blocks > 0 && proof.blocks.is_empty() { return false; }
    let expected_indices = derive_challenge_indices(challenge_nonce, stored_commitment.num_blocks, proof.blocks.len());
    for (block, &expected_idx) in proof.blocks.iter().zip(expected_indices.iter()) {
        if block.index != expected_idx { return false; }
        let leaf = accountable_cipher_leaf(&block.block);
        if !verify_merkle_path(&leaf, block.index as usize, &block.merkle_path, &stored_commitment.root_hash) { return false; }
    }
    proof.batch_proof.verify(proof_context, file_public_key, &proof.blocks)
}

pub fn verify_accountable_file_proof_with_confidence(proof: &AccountableFileProof, stored_commitment: &FileCommitment, challenge_nonce: &[u8; 32], file_public_key: &RistrettoPoint, proof_context: &[u8], confidence: f64) -> bool {
    if proof.blocks.len() != expected_challenge_count(stored_commitment, confidence) { return false; }
    verify_accountable_file_proof(proof, stored_commitment, challenge_nonce, file_public_key, proof_context)
}

pub fn decrypt_accountable_file_from_ciphertexts(public_blocks: &[AccountableCiphertextBlock], commitment: &FileCommitment, x: &Scalar) -> Result<Vec<u8>, PointEncodingError> {
    if commitment.encoding_version != ACCOUNTABLE_FILE_ENCODING_V2 { return Err(PointEncodingError::InvalidDecodedLength { len: commitment.encoding_version as usize, max: ACCOUNTABLE_FILE_ENCODING_V2 as usize }); }
    if public_blocks.len() as u64 != commitment.num_blocks { return Err(PointEncodingError::InvalidDecodedLength { len: public_blocks.len(), max: commitment.num_blocks as usize }); }
    let mut out = Vec::with_capacity(commitment.file_size as usize);
    for block in public_blocks {
        let shared = x * block.c1;
        for (c2, len) in block.c2_points.iter().zip(block.point_lengths.iter()) {
            if out.len() >= commitment.file_size as usize { break; }
            let m = *c2 - shared;
            let remaining = commitment.file_size as usize - out.len();
            let chunk_len = remaining.min(*len as usize);
            out.extend_from_slice(&decode_point_to_chunk(&m, chunk_len)?);
        }
    }
    out.truncate(commitment.file_size as usize);
    Ok(out)
}


#[cfg(test)]
mod file_binding_reversible_tests {
    use super::*;
    use rand::rngs::OsRng;
    use rand_core::RngCore;

    #[test]
    fn reversible_point_encoding_roundtrip_all_lengths() {
        let mut rng = OsRng;
        for len in 0..=REVERSIBLE_POINT_PAYLOAD_SIZE {
            for _ in 0..3 {
                let mut chunk = vec![0u8; len];
                rng.fill_bytes(&mut chunk);
                let point = encode_chunk_to_point(&chunk).expect("chunk should encode");
                let decoded = decode_point_to_chunk(&point, len).expect("point should decode");
                assert_eq!(decoded, chunk);
            }
        }
    }

    #[test]
    fn elgamal_file_roundtrip_recovers_original_bytes() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let mut file = vec![0u8; 257];
        rng.fill_bytes(&mut file);

        let (commitment, ciphertexts, _leaves) = create_file_commitment_auto(&mut rng, [7u8; 32], &file, &x);
        assert_eq!(commitment.block_size, REVERSIBLE_POINT_PAYLOAD_SIZE);
        assert_eq!(commitment.file_size, file.len() as u64);

        let recovered = decrypt_file_from_ciphertexts(&ciphertexts, &commitment, &x).expect("file should decrypt and decode");
        assert_eq!(recovered, file);
    }

    #[test]
    fn hidden_plaintext_file_proof_does_not_reveal_decrypted_points() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let file_public_key = x * RISTRETTO_BASEPOINT_POINT;
        let mut file = vec![0u8; 257];
        rng.fill_bytes(&mut file);

        let (commitment, private_blocks, leaves, witnesses) =
            create_private_file_commitment_auto(&mut rng, [11u8; 32], &file, &file_public_key);
        let challenge_nonce = commitment.nonce;
        let proof_context = b"test hidden plaintext context";
        let num_challenges = 4;
        let proof = create_private_file_proof(
            &mut rng,
            commitment.file_id,
            &private_blocks,
            &leaves,
            &commitment.root_hash,
            &challenge_nonce,
            num_challenges,
            &file_public_key,
            &witnesses,
            proof_context,
        );

        assert_eq!(proof.blocks.len(), num_challenges);
        assert!(verify_private_file_proof(&proof, &commitment, &challenge_nonce, &file_public_key, proof_context));
        let recovered = decrypt_private_file_from_ciphertexts(&private_blocks, &commitment, &x).expect("private file decrypts");
        assert_eq!(recovered, file);
    }

    #[test]
    fn dleq_same_x_proof_still_verifies_with_reversible_blocks() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let mut file = vec![0u8; 257];
        rng.fill_bytes(&mut file);

        let (commitment, ciphertexts, leaves) = create_file_commitment_auto(&mut rng, [9u8; 32], &file, &x);
        let slot_hash = Sha512::digest(b"test slot generator");
        let slot_generator = RistrettoPoint::from_uniform_bytes(&slot_hash.into());
        let tag = slot_generator * x;
        let challenge_nonce = [3u8; 32];
        let num_challenges = 4;

        let proof = create_file_proof(
            &mut rng,
            &x,
            commitment.file_id,
            &ciphertexts,
            &leaves,
            &commitment.root_hash,
            &challenge_nonce,
            num_challenges,
            &slot_generator,
            &tag,
        );

        assert!(verify_file_proof(&proof, &commitment, &challenge_nonce, &slot_generator, &tag));
    }

    #[test]
    fn challenged_blocks_encrypted_under_y_fail_when_verified_under_ebut_x() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let y = random_scalar(&mut rng);
        let x_public_key = x * RISTRETTO_BASEPOINT_POINT;
        let y_public_key = y * RISTRETTO_BASEPOINT_POINT;
        assert_ne!(x_public_key, y_public_key);

        // Malicious uploader encrypts the committed file under y, not x.
        let mut file = vec![0u8; 512];
        rng.fill_bytes(&mut file);
        let (commitment, private_blocks, leaves, witnesses) =
            create_private_file_commitment_auto(&mut rng, [42u8; 32], &file, &y_public_key);

        // Challenge/proof is then attempted against x.  This is the attack we
        // must reject: using x only for show while ciphertext equations were
        // actually generated with y.
        let challenge_nonce = [9u8; 32];
        let proof_context = b"wrong-key-accountability-test";
        let expected = expected_challenge_count(&commitment, 0.90);
        let proof_claiming_x = create_private_file_proof(
            &mut rng,
            commitment.file_id,
            &private_blocks,
            &leaves,
            &commitment.root_hash,
            &challenge_nonce,
            expected,
            &x_public_key,
            &witnesses,
            proof_context,
        );

        assert!(!verify_private_file_proof_with_confidence(
            &proof_claiming_x,
            &commitment,
            &challenge_nonce,
            &x_public_key,
            proof_context,
            0.90,
        ));

        // The same ciphertext does verify under y, proving the test is checking
        // the key binding rather than merely corrupting data.
        let proof_under_y = create_private_file_proof(
            &mut rng,
            commitment.file_id,
            &private_blocks,
            &leaves,
            &commitment.root_hash,
            &challenge_nonce,
            expected,
            &y_public_key,
            &witnesses,
            proof_context,
        );
        assert!(verify_private_file_proof_with_confidence(
            &proof_under_y,
            &commitment,
            &challenge_nonce,
            &y_public_key,
            proof_context,
            0.90,
        ));
    }

    #[test]
    fn audit_policy_50kb_small_file_is_fully_challenged() {
        let commitment = FileCommitment {
            file_id: [1u8; 32],
            root_hash: [2u8; 32],
            num_blocks: TEST_FILE_SIZE_BYTES.div_ceil(REVERSIBLE_POINT_PAYLOAD_SIZE) as u64,
            block_size: REVERSIBLE_POINT_PAYLOAD_SIZE,
            file_size: TEST_FILE_SIZE_BYTES as u64,
            encoding_version: REVERSIBLE_POINT_ENCODING_V1,
            nonce: [3u8; 32],
        };
        assert_eq!(expected_challenge_count(&commitment, 0.90), commitment.num_blocks as usize);
        assert_eq!(derive_challenge_indices(&commitment.nonce, commitment.num_blocks, commitment.num_blocks as usize).len(), commitment.num_blocks as usize);
    }

    #[test]
    fn audit_policy_large_file_is_capped_and_confidence_based() {
        let big_blocks = 1_000_000u64;
        let commitment = FileCommitment {
            file_id: [4u8; 32],
            root_hash: [5u8; 32],
            num_blocks: big_blocks,
            block_size: REVERSIBLE_POINT_PAYLOAD_SIZE,
            file_size: 10 * FULL_AUDIT_FILE_BYTES,
            encoding_version: REVERSIBLE_POINT_ENCODING_V1,
            nonce: [6u8; 32],
        };
        let expected = expected_challenge_count(&commitment, 0.90);
        assert!(expected <= MAX_AUDIT_CHALLENGES);
        assert!(expected >= 20, "90% confidence against 10% bad blocks should need about 22 samples");
    }


    #[test]
    fn accountable_packed_file_roundtrip_and_wrong_key_fails() {
        let mut rng = OsRng;
        let x = random_scalar(&mut rng);
        let y = random_scalar(&mut rng);
        let x_pk = x * RISTRETTO_BASEPOINT_POINT;
        let y_pk = y * RISTRETTO_BASEPOINT_POINT;
        let mut file = vec![0u8; TEST_FILE_SIZE_BYTES];
        rng.fill_bytes(&mut file);

        let (commitment, blocks, leaves, witnesses) =
            create_accountable_file_commitment_auto(&mut rng, [0x51u8; 32], &file, &x_pk);
        assert_eq!(commitment.encoding_version, ACCOUNTABLE_FILE_ENCODING_V2);

        let challenge_nonce = [0x42u8; 32];
        let ctx = b"accountable packed test";
        let challenge_count = expected_challenge_count(&commitment, 0.90);
        let proof = create_accountable_file_proof(
            &mut rng, commitment.file_id, &blocks, &leaves, &commitment.root_hash,
            &challenge_nonce, challenge_count, &x_pk, &witnesses, ctx,
        );
        assert!(verify_accountable_file_proof_with_confidence(&proof, &commitment, &challenge_nonce, &x_pk, ctx, 0.90));
        assert!(!verify_accountable_file_proof_with_confidence(&proof, &commitment, &challenge_nonce, &y_pk, ctx, 0.90));

        let recovered = decrypt_accountable_file_from_ciphertexts(&blocks, &commitment, &x).expect("accountable file decrypts");
        assert_eq!(recovered, file);
    }

}
