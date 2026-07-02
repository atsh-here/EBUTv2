//! Cache-free invertible Ristretto/Elligator codec interface for Option 1.
//!
//! This module deliberately does **not** use the old compressed-Ristretto
//! suffix-search encoder.  The production codec is an FFI wrapper around an
//! external audited Ristretto Elligator implementation such as
//! `oblivious-file-sharing/libristretto-elgamal`.
//!
//! Mathematical contract:
//!
//! ```text
//! m in {0,1}^248                 // 31 bytes
//! u = pack(m) in F_p, p=2^255-19 // injective, no mod reduction
//! M = Phi(u) in G_R              // total Ristretto/Elligator map
//! InvPhi(M) = {u_0,...,u_7}      // Ristretto quotient gives 8 candidates
//! tau in {0,...,7}, u_tau = u
//! Encode(m) = (M,tau)
//! Decode(M,tau) = unpack(u_tau) = m
//! ```
//!
//! The selector `tau` is only three bits.  It is file-format metadata, not a
//! process cache.  The Option 1 file-binding layer encrypts these selector bits
//! under the same ElGamal shared secret `rX_f = xC1_b`.

use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};

/// Exact byte payload encoded into one Ristretto point by the Option 1 codec.
/// 31 bytes = 248 bits, safely below the Curve25519 base-field modulus
/// `p = 2^255 - 19`.  Do not change to 32 bytes: that would require modulo
/// reduction or rejection and would destroy injectivity/totality.
pub const ELLIGATOR_PAYLOAD_BYTES: usize = 31;

/// Ristretto Elligator inverse has eight candidates, so the selector is 3 bits.
pub const ELLIGATOR_SELECTOR_BITS: usize = 3;
pub const ELLIGATOR_SELECTOR_VALUES: u8 = 8;

/// Version identifier for the audited Option 1 codec.
pub const ELLIGATOR_CODEC_VERSION: u32 = 3;

/// Errors from the invertible Ristretto codec layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElligatorCodecError {
    ChunkTooLarge { len: usize, max: usize },
    InvalidSelector { selector: u8 },
    InvalidPointEncoding,
    ExternalCodecUnavailable,
    ExternalCodecRejected,
}

/// Output of the cache-free invertible encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncodedRistrettoChunk {
    pub point: RistrettoPoint,
    /// Selector in `[0,7]` identifying the correct inverse preimage.
    pub selector: u8,
    /// Exact plaintext length for final partial chunks.
    pub len: u8,
}

/// Encode up to 31 bytes into `(M,tau)`.
pub fn encode_chunk(chunk: &[u8]) -> Result<EncodedRistrettoChunk, ElligatorCodecError> {
    if chunk.len() > ELLIGATOR_PAYLOAD_BYTES {
        return Err(ElligatorCodecError::ChunkTooLarge { len: chunk.len(), max: ELLIGATOR_PAYLOAD_BYTES });
    }
    external::encode_chunk(chunk)
}

/// Decode `(M,tau,len)` back to the original file chunk.
pub fn decode_chunk(point: &RistrettoPoint, selector: u8, len: u8) -> Result<Vec<u8>, ElligatorCodecError> {
    if selector >= ELLIGATOR_SELECTOR_VALUES { return Err(ElligatorCodecError::InvalidSelector { selector }); }
    if (len as usize) > ELLIGATOR_PAYLOAD_BYTES {
        return Err(ElligatorCodecError::ChunkTooLarge { len: len as usize, max: ELLIGATOR_PAYLOAD_BYTES });
    }
    external::decode_chunk(point, selector, len)
}

/// Pack selectors into a compact 3-bit stream.
pub fn pack_selectors(selectors: &[u8]) -> Result<Vec<u8>, ElligatorCodecError> {
    let bit_len = selectors.len() * ELLIGATOR_SELECTOR_BITS;
    let mut out = vec![0u8; (bit_len + 7) / 8];
    for (i, &sel) in selectors.iter().enumerate() {
        if sel >= ELLIGATOR_SELECTOR_VALUES { return Err(ElligatorCodecError::InvalidSelector { selector: sel }); }
        for bit in 0..ELLIGATOR_SELECTOR_BITS {
            if ((sel >> bit) & 1) == 1 {
                let bit_index = i * ELLIGATOR_SELECTOR_BITS + bit;
                out[bit_index / 8] |= 1u8 << (bit_index % 8);
            }
        }
    }
    Ok(out)
}

/// Unpack a compact 3-bit selector stream.
pub fn unpack_selectors(bytes: &[u8], count: usize) -> Result<Vec<u8>, ElligatorCodecError> {
    let need = (count * ELLIGATOR_SELECTOR_BITS + 7) / 8;
    if bytes.len() < need { return Err(ElligatorCodecError::ExternalCodecRejected); }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut sel = 0u8;
        for bit in 0..ELLIGATOR_SELECTOR_BITS {
            let bit_index = i * ELLIGATOR_SELECTOR_BITS + bit;
            if ((bytes[bit_index / 8] >> (bit_index % 8)) & 1) == 1 { sel |= 1u8 << bit; }
        }
        if sel >= ELLIGATOR_SELECTOR_VALUES { return Err(ElligatorCodecError::InvalidSelector { selector: sel }); }
        out.push(sel);
    }
    Ok(out)
}

#[cfg(not(ebut_external_elligator_codec))]
mod external {
    use super::*;

    pub(super) fn encode_chunk(_chunk: &[u8]) -> Result<EncodedRistrettoChunk, ElligatorCodecError> {
        Err(ElligatorCodecError::ExternalCodecUnavailable)
    }

    pub(super) fn decode_chunk(_point: &RistrettoPoint, _selector: u8, _len: u8) -> Result<Vec<u8>, ElligatorCodecError> {
        Err(ElligatorCodecError::ExternalCodecUnavailable)
    }
}

/// Production FFI wrapper.  Enable with:
///
/// ```text
/// EBUT_RISTRETTO_ELGAMAL_LIB_DIR=/path/to/lib cargo build
/// ```
///
/// and link against `libristretto_elgamal.a` from
/// `oblivious-file-sharing/libristretto-elgamal`.
#[cfg(ebut_external_elligator_codec)]
#[allow(unsafe_code)]
mod external {
    use super::*;
    use core::ffi::{c_int, c_uchar};

    #[cfg(target_pointer_width = "64")]
    type Word = u64;
    #[cfg(target_pointer_width = "32")]
    type Word = u32;

    #[cfg(target_pointer_width = "64")]
    type Mask = u64;
    #[cfg(target_pointer_width = "32")]
    type Mask = u32;

    #[repr(C, align(32))]
    #[derive(Clone, Copy)]
    struct Gf25519 {
        // RISTRETTO255_FIELD_LIMBS = 40 / sizeof(word_t)
        limb: [Word; 40 / core::mem::size_of::<Word>()],
    }

    #[repr(C, align(32))]
    #[derive(Clone, Copy)]
    struct CPoint {
        x: Gf25519,
        y: Gf25519,
        z: Gf25519,
        t: Gf25519,
    }

    // Native library linkage is emitted by build.rs only when
    // EBUT_RISTRETTO_ELGAMAL_LIB_DIR is set.  Do not put #[link] here,
    // otherwise rustc may try to find a dynamic lib even when build.rs has
    // already selected the static archive.
    extern "C" {
        fn ristretto_elgamal_encode_single_message(
            p: *mut CPoint,
            ser: *const c_uchar,
            sgn_ed_T: *mut Mask,
            sgn_altx: *mut Mask,
            sgn_s: *mut Mask,
        );
        fn ristretto_elgamal_decode_single_message(
            p: *const CPoint,
            ser: *mut c_uchar,
            sgn_ed_T: Mask,
            sgn_altx: Mask,
            sgn_s: Mask,
        );
        fn Serialize_Malicious(out: *mut c_uchar, input: *mut CPoint, num_of_points: c_int);
        fn Deserialize_Malicious(out: *mut CPoint, input: *mut c_uchar, num_of_points: c_int) -> c_int;
    }

    fn payload_to_ser(chunk: &[u8]) -> [u8; 32] {
        // Shift 248 payload bits into bits 1..248.  This satisfies the external
        // codec requirement: ser[0] low bit = 0 and ser[31] high bit = 0.
        let mut ser = [0u8; 32];
        for i in 0..(chunk.len() * 8) {
            let bit = (chunk[i / 8] >> (i % 8)) & 1;
            if bit == 1 {
                let out_bit = i + 1;
                ser[out_bit / 8] |= 1u8 << (out_bit % 8);
            }
        }
        ser
    }

    fn ser_to_payload(ser: &[u8; 32], len: u8) -> Vec<u8> {
        let mut out = vec![0u8; len as usize];
        for i in 0..((len as usize) * 8) {
            let in_bit = i + 1;
            let bit = (ser[in_bit / 8] >> (in_bit % 8)) & 1;
            if bit == 1 { out[i / 8] |= 1u8 << (i % 8); }
        }
        out
    }

    pub(super) fn encode_chunk(chunk: &[u8]) -> Result<EncodedRistrettoChunk, ElligatorCodecError> {
        if chunk.len() > ELLIGATOR_PAYLOAD_BYTES {
            return Err(ElligatorCodecError::ChunkTooLarge { len: chunk.len(), max: ELLIGATOR_PAYLOAD_BYTES });
        }
        let ser = payload_to_ser(chunk);
        let mut point = CPoint {
            x: Gf25519 { limb: [0 as Word; 40 / core::mem::size_of::<Word>()] },
            y: Gf25519 { limb: [0 as Word; 40 / core::mem::size_of::<Word>()] },
            z: Gf25519 { limb: [0 as Word; 40 / core::mem::size_of::<Word>()] },
            t: Gf25519 { limb: [0 as Word; 40 / core::mem::size_of::<Word>()] },
        };
        let mut sgn_ed_t: Mask = 0;
        let mut sgn_altx: Mask = 0;
        let mut sgn_s: Mask = 0;
        unsafe {
            ristretto_elgamal_encode_single_message(&mut point, ser.as_ptr(), &mut sgn_ed_t, &mut sgn_altx, &mut sgn_s);
        }
        let selector = ((sgn_ed_t != 0) as u8) | (((sgn_altx != 0) as u8) << 1) | (((sgn_s != 0) as u8) << 2);
        let mut encoded = [0u8; 32];
        unsafe { Serialize_Malicious(encoded.as_mut_ptr(), &mut point, 1); }
        let rust_point = CompressedRistretto(encoded).decompress().ok_or(ElligatorCodecError::InvalidPointEncoding)?;
        Ok(EncodedRistrettoChunk { point: rust_point, selector, len: chunk.len() as u8 })
    }

    pub(super) fn decode_chunk(point: &RistrettoPoint, selector: u8, len: u8) -> Result<Vec<u8>, ElligatorCodecError> {
        if selector >= ELLIGATOR_SELECTOR_VALUES { return Err(ElligatorCodecError::InvalidSelector { selector }); }
        if (len as usize) > ELLIGATOR_PAYLOAD_BYTES { return Err(ElligatorCodecError::ChunkTooLarge { len: len as usize, max: ELLIGATOR_PAYLOAD_BYTES }); }
        let mut encoded = point.compress().to_bytes();
        let mut cpoint = CPoint {
            x: Gf25519 { limb: [0 as Word; 40 / core::mem::size_of::<Word>()] },
            y: Gf25519 { limb: [0 as Word; 40 / core::mem::size_of::<Word>()] },
            z: Gf25519 { limb: [0 as Word; 40 / core::mem::size_of::<Word>()] },
            t: Gf25519 { limb: [0 as Word; 40 / core::mem::size_of::<Word>()] },
        };
        let ok = unsafe { Deserialize_Malicious(&mut cpoint, encoded.as_mut_ptr(), 1) };
        if ok == 0 { return Err(ElligatorCodecError::InvalidPointEncoding); }
        let sgn_ed_t: Mask = if (selector & 1) != 0 { !0 } else { 0 };
        let sgn_altx: Mask = if (selector & 2) != 0 { !0 } else { 0 };
        let sgn_s: Mask = if (selector & 4) != 0 { !0 } else { 0 };
        let mut ser = [0u8; 32];
        unsafe { ristretto_elgamal_decode_single_message(&cpoint, ser.as_mut_ptr(), sgn_ed_t, sgn_altx, sgn_s); }
        if (ser[0] & 1) != 0 || (ser[31] & 0x80) != 0 { return Err(ElligatorCodecError::ExternalCodecRejected); }
        Ok(ser_to_payload(&ser, len))
    }
}
