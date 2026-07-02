use ff::Field; // FIX: Gives access to BlsScalar::ZERO
use blstrs::Scalar as BlsScalar;
use curve25519_dalek_ng::scalar::Scalar as RistrettoScalar;
use ff::PrimeField;
use num_bigint::BigUint;

pub fn biguint_to_ristretto_scalar(x: &BigUint) -> RistrettoScalar {
    let q = BigUint::parse_bytes(b"1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16).unwrap();
    let reduced = x % &q;
    let mut array = [0u8; 32];
    let bytes_le = reduced.to_bytes_le();
    array[..bytes_le.len().min(32)].copy_from_slice(&bytes_le[..bytes_le.len().min(32)]);
    RistrettoScalar::from_bytes_mod_order(array)
}

pub fn biguint_to_bls_scalar(x: &BigUint) -> BlsScalar {
    let r = BigUint::parse_bytes(b"73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16).unwrap();
    let reduced = x % &r;
    let mut array = [0u8; 32];
    let bytes_le = reduced.to_bytes_le();
    array[..bytes_le.len().min(32)].copy_from_slice(&bytes_le[..bytes_le.len().min(32)]);
    BlsScalar::from_repr_vartime(array).unwrap_or(BlsScalar::ZERO)
}
