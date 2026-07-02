use curve25519_dalek_ng::ristretto::{CompressedRistretto, RistrettoPoint};
use serde::{Serializer, Deserializer, de};

pub mod ristretto_serde {
    use super::*;
    pub fn serialize<S>(p: &RistrettoPoint, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        s.serialize_bytes(p.compress().as_bytes())
    }
    pub fn deserialize<'de, D>(d: D) -> Result<RistrettoPoint, D::Error>
    where D: Deserializer<'de> {
        let b: [u8; 32] = serde::Deserialize::deserialize(d)?;
        CompressedRistretto(b).decompress().ok_or_else(|| de::Error::custom("Invalid RistrettoPoint"))
    }
}
