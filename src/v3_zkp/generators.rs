use blstrs::{G1Affine, G2Affine, G2Prepared, G2Projective};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use group::{Curve, Group};
use sha2::{Digest, Sha512};
use std::sync::OnceLock;

use crate::setup::Generators;

static RISTRETTO_GV: OnceLock<RistrettoPoint> = OnceLock::new();
pub fn ristretto_gv() -> RistrettoPoint {
    *RISTRETTO_GV.get_or_init(|| {
        let h = Sha512::digest(b"EBUT:V3:Ristretto:GV");
        RistrettoPoint::from_uniform_bytes(&h.into())
    })
}

static RISTRETTO_G1: OnceLock<RistrettoPoint> = OnceLock::new();
pub fn ristretto_g1() -> RistrettoPoint {
    *RISTRETTO_G1.get_or_init(|| {
        let h = Sha512::digest(b"EBUT:V3:Ristretto:G1");
        RistrettoPoint::from_uniform_bytes(&h.into())
    })
}

static BLS_G1_AFFINE: OnceLock<G1Affine> = OnceLock::new();
pub fn bls_g1_affine() -> G1Affine {
    *BLS_G1_AFFINE.get_or_init(|| {
        // Use the same EBUT value base as the signed Emax commitment.
        // This lets the revocation gap proof consume C_Emax = Emax*h5 + r*h0
        // directly from RefreshProof/SpendProof instead of an unrelated BLS commitment.
        Generators::new().h[5].to_affine()
    })
}

static BLS_H1_AFFINE: OnceLock<G1Affine> = OnceLock::new();
pub fn bls_h1_affine() -> G1Affine {
    *BLS_H1_AFFINE.get_or_init(|| {
        // Same EBUT blinding base h0.
        Generators::new().h[0].to_affine()
    })
}

static NEG_G2_PREPARED: OnceLock<G2Prepared> = OnceLock::new();
pub fn neg_g2_prepared() -> &'static G2Prepared {
    NEG_G2_PREPARED.get_or_init(|| G2Prepared::from(-G2Affine::from(G2Projective::generator())))
}
