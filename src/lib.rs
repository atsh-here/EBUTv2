//! EBUT + reversible NTAT file binding integration draft.
//!
//! This tree keeps EBUT's master/refresh/spend flow and adds the pieces taken
//! from NTAT that still fit: reversible Ristretto ElGamal file binding and
//! batch-DLEQ proof helpers. Old NTAT rate limiting is deliberately not exported.

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod types;
pub mod hash;
pub mod msm;
pub mod setup;
pub mod commitments;
pub mod serde_utils;
#[cfg(feature = "std")]
pub mod bbs_proof;
#[cfg(feature = "std")]
pub mod batched_eq;
#[cfg(feature = "std")]
pub mod master_mint;
#[cfg(feature = "std")]
pub mod epoch_refresh;
#[cfg(feature = "std")]
pub mod spend;
#[cfg(feature = "std")]
pub mod file_binding;
#[cfg(feature = "std")]
pub mod ristretto_elligator_codec;
#[cfg(feature = "std")]
pub mod option1_file_binding;
#[cfg(feature = "std")]
pub mod revocation;
#[cfg(feature = "std")]
pub mod same_x_bridge;
#[cfg(feature = "std")]
pub mod upload;
#[cfg(feature = "std")]
pub mod v3_zkp;
#[cfg(feature = "server")]
pub mod server;

pub use error::{ActError, Result};
pub use types::{CompressedG1, CompressedG2, HexG1, HexG2, HexScalar, Scalar};
pub use setup::{Generators, ServerKeys};
#[cfg(feature = "std")]
pub use bbs_proof::{BbsProof, BbsSignature};
pub use hash::{compute_h_ctx, hash_to_g1, hash_to_scalar};
pub use commitments::{commit, verify_bridge, verify_bridge_single_base};
#[cfg(feature = "std")]
pub use master_mint::{MasterMintClient, MasterMintRequest, MasterMintServer, ProofOfKnowledge};
#[cfg(feature = "std")]
pub use epoch_refresh::{RefreshProof, RefreshProver, RefreshResponse, verify_refresh, verify_refresh_batch};
#[cfg(feature = "std")]
pub use spend::{SpendProof, SpendProver, SpendResponse, verify_spend, verify_spend_batch};

/// Number of BBS+ message generators after non-transferability integration:
/// h0 = signature blinding, h1 = x, h2 = current token secret, h3 = balance,
/// h4 = epoch, h5 = unique Unix Emax.
pub const MESSAGE_GENERATOR_COUNT: usize = 5;

/// The current range proof size. The integrated BEQ/range layer uses 64-bit range proofs for balances, expiry deltas, and revocation gap differences.
pub const RANGE_PROOF_BITS: usize = 64;
