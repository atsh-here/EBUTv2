//! EBUT full-stack micro/flow benchmark runner.
//!
//! Run with:
//!   cargo run --release --all-features --bin benchmarks -- --file-size 51200
//!
//! This is intentionally dependency-light. It prints per-stage wall-clock
//! timings and approximate/wire sizes so slow spots are visible without needing
//! Criterion setup.

use std::time::{Duration, Instant};

use blstrs::{G1Projective, Scalar as BlsScalar};
use curve25519_dalek_ng::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar as RistrettoScalar;
use rand::rngs::OsRng;
use rand_core::{CryptoRng, RngCore};

use ebut_storage_integrated::batched_eq::BatchedEqualityProof;
use ebut_storage_integrated::epoch_refresh::{verify_refresh, RefreshProof, RefreshProver};
use ebut_storage_integrated::file_binding::{
    create_accountable_file_commitment_auto, create_accountable_file_proof,
    expected_challenge_count, verify_accountable_file_proof_with_confidence,
    AccountableFileProof, FileCommitment, ACCOUNTABLE_POINT_PAYLOAD_SIZE,
    ACCOUNTABLE_POINTS_PER_BLOCK, ACCOUNTABLE_PACKED_BLOCK_PAYLOAD_SIZE,
};
use ebut_storage_integrated::hash::compute_h_ctx;
use ebut_storage_integrated::master_mint::{MasterMintClient, MasterMintServer};
use ebut_storage_integrated::same_x_bridge::{CanonicalX, SameXProof, SameXStatement};
use ebut_storage_integrated::setup::{Generators, ServerKeys};
use ebut_storage_integrated::spend::{verify_spend, SpendProof, SpendProver};
use ebut_storage_integrated::types::Scalar;
use ebut_storage_integrated::{BbsSignature, Result};

const DEFAULT_FILE_SIZE: usize = 50 * 1024;
const DEFAULT_CONFIDENCE: f64 = 0.90;

fn now<T>(label: &str, f: impl FnOnce() -> T) -> (T, Duration) {
    let start = Instant::now();
    let out = f();
    let elapsed = start.elapsed();
    println!("{:<42} {:>12.3} ms", label, elapsed.as_secs_f64() * 1000.0);
    (out, elapsed)
}

fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> RistrettoScalar {
    let mut bytes = [0u8; 64];
    rng.fill_bytes(&mut bytes);
    RistrettoScalar::from_bytes_mod_order_wide(&bytes)
}

fn parse_file_size() -> usize {
    let mut args = std::env::args().skip(1);
    let mut size = DEFAULT_FILE_SIZE;
    while let Some(arg) = args.next() {
        if arg == "--file-size" {
            if let Some(v) = args.next() {
                size = v.parse::<usize>().expect("--file-size must be bytes");
            }
        }
    }
    size
}

fn beq_size(p: &BatchedEqualityProof) -> usize { p.to_bytes().len() }

fn refresh_proof_size(p: &RefreshProof) -> usize {
    // Compressed estimate: 15 G1 points + 10 BLS scalars + one BEQ proof.
    15 * 48 + 10 * 32 + beq_size(&p.batched_eq)
}

fn spend_proof_size(p: &SpendProof) -> usize {
    // Compressed estimate: 17 G1 points + 12 scalar-ish fields + two BEQ proofs
    // + small public integers. Keep this explicit so proof-size changes show up.
    17 * 48 + 12 * 32 + beq_size(&p.batched_eq) + beq_size(&p.expiry_eq) + 4 + 4 + 8
}

fn same_x_proof_size(p: &SameXProof) -> usize {
    48 + 32 + 16 + p.z_x_le.len() + 32 + 32
}

fn private_file_public_ciphertext_size(commitment: &FileCommitment) -> usize {
    // Accountable packed storage/proof carries one C1 plus C2 and K for each
    // packed plaintext point.  This is exact for full blocks and a small
    // overestimate for the final partial block.
    commitment.num_blocks as usize * (32 + ACCOUNTABLE_POINTS_PER_BLOCK * 64)
}

fn private_file_proof_size(proof: &AccountableFileProof) -> usize {
    bincode::serialize(proof).expect("PrivateFileProof should serialize").len()
}

fn main() {
    if let Err(e) = run() {
        eprintln!("benchmark failed: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let file_size = parse_file_size();
    let mut rng = OsRng;

    println!("\nEBUT integrated benchmark");
    println!("file_size_bytes: {file_size}");
    println!("point_payload_bytes_per_point: {ACCOUNTABLE_POINT_PAYLOAD_SIZE}");
    println!("points_per_audit_block: {ACCOUNTABLE_POINTS_PER_BLOCK}");
    println!("payload_bytes_per_audit_block: {ACCOUNTABLE_PACKED_BLOCK_PAYLOAD_SIZE}");
    println!("confidence: {DEFAULT_CONFIDENCE:.2}\n");

    let (generators, _) = now("setup: Generators::new", Generators::new);
    let (keys, _) = now("setup: ServerKeys::generate", || ServerKeys::generate(&mut rng));
    let h_ctx = compute_h_ctx("bench-app", &keys.pk_master, &keys.pk_daily, &generators);

    let c_max = 100u32;
    let e_max = 5_000_000_000u64;
    let epoch = 1000u32;
    let now_unix = 1_700_000_000u64;

    let ((master_client, mint_req), _) = now("master: client begin + PoK", || {
        MasterMintClient::begin(&mut rng, c_max, e_max, &generators, h_ctx)
    });
    let canonical_x: CanonicalX = master_client.canonical_x;
    let k_sub = master_client.k_sub;

    let ((a_sub, e_sub, s_prime_sub), _) = now("master: server issue", || {
        MasterMintServer::issue(&mut rng, &mint_req, c_max, e_max, &generators, &keys, h_ctx)
            .expect("master issue")
    });
    let master_sig = master_client.finalize(a_sub, e_sub, s_prime_sub);

    let ((refresh_client, refresh_proof), _) = now("refresh: prove", || {
        RefreshProver::prove(
            &mut rng, &master_sig, k_sub, c_max, e_max, epoch, now_unix,
            &generators, &keys.pk_master, h_ctx,
        ).expect("refresh prove")
    });
    let (refresh_response, _) = now("refresh: verify + issue daily", || {
        verify_refresh(&refresh_proof, epoch, now_unix, &generators, &keys.pk_master, &keys, h_ctx, &mut rng)
            .expect("refresh verify")
    });
    let (daily_sig, k_daily) = refresh_client.finalize(refresh_response);

    let nonce = [0xAAu8; 16];
    let ((spend_client, spend_proof), _) = now("spend: prove", || {
        SpendProver::prove(
            &mut rng, &daily_sig, k_sub, k_daily, c_max, epoch, e_max, now_unix,
            30, &nonce, &generators, &keys.pk_daily, h_ctx,
        ).expect("spend prove")
    });
    let (_spend_response, _) = now("spend: verify + issue refund", || {
        verify_spend(&spend_proof, epoch, now_unix, &nonce, &generators, &keys.pk_daily, &keys, h_ctx, &mut rng)
            .expect("spend verify")
    });
    std::hint::black_box(spend_client);

    let x_rist = canonical_x.to_ristretto_scalar();
    let file_public_key = x_rist * RISTRETTO_BASEPOINT_POINT;
    let file_data: Vec<u8> = (0..file_size).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7)).collect();

    let ((file_commitment, private_blocks, leaves, witnesses), enc_time) = now("file: encrypt WHOLE file", || {
        create_accountable_file_commitment_auto(&mut rng, [0x44u8; 32], &file_data, &file_public_key)
    });
    assert_eq!(private_blocks.len() as u64, file_commitment.num_blocks, "every block must be encrypted");
    assert_eq!(file_commitment.file_size, file_size as u64, "file_size must commit to the whole file");

    let challenge_count = expected_challenge_count(&file_commitment, DEFAULT_CONFIDENCE);
    println!("{:<42} {:>12}", "file: total encrypted blocks", file_commitment.num_blocks);
    println!("{:<42} {:>12}", "file: challenged blocks", challenge_count);

    let file_challenge_nonce = [0x77u8; 32];
    let proof_context = b"bench hidden-M file proof context";
    let (file_proof, proof_time) = now("file: accountable proof create", || {
        create_accountable_file_proof(
            &mut rng,
            file_commitment.file_id,
            &private_blocks,
            &leaves,
            &file_commitment.root_hash,
            &file_challenge_nonce,
            challenge_count,
            &file_public_key,
            &witnesses,
            proof_context,
        )
    });
    let (file_ok, verify_time) = now("file: accountable proof verify", || {
        verify_accountable_file_proof_with_confidence(
            &file_proof,
            &file_commitment,
            &file_challenge_nonce,
            &file_public_key,
            proof_context,
            DEFAULT_CONFIDENCE,
        )
    });
    assert!(file_ok, "private file proof must verify");

    let r_bls = Scalar::rand(&mut rng);
    let bls_x_commitment = generators.h[1] * k_sub.0 + generators.h[0] * r_bls.0;
    let same_x_statement = SameXStatement {
        bls_x_base: generators.h[1],
        bls_blind_base: generators.h[0],
        bls_x_commitment,
        ristretto_x_base: RISTRETTO_BASEPOINT_POINT,
        ristretto_blind_base: RistrettoPoint::default(),
        ristretto_x_commitment: file_public_key,
    };
    let (same_x_proof, _) = now("same-x: prove EBUT x == file x", || {
        SameXProof::prove(
            &mut rng,
            b"bench same-x",
            canonical_x,
            r_bls.0,
            RistrettoScalar::from(0u64),
            &same_x_statement,
        ).expect("same-x prove")
    });
    let (_, _) = now("same-x: verify", || {
        same_x_proof.verify(b"bench same-x", &same_x_statement).expect("same-x verify")
    });

    println!("\nSizes");
    println!("{:<42} {:>12} bytes", "refresh proof approx", refresh_proof_size(&refresh_proof));
    println!("{:<42} {:>12} bytes", "spend proof approx", spend_proof_size(&spend_proof));
    println!("{:<42} {:>12} bytes", "same-x proof approx", same_x_proof_size(&same_x_proof));
    println!("{:<42} {:>12} bytes", "accountable file proof serialized", private_file_proof_size(&file_proof));
    println!("{:<42} {:>12} bytes", "public encrypted file storage", private_file_public_ciphertext_size(&file_commitment));

    println!("\nThroughput");
    let mb = file_size as f64 / (1024.0 * 1024.0);
    println!("{:<42} {:>12.3} MiB/s", "file encryption throughput", mb / enc_time.as_secs_f64());
    println!("{:<42} {:>12.3} blocks/s", "proof creation challenged-block rate", challenge_count as f64 / proof_time.as_secs_f64());
    println!("{:<42} {:>12.3} blocks/s", "proof verification challenged-block rate", challenge_count as f64 / verify_time.as_secs_f64());

    println!("\nPolicy check");
    if file_commitment.file_size <= ebut_storage_integrated::file_binding::FULL_AUDIT_FILE_BYTES {
        assert_eq!(challenge_count, file_commitment.num_blocks as usize);
        println!("small-file policy: full challenge confirmed");
    } else {
        println!("large-file policy: statistical challenge confirmed");
    }

    Ok(())
}
