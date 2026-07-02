# Security and Optimization Patch Notes

This pass focuses on hardening the integrated EBUT codebase after the previous
agent only partially addressed revocation proof safety.

## Security hardening applied

1. **Revocation proof panics removed and optimized**
   - `create_non_membership_proof_timed` remains fallible.
   - Gap differences are checked before range proving.
   - Bulletproof generators are cached.
   - 32-bit revocation range proofs are used when both gap differences fit in
     `u32`; 64-bit is used only for wider gaps.

2. **Revocation gap signatures are now context-bound**
   - Added `yctx` to the gap-signing key.
   - Added `sign_interval_with_context(ea, eb, gap_ctx)`.
   - `gap_ctx` is derived from `app_id`, `policy_id`, `server_key_id`, and
     `revocation_list_version`.
   - This prevents replaying an old signed gap after the revocation list changes.

3. **Cross-curve revocation equality challenge hardened**
   - The v3 batched equality challenge now binds the full public statement:
     Ristretto commitments, BLS commitments, and prover response commitments.
   - This reduces transcript-splicing risk.

4. **File proof challenge-count enforcement**
   - Upload verification now requires the expected number of file challenges for
     `DEFAULT_FILE_AUDIT_CONFIDENCE = 0.99`.
   - A malicious client can no longer submit an empty or artificially tiny file
     proof and have it accepted by the upload verifier.

5. **File-binding generator is now verifier-derived**
   - The upload verifier recomputes the Ristretto file-binding generator from:
     `h_ctx`, epoch, time, `Emax`, file ID, root hash, file size/shape, encoding
     version, and revocation list version.
   - This prevents a client from choosing an arbitrary generator unrelated to the
     file or EBUT context.

6. **Same-x bridge statement validation**
   - Same-x proofs now reject identity bases/commitments.
   - `z_x` must be canonical little-endian and within the configured bound.

7. **Server nonce and epoch edge fixes**
   - `generate_nonce` no longer pre-stores the nonce in Redis, because
     `verify_and_consume` uses SET-if-absent semantics.
   - Previous-epoch checks no longer underflow when `current_epoch == 0`.

8. **BBS proof API no longer panics on message length mismatch**
   - Prover returns `ActError::ProtocolError` instead of using `assert!`.
   - Verifier now supports the integrated five-message layout.

## Performance optimizations applied

1. **32-bit Bulletproofs where possible**
   - The main BEQ/range proof chooses 32-bit proofs when the value fits in
     `u32`, and 64-bit only when required.
   - Spend balances are `u32`, so spend balance range proofs are now 32-bit.
   - Normal Unix expiry deltas are usually below `u32::MAX` seconds (~136 years),
     so expiry proofs are usually also 32-bit while still supporting 64-bit if a
     deployment really needs it.

2. **Cached Bulletproof/Pedersen generators**
   - Main BEQ uses cached 32-bit and 64-bit Bulletproof generator sets.
   - Revocation uses cached 32-bit and 64-bit two-party generator sets.

3. **No old NTAT rate-limit verifier**
   - EBUT remains the rate-limit source of truth. The old slot/tag `used_tags`
     layer is not reintroduced.

## Remaining production caveats

- `blstrs::Gt` does not expose canonical serialization in this dependency set.
  The gap proof still uses a marked debug serialization fallback for the target
  group transcript component. Replace this with canonical `Gt` bytes from a
  library that exposes them before production deployment.
- The reversible file proof reveals challenged decrypted Ristretto points. For a
  non-TEE verifier, this leaks challenged chunks. A fully private variant needs a
  ZK circuit proving correct decryption without revealing the plaintext point.
- This environment has no Rust toolchain, so this patch is static. Run
  `cargo check --all-features` and `cargo test --all-features -- --nocapture`
  locally.
