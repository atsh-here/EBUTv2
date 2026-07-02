# Integration Audit

This file supersedes the older draft audit. See `FULL_CODEBASE_AUDIT.md` for the current detailed status.

Current package status:

- EBUT rate limiting is retained as the core; old NTAT rate limiting is removed.
- Daily/refund tokens are non-transferable because they carry hidden `x`.
- Refresh and spend both prove `now_unix <= Emax` with 64-bit BEQ/range proofs.
- Revocation uses signed gaps over hidden `Emax` and is tied to EBUT Emax commitments.
- Upload verifies EBUT spend, reversible file binding, same-`x` bridge, and optionally revocation.
- The same-x bridge connects `spend_proof.x_bls_commitment` to the Ristretto file-binding tag.

Not run here:

- `cargo check`
- `cargo test`

The sandbox does not include Rust tooling.
