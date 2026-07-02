# Full Codebase Integration Audit

## Implemented / patched

### 1. EBUT remains the rate-limit core

The old NTAT rate-limit layer is intentionally not exported. EBUT refresh computes `N_T = x * H_epoch(T)` and the server should enforce freshness through `DBepoch`. Spend/refund should be enforced through `DBspend` and nonce state.

### 2. Reversible file binding

`src/file_binding.rs` uses 28-byte reversible compressed-Ristretto encoding and ElGamal:

```text
M_i = Encode(chunk_i)
C1_i = r_i * G
C2_i = M_i + r_i * (xG)
```

The proof verifies:

```text
D_i = C2_i - M_i = x * C1_i
```

against a file-binding tag:

```text
B_file = x * H_file
```

### 3. Cross-curve same-x bridge

`src/same_x_bridge.rs` now implements a real Sigma proof that the same 248-bit canonical integer `x` opens both:

```text
C_bls  = x * G_bls + r_bls * H_bls
C_rist = x * G_rist + r_rist * H_rist
```

For file binding, `C_rist` can be the unblinded file tag `B_file = x * H_file` with zero Ristretto blinding.

This proof does not magically prove that the BLS commitment is tied to the BBS+ token. EBUT spend/refresh proof code must expose a BLS commitment to hidden `x` and prove inside the BBS+ possession proof that this commitment contains the signed hidden `x`.

### 4. Revocation wrapper

`src/revocation.rs` wraps the uploaded signed-gap proof. It treats `Emax` as the hidden blacklist value and checks:

```text
ea < Emax < eb
now <= Emax
```

The wrapper rejects gaps wider than `2^32 - 1` because the current gap proof uses 32-bit Bulletproof ranges.

### 5. Upload composition

`src/upload.rs` now verifies:

1. EBUT spend proof,
2. file Merkle/DLEQ proof,
3. same-x cross-curve proof.

It also checks that the same-x statement's Ristretto commitment matches the file-binding tag.

## Still required before production

### A. Finish non-transferable EBUT token layout in refresh/spend

Daily/refund tokens must include hidden `x` and `Emax`:

```text
DailyToken  = Sig(x, k_daily, cbal, T, Emax, policy_id)
RefundToken = Sig(x, k_next,  m,    T, Emax, policy_id)
```

The current EBUT files were only partially adapted. Re-derive and test `RefreshProof` and `SpendProof` equations for this five-message layout.

### B. Bind BLS x commitment to BBS+ hidden x

`same_x_bridge.rs` proves equality between a BLS commitment and a Ristretto tag. The EBUT proof must additionally prove that the BLS commitment opens to the same hidden `x` inside the BBS+ token. Add a bridge equation analogous to existing `verify_bridge` logic.

### C. Upgrade Unix `Emax` to u64 everywhere

The original EBUT files use `u32` for `e_max` and epochs. If `Emax` is Unix seconds, this only works safely until 2106 and only if deltas fit 32 bits. Upgrade expiry/gap BEQ to 64-bit or represent `Emax` as two 32-bit limbs.

### D. Harden v3 gap proof transcript

The uploaded gap proof still uses debug formatting for `Gt` in Fiat-Shamir. Replace that with canonical serialization before production.

### E. Run cargo tests and independent audit

This environment lacked `cargo` and `rustc`; no compilation or test execution was possible here.
