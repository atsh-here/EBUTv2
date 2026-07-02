# Hidden-plaintext file proof patch

The previous reversible file proof revealed `decrypted_point` for each challenged block. That proves correctness, but for reversible encoding it leaks the challenged plaintext-equivalent Ristretto point.

This patch adds a private file proof that keeps every `M_i` hidden.

For each encrypted block, the client publishes:

```text
C1_i = r_i G
C2_i = M_i + r_i X_file
K_i  = M_i + s_i H_file_commit
```

where:

- `M_i` is the reversible Ristretto encoding of the plaintext chunk.
- `X_file = x G` is the ElGamal public key.
- `x` is linked to the hidden EBUT secret through `same_x_bridge`.
- `K_i` is a perfectly hiding commitment to `M_i`.

For challenged blocks, the proof no longer sends `M_i`. Instead it proves knowledge of `r_i` and `s_i` such that:

```text
C1_i       = r_i G
C2_i - K_i = r_i X_file - s_i H_file_commit
```

The implementation batches challenged blocks using Fiat-Shamir random linear combination, so one proof verifies all sampled blocks:

```text
sum rho_i C1_i              = R G
sum rho_i (C2_i - K_i)      = R X_file + T H_file_commit
```

This is much faster than a general SNARK and uses only Ristretto group operations. It hides `M_i`, `x`, `r_i`, and `s_i`.

## What it proves

It proves sampled ciphertexts are consistent with hidden plaintext commitments and encrypted under `X_file`, and upload verification checks `X_file = xG` for the same EBUT hidden `x`.

## What it cannot prove by itself

No non-interactive proof can prove that an encrypted hidden file has some external semantic meaning unless that meaning is also committed publicly. This patch commits to hidden chunks through `K_i` and the Merkle root. It does not reveal bytes and does not prove arbitrary predicates about the bytes. For byte-level predicates, a heavier ZK circuit is still required.
