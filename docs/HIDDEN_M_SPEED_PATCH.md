# Hidden-M file proof speed patch

This patch keeps the hidden-plaintext file proof design but removes avoidable test/runtime overhead.

## Security design

For every encrypted block, the public data is:

```text
C1 = rG
C2 = M + rX
K  = M + sH
```

The proof shows, without revealing `M`, that:

```text
C1 = rG
C2 - K = rX - sH
```

The plaintext point cancels out, so the verifier learns neither the decrypted Ristretto point nor the original file chunk.

## Performance changes

- Challenge index selection is now O(k) instead of allocating and shuffling all `num_blocks`.
- Merkle paths are generated from one precomputed Merkle tree instead of rebuilding the tree for every challenged block.
- Crypto-heavy tests run with profile.test opt-level=2.
- Test file sizes/challenge counts were reduced so default `cargo test` is a fast smoke test.

For benchmarking real costs, run release tests or add dedicated benches.
