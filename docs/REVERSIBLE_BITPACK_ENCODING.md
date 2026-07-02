# Reversible bit-packed Ristretto encoding fix

The earlier accountable point-ElGamal file layer failed with `NoValidEncoding` because it copied user bytes directly into the beginning of the compressed Ristretto encoding. That is not valid: Ristretto decoding rejects encodings whose field element is negative, and in this representation that depends on the low bit. If the first payload byte had its low bit set, no suffix could ever make the encoding valid.

The fixed encoder stores 17 payload bytes by bit-packing payload bit `i` into compressed encoding bit `i + 1`, while compressed bit 0 is always zero. The high unused bits are generated from `SHA512(domain, payload, counter)` and searched until `CompressedRistretto(candidate).decompress()` succeeds and round-trips canonically.

This keeps the packed accountable design under 4x:

- 17 payload bytes per point
- 16 points per packed block = 272 plaintext bytes
- public accountable block = 1 shared `C1` + 16 `C2` + 16 `K` = 1056 bytes
- ratio = 1056 / 272 = 3.88x

The security equation is unchanged. For challenged packed blocks the proof verifies:

```text
C1 = rG
C2_j - K_j = rX_file - s_jH
```

where `X_file = xG` is linked to the EBUT hidden `x` by the same-x bridge.
