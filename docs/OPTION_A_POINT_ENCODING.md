# Option A: Accountable point-ElGamal with bounded proof expansion

This package uses the point-ElGamal accountable audit path rather than the earlier header-only byte-ECIES path.

## What is enforced

For each file chunk, the public encrypted block is:

```text
X_file = x * G
C1_i   = r_i * G
C2_i   = M_i + r_i * X_file
K_i    = M_i + s_i * H
```

The challenge proof verifies, for sampled blocks only:

```text
C1_i       = r_i * G
C2_i - K_i = r_i * X_file - s_i * H
```

The same-x bridge separately proves that `X_file = x * G` uses the same hidden `x` as the EBUT spend/refresh token commitment. If a sampled block was encrypted under `Y = y * G` while the file statement uses `X_file = x * G`, the challenged equation fails unless `x = y`.

## Encoding choice and size

Each point plaintext carries 24 payload bytes. Each public encrypted block stores three compressed Ristretto points:

```text
C1_i: 32 bytes
C2_i: 32 bytes
K_i : 32 bytes
Total: 96 bytes per 24 plaintext bytes = 4.0x public encrypted storage
```

This meets the requested hard ceiling of not exceeding 4x for the accountable point-ElGamal representation. A 2x–3x version would require either a larger guaranteed reversible point encoding or a heavier byte-cipher ZK circuit; the 24-byte point payload is the conservative reliable setting.

## Encoding fix

The reversible point encoder keeps the payload in the first 24 bytes of the canonical compressed Ristretto encoding and searches over a hash-derived 8-byte suffix:

```text
compressed[0..24]  = payload
compressed[24..32] = SHA512(domain, payload, counter)[0..8]
```

The older sequential-counter suffix caused `NoValidEncoding` failures on random file bytes. The hash-derived suffix makes the suffix search behave like a randomized 64-bit search space while preserving trivial decoding from the canonical compressed point.

## Challenge model

The whole file is encrypted and committed first. The server then supplies a random challenge nonce. Small files up to 100 KiB are fully challenged. Larger files use capped random sampling at the configured confidence level.


## Encoding fix applied

The reversible point encoder now bit-packs payload bits starting at compressed bit 1 and leaves compressed bit 0 fixed to zero. This matters because Ristretto decoding rejects negative encodings, and directly copying arbitrary file bytes into bit 0 made many payloads impossible to encode. The high non-payload bits are hash-derived from `(payload, counter)`, so the encoder searches a large random-looking suffix space while decoding remains exact.
