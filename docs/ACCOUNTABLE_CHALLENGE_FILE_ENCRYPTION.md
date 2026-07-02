# Accountable challenged file encryption

This patch restores the file layer to the stronger accountable design:

```text
X_file = x * G
C1_i   = r_i * G
C2_i   = M_i + r_i * X_file
K_i    = M_i + s_i * H
```

`x` is the same hidden ownership secret that EBUT proves inside the spend/refresh token.  Upload verification uses the same-x bridge to bind EBUT's BLS commitment to `x` with the Ristretto public key `X_file = xG`.

For challenged blocks, the user proves in zero knowledge:

```text
C1_i       = r_i * G
C2_i - K_i = r_i * X_file - s_i * H
```

Because:

```text
C2_i - K_i = (M_i + r_iX_file) - (M_i + s_iH)
           = r_iX_file - s_iH
```

The server learns neither `x`, `r_i`, `s_i`, nor `M_i`, but it verifies that the challenged ciphertext blocks were formed under `X_file`.  If a user encrypts under another public key `Y = yG` and tries to pass the proof under `X_file = xG`, challenged blocks fail verification except with negligible proof-forgery probability.

## Why this fixes the “x only for show” attack

The previous byte-ECIES/header-only proof could prove that a DH header was tied to `x` while leaving the ciphertext bytes arbitrary.  That allowed a malicious uploader to generate ciphertext bytes under `y` and use `x` only for a separate show-header.

This patch puts the ciphertext body back into the group equation itself as `C2_i = M_i + r_iX_file`.  The proof statement includes `C2_i`, so using `y` changes the public equation and is caught on challenged blocks.

## Challenge policy

The whole file is encrypted and committed first.  The server then provides an unpredictable challenge nonce.

Small files at or below `FULL_AUDIT_FILE_BYTES` are fully challenged.  Larger files are sampled according to `DEFAULT_FILE_AUDIT_CONFIDENCE` and capped by `MAX_AUDIT_CHALLENGES`.

This means a large-file cheater can escape if none of the bad blocks are sampled; that is the accepted statistical audit risk.  But for any challenged bad block, the wrong-key proof fails.

## Reversible encoding

The file bytes are split into small point payloads.  Each payload is reversibly embedded into a compressed Ristretto point.  The encoder now uses 24-byte payloads with an 8-byte counter suffix, instead of the brittle 28-byte payload / 4-byte counter variant.  This keeps point-ElGamal accountability while avoiding the `NoValidEncoding` failures seen with random 28-byte prefixes.

The proof does not need to show byte-validity in zero knowledge.  The verifier only checks the group-level encryption/accountability statement for challenged blocks.  If the user later reveals a file, they can reveal/decrypt the point payloads normally.

## Accountability rule

A scalar leaked as the official file decryption key is valid only if:

```text
key * G == X_file
```

Since upload verification binds `X_file` to EBUT's hidden `x`, leaking the official scalar key reveals `x`.

A user can always leak plaintext directly; no cryptographic protocol can force plaintext leakage to reveal `x`.  What this construction enforces is that the encrypted, committed file accepted by the server is decryptable by the EBUT-bound key `x` on challenged blocks, with the configured statistical assurance.
