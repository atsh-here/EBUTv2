# EBUT Storage Integrated Codebase

This repository integrates:

- non-transferable EBUT tokens,
- EBUT epoch rate limiting,
- expiry through a unique per-user Unix `Emax`,
- revocation through signed gap non-membership over hidden `Emax`,
- reversible Ristretto ElGamal file binding,
- BLS12-381 ↔ Ristretto same-`x` equality for upload accountability.

## Important design

Use one canonical ownership secret:

```text
x = CanonicalX, 248-bit integer
```

Embed it into both worlds:

```text
x_BLS       -> EBUT/BBS+ token messages
x_Ristretto -> file-binding ElGamal/DLEQ
```

`Emax` is a unique Unix timestamp per user. It is hidden in EBUT proofs and used for both expiry and blacklist revocation.

## Main modules

- `master_mint.rs`: blind master minting on `(x, cmax, Emax)`.
- `epoch_refresh.rs`: EBUT refresh, epoch nullifier, expiry proof, BLS x commitment.
- `spend.rs`: non-transferable spend/refund, balance proof, spend-time expiry proof, BLS x commitment.
- `revocation.rs`: signed-gap non-membership wrappers for hidden `Emax`.
- `file_binding.rs`: reversible Ristretto ElGamal file binding.
- `same_x_bridge.rs`: cross-curve equality proof for `x`.
- `upload.rs`: EBUT spend + revocation + file binding + same-x composition.

## Removed from old NTAT

The old NTAT `rate_limit.rs`, slot generators, `RateLimitState`, `RateLimitProof`, and `used_tags` are not used. EBUT replaces them.

## Build note

This sandbox did not include `cargo` or `rustc`, so I could not run the compiler here. Run:

```bash
cargo check
cargo test
```

in a local Rust environment before treating this as working code.


## compile-fix patch

This package includes fixes for the first `cargo check --all-features` errors: Redis `set_ex` TTL type, `Debug` derives for upload structs, and removal of mixed Dalek Pedersen generator use from `v3_zkp/generators.rs`.

## Latest hardening pass

See `docs/SECURITY_OPTIMIZATION_PATCHES.md` for the security/optimization pass:
context-bound revocation gaps, dynamic 32/64-bit Bulletproof selection, enforced
file challenge counts, verifier-derived file-binding generators, same-x statement
validation, and server nonce/epoch edge fixes.

## Accountable challenged file encryption patch

The file layer now uses point-ElGamal accountability for challenged blocks:

```text
X_file = xG
C1_i = r_iG
C2_i = M_i + r_iX_file
K_i  = M_i + s_iH
```

The upload verifier binds `X_file` to the EBUT hidden `x` through the same-x bridge and verifies challenged ciphertext blocks with the hidden-plaintext proof.  If a user encrypts challenged blocks under a different key `y`, verification under EBUT `x` fails.  See `docs/ACCOUNTABLE_CHALLENGE_FILE_ENCRYPTION.md`.


## Latest Option A accountable encoding patch

The file layer now uses accountable challenged point-ElGamal with 24-byte payloads per Ristretto plaintext point and a hash-derived reversible suffix search. This keeps public encrypted storage at exactly 4x of plaintext bytes for the point-ElGamal block representation and makes the previous `NoValidEncoding` failures much less likely. See `docs/OPTION_A_POINT_ENCODING.md`.


## Encoding fix applied

The reversible point encoder now bit-packs payload bits starting at compressed bit 1 and leaves compressed bit 0 fixed to zero. This matters because Ristretto decoding rejects negative encodings, and directly copying arbitrary file bytes into bit 0 made many payloads impossible to encode. The high non-payload bits are hash-derived from `(payload, counter)`, so the encoder searches a large random-looking suffix space while decoding remains exact.

## Option 1 Elligator file-binding patch

This tree adds the new cache-free Option 1 file-binding path:

- `src/ristretto_elligator_codec.rs`
- `src/option1_file_binding.rs`
- `docs/OPTION1_ELLIGATOR_FILE_BINDING.md`

Use this new path instead of the old compressed-Ristretto suffix-search file binding.

The new path uses fresh per-file bases `B_f`, unlinkable file public keys `X_f=xB_f`, 31-byte payload points, 3-bit Ristretto inverse selectors, and encrypted selector metadata.

The production codec is feature-gated behind `external_elligator_codec` and expects a real external Ristretto/Elligator implementation. Without that feature it fails closed with `ExternalCodecUnavailable`.


## Option 1 external Elligator codec build fix

The native Ristretto/Elligator codec is no longer tied to a Cargo feature, so
`cargo test --all-features` will not fail by trying to link `-lristretto_elgamal`
on machines where the native library is not installed.

To enable the real codec:

```bash
sudo apt-get install -y build-essential git libssl-dev
./scripts/install_libristretto_elgamal.sh
export EBUT_RISTRETTO_ELGAMAL_LIB_DIR="/path/printed/by/script"
cargo clean
cargo test --all-features
```

Without that environment variable, the Option 1 codec fails closed with
`ExternalCodecUnavailable`; it does not use a fake reverse cache or suffix
search fallback.


### Option 1 external codec build fix

The external Ristretto/Elligator install script now patches the pinned upstream
Makefile by removing `-Werror`, builds only `make lib`, and creates
`build/lib/libristretto_elgamal.a`.  Export:

```bash
export EBUT_RISTRETTO_ELGAMAL_LIB_DIR="$PWD/vendor/libristretto-elgamal/build/lib"
```

before running codec-enabled tests.

## Non-transferable Emax revocation

This tree now includes a signed-gap non-revocation layer for hidden `Emax` values. The server sorts a blacklist of revoked `Emax` handles, signs the open gaps, and the client proves that the `Emax` carried in the master/daily/refund token lies inside one signed gap. See `docs/NONTRANSFERABLE_EMAX_REVOCATION_INTEGRATION.md`.
