# Option 1: cache-free Ristretto/Elligator file binding

This patch separates the file-binding layer from EBUT and adds the new implementation path in:

- `src/ristretto_elligator_codec.rs`
- `src/option1_file_binding.rs`

The old compressed-Ristretto suffix-search encoder is not used by this new path.

## Mathematical construction

For every file/session, derive a fresh Ristretto base:

\[
B_f = H_{\mathbb G_R}(\texttt{EBUT:FileBase}\parallel app\_id\parallel policy\_id\parallel \nu_{server}\parallel \sigma_f\parallel file\_id)
\]

The file public key is unlinkable:

\[
X_f = xB_f
\]

not the linkable fixed-base key \(xG\).

Every plaintext chunk is encoded using an invertible Ristretto/Elligator codec:

\[
m\in\{0,1\}^{248},\quad u=pack(m)<2^{248}<p,
\]

\[
M=\Phi(u),\quad Inv_\Phi(M)=\{u_0,\ldots,u_7\},\quad u_\tau=u.
\]

The output is:

\[
Encode(m)=(M,\tau),\quad \tau\in\{0,\ldots,7\}.
\]

The selector \(\tau\) is 3 bits per point. The new file-binding path encrypts packed selectors under the same ElGamal block secret:

\[
Z_b=r_bX_f=xC_{1,b}.
\]

For audit block \(b\):

\[
C_{1,b}=r_bB_f,
\]

\[
C_{2,b,j}=M_{b,j}+r_bX_f,
\]

\[
K_{b,j}=M_{b,j}+s_{b,j}H_f.
\]

The challenged proof checks:

\[
C_{2,b,j}-K_{b,j}=r_bX_f-s_{b,j}H_f.
\]

This hides \(M_{b,j}\), \(x\), \(r_b\), and \(s_{b,j}\).

Decryption with the official key \(x\):

\[
M_{b,j}=C_{2,b,j}-xC_{1,b},
\]

\[
\tau_b=Dec_{H(xC_{1,b})}(selector\_ciphertext),
\]

\[
m_{b,j}=Decode(M_{b,j},\tau_{b,j}).
\]

Therefore:

\[
EncryptedFile+x\rightarrow F.
\]

## External codec requirement

A correct implementation of \(\Phi\) and \(Inv_\Phi\) is non-trivial. It must not be replaced by:

- compressed-point suffix search,
- modulo reduction of arbitrary file bytes,
- hash-to-point with a reverse cache.

This patch provides an FFI wrapper behind:

```bash
cargo build --features external_elligator_codec
```

It expects an installed/linkable `libristretto_elgamal` compatible with `oblivious-file-sharing/libristretto-elgamal`.

Without that feature, the codec returns `ExternalCodecUnavailable` instead of silently falling back to an insecure implementation.

## New API

Use:

```rust
use ebut_storage_integrated::option1_file_binding::*;
```

Main functions:

- `derive_option1_file_base(...)`
- `create_option1_file_commitment_auto(...)`
- `create_option1_file_proof(...)`
- `verify_option1_file_proof_with_confidence(...)`
- `decrypt_option1_file_from_ciphertexts(...)`

## Important status

I did not claim this is production-audited. The new code removes the fake/reverse-cache idea and implements the correct file-binding wiring, but the actual Ristretto/Elligator primitive must come from a real audited codec implementation.
