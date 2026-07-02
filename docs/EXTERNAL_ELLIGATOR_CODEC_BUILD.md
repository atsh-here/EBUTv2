# External Elligator codec build

The Option 1 file-binding code uses an invertible Ristretto/Elligator codec. It
must not use the old compressed-point suffix search or a reverse cache.

The Rust crate now fails closed unless the native codec is explicitly installed.
This avoids the previous link failure when running:

```bash
cargo test --all-features
```

because `--all-features` must not silently imply that a native C library is
present on the machine.

## Build the native codec

```bash
sudo apt-get update
sudo apt-get install -y build-essential git libssl-dev
./scripts/install_libristretto_elgamal.sh
```

The script pins upstream `oblivious-file-sharing/libristretto-elgamal` to commit:

```text
04b9219a84dda9812a72e8a184188b705daa8aeb
```

It prints the library directory. Export it:

```bash
export EBUT_RISTRETTO_ELGAMAL_LIB_DIR="/path/printed/by/script"
cargo clean
cargo test --all-features
```

When `EBUT_RISTRETTO_ELGAMAL_LIB_DIR` is set and contains
`libristretto_elgamal.a`, `build.rs` enables the internal cfg:

```text
ebut_external_elligator_codec
```

Then `src/ristretto_elligator_codec.rs` links the native functions:

```text
ristretto_elgamal_encode_single_message
ristretto_elgamal_decode_single_message
Serialize_Malicious
Deserialize_Malicious
```

## No insecure fallback

If the native codec is not linked, Option 1 encode/decode returns:

```text
ExternalCodecUnavailable
```

This is intentional. It prevents accidental use of an insecure mock encoder,
reverse cache, or compressed-Ristretto suffix search.


## Modern GCC warning fix

The pinned upstream `libristretto-elgamal` Makefile uses `-Werror`.  Newer GCC
versions can emit `-Warray-parameter` for an old declaration mismatch in
`src/f_arithmetic.c`/`src/f_field.h`; treating that warning as an error stops the
build before the static archive is produced.  The install script removes
`-Werror` in the vendored checkout and builds only `make lib`, then copies the
resulting archive to `build/lib/libristretto_elgamal.a` for EBUT's build script.

The Rust crate links this archive only when:

```bash
export EBUT_RISTRETTO_ELGAMAL_LIB_DIR="$PWD/vendor/libristretto-elgamal/build/lib"
```

Normal `cargo test --all-features` remains link-clean when that variable is not
set.
