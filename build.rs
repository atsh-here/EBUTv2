use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=EBUT_RISTRETTO_ELGAMAL_LIB_DIR");
    println!("cargo:rerun-if-env-changed=EBUT_RISTRETTO_ELGAMAL_INCLUDE_DIR");
    println!("cargo:rustc-check-cfg=cfg(ebut_external_elligator_codec)");

    // Important: do NOT link libristretto_elgamal just because the user runs
    // `cargo test --all-features`.  The external codec is enabled only when
    // the native library path is explicitly supplied.  This keeps all normal
    // tests/builds link-clean while preserving fail-closed behavior for the
    // Option 1 codec when the native library is not installed.
    if let Ok(lib_dir) = env::var("EBUT_RISTRETTO_ELGAMAL_LIB_DIR") {
        let lib_dir = PathBuf::from(lib_dir);
        if lib_dir.exists() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            println!("cargo:rustc-link-lib=static=ristretto_elgamal");
            // The pinned C implementation uses OpenSSL SHA routines and OpenMP.
            // Keep these links here rather than in source-level #[link] attrs so
            // normal `cargo test --all-features` does not try to link native code.
            println!("cargo:rustc-link-lib=dylib=crypto");
            println!("cargo:rustc-link-lib=dylib=ssl");
            let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
            if target_os == "linux" {
                println!("cargo:rustc-link-lib=dylib=gomp");
            }
            println!("cargo:rustc-cfg=ebut_external_elligator_codec");
        }
    }
}
