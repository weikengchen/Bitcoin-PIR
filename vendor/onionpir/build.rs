// Build script for the `onionpir` Rust crate.
//
// Runs the crate-local CMake project (rust/onionpir/CMakeLists.txt) with
// `-DONIONPIR_BUILD_FFI=ON` to produce `libonionpir.a`, then links it (plus
// the C++ runtime) into the crate. The FFI surface itself is declared in
// `src/lib.rs`.
//
// The CMake project, the cpp/ engine sources and this script all live inside
// the crate dir — no path here reaches outside CARGO_MANIFEST_DIR — so
// `cargo vendor` ships a self-contained, buildable crate.
//
// Re-runs when the C ABI header or any C++ source changes.

use std::env;
use std::path::PathBuf;

fn main() {
    // The crate is self-contained: CMakeLists.txt + cpp/ both live inside the
    // crate dir, so the CMake source dir IS the manifest dir. The previous
    // layout used manifest_dir.parent().parent() to reach a repo-root CMake
    // project, which broke any cargo-vendored consumer — cargo flattens a git
    // dep down to just the consumed subcrate, dropping everything above it.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());

    // Upstream gates the debug/benchmark print macros (DEBUG_PRINT,
    // PRINT_INT_ARRAY) on _BENCHMARK or _DEBUG. Plain Release leaves them
    // undefined → compile errors. Build type "Benchmark" defines _BENCHMARK
    // and uses the same -O3 -march=native flags.
    let dst = cmake::Config::new(&manifest_dir)
        .define("ONIONPIR_BUILD_FFI", "ON")
        .define("CMAKE_BUILD_TYPE", "Benchmark")
        .profile("Benchmark")  // tell cmake-rs not to override CMAKE_BUILD_TYPE
        .build_target("onionpir")
        .build();

    // cmake-rs runs the build in <dst>/build; the onionpir target pins its
    // ARCHIVE_OUTPUT_DIRECTORY to CMAKE_BINARY_DIR, which is exactly that dir.
    let lib_dir = dst.join("build");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=onionpir");

    // C++ runtime: libc++ on Apple (clang default), libstdc++ on Linux GCC.
    let target = env::var("TARGET").unwrap_or_default();
    if target.contains("apple") {
        println!("cargo:rustc-link-lib=dylib=c++");
    } else {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    // Re-run triggers.
    let watch = [
        manifest_dir.join("cpp/includes/onion_ffi.h"),
        manifest_dir.join("cpp/onion_ffi.cpp"),
        manifest_dir.join("CMakeLists.txt"),
    ];
    for p in &watch {
        println!("cargo:rerun-if-changed={}", p.display());
    }
    // Also rerun if anything under cpp/ changes — broader than ideal but
    // catches edits to the engine that affect the FFI's behavior.
    println!("cargo:rerun-if-changed={}", manifest_dir.join("cpp").display());
}
