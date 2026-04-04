use std::env;
use std::path::PathBuf;

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let longfellow_dir = manifest_dir
        .parent()
        .unwrap() // crates/
        .parent()
        .unwrap() // workspace root
        .join("vendor/longfellow-zk");

    let lib_dir = longfellow_dir.join("lib");

    // Build Longfellow via CMake — target only mdoc_static to save time/memory
    let dst = cmake::Config::new(&lib_dir)
        .define("CMAKE_BUILD_TYPE", "Release")
        .build_target("mdoc_static")
        .very_verbose(false)
        // Limit parallelism to avoid OOM on 32GB machines
        .env("CMAKE_BUILD_PARALLEL_LEVEL", "4")
        .build();

    let build_dir = dst.join("build");

    // Link the static library
    println!(
        "cargo:rustc-link-search=native={}/circuits/mdoc",
        build_dir.display()
    );
    println!("cargo:rustc-link-lib=static=mdoc_static");

    // Link system dependencies that Longfellow needs
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=ssl");
    println!("cargo:rustc-link-lib=dylib=crypto");
    println!("cargo:rustc-link-lib=dylib=zstd");
    println!("cargo:rustc-link-lib=dylib=z");

    // Only rebuild if the Longfellow source changes
    println!("cargo:rerun-if-changed={}", lib_dir.display());

    // Generate Rust bindings from a C-only wrapper header
    // (avoids C++ includes that break bindgen's libclang)
    let wrapper = manifest_dir.join("wrapper.h");

    let bindings = bindgen::Builder::default()
        .header(wrapper.to_str().unwrap())
        .generate()
        .expect("failed to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("failed to write bindings");
}
