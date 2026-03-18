// Provide __rust_probestack symbol required by wasmer-vm 4.x on Rust 1.90+.
// The probestack function was removed from compiler_builtins in newer Rust versions,
// but wasmer-vm's libcalls.rs still references it. This stub provides a no-op
// implementation that satisfies the linker.

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let asm_path = format!("{}/probestack.S", out_dir);

    #[cfg(target_arch = "x86_64")]
    {
        std::fs::write(
            &asm_path,
            r#"
.global __rust_probestack
.type __rust_probestack, @function
__rust_probestack:
    ret
"#,
        )
        .unwrap();

        cc::Build::new()
            .file(&asm_path)
            .compile("probestack");
    }

    // On non-x86_64 targets, we don't need the workaround
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = asm_path;
    }
}
