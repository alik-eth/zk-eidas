//! Pre-generate Longfellow circuit cache files for all attribute counts (1-4).
//! Usage: generate-circuits <output-dir>

fn main() {
    let dir = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: generate-circuits <output-dir>");
        std::process::exit(1);
    });
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();

    for n in 1..=4usize {
        let path = dir.join(format!("mdoc-{n}attr.bin"));
        eprint!("[generate] Circuit {n}-attr... ");
        let t0 = std::time::Instant::now();
        let circuit = longfellow_sys::mdoc::MdocCircuit::generate(n)
            .unwrap_or_else(|e| panic!("circuit {n} failed: {e}"));
        circuit.save(&path).unwrap();
        let size = std::fs::metadata(&path).unwrap().len();
        eprintln!("done in {:.1}s ({size} bytes)", t0.elapsed().as_secs_f64());
    }
    eprintln!("[generate] All circuits saved to {}", dir.display());
}
