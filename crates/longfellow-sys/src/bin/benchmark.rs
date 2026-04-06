//! Benchmark suite for zk-eidas v2.0 Longfellow proving system.
//!
//! Measures ZK proving pipeline (1–4 attributes) and identity escrow operations.
//! Usage: benchmark [--json]

use std::time::Instant;

// ── System Info ──────────────────────────────────────────────────────

struct SystemInfo {
    cpu: String,
    cores: u32,
    threads: u32,
    ram_gb: u32,
    os: String,
    rust_version: String,
}

fn collect_system_info() -> SystemInfo {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());

    let mut physical_ids = std::collections::HashSet::new();
    let mut processors = 0u32;
    let mut cores_per_socket = 1u32;
    for line in cpuinfo.lines() {
        if line.starts_with("processor") {
            processors += 1;
        }
        if let Some(val) = line.strip_prefix("physical id") {
            if let Some(id) = val.split(':').nth(1) {
                physical_ids.insert(id.trim().to_string());
            }
        }
        if let Some(val) = line.strip_prefix("cpu cores") {
            if let Some(n) = val.split(':').nth(1) {
                if let Ok(c) = n.trim().parse::<u32>() {
                    cores_per_socket = c;
                }
            }
        }
    }
    let sockets = physical_ids.len().max(1) as u32;
    let cores = sockets * cores_per_socket;
    let threads = processors;

    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let ram_kb = meminfo
        .lines()
        .find(|l| l.starts_with("MemTotal"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let ram_gb = (ram_kb / 1_048_576) as u32;

    let uname = std::process::Command::new("uname")
        .args(["-r", "-m"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let os = format!("Linux {uname}");

    let rust_version = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .strip_prefix("rustc ")
                .unwrap_or("unknown")
                .to_string()
        })
        .unwrap_or_else(|_| "unknown".into());

    SystemInfo {
        cpu,
        cores,
        threads,
        ram_gb,
        os,
        rust_version,
    }
}

// ── Measurement Helpers ─────────────────────────────────────────────

fn read_rss_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find(|l| l.starts_with("VmRSS"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

fn read_cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let fields: Vec<&str> = stat.split_whitespace().collect();
    if fields.len() < 15 {
        return 0;
    }
    let utime = fields[13].parse::<u64>().unwrap_or(0);
    let stime = fields[14].parse::<u64>().unwrap_or(0);
    utime + stime
}

fn clock_ticks_per_sec() -> u64 {
    unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 }
}

struct Measurement {
    wall_ms: f64,
    rss_after_kb: u64,
    cpu_pct: f64,
}

fn measure<F: FnOnce()>(f: F) -> Measurement {
    let ticks_per_sec = clock_ticks_per_sec();
    let cpu_before = read_cpu_ticks();
    let start = Instant::now();

    f();

    let wall = start.elapsed();
    let cpu_after = read_cpu_ticks();
    let rss_after = read_rss_kb();

    let wall_ms = wall.as_secs_f64() * 1000.0;
    let cpu_ticks = cpu_after.saturating_sub(cpu_before);
    let cpu_secs = cpu_ticks as f64 / ticks_per_sec as f64;
    let cpu_pct = if wall.as_secs_f64() > 0.0 {
        (cpu_secs / wall.as_secs_f64()) * 100.0
    } else {
        0.0
    };

    Measurement {
        wall_ms,
        rss_after_kb: rss_after,
        cpu_pct,
    }
}

fn measure_median<F: Fn() -> R, R>(iterations: usize, f: F) -> (Measurement, R) {
    let mut measurements = Vec::with_capacity(iterations);
    let mut last_result = None;

    for _ in 0..iterations {
        let mut result = None;
        let m = measure(|| {
            result = Some(f());
        });
        last_result = result;
        measurements.push(m);
    }

    measurements.sort_by(|a, b| a.wall_ms.partial_cmp(&b.wall_ms).unwrap());
    let mid = measurements.len() / 2;
    let median = measurements.remove(mid);

    (median, last_result.unwrap())
}

// ── ZK Pipeline Benchmark ───────────────────────────────────────────

const ITERATIONS: usize = 5;
const CACHE_DIR: &str = "circuit-cache";

struct ZkResult {
    attributes: usize,
    circuit_gen: Measurement,
    circuit_load: Measurement,
    prove: Measurement,
    verify: Measurement,
    proof_size_bytes: usize,
}

fn bench_zk_pipeline() -> Vec<ZkResult> {
    use longfellow_sys::mdoc::MdocCircuit;

    let mut results = Vec::new();

    for n in 1..=4 {
        eprintln!("[ZK] Benchmarking {n}-attribute circuit...");

        // Circuit generation (cold)
        eprintln!("  circuit generate ({ITERATIONS} iterations)...");
        let (circuit_gen, circuit) = measure_median(ITERATIONS, || {
            MdocCircuit::generate(n).expect("circuit generation failed")
        });

        // Circuit load from cache
        let cache_path =
            std::path::PathBuf::from(CACHE_DIR).join(format!("mdoc-{n}attr.bin"));
        let circuit_load = if cache_path.exists() {
            eprintln!("  circuit load ({ITERATIONS} iterations)...");
            let (m, _) = measure_median(ITERATIONS, || {
                MdocCircuit::load(&cache_path, n).expect("circuit load failed")
            });
            m
        } else {
            eprintln!("  WARN: cache file not found: {}", cache_path.display());
            Measurement {
                wall_ms: f64::NAN,
                rss_after_kb: 0,
                cpu_pct: 0.0,
            }
        };

        // Prove + verify
        eprintln!("  prove + verify ({ITERATIONS} iterations each)...");
        let (prove_m, verify_m, proof_size) = bench_prove_verify(n, &circuit);

        results.push(ZkResult {
            attributes: n,
            circuit_gen,
            circuit_load,
            prove: prove_m,
            verify: verify_m,
            proof_size_bytes: proof_size,
        });

        eprintln!("[ZK] {n}-attribute done.");
    }

    results
}

fn bench_prove_verify(
    n: usize,
    circuit: &longfellow_sys::mdoc::MdocCircuit,
) -> (Measurement, Measurement, usize) {
    use longfellow_sys::mdoc::{prove, verify, AttributeRequest};
    use longfellow_sys::safe::VerifyType;
    use zk_eidas_types::credential::ClaimValue;

    let padding_names = ["given_name", "family_name", "document_number"];

    // Build claims for the test mdoc
    let mut claims: Vec<(&str, ClaimValue)> =
        vec![("age_over_18", ClaimValue::Boolean(true))];
    for i in 1..n {
        claims.push((padding_names[i - 1], ClaimValue::String("Test".into())));
    }

    let (mdoc_bytes, pub_key_x, pub_key_y) =
        zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(claims, "bench-issuer");
    let pkx_hex = format!("0x{}", hex::encode(pub_key_x));
    let pky_hex = format!("0x{}", hex::encode(pub_key_y));

    // Build attribute requests
    let mut attributes = vec![AttributeRequest {
        namespace: "org.iso.18013.5.1".into(),
        identifier: "age_over_18".into(),
        cbor_value: vec![0xf5], // CBOR true
        verify_type: VerifyType::Geq,
    }];
    for i in 1..n {
        attributes.push(AttributeRequest {
            namespace: "org.iso.18013.5.1".into(),
            identifier: padding_names[i - 1].into(),
            cbor_value: vec![0x64, 0x54, 0x65, 0x73, 0x74], // CBOR text(4) "Test"
            verify_type: VerifyType::Eq,
        });
    }

    // Prove
    let (prove_m, proof) = measure_median(ITERATIONS, || {
        prove(
            circuit,
            &mdoc_bytes,
            &pkx_hex,
            &pky_hex,
            b"zk-eidas-demo",
            &attributes,
            "2026-01-01T00:00:00Z",
            &[0u8; 8],
        )
        .expect("prove failed")
    });

    let proof_size = proof.proof_bytes.len();

    // Verify
    let (verify_m, _) = measure_median(ITERATIONS, || {
        verify(
            circuit,
            &proof,
            &pkx_hex,
            &pky_hex,
            b"zk-eidas-demo",
            &attributes,
            "2026-01-01T00:00:00Z",
            "org.iso.18013.5.1.mDL",
            &[0u8; 8],
        )
        .expect("verify failed")
    });

    (prove_m, verify_m, proof_size)
}

// ── Escrow Benchmark ───────────────────────────────────────────────

struct EscrowResult {
    mlkem_keygen: Measurement,
    field_packing: Measurement,
    aes_encrypt: Measurement,
    mlkem_encrypt_k: Measurement,
    mlkem_decrypt_k: Measurement,
    aes_decrypt: Measurement,
}

fn bench_escrow_pipeline() -> EscrowResult {
    use std::collections::BTreeMap;
    use zk_eidas::escrow;
    use zk_eidas_types::credential::{ClaimValue, Credential, SignatureData};

    // Build test credential
    let mut claims = BTreeMap::new();
    claims.insert("name".to_string(), ClaimValue::String("Alice".into()));
    claims.insert("address".to_string(), ClaimValue::String("123 Main St".into()));
    claims.insert("document_number".to_string(), ClaimValue::String("UA-1234567890".into()));
    claims.insert("age".to_string(), ClaimValue::Integer(25));
    let credential = Credential::new(
        claims,
        "bench-issuer".into(),
        SignatureData::Opaque { signature: vec![], public_key: vec![] },
        BTreeMap::new(),
    );

    let field_names: Vec<String> = vec![
        "name".into(),
        "address".into(),
        "document_number".into(),
        "age".into(),
    ];

    // 1. ML-KEM-768 keygen
    eprintln!("  ML-KEM-768 keygen ({ITERATIONS} iterations)...");
    let (mlkem_keygen, (seed, _ek)) = measure_median(ITERATIONS, || {
        escrow::generate_authority_keypair()
    });

    // 2. Field packing
    eprintln!("  field packing ({ITERATIONS} iterations)...");
    let (field_packing, (packed_data, _claim_idx)) = measure_median(ITERATIONS, || {
        escrow::pack_credential_fields(&credential, &field_names, "name").unwrap()
    });

    // 3. AES-256-GCM encrypt
    let field_bytes: Vec<(&str, [u8; 31])> = field_names
        .iter()
        .map(|name| {
            let cv = credential.claims().get(name).unwrap();
            (name.as_str(), cv.to_escrow_field())
        })
        .collect();
    let aes_key = [0x42u8; 32];
    let fields_ref: Vec<(&str, &[u8])> = field_bytes
        .iter()
        .map(|(n, v)| (*n, v.as_ref() as &[u8]))
        .collect();

    eprintln!("  AES-256-GCM encrypt ({ITERATIONS} iterations)...");
    let (aes_encrypt, (ciphertexts, tags)) = measure_median(ITERATIONS, || {
        escrow::encrypt_fields_aes_gcm(&fields_ref, &aes_key).unwrap()
    });

    // 4. Derive escrow key + ML-KEM encrypt K
    let k = escrow::derive_escrow_key(&packed_data, &seed);

    eprintln!("  ML-KEM encrypt K ({ITERATIONS} iterations)...");
    let (mlkem_encrypt_k, encrypted_k) = measure_median(ITERATIONS, || {
        escrow::encrypt_key_to_authority(&k, &seed).unwrap()
    });

    // 5. ML-KEM decrypt K
    eprintln!("  ML-KEM decrypt K ({ITERATIONS} iterations)...");
    let (mlkem_decrypt_k, _decrypted_k) = measure_median(ITERATIONS, || {
        escrow::decrypt_key(&encrypted_k, &seed).unwrap()
    });

    // 6. AES-256-GCM decrypt
    eprintln!("  AES-256-GCM decrypt ({ITERATIONS} iterations)...");
    let (aes_decrypt, _plaintexts) = measure_median(ITERATIONS, || {
        escrow::decrypt_fields_aes_gcm(&ciphertexts, &tags, &aes_key).unwrap()
    });

    EscrowResult {
        mlkem_keygen,
        field_packing,
        aes_encrypt,
        mlkem_encrypt_k,
        mlkem_decrypt_k,
        aes_decrypt,
    }
}

fn print_escrow_table(r: &EscrowResult) {
    println!("--- Identity Escrow Pipeline ---");
    println!();

    let label_w = 28;
    let time_w = 14;

    println!("{:<label_w$}{:>time_w$}", "Operation", "Time");
    println!("{:<label_w$}{:>time_w$}", "", "──────────");

    let rows: &[(&str, &Measurement)] = &[
        ("ML-KEM-768 keygen",    &r.mlkem_keygen),
        ("Field packing",        &r.field_packing),
        ("AES-256-GCM encrypt",  &r.aes_encrypt),
        ("ML-KEM encrypt K",     &r.mlkem_encrypt_k),
        ("ML-KEM decrypt K",     &r.mlkem_decrypt_k),
        ("AES-256-GCM decrypt",  &r.aes_decrypt),
    ];

    for (name, m) in rows {
        println!(
            "{:<label_w$}{:>time_w$}",
            name,
            fmt_ms(m.wall_ms),
        );
    }

    println!();
}

// ── Formatting Helpers ─────────────────────────────────────────────

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round0(v: f64) -> f64 {
    v.round()
}

fn fmt_ms(v: f64) -> String {
    if v.is_nan() {
        "N/A".into()
    } else if v >= 1000.0 {
        format!("{:.2}s", v / 1000.0)
    } else {
        format!("{:.2}ms", v)
    }
}

fn fmt_pct(v: f64) -> String {
    format!("{:.0}%", v)
}

fn print_zk_table(results: &[ZkResult]) {
    // Header
    println!("--- ZK Proving Pipeline ---");
    println!();

    let col_w = 14;
    let label_w = 22;

    // Column headers
    print!("{:<label_w$}", "");
    for r in results {
        print!("{:>col_w$}", format!("{}-attr", r.attributes));
    }
    println!();
    print!("{:<label_w$}", "");
    for _ in results {
        print!("{:>col_w$}", "──────────");
    }
    println!();

    // Circuit generation
    print!("{:<label_w$}", "Circuit gen (cold)");
    for r in results {
        print!("{:>col_w$}", fmt_ms(r.circuit_gen.wall_ms));
    }
    println!();

    // Circuit load
    print!("{:<label_w$}", "Circuit load (cache)");
    for r in results {
        print!("{:>col_w$}", fmt_ms(r.circuit_load.wall_ms));
    }
    println!();

    // Prove
    print!("{:<label_w$}", "Prove");
    for r in results {
        print!("{:>col_w$}", fmt_ms(r.prove.wall_ms));
    }
    println!();

    // Verify
    print!("{:<label_w$}", "Verify");
    for r in results {
        print!("{:>col_w$}", fmt_ms(r.verify.wall_ms));
    }
    println!();

    // Proof size
    print!("{:<label_w$}", "Proof size");
    for r in results {
        let kb = r.proof_size_bytes as f64 / 1024.0;
        print!("{:>col_w$}", format!("{:.1} KB", kb));
    }
    println!();

    println!();

    // Memory / CPU detail
    print!("{:<label_w$}", "Gen RSS (MB)");
    for r in results {
        print!("{:>col_w$}", format!("{:.0}", r.circuit_gen.rss_after_kb as f64 / 1024.0));
    }
    println!();

    print!("{:<label_w$}", "Gen CPU util");
    for r in results {
        print!("{:>col_w$}", fmt_pct(r.circuit_gen.cpu_pct));
    }
    println!();

    print!("{:<label_w$}", "Prove RSS (MB)");
    for r in results {
        print!("{:>col_w$}", format!("{:.0}", r.prove.rss_after_kb as f64 / 1024.0));
    }
    println!();

    print!("{:<label_w$}", "Prove CPU util");
    for r in results {
        print!("{:>col_w$}", fmt_pct(r.prove.cpu_pct));
    }
    println!();

    print!("{:<label_w$}", "Verify RSS (MB)");
    for r in results {
        print!("{:>col_w$}", format!("{:.0}", r.verify.rss_after_kb as f64 / 1024.0));
    }
    println!();

    print!("{:<label_w$}", "Verify CPU util");
    for r in results {
        print!("{:>col_w$}", fmt_pct(r.verify.cpu_pct));
    }
    println!();

    println!();
}

fn print_json(info: &SystemInfo, zk_results: &[ZkResult], escrow: &EscrowResult) {
    let zk_entries: Vec<String> = zk_results
        .iter()
        .map(|r| {
            format!(
                concat!(
                    "{{",
                    "\"attributes\":{attr},",
                    "\"circuit_gen_ms\":{cg},",
                    "\"circuit_load_ms\":{cl},",
                    "\"prove_ms\":{pm},",
                    "\"verify_ms\":{vm},",
                    "\"proof_size_bytes\":{ps},",
                    "\"gen_rss_mb\":{gm},",
                    "\"gen_cpu_pct\":{gc},",
                    "\"prove_rss_mb\":{pm_r},",
                    "\"prove_cpu_pct\":{pc},",
                    "\"verify_rss_mb\":{vm_r},",
                    "\"verify_cpu_pct\":{vc}",
                    "}}"
                ),
                attr = r.attributes,
                cg = round2(r.circuit_gen.wall_ms),
                cl = if r.circuit_load.wall_ms.is_nan() {
                    "null".to_string()
                } else {
                    format!("{}", round2(r.circuit_load.wall_ms))
                },
                pm = round2(r.prove.wall_ms),
                vm = round2(r.verify.wall_ms),
                ps = r.proof_size_bytes,
                gm = round0(r.circuit_gen.rss_after_kb as f64 / 1024.0),
                gc = round0(r.circuit_gen.cpu_pct),
                pm_r = round0(r.prove.rss_after_kb as f64 / 1024.0),
                pc = round0(r.prove.cpu_pct),
                vm_r = round0(r.verify.rss_after_kb as f64 / 1024.0),
                vc = round0(r.verify.cpu_pct),
            )
        })
        .collect();

    let escrow_json = format!(
        concat!(
            "{{",
            "\"mlkem_keygen_ms\":{kg},",
            "\"field_packing_ms\":{fp},",
            "\"aes_encrypt_ms\":{ae},",
            "\"mlkem_encrypt_k_ms\":{ek},",
            "\"mlkem_decrypt_k_ms\":{dk},",
            "\"aes_decrypt_ms\":{ad}",
            "}}"
        ),
        kg = round2(escrow.mlkem_keygen.wall_ms),
        fp = round2(escrow.field_packing.wall_ms),
        ae = round2(escrow.aes_encrypt.wall_ms),
        ek = round2(escrow.mlkem_encrypt_k.wall_ms),
        dk = round2(escrow.mlkem_decrypt_k.wall_ms),
        ad = round2(escrow.aes_decrypt.wall_ms),
    );

    let json = format!(
        concat!(
            "{{",
            "\"system\":{{",
            "\"cpu\":{cpu},",
            "\"cores\":{cores},",
            "\"threads\":{threads},",
            "\"ram_gb\":{ram},",
            "\"os\":{os},",
            "\"rust_version\":{rv}",
            "}},",
            "\"zk_pipeline\":[{zk}],",
            "\"escrow\":{escrow}",
            "}}"
        ),
        cpu = serde_json::to_string(&info.cpu).unwrap(),
        cores = info.cores,
        threads = info.threads,
        ram = info.ram_gb,
        os = serde_json::to_string(&info.os).unwrap(),
        rv = serde_json::to_string(&info.rust_version).unwrap(),
        zk = zk_entries.join(","),
        escrow = escrow_json,
    );

    println!("{json}");
}

// ── Main ────────────────────────────────────────────────────────────

fn main() {
    let json_mode = std::env::args().any(|a| a == "--json");
    let info = collect_system_info();

    if !json_mode {
        println!("=== zk-eidas v2.0 Benchmark ===");
        println!(
            "System: {}, {}C/{}T, {}GB RAM",
            info.cpu, info.cores, info.threads, info.ram_gb
        );
        println!("OS: {}", info.os);
        println!("Rust: {}, release build", info.rust_version);
        println!();
    }

    let zk_results = bench_zk_pipeline();

    eprintln!("Running escrow pipeline benchmark...");
    let escrow_result = bench_escrow_pipeline();

    if json_mode {
        print_json(&info, &zk_results, &escrow_result);
    } else {
        print_zk_table(&zk_results);
        print_escrow_table(&escrow_result);
    }
}
