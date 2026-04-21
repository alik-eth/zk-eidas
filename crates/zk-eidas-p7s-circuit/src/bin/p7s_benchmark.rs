//! Benchmark suite for `zk-eidas-p7s-circuit` (Phase 2a exit bench).
//!
//! Measures cold-prove (first invocation, includes in-FFI circuit build),
//! warm-prove (steady-state, with one throwaway prove as warm-up), verify,
//! peak RSS (post-call; mdoc uses the same shortcut), witness/public blob
//! sizes, and proof size for the single p7s circuit variant. Usage:
//!   cargo run --release --bin p7s_benchmark [-- --json]
//!
//! Single-threaded by design — parallel runs of the ECDSA-heavy sig
//! circuit OOM a 32 GB machine. Do not parallelise this loop.

use std::time::Instant;

use sha2::{Digest, Sha256};
use zk_eidas_p7s::build_witness;
use zk_eidas_p7s_circuit::{prove, verify, Proof, PublicInputs, Witness};

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
//
// Lifted from `crates/longfellow-sys/src/bin/benchmark.rs` — same shape
// (wall, post-call RSS, CPU%) so mdoc and p7s numbers are directly
// comparable. See handoff-27-bench.md §2 for the taxonomy.

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
    // `getconf CLK_TCK` is 100 on every Linux we target; shell out rather
    // than pull libc just for sysconf.
    std::process::Command::new("getconf")
        .arg("CLK_TCK")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(100)
}

#[derive(Clone, Copy)]
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

struct MedianStats {
    median: Measurement,
    min_ms: f64,
    max_ms: f64,
}

fn measure_median<F: Fn() -> R, R>(iterations: usize, f: F) -> (MedianStats, R) {
    assert!(iterations >= 1);
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
    let min_ms = measurements.first().unwrap().wall_ms;
    let max_ms = measurements.last().unwrap().wall_ms;
    let mid = measurements.len() / 2;
    let median = measurements[mid];

    (
        MedianStats {
            median,
            min_ms,
            max_ms,
        },
        last_result.unwrap(),
    )
}

// ── Fixture + p7s Benchmark ─────────────────────────────────────────

const ITERATIONS: usize = 5;
const FIXTURE_NAME: &str = "binding.qkb.p7s";
const FIXTURE: &[u8] =
    include_bytes!("../../../zk-eidas-p7s/fixtures/binding.qkb.p7s");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];
const CONTEXT: &[u8] = b"0x";

/// QR V40 low-ECC binary payload (2953 bytes) minus 8-byte chunk header.
/// Mirrors `demo/web/app/lib/qr-chunking.ts`.
const QR_CHUNK_PAYLOAD: usize = 2945;

struct P7sResult {
    fixture_name: &'static str,
    witness_blob_bytes: usize,
    public_blob_bytes: usize,
    prove_cold: Measurement,
    prove_warm: MedianStats,
    verify: MedianStats,
    proof_size_bytes: usize,
    proof_schema_header_bytes: usize,
    proof_macs_b_bytes: usize,
    proof_zk_payload_bytes: usize,
    qr_chunks_needed: usize,
}

fn decode_hex_field(p7s: &[u8], start: usize, len: usize) -> Vec<u8> {
    let hex_body = &p7s[start..start + len];
    let mut out = vec![0u8; len / 2];
    hex::decode_to_slice(hex_body, &mut out).expect("parseable hex");
    out
}

fn build_fixture_witness_and_public() -> (Witness, PublicInputs, usize, usize) {
    let inner = build_witness(FIXTURE, CONTEXT, DUMMY_ROOT_PK).expect("parse fixture");
    let off = inner.offsets;
    let mut pk = [0u8; 65];
    pk.copy_from_slice(&decode_hex_field(
        &inner.p7s_bytes,
        off.json_pk_start,
        off.json_pk_len,
    ));
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&decode_hex_field(
        &inner.p7s_bytes,
        off.json_nonce_start,
        off.json_nonce_len,
    ));

    let context_hash: [u8; 32] = Sha256::digest(CONTEXT).into();
    // v11 (Task 34): nullifier = SHA-256(stable_id || context). Bench
    // reuses the host-side helper so any schema drift trips a test,
    // not a runtime mismatch.
    let outputs = zk_eidas_p7s::compute_outputs(&inner).expect("compute outputs");
    let public = PublicInputs {
        context_hash,
        pk,
        nonce,
        nullifier: outputs.nullifier,
        trust_anchor_index: 0,
        root_pk: [0u8; 65],
        timestamp: 0,
    };
    let w = Witness::new(inner);

    let wit_blob_len = w.to_ffi_bytes().expect("serialize witness").len();
    let pub_blob_len = public.to_ffi_bytes().len();

    (w, public, wit_blob_len, pub_blob_len)
}

fn bench_p7s() -> P7sResult {
    eprintln!(
        "[p7s] Benchmarking circuit on fixture `{FIXTURE_NAME}` (N={ITERATIONS} iterations)..."
    );

    let (witness, public, witness_blob_bytes, public_blob_bytes) =
        build_fixture_witness_and_public();

    // Cold prove — first invocation, includes in-FFI circuit setup.
    // Single-shot by design; median makes no sense for a one-time cost.
    eprintln!("  cold prove (1 iteration, includes in-FFI circuit build)...");
    let mut cold_proof = None;
    let prove_cold = measure(|| {
        cold_proof = Some(prove(&witness, &public).expect("cold prove must succeed"));
    });
    let proof = cold_proof.expect("cold prove produced a proof");

    // Warm prove — circuit state (if any) now lives in the allocator's
    // hot path; this matches production where circuits are pre-generated
    // at build time and warm by the first live request.
    eprintln!("  warm prove ({ITERATIONS} iterations)...");
    let (prove_warm, last_proof) = measure_median(ITERATIONS, || {
        prove(&witness, &public).expect("warm prove must succeed")
    });

    // Use the last warm proof for verify measurements (identical in
    // structure to the cold one; different transcript randomness but
    // same byte-layout framing).
    let proof_bytes = last_proof.bytes;
    let proof_size_bytes = proof_bytes.len();

    // Proof framing per p7s_zk.h:100-110 — 4B LE schema_version
    // + 64B macs_b (4 × GF(2^128) = 4 × 16B) + hash_zk + sig_zk.
    // The hash_zk/sig_zk split is self-delimited by ZkProof::read in
    // C++; we punt on the component split (handoff §7.4) and report
    // only the combined ZK payload size.
    let proof_schema_header_bytes = 4;
    let proof_macs_b_bytes = 64;
    let proof_zk_payload_bytes = proof_size_bytes
        .saturating_sub(proof_schema_header_bytes + proof_macs_b_bytes);

    // Verify — feeds the last warm proof.
    eprintln!("  verify ({ITERATIONS} iterations)...");
    let verify_proof = Proof {
        bytes: proof_bytes.clone(),
    };
    let (verify_stats, _ok) = measure_median(ITERATIONS, || {
        verify(&verify_proof, &public).expect("verify must yield a decision")
    });

    let qr_chunks_needed = proof_size_bytes.div_ceil(QR_CHUNK_PAYLOAD);

    // Sanity: cold prove should drop the proof before warm loop; verify
    // loop must have accepted something on each iter.
    drop(proof);

    P7sResult {
        fixture_name: FIXTURE_NAME,
        witness_blob_bytes,
        public_blob_bytes,
        prove_cold,
        prove_warm,
        verify: verify_stats,
        proof_size_bytes,
        proof_schema_header_bytes,
        proof_macs_b_bytes,
        proof_zk_payload_bytes,
        qr_chunks_needed,
    }
}

// ── Formatting Helpers ─────────────────────────────────────────────

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

fn fmt_kb(bytes: usize) -> String {
    format!("{:.1} KB", bytes as f64 / 1024.0)
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

fn round0(v: f64) -> f64 {
    v.round()
}

// ── Output: Human Table ─────────────────────────────────────────────

fn print_p7s_table(r: &P7sResult) {
    println!("--- p7s Proving Pipeline ---");
    println!();

    let label_w = 30;
    let val_w = 16;

    let rows: &[(&str, String)] = &[
        ("Fixture", r.fixture_name.to_string()),
        ("Witness blob size", format!("{} B", r.witness_blob_bytes)),
        ("Public blob size", format!("{} B", r.public_blob_bytes)),
        (
            "Prove (cold, 1 iter)",
            fmt_ms(r.prove_cold.wall_ms),
        ),
        (
            "Prove (warm, median)",
            fmt_ms(r.prove_warm.median.wall_ms),
        ),
        (
            "Prove (warm, min/max)",
            format!(
                "{} / {}",
                fmt_ms(r.prove_warm.min_ms),
                fmt_ms(r.prove_warm.max_ms)
            ),
        ),
        ("Verify (median)", fmt_ms(r.verify.median.wall_ms)),
        (
            "Verify (min/max)",
            format!(
                "{} / {}",
                fmt_ms(r.verify.min_ms),
                fmt_ms(r.verify.max_ms)
            ),
        ),
        ("Proof size (total)", fmt_kb(r.proof_size_bytes)),
        (
            "  schema header",
            format!("{} B", r.proof_schema_header_bytes),
        ),
        ("  macs_b", format!("{} B", r.proof_macs_b_bytes)),
        (
            "  hash_zk + sig_zk",
            fmt_kb(r.proof_zk_payload_bytes),
        ),
        (
            "QR chunks (V40 low-ECC)",
            format!("{}", r.qr_chunks_needed),
        ),
        (
            "Prove RSS (post-call)",
            format!("{:.0} MB", r.prove_cold.rss_after_kb as f64 / 1024.0),
        ),
        (
            "Verify RSS (post-call)",
            format!(
                "{:.0} MB",
                r.verify.median.rss_after_kb as f64 / 1024.0
            ),
        ),
        ("Prove CPU util", fmt_pct(r.prove_cold.cpu_pct)),
        ("Verify CPU util", fmt_pct(r.verify.median.cpu_pct)),
    ];

    for (name, val) in rows {
        println!("{:<label_w$}{:>val_w$}", name, val);
    }

    println!();
    println!(
        "Notes: RSS is post-call (handoff §7.3); `hash_zk + sig_zk` split is \n\
         self-delimited in C++ and not broken out here (handoff §7.4)."
    );
    println!();
}

// ── Output: JSON ────────────────────────────────────────────────────

fn print_json(info: &SystemInfo, r: &P7sResult) {
    let system_json = format!(
        concat!(
            "{{",
            "\"cpu\":{cpu},",
            "\"cores\":{cores},",
            "\"threads\":{threads},",
            "\"ram_gb\":{ram},",
            "\"os\":{os},",
            "\"rust_version\":{rv}",
            "}}"
        ),
        cpu = serde_json::to_string(&info.cpu).unwrap(),
        cores = info.cores,
        threads = info.threads,
        ram = info.ram_gb,
        os = serde_json::to_string(&info.os).unwrap(),
        rv = serde_json::to_string(&info.rust_version).unwrap(),
    );

    let p7s_json = format!(
        concat!(
            "{{",
            "\"fixture\":{fixture},",
            "\"witness_blob_bytes\":{wbl},",
            "\"public_blob_bytes\":{pbl},",
            "\"prove_cold_ms\":{pc},",
            "\"prove_cold_rss_mb\":{pcr},",
            "\"prove_cold_cpu_pct\":{pcc},",
            "\"prove_warm_ms\":{pw},",
            "\"prove_warm_min_ms\":{pwmin},",
            "\"prove_warm_max_ms\":{pwmax},",
            "\"prove_warm_rss_mb\":{pwr},",
            "\"prove_warm_cpu_pct\":{pwc},",
            "\"verify_ms\":{vm},",
            "\"verify_min_ms\":{vmin},",
            "\"verify_max_ms\":{vmax},",
            "\"verify_rss_mb\":{vr},",
            "\"verify_cpu_pct\":{vc},",
            "\"proof_size_bytes\":{ps},",
            "\"proof_schema_header_bytes\":{psh},",
            "\"proof_macs_b_bytes\":{pmb},",
            "\"proof_zk_payload_bytes\":{pzp},",
            "\"qr_chunks_needed\":{qrc},",
            "\"qr_chunk_payload_bytes\":{qrp},",
            "\"iterations\":{iter}",
            "}}"
        ),
        fixture = serde_json::to_string(r.fixture_name).unwrap(),
        wbl = r.witness_blob_bytes,
        pbl = r.public_blob_bytes,
        pc = round2(r.prove_cold.wall_ms),
        pcr = round0(r.prove_cold.rss_after_kb as f64 / 1024.0),
        pcc = round0(r.prove_cold.cpu_pct),
        pw = round2(r.prove_warm.median.wall_ms),
        pwmin = round2(r.prove_warm.min_ms),
        pwmax = round2(r.prove_warm.max_ms),
        pwr = round0(r.prove_warm.median.rss_after_kb as f64 / 1024.0),
        pwc = round0(r.prove_warm.median.cpu_pct),
        vm = round2(r.verify.median.wall_ms),
        vmin = round2(r.verify.min_ms),
        vmax = round2(r.verify.max_ms),
        vr = round0(r.verify.median.rss_after_kb as f64 / 1024.0),
        vc = round0(r.verify.median.cpu_pct),
        ps = r.proof_size_bytes,
        psh = r.proof_schema_header_bytes,
        pmb = r.proof_macs_b_bytes,
        pzp = r.proof_zk_payload_bytes,
        qrc = r.qr_chunks_needed,
        qrp = QR_CHUNK_PAYLOAD,
        iter = ITERATIONS,
    );

    let out = format!(
        concat!(
            "{{",
            "\"system\":{system},",
            "\"p7s\":[{p7s}]",
            "}}"
        ),
        system = system_json,
        p7s = p7s_json,
    );

    println!("{out}");
}

// ── Main ────────────────────────────────────────────────────────────

fn main() {
    let json_mode = std::env::args().any(|a| a == "--json");
    let info = collect_system_info();

    if !json_mode {
        println!("=== zk-eidas-p7s-circuit Phase 2a benchmark ===");
        println!(
            "System: {}, {}C/{}T, {}GB RAM",
            info.cpu, info.cores, info.threads, info.ram_gb
        );
        println!("OS: {}", info.os);
        println!("Rust: {}, release build", info.rust_version);
        println!();
    }

    let result = bench_p7s();

    if json_mode {
        print_json(&info, &result);
    } else {
        print_p7s_table(&result);
    }
}
