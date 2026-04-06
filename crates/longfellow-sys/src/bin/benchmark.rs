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
    rss_delta_kb: i64,
    cpu_pct: f64,
}

fn measure<F: FnOnce()>(f: F) -> Measurement {
    let ticks_per_sec = clock_ticks_per_sec();
    let rss_before = read_rss_kb();
    let cpu_before = read_cpu_ticks();
    let start = Instant::now();

    f();

    let wall = start.elapsed();
    let cpu_after = read_cpu_ticks();
    let rss_after = read_rss_kb();

    let wall_ms = wall.as_secs_f64() * 1000.0;
    let rss_delta_kb = rss_after as i64 - rss_before as i64;
    let cpu_ticks = cpu_after.saturating_sub(cpu_before);
    let cpu_secs = cpu_ticks as f64 / ticks_per_sec as f64;
    let cpu_pct = if wall.as_secs_f64() > 0.0 {
        (cpu_secs / wall.as_secs_f64()) * 100.0
    } else {
        0.0
    };

    Measurement {
        wall_ms,
        rss_delta_kb,
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

    // ZK pipeline and escrow benchmarks added in subsequent tasks.
    if json_mode {
        println!("{{}}"); // placeholder
    }
}
