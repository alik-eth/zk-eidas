//! Pre-warm script: issues default credentials and pre-computes proofs
//! for all credential presets. Saves results to proof-cache.json.
//!
//! Run: cargo run --bin pre-warm
//! Requires the API server to be running on localhost:3001.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    credential: String,
    format: String,
    credential_type: String,
    claims: serde_json::Value,
    predicates: serde_json::Value,
    compound_proof_json: String,
    op: String,
    hidden_fields: Vec<String>,
    sub_proofs_count: usize,
    compressed_cbor_base64: String,
}

#[derive(Serialize, Deserialize)]
struct BindingCacheEntry {
    proofs_a: Vec<ProofResultEntry>,
    proofs_b: Vec<ProofResultEntry>,
    binding_hash: String,
    binding_verified: bool,
    hidden_fields_a: Vec<String>,
    hidden_fields_b: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ProofResultEntry {
    predicate: String,
    proof_json: String,
    proof_hex: String,
    op: String,
}

#[derive(Serialize, Deserialize)]
struct ProofCache {
    generated_at: String,
    entries: HashMap<String, CacheEntry>,
    #[serde(default)]
    binding_entries: HashMap<String, BindingCacheEntry>,
}

/// Compute a binding cache key — MUST match compute_binding_cache_key in main.rs
fn binding_cache_key(binding_claim: &str, binding_claim_b: &str) -> String {
    let key_material = format!("binding|{}|{}", binding_claim, binding_claim_b);
    format!("{:016x}", fnv_hash(key_material.as_bytes()))
}

/// Compute a cache key — MUST match compute_cache_key in main.rs
fn cache_key(format: &str, predicates: &serde_json::Value) -> String {
    // For gte/lte ops, omit value (epoch_days drifts after build)
    let preds: Vec<serde_json::Value> = predicates.as_array().unwrap().iter().map(|p| {
        if matches!(p["op"].as_str(), Some("gte" | "lte")) {
            serde_json::json!({"claim": p["claim"], "op": p["op"]})
        } else {
            serde_json::json!({"claim": p["claim"], "op": p["op"], "value": p["value"]})
        }
    }).collect();
    let key_material = format!("{}|{}", format, serde_json::to_string(&preds).unwrap());
    format!("{:016x}", fnv_hash(key_material.as_bytes()))
}

fn fnv_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[tokio::main]
async fn main() {
    let base_url = std::env::var("API_URL").unwrap_or_else(|_| "http://localhost:3001".to_string());
    let client = reqwest::Client::new();

    // Check API is running
    match client.get(format!("{base_url}/issuer/revocation-root")).send().await {
        Ok(r) if r.status().is_success() => println!("API is running at {base_url}"),
        _ => {
            eprintln!("ERROR: API not running at {base_url}. Start it first with: cargo run -p zk-eidas-demo-api");
            std::process::exit(1);
        }
    }

    let mut cache = ProofCache {
        generated_at: chrono_now(),
        entries: HashMap::new(),
        binding_entries: HashMap::new(),
    };

    let presets: Vec<(&str, serde_json::Value, serde_json::Value, &str)> = vec![
        // PID — age >= 18 + document_number eq (matches contract templates: age_verification, vehicle_sale seller/buyer)
        ("pid", serde_json::json!({
            "given_name": "Олександр", "family_name": "Петренко",
            "birth_date": "1998-05-14", "age_over_18": "true",
            "nationality": "UA", "issuing_country": "UA",
            "resident_country": "UA", "resident_city": "Київ",
            "gender": "M", "document_number": "UA-1234567890",
            "expiry_date": "2035-05-14",
            "issuing_authority": "Міністерство цифрової трансформації"
        }), serde_json::json!([
            { "claim": "birth_date", "op": "gte", "value": 18 },
            { "claim": "document_number", "op": "eq", "value": "UA-1234567890" }
        ]), "https://diia.gov.ua"),

        // Driver's License — valid + category B + experienced + license_number eq
        ("drivers_license", serde_json::json!({
            "holder_name": "Kadri Tamm", "category": "A, B, C1",
            "issue_date": "2019-03-22", "expiry_date": "2034-03-22",
            "restrictions": "None", "license_number": "EE-DL-49301150123"
        }), serde_json::json!([
            { "claim": "expiry_date", "op": "gte", "value": epoch_days_today() },
            { "claim": "category", "op": "eq", "value": "A, B, C1" },
            { "claim": "issue_date", "op": "lte", "value": epoch_days_years_ago(2) },
            { "claim": "license_number", "op": "eq", "value": "EE-DL-49301150123" }
        ]), "https://ppa.ee"),

        // Student ID — active_student + student_number eq
        ("student_id", serde_json::json!({
            "student_name": "Katarzyna Nowak",
            "university": "Uniwersytet Warszawski",
            "faculty": "Informatyka",
            "enrollment_year": "2022",
            "valid_until": "2026-09-30",
            "student_number": "PL-UW-STU-22-31547"
        }), serde_json::json!([
            { "claim": "valid_until", "op": "gte", "value": epoch_days_today() },
            { "claim": "student_number", "op": "eq", "value": "PL-UW-STU-22-31547" }
        ]), "https://uw.edu.pl"),

        // Vehicle — insured + vin_active + vin eq
        ("vehicle", serde_json::json!({
            "owner_name": "Maximilian Schneider",
            "owner_document_number": "UA-1234567890",
            "plate_number": "B-MS 2847",
            "make_model": "Volkswagen Golf",
            "vin": "WVWZZZ1JZYW000001",
            "insurance_expiry": "2027-01-15",
            "registration_date": "2021-06-10"
        }), serde_json::json!([
            { "claim": "insurance_expiry", "op": "gte", "value": epoch_days_today() },
            { "claim": "vin", "op": "neq", "value": "REVOKED" },
            { "claim": "vin", "op": "eq", "value": "WVWZZZ1JZYW000001" }
        ]), "https://kba.de"),

        // Diploma for playground — defaults: stem + recent_grad + diploma_number
        ("diploma", serde_json::json!({
            "student_name": "Camille Dubois",
            "university": "Sorbonne Université",
            "degree": "Master (M2)",
            "field_of_study": "Computer Science",
            "graduation_year": "2023",
            "diploma_number": "FR-SORB-2023-04521",
            "honors": "Magna Cum Laude"
        }), serde_json::json!([
            { "claim": "field_of_study", "op": "set_member", "value": ["Computer Science", "Mathematics", "Physics", "Chemistry", "Biology", "Engineering"] },
            { "claim": "graduation_year", "op": "gte", "value": 2020 },
            { "claim": "diploma_number", "op": "eq", "value": "FR-SORB-2023-04521" }
        ]), "https://sorbonne-universite.fr"),

        // Drivers License for playground — defaults: category_b + valid + license_number
        ("drivers_license", serde_json::json!({
            "holder_name": "Kadri Tamm", "category": "A, B, C1",
            "issue_date": "2019-03-22", "expiry_date": "2034-03-22",
            "restrictions": "None", "license_number": "EE-DL-49301150123"
        }), serde_json::json!([
            { "claim": "category", "op": "eq", "value": "A, B, C1" },
            { "claim": "expiry_date", "op": "gte", "value": epoch_days_today() },
            { "claim": "license_number", "op": "eq", "value": "EE-DL-49301150123" }
        ]), "https://ppa.ee"),

        // Vehicle for playground — defaults: insured + eu_type + vin
        ("vehicle", serde_json::json!({
            "owner_name": "Maximilian Schneider",
            "owner_document_number": "UA-1234567890",
            "plate_number": "B-MS 2847",
            "make_model": "Volkswagen Golf",
            "vin": "WVWZZZ1JZYW000001",
            "insurance_expiry": "2027-01-15",
            "registration_date": "2021-06-10"
        }), serde_json::json!([
            { "claim": "insurance_expiry", "op": "gte", "value": epoch_days_today() },
            { "claim": "make_model", "op": "set_member", "value": ["Volkswagen Golf", "BMW 3 Series", "Toyota Corolla", "Renault Clio", "Fiat 500"] },
            { "claim": "vin", "op": "eq", "value": "WVWZZZ1JZYW000001" }
        ]), "https://kba.de"),

        // PID — buyer in vehicle sale contract (DE document number)
        ("pid", serde_json::json!({
            "given_name": "Maximilian", "family_name": "Schneider",
            "birth_date": "1990-03-22", "age_over_18": "true",
            "nationality": "DE", "issuing_country": "DE",
            "resident_country": "DE", "resident_city": "Berlin",
            "gender": "M", "document_number": "DE-9876543210",
            "expiry_date": "2033-08-01",
            "issuing_authority": "Bundesdruckerei"
        }), serde_json::json!([
            { "claim": "birth_date", "op": "gte", "value": 18 },
            { "claim": "document_number", "op": "eq", "value": "DE-9876543210" }
        ]), "https://bdr.de"),

        // PID — landing page Live Proof (age >= 18 only, no document eq)
        ("pid", serde_json::json!({
            "given_name": "Олександр", "family_name": "Петренко",
            "birth_date": "1998-05-14", "age_over_18": "true",
            "nationality": "UA", "issuing_country": "UA",
            "resident_country": "UA", "resident_city": "Київ",
            "gender": "M", "document_number": "UA-1234567890",
            "expiry_date": "2035-05-14",
            "issuing_authority": "Міністерство цифрової трансформації"
        }), serde_json::json!([
            { "claim": "birth_date", "op": "gte", "value": 18 }
        ]), "https://diia.gov.ua"),

        // PID for demo playground — age + nationality + document_number (discloseDocNumber is on by default)
        ("pid", serde_json::json!({
            "given_name": "Олександр", "family_name": "Петренко",
            "birth_date": "1998-05-14", "age_over_18": "true",
            "nationality": "UA", "issuing_country": "UA",
            "resident_country": "UA", "resident_city": "Київ",
            "gender": "M", "document_number": "UA-1234567890",
            "expiry_date": "2035-05-14",
            "issuing_authority": "Міністерство цифрової трансформації"
        }), serde_json::json!([
            { "claim": "birth_date", "op": "gte", "value": 18 },
            { "claim": "nationality", "op": "set_member", "value": eu_countries() },
            { "claim": "document_number", "op": "eq", "value": "UA-1234567890" }
        ]), "https://diia.gov.ua"),
    ];

    for (i, (cred_type, claims, predicates, issuer)) in presets.iter().enumerate() {
        println!("\n[{}/{}] Pre-warming: {}", i + 1, presets.len(), cred_type);

        // Issue credential
        let issue_res: serde_json::Value = client
            .post(format!("{base_url}/issuer/issue"))
            .json(&serde_json::json!({
                "credential_type": cred_type,
                "claims": claims,
                "issuer": issuer,
            }))
            .send()
            .await
            .expect("issue failed")
            .json()
            .await
            .expect("issue parse failed");

        let credential = issue_res["credential"].as_str().unwrap();
        let format = issue_res["format"].as_str().unwrap();
        println!("  Issued: {} ({})", cred_type, format);

        // Prove compound
        let t0 = std::time::Instant::now();
        let prove_res = client
            .post(format!("{base_url}/holder/prove-compound"))
            .json(&serde_json::json!({
                "credential": credential,
                "format": format,
                "predicates": predicates,
                "op": "and",
            }))
            .send()
            .await
            .expect("prove failed");

        if !prove_res.status().is_success() {
            let err = prove_res.text().await.unwrap_or_default();
            eprintln!("  FAILED to prove {}: {}", cred_type, err);
            continue;
        }
        let prove_data: serde_json::Value = prove_res.json().await.unwrap();
        println!("  Proved in {:.1}s", t0.elapsed().as_secs_f64());

        let compound_proof_json = prove_data["compound_proof_json"].as_str().unwrap();

        // Export compound with compression
        let export_res: serde_json::Value = client
            .post(format!("{base_url}/holder/proof-export-compound?compress=true"))
            .json(&serde_json::json!({
                "compound_proof_json": compound_proof_json,
            }))
            .send()
            .await
            .expect("export failed")
            .json()
            .await
            .expect("export parse failed");

        let key = cache_key(format, predicates);
        println!("  Cache key: {key}");

        let hidden_fields: Vec<String> = prove_data["hidden_fields"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let sub_proofs_count = prove_data["sub_proofs_count"].as_u64().unwrap_or(0) as usize;

        cache.entries.insert(key, CacheEntry {
            credential: credential.to_string(),
            format: format.to_string(),
            credential_type: cred_type.to_string(),
            claims: claims.clone(),
            predicates: predicates.clone(),
            compound_proof_json: compound_proof_json.to_string(),
            op: prove_data["op"].as_str().unwrap_or("And").to_string(),
            hidden_fields,
            sub_proofs_count,
            compressed_cbor_base64: export_res["compressed_cbor_base64"]
                .as_str()
                .unwrap_or("")
                .to_string(),
        });
    }

    // Pre-warm holder binding (vehicle_sale: seller PID ↔ vehicle registration)
    println!("\n[binding] Pre-warming holder binding: document_number ↔ owner_document_number");
    {
        // Issue fresh PID credential for seller
        let pid_res: serde_json::Value = client
            .post(format!("{base_url}/issuer/issue"))
            .json(&serde_json::json!({
                "credential_type": "pid",
                "claims": {
                    "given_name": "Олександр", "family_name": "Петренко",
                    "birth_date": "1998-05-14", "age_over_18": "true",
                    "nationality": "UA", "issuing_country": "UA",
                    "resident_country": "UA", "resident_city": "Київ",
                    "gender": "M", "document_number": "UA-1234567890",
                    "expiry_date": "2035-05-14",
                    "issuing_authority": "Міністерство цифрової трансформації"
                },
                "issuer": "https://diia.gov.ua",
            }))
            .send().await.expect("issue PID failed").json().await.expect("parse failed");

        // Issue fresh vehicle credential
        let veh_res: serde_json::Value = client
            .post(format!("{base_url}/issuer/issue"))
            .json(&serde_json::json!({
                "credential_type": "vehicle",
                "claims": {
                    "owner_name": "Maximilian Schneider",
                    "owner_document_number": "UA-1234567890",
                    "plate_number": "B-MS 2847",
                    "make_model": "Volkswagen Golf",
                    "vin": "WVWZZZ1JZYW000001",
                    "insurance_expiry": "2027-01-15",
                    "registration_date": "2021-06-10"
                },
                "issuer": "https://kba.de",
            }))
            .send().await.expect("issue vehicle failed").json().await.expect("parse failed");

        let t0 = std::time::Instant::now();
        let binding_res = client
            .post(format!("{base_url}/holder/prove-binding"))
            .json(&serde_json::json!({
                "sdjwt_a": pid_res["credential"].as_str().unwrap(),
                "sdjwt_b": veh_res["credential"].as_str().unwrap(),
                "binding_claim": "document_number",
                "binding_claim_b": "owner_document_number",
                "predicates_a": [],
                "predicates_b": [],
            }))
            .send().await.expect("binding prove failed");

        if binding_res.status().is_success() {
            let data: serde_json::Value = binding_res.json().await.unwrap();
            println!("  Binding proved in {:.1}s", t0.elapsed().as_secs_f64());

            let key = binding_cache_key("document_number", "owner_document_number");
            println!("  Binding cache key: {key}");

            let to_entries = |arr: &serde_json::Value| -> Vec<ProofResultEntry> {
                arr.as_array().unwrap_or(&vec![]).iter().map(|p| ProofResultEntry {
                    predicate: p["predicate"].as_str().unwrap_or("").to_string(),
                    proof_json: p["proof_json"].as_str().unwrap_or("").to_string(),
                    proof_hex: p["proof_hex"].as_str().unwrap_or("").to_string(),
                    op: p["op"].as_str().unwrap_or("").to_string(),
                }).collect()
            };

            cache.binding_entries.insert(key, BindingCacheEntry {
                proofs_a: to_entries(&data["proofs_a"]),
                proofs_b: to_entries(&data["proofs_b"]),
                binding_hash: data["binding_hash"].as_str().unwrap_or("").to_string(),
                binding_verified: data["binding_verified"].as_bool().unwrap_or(false),
                hidden_fields_a: data["hidden_fields_a"].as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                hidden_fields_b: data["hidden_fields_b"].as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
            });
        } else {
            eprintln!("  FAILED binding prove: {}", binding_res.text().await.unwrap_or_default());
        }
    }

    // Write cache
    let cache_path = std::env::var("CACHE_OUTPUT")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("proof-cache.json"));
    let json = serde_json::to_string_pretty(&cache).unwrap();
    std::fs::write(&cache_path, &json).unwrap();
    println!("\n✓ Cache written to {} ({} proof entries + {} binding entries, {:.1} KB)",
        cache_path.display(), cache.entries.len(), cache.binding_entries.len(), json.len() as f64 / 1024.0);
}

fn epoch_days_today() -> i64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    (now.as_secs() / 86400) as i64
}

fn epoch_days_years_ago(years: i64) -> i64 {
    epoch_days_today() - years * 365
}

fn eu_countries() -> Vec<&'static str> {
    vec!["UA","DE","FR","IT","ES","PL","NL","BE","AT","SE","CZ","RO","BG","HR","IE","LT","LV","EE","SK","SI","FI","DK","PT","HU","EL","LU","MT","CY"]
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    format!("{}", now.as_secs())
}
