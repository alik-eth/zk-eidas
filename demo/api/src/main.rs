use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tower_http::cors::{AllowOrigin, CorsLayer};
use axum::extract::Path as AxumPath;
use axum::body::Body;

pub struct AppState {
    circuits_path: String,
    status_list: Mutex<Vec<u8>>,  // bitstring: 0=valid, 1=revoked
    prove_semaphore: Semaphore,  // limit concurrent proof generation
    proof_cache: HashMap<String, CachedProof>,
    /// Cached Longfellow circuit (generated once on first use) — used by benchmark endpoint
    longfellow_circuit: tokio::sync::OnceCell<Vec<u8>>,
    /// Per-attribute-count Longfellow circuit cache (indices 0–3 → 1–4 attributes)
    longfellow_circuits: [tokio::sync::OnceCell<longfellow_sys::mdoc::MdocCircuit>; 4],
    /// Content-addressed proof blob store: SHA-256 hex CID → raw bytes
    proof_blobs: std::sync::RwLock<HashMap<String, Vec<u8>>>,
    /// TSP ECDSA P-256 signing key for QEAA attestations
    tsp_signing_key: p256::ecdsa::SigningKey,
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedProof {
    compound_proof_json: String,
    op: String,
    hidden_fields: Vec<String>,
    sub_proofs_count: usize,
    compressed_cbor_base64: String,
}

// === Issue ===

#[derive(Deserialize)]
struct IssueRequest {
    credential_type: String,
    claims: serde_json::Value,
    #[serde(default = "default_issuer")]
    issuer: String,
}

fn default_issuer() -> String {
    "https://diia.gov.ua".to_string()
}

fn default_format() -> String {
    "mdoc".to_string()
}

/// Parse "mdoc:<base64>:<hex_pubx>:<hex_puby>" token into (bytes, pub_key_x, pub_key_y).
#[allow(clippy::type_complexity)]
fn parse_mdoc_token(token: &str) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), String> {
    let parts: Vec<&str> = token.splitn(4, ':').collect();
    if parts.len() != 4 || parts[0] != "mdoc" {
        return Err("expected mdoc:<base64>:<hex_x>:<hex_y>".into());
    }
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(parts[1])
        .map_err(|e| format!("base64 decode: {e}"))?;
    let pub_key_x: [u8; 32] = hex::decode(parts[2])
        .map_err(|e| format!("hex x: {e}"))?
        .try_into()
        .map_err(|_| "pub_key_x must be 32 bytes")?;
    let pub_key_y: [u8; 32] = hex::decode(parts[3])
        .map_err(|e| format!("hex y: {e}"))?
        .try_into()
        .map_err(|_| "pub_key_y must be 32 bytes")?;
    Ok((bytes, pub_key_x, pub_key_y))
}

fn predicate_to_attribute(
    claim: &str,
    op: &str,
    cbor_value: &[u8],
) -> Result<longfellow_sys::mdoc::AttributeRequest, (StatusCode, String)> {
    use longfellow_sys::safe::VerifyType;
    let verify_type = match op {
        "gte" => VerifyType::Geq,
        "lte" => VerifyType::Leq,
        "eq" | "disclosure" | "set_member" => VerifyType::Eq,
        "neq" => VerifyType::Neq,
        other => return Err((StatusCode::BAD_REQUEST, format!("unsupported predicate op: {other}"))),
    };
    Ok(longfellow_sys::mdoc::AttributeRequest {
        namespace: "org.iso.18013.5.1".into(),
        identifier: claim.into(),
        cbor_value: cbor_value.to_vec(),
        verify_type,
    })
}

fn parse_mdoc_for_longfellow(token: &str) -> Result<(Vec<u8>, String, String), (StatusCode, String)> {
    let (mdoc_bytes, pk_x, pk_y) = parse_mdoc_token(token)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
    let pkx_hex = format!("0x{}", hex::encode(pk_x));
    let pky_hex = format!("0x{}", hex::encode(pk_y));
    Ok((mdoc_bytes, pkx_hex, pky_hex))
}

fn claim_to_cbor(value: &zk_eidas_types::credential::ClaimValue) -> Vec<u8> {
    use zk_eidas_types::credential::ClaimValue;
    match value {
        ClaimValue::Boolean(true) => vec![0xf5],
        ClaimValue::Boolean(false) => vec![0xf4],
        ClaimValue::Integer(n) if *n >= 0 && *n <= 23 => vec![*n as u8],
        ClaimValue::Integer(n) if *n >= 0 && *n <= 255 => vec![0x18, *n as u8],
        ClaimValue::Integer(n) if *n >= 0 => vec![0x19, (*n >> 8) as u8, *n as u8],
        ClaimValue::Integer(n) => {
            let abs = ((-1 - *n) as u64).to_be_bytes();
            let mut v = vec![0x3b];
            v.extend_from_slice(&abs);
            v
        }
        ClaimValue::String(s) => {
            let mut v = Vec::new();
            let len = s.len();
            if len <= 23 { v.push(0x60 + len as u8); }
            else { v.push(0x78); v.push(len as u8); }
            v.extend_from_slice(s.as_bytes());
            v
        }
        ClaimValue::Date { year, month, day } => {
            let s = format!("{year:04}-{month:02}-{day:02}");
            let mut v = vec![0xD9, 0x03, 0xEC]; // tag(1004)
            v.push(0x60 + s.len() as u8);
            v.extend_from_slice(s.as_bytes());
            v
        }
    }
}

/// Pad threshold CBOR to match the credential value's CBOR length.
/// The Longfellow circuit asserts vlen (from threshold) == actual value length.
/// For neq/gte/lte with different-length CBOR, we must pad the threshold with zeros.
fn pad_threshold_cbor(
    threshold_cbor: &[u8],
    claim_name: &str,
    claims: &std::collections::BTreeMap<String, zk_eidas_types::credential::ClaimValue>,
) -> Vec<u8> {
    if let Some(cv) = claims.get(claim_name) {
        let actual_cbor = claim_to_cbor(cv);
        if threshold_cbor.len() < actual_cbor.len() {
            let mut padded = threshold_cbor.to_vec();
            padded.resize(actual_cbor.len(), 0);
            return padded;
        }
    }
    threshold_cbor.to_vec()
}

/// Parse a threshold value string into a `ClaimValue` for CBOR encoding.
fn parse_threshold_value(_claim: &str, value_str: &str) -> zk_eidas_types::credential::ClaimValue {
    use zk_eidas_types::credential::ClaimValue;
    // Try date (YYYY-MM-DD)
    if value_str.len() == 10 && value_str.chars().nth(4) == Some('-') {
        let parts: Vec<&str> = value_str.split('-').collect();
        if parts.len() == 3 {
            if let (Ok(y), Ok(m), Ok(d)) = (parts[0].parse(), parts[1].parse(), parts[2].parse()) {
                return ClaimValue::Date { year: y, month: m, day: d };
            }
        }
    }
    // Try boolean
    if value_str == "true" { return ClaimValue::Boolean(true); }
    if value_str == "false" { return ClaimValue::Boolean(false); }
    // Try integer
    if let Ok(n) = value_str.parse::<i64>() { return ClaimValue::Integer(n); }
    // Default to string
    ClaimValue::String(value_str.to_string())
}

#[derive(Serialize)]
struct IssueResponse {
    credential: String,
    format: String,
    credential_type: String,
    credential_display: CredentialDisplay,
}

#[derive(Serialize)]
struct CredentialDisplay {
    fields: Vec<FieldDisplay>,
}

#[derive(Serialize)]
struct FieldDisplay {
    name: String,
    label: String,
    value: String,
}

async fn issue_credential(
    Json(req): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, (StatusCode, String)> {
    let known_types = ["pid", "drivers_license", "diploma", "vehicle", "student_id"];
    if !known_types.contains(&req.credential_type.as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unknown credential_type: {}", req.credential_type),
        ));
    }

    let claims_obj = req.claims.as_object().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "claims must be a JSON object".into(),
        )
    })?;

    let fields: Vec<FieldDisplay> = claims_obj
        .iter()
        .map(|(k, v)| FieldDisplay {
            name: k.clone(),
            label: k.clone(),
            value: match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            },
        })
        .collect();

    // Build mdoc credential for all types
    use zk_eidas_types::credential::ClaimValue;
    let claims_vec: Vec<(String, ClaimValue)> = claims_obj
        .iter()
        .map(|(k, v)| json_value_to_mdoc_claim(k, v).map(|cv| (k.clone(), cv)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("claim conversion error: {e}"),
            )
        })?;

    let claims_ref: Vec<(&str, ClaimValue)> = claims_vec
        .iter()
        .map(|(k, v)| (k.as_str(), v.clone()))
        .collect();

    let (mdoc_bytes, pub_key_x, pub_key_y) =
        zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(claims_ref, &req.issuer);

    use base64::Engine;
    let credential = format!(
        "mdoc:{}:{}:{}",
        base64::engine::general_purpose::STANDARD.encode(&mdoc_bytes),
        hex::encode(pub_key_x),
        hex::encode(pub_key_y),
    );
    let format = "mdoc".to_string();

    Ok(Json(IssueResponse {
        credential,
        format,
        credential_type: req.credential_type,
        credential_display: CredentialDisplay { fields },
    }))
}

/// Normalize a claim value for SD-JWT embedding.
/// Numeric strings become JSON numbers; non-birthdate date strings become
/// epoch-day integers so the parser won't misinterpret them as Date claims.
#[allow(dead_code)]
fn normalize_claim_for_sdjwt(name: &str, value: &serde_json::Value) -> serde_json::Value {
    let s = match value.as_str() {
        Some(s) => s,
        None => return value.clone(),
    };
    if let Ok(n) = s.parse::<i64>() {
        return serde_json::Value::Number(n.into());
    }
    let is_birthdate = name == "birthdate" || name == "birth_date";
    if !is_birthdate && looks_like_date(s) {
        if let Ok(cv) = parse_date_claim(s) {
            if let zk_eidas_types::credential::ClaimValue::Date { year, month, day } = cv {
                let epoch = zk_eidas_utils::date_to_epoch_days(year as u32, month as u32, day as u32);
                return serde_json::Value::Number(epoch.into());
            }
        }
    }
    value.clone()
}

fn looks_like_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10 && b[4] == b'-' && b[7] == b'-' && b[..4].iter().all(|c| c.is_ascii_digit())
}

/// Parse "YYYY-MM-DD" into ClaimValue::Date.
fn parse_date_claim(s: &str) -> Result<zk_eidas_types::credential::ClaimValue, String> {
    zk_eidas_types::credential::ClaimValue::from_date_str(s)
        .map_err(|e| e.to_string())
}

#[allow(dead_code)]
fn json_value_to_claim(
    name: &str,
    value: &serde_json::Value,
) -> Result<zk_eidas_types::credential::ClaimValue, String> {
    use zk_eidas_types::credential::ClaimValue;
    match value {
        serde_json::Value::Number(n) => {
            Ok(ClaimValue::Integer(n.as_i64().ok_or("not an integer")?))
        }
        serde_json::Value::String(s) => {
            let is_birthdate = name == "birthdate" || name == "birth_date";
            if looks_like_date(s) && is_birthdate {
                parse_date_claim(s)
            } else if looks_like_date(s) {
                let cv = parse_date_claim(s)?;
                let ClaimValue::Date { year, month, day } = cv else { unreachable!() };
                let epoch_days = zk_eidas_utils::date_to_epoch_days(year as u32, month as u32, day as u32);
                Ok(ClaimValue::Integer(epoch_days))
            } else {
                Ok(ClaimValue::String(s.clone()))
            }
        }
        serde_json::Value::Bool(b) => Ok(ClaimValue::Boolean(*b)),
        _ => Err(format!("unsupported claim value type: {value}")),
    }
}

/// Convert a JSON value to a ClaimValue for mdoc credentials.
/// Unlike `json_value_to_claim`, dates are kept as `ClaimValue::Date` (not epoch days)
/// since the mdoc CBOR format preserves date types natively.
fn json_value_to_mdoc_claim(
    name: &str,
    value: &serde_json::Value,
) -> Result<zk_eidas_types::credential::ClaimValue, String> {
    use zk_eidas_types::credential::ClaimValue;
    match value {
        serde_json::Value::Number(n) => {
            Ok(ClaimValue::Integer(n.as_i64().ok_or("not an integer")?))
        }
        serde_json::Value::String(s) => {
            // Heuristic: if it matches YYYY-MM-DD or field name ends with _date, parse as Date
            if looks_like_date(s) || name.ends_with("_date") || name == "birthdate" {
                parse_date_claim(s)
            } else {
                Ok(ClaimValue::String(s.clone()))
            }
        }
        serde_json::Value::Bool(b) => Ok(ClaimValue::Boolean(*b)),
        _ => Err(format!("unsupported claim value type: {value}")),
    }
}

// === Prove ===

#[derive(Deserialize)]
struct ProveRequest {
    credential: String,
    #[serde(default = "default_format")]
    format: String,
    predicates: Vec<PredicateRequest>,
    now: Option<String>,
}

#[derive(Deserialize, Clone)]
struct PredicateRequest {
    claim: String,
    op: String,
    value: serde_json::Value,
}

#[derive(Serialize)]
struct ProveResponse {
    proofs: Vec<ProofResult>,
    hidden_fields: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nullifier: Option<String>,
}

#[derive(Serialize, Clone)]
struct ProofResult {
    predicate: String,
    proof_json: String,
    proof_hex: String,
    op: String,
}


async fn generate_proof(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, String)> {
    // Longfellow only supports mdoc credentials
    if req.format != "mdoc" {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "SD-JWT proving not implemented — only mdoc is supported".into(),
        ));
    }

    // Parse the mdoc token for Longfellow (hex public key strings)
    let (mdoc_bytes, pkx_hex, pky_hex) = parse_mdoc_for_longfellow(&req.credential)?;

    // Also parse the mdoc to extract claim values (needed for eq/disclosure CBOR encoding)
    let (mdoc_bytes_parse, pk_x, pk_y) = parse_mdoc_token(&req.credential)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc token: {e}")))?;
    let credential =
        zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&mdoc_bytes_parse, pk_x, pk_y)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
    let claims = credential.claims().clone();

    // Build AttributeRequest list from predicates
    let mut attrs: Vec<longfellow_sys::mdoc::AttributeRequest> = Vec::new();
    for p in &req.predicates {
        let cbor_value = match p.op.as_str() {
            "eq" | "disclosure" | "set_member" => {
                // Use the actual claim value from the credential
                let cv = claims.get(&p.claim).ok_or_else(|| {
                    (StatusCode::BAD_REQUEST, format!("claim '{}' not found in credential", p.claim))
                })?;
                claim_to_cbor(cv)
            }
            _ => {
                // Use the threshold value from the request
                let value_str = p.value.as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| p.value.to_string());
                let cv = parse_threshold_value(&p.claim, &value_str);
                pad_threshold_cbor(&claim_to_cbor(&cv), &p.claim, &claims)
            }
        };
        attrs.push(predicate_to_attribute(&p.claim, &p.op, &cbor_value)?);
    }

    // Debug: dump attribute CBOR bytes
    eprintln!("[prove] {} attrs:", attrs.len());
    for attr in &attrs {
        eprintln!("  attr: id={} vtype={:?} cbor_hex={}",
            attr.identifier, attr.verify_type, hex::encode(&attr.cbor_value));
    }
    for (name, cv) in &claims {
        let cbor = claim_to_cbor(cv);
        eprintln!("  cred: {} = {:?} → cbor={}", name, cv, hex::encode(&cbor));
    }

    // Get or generate the cached circuit for this attribute count
    let _circuit_ref = get_circuit(&state, attrs.len()).await?;

    // Default `now` to current UTC time in ISO 8601 format
    let now = req.now.unwrap_or_else(|| {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        // Simple UTC timestamp: seconds since epoch → YYYY-MM-DDTHH:MM:SSZ
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;
        // Days since 1970-01-01
        let (year, month, day) = epoch_days_to_date(days as i64);
        format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
    });

    // Acquire proving semaphore (only one proof at a time)
    let _permit = state.prove_semaphore.acquire().await.map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "proving unavailable".to_string())
    })?;

    // Clone Arc<AppState> so the spawn_blocking closure can access the circuit
    let state_clone = Arc::clone(&state);
    let num_attrs = attrs.len();
    let attrs_clone = attrs.clone();
    let mdoc_bytes_clone = mdoc_bytes.clone();
    let pkx_clone = pkx_hex.clone();
    let pky_clone = pky_hex.clone();
    let now_clone = now.clone();

    let proof = tokio::task::spawn_blocking(move || {
        // SAFETY: nice() only adjusts scheduling priority; safe to call from any thread.
        unsafe { libc::nice(10) };
        let circuit = state_clone.longfellow_circuits[num_attrs - 1]
            .get()
            .ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, "circuit not initialized".to_string())
            })?;
        longfellow_sys::mdoc::prove(
            circuit,
            &mdoc_bytes_clone,
            &pkx_clone,
            &pky_clone,
            b"zk-eidas-demo",
            &attrs_clone,
            &now_clone,
            &[0u8; 8],
            &[[0u8; 32]; 8],
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove: {e}")))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))??;

    // Format response
    let proof_hex = format!("0x{}", hex::encode(&proof.proof_bytes));
    let proof_json = serde_json::json!({
        "proof_bytes": proof.proof_bytes,
        "nullifier_hash": hex::encode(proof.nullifier_hash),
        "binding_hash": hex::encode(proof.binding_hash),
    })
    .to_string();

    let results: Vec<ProofResult> = req.predicates.iter().map(|p| ProofResult {
        predicate: format!("{} {} {}", p.claim, p.op, p.value),
        proof_json: proof_json.clone(),
        proof_hex: proof_hex.clone(),
        op: p.op.clone(),
    }).collect();

    let hidden_fields: Vec<String> = req.predicates.iter()
        .filter(|p| p.op == "eq" || p.op == "disclosure")
        .map(|p| p.claim.clone())
        .collect();

    Ok(Json(ProveResponse {
        proofs: results,
        hidden_fields,
        nullifier: None,
    }))
}

/// Convert days since Unix epoch to (year, month, day).
fn epoch_days_to_date(days: i64) -> (i64, u32, u32) {
    // Civil calendar algorithm from Howard Hinnant
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

// === Verify ===

#[derive(Deserialize)]
struct VerifyProofInput {
    proof_json: String,
    predicate: String,
}

#[derive(Deserialize)]
struct VerifyRequest {
    proofs: Vec<VerifyProofInput>,
    #[serde(default)]
    hidden_fields: Vec<String>,
}

#[derive(Serialize)]
struct VerifyResponse {
    results: Vec<VerifyResult>,
    not_disclosed: Vec<String>,
}

#[derive(Serialize)]
struct VerifyResult {
    predicate: String,
    valid: bool,
}

async fn verify_proof(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    // Longfellow verification: structural check on each proof JSON.
    // Full ZK verification (sumcheck+ligero) happens on-chain; the demo endpoint
    // validates proof shape and extracts nullifier/binding hashes for display.
    let hidden_fields = req.hidden_fields;
    let mut results = Vec::new();

    for proof_input in &req.proofs {
        let proof_data: serde_json::Value =
            serde_json::from_str(&proof_input.proof_json)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid proof: {e}")))?;

        let valid = proof_data.get("proof_bytes").is_some()
            && proof_data.get("nullifier_hash").is_some()
            && proof_data.get("binding_hash").is_some();

        results.push(VerifyResult {
            predicate: proof_input.predicate.clone(),
            valid,
        });
    }

    Ok(Json(VerifyResponse {
        results,
        not_disclosed: hidden_fields,
    }))
}

// === Compound Prove ===

#[derive(Deserialize, Clone)]
struct CompoundProveRequest {
    credential: String,
    #[serde(default = "default_format")]
    format: String,
    predicates: Vec<PredicateRequest>,
    op: String, // "and" or "or"
    #[serde(default)]
    skip_cache: bool,
    #[serde(default)]
    identity_escrow: Option<EscrowRequest>,
}

#[derive(Deserialize, Clone)]
struct EscrowRequest {
    field_names: Vec<String>,
    authority_pubkey: String, // hex-encoded secp256k1 pubkey
}

#[derive(Deserialize)]
struct EscrowDecryptRequest {
    /// ECIES-encrypted symmetric key K (hex)
    encrypted_key: String,
    /// Escrow authority's secret key (hex)
    secret_key: String,
    /// Poseidon-CTR ciphertext field elements (hex strings)
    ciphertext: Vec<String>,
    /// Names of the encrypted fields
    field_names: Vec<String>,
}

#[derive(Serialize)]
struct EscrowDecryptResponse {
    /// Decrypted field name → value pairs
    fields: std::collections::HashMap<String, String>,
    /// Recovered symmetric key K (decimal)
    key: String,
}

#[derive(Serialize)]
struct CompoundProveResponse {
    compound_proof_json: String,
    op: String,
    sub_proofs_count: usize,
    hidden_fields: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cached: bool,
}

async fn generate_compound_proof(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CompoundProveRequest>,
) -> Result<Json<CompoundProveResponse>, (StatusCode, String)> {
    // Longfellow only supports mdoc credentials
    if req.format != "mdoc" {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "SD-JWT proving not implemented — only mdoc is supported".into(),
        ));
    }

    // Parse the mdoc token for Longfellow (hex public key strings)
    let (mdoc_bytes, pkx_hex, pky_hex) = parse_mdoc_for_longfellow(&req.credential)?;

    // Also parse the mdoc to extract claim values (needed for eq/disclosure CBOR encoding)
    let (mdoc_bytes_parse, pk_x, pk_y) = parse_mdoc_token(&req.credential)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc token: {e}")))?;
    let credential =
        zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&mdoc_bytes_parse, pk_x, pk_y)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
    let claims = credential.claims().clone();
    let all_field_names: Vec<String> = claims.keys().cloned().collect();

    // Build AttributeRequest list from predicates
    let mut attrs: Vec<longfellow_sys::mdoc::AttributeRequest> = Vec::new();
    let mut proven_claims: Vec<String> = Vec::new();
    for p in &req.predicates {
        if !proven_claims.contains(&p.claim) {
            proven_claims.push(p.claim.clone());
        }
        let cbor_value = match p.op.as_str() {
            "eq" | "disclosure" | "set_member" => {
                let cv = claims.get(&p.claim).ok_or_else(|| {
                    (StatusCode::BAD_REQUEST, format!("claim '{}' not found in credential", p.claim))
                })?;
                claim_to_cbor(cv)
            }
            _ => {
                let value_str = p.value.as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| p.value.to_string());
                let cv = parse_threshold_value(&p.claim, &value_str);
                pad_threshold_cbor(&claim_to_cbor(&cv), &p.claim, &claims)
            }
        };
        attrs.push(predicate_to_attribute(&p.claim, &p.op, &cbor_value)?);
    }

    // Check proof cache (after building attrs so we know the request is valid)
    let cache_key = compute_cache_key(&req);
    if !req.skip_cache {
        if let Some(cached) = state.proof_cache.get(&cache_key) {
            eprintln!("[prove-compound] CACHE HIT for key {cache_key}");
            let mut compound_json = cached.compound_proof_json.clone();
            if let Some(ref escrow_req) = req.identity_escrow {
                let (escrow_data, _escrow_fields) = generate_escrow_data(&claims, escrow_req)?;
                let mut compound: serde_json::Value = serde_json::from_str(&compound_json)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("cache parse: {e}")))?;
                compound["identity_escrow"] = escrow_data;
                compound_json = compound.to_string();
            }
            return Ok(Json(CompoundProveResponse {
                compound_proof_json: compound_json,
                op: cached.op.clone(),
                sub_proofs_count: cached.sub_proofs_count,
                hidden_fields: cached.hidden_fields.clone(),
                cached: true,
            }));
        }
    }
    eprintln!("[prove-compound] {} for key {cache_key}", if req.skip_cache { "CACHE SKIPPED" } else { "CACHE MISS" });

    // Log what we're about to prove
    eprintln!("[prove-compound] format={} predicates:", req.format);
    for pred in &req.predicates {
        eprintln!("  claim={} op={} value={}", pred.claim, pred.op, pred.value);
    }
    // Debug: dump attribute CBOR bytes
    for attr in &attrs {
        eprintln!("[prove-compound] attr: ns={} id={} vtype={:?} cbor_hex={}",
            attr.namespace, attr.identifier, attr.verify_type,
            hex::encode(&attr.cbor_value));
    }
    // Debug: also dump the actual claim values from the credential
    eprintln!("[prove-compound] credential claims:");
    for (name, cv) in &claims {
        let cbor = claim_to_cbor(cv);
        eprintln!("  {} = {:?} → cbor_hex={}", name, cv, hex::encode(&cbor));
    }

    // Get or generate the cached circuit for this attribute count
    let _circuit_ref = get_circuit(&state, attrs.len()).await?;

    // Default `now` to current UTC time in ISO 8601 format
    let now = {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;
        let (year, month, day) = epoch_days_to_date(days as i64);
        format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
    };

    // Acquire proving semaphore (only one proof at a time)
    let _permit = state.prove_semaphore.acquire().await.map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "proving unavailable".to_string())
    })?;

    // Pre-compute escrow_fields before spawning (needed by the circuit)
    let (escrow_json_value_opt, escrow_fields) = if let Some(ref escrow_req) = req.identity_escrow {
        let (json_val, fields) = generate_escrow_data(&claims, escrow_req)?;
        (Some(json_val), fields)
    } else {
        (None, [[0u8; 32]; 8])
    };

    // Clone for the spawn_blocking closure
    let state_clone = Arc::clone(&state);
    let num_attrs = attrs.len();
    let attrs_clone = attrs.clone();
    let mdoc_bytes_clone = mdoc_bytes.clone();
    let pkx_clone = pkx_hex.clone();
    let pky_clone = pky_hex.clone();
    let now_clone = now.clone();

    let proof = tokio::task::spawn_blocking(move || {
        // SAFETY: nice() only adjusts scheduling priority; safe to call from any thread.
        unsafe { libc::nice(10) };
        let circuit = state_clone.longfellow_circuits[num_attrs - 1]
            .get()
            .ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, "circuit not initialized".to_string())
            })?;
        longfellow_sys::mdoc::prove(
            circuit,
            &mdoc_bytes_clone,
            &pkx_clone,
            &pky_clone,
            b"zk-eidas-demo",
            &attrs_clone,
            &now_clone,
            &[0u8; 8],
            &escrow_fields,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove: {e}")))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))??;

    // Serialize MdocProof as the compound proof JSON
    let mut compound_proof_json_val = serde_json::json!({
        "proof_bytes": proof.proof_bytes,
        "nullifier_hash": hex::encode(proof.nullifier_hash),
        "binding_hash": hex::encode(proof.binding_hash),
    });

    let op_label = req.op.clone();
    let sub_proofs_count = req.predicates.len();

    let hidden_fields: Vec<String> = all_field_names
        .iter()
        .filter(|f| !proven_claims.contains(f))
        .cloned()
        .collect();

    // Identity escrow: attach escrow data including circuit-computed escrow_digest
    if let Some(mut escrow_data) = escrow_json_value_opt {
        escrow_data["escrow_digest"] = serde_json::json!(proof.escrow_digest.to_vec());
        compound_proof_json_val["identity_escrow"] = escrow_data;
    }

    let compound_proof_json = compound_proof_json_val.to_string();

    Ok(Json(CompoundProveResponse {
        compound_proof_json,
        op: op_label,
        sub_proofs_count,
        hidden_fields,
        cached: false,
    }))
}

// === Compound Verify ===

#[derive(Deserialize)]
struct CompoundVerifyRequest {
    compound_proof_json: String,
    #[serde(default)]
    hidden_fields: Vec<String>,
}

#[derive(Serialize)]
struct CompoundVerifyResponse {
    valid: bool,
    op: String,
    sub_proofs_verified: usize,
    not_disclosed: Vec<String>,
}

async fn verify_compound_proof(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<CompoundVerifyRequest>,
) -> Result<Json<CompoundVerifyResponse>, (StatusCode, String)> {
    // Longfellow compound verification: structural check on the compound proof JSON.
    // In Longfellow all predicates are proved in a single circuit; "compound" is one
    // proof blob.  Full verification happens on-chain; the demo endpoint validates
    // proof shape and extracts nullifier/binding hashes for display.
    let proof_data: serde_json::Value =
        serde_json::from_str(&req.compound_proof_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid compound proof: {e}"),
            )
        })?;

    // Longfellow compound proofs come in two shapes:
    // 1. Direct: { proof_bytes, nullifier_hash, binding_hash } (from prove-compound)
    // 2. Contract: { sub_proofs: [...], nullifier_hash, op, role } (from contract-prove)
    let has_direct_proof = proof_data.get("proof_bytes").is_some();
    let sub_proofs = proof_data.get("sub_proofs").and_then(|sp| sp.as_array());
    let has_sub_proofs = sub_proofs.map(|arr| !arr.is_empty()).unwrap_or(false);

    let valid = has_direct_proof || has_sub_proofs;
    let sub_count = if has_direct_proof {
        // Direct proof proves all predicates in one circuit
        req.hidden_fields.len().max(1)
    } else {
        sub_proofs.map(|arr| arr.len()).unwrap_or(1)
    };

    Ok(Json(CompoundVerifyResponse {
        valid,
        op: "and".to_string(),
        sub_proofs_verified: if valid { sub_count } else { 0 },
        not_disclosed: req.hidden_fields,
    }))
}

// === Holder Binding ===

#[derive(Deserialize)]
struct ProveBindingRequest {
    credential_a: String,
    credential_b: String,
    #[serde(default = "default_format")]
    format_a: String,
    #[serde(default = "default_format")]
    format_b: String,
    binding_claim_a: String,
    binding_claim_b: String,
    predicates_a: Vec<PredicateRequest>,
    predicates_b: Vec<PredicateRequest>,
}

#[derive(Serialize)]
struct ProveBindingResponse {
    proofs_a: Vec<ProofResult>,
    proofs_b: Vec<ProofResult>,
    binding_hash: String,
    binding_verified: bool,
    hidden_fields_a: Vec<String>,
    hidden_fields_b: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    cached: bool,
}

async fn prove_binding(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveBindingRequest>,
) -> Result<Json<ProveBindingResponse>, (StatusCode, String)> {
    // Longfellow only supports mdoc credentials
    if req.format_a != "mdoc" || req.format_b != "mdoc" {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "SD-JWT proving not implemented — only mdoc is supported".into(),
        ));
    }

    // --- Helper closure: parse credential, build attrs, prove ---
    // Returns (proof, proofs_results, hidden_fields)
    async fn prove_one_credential(
        state: &Arc<AppState>,
        credential: &str,
        binding_claim: &str,
        predicates: &[PredicateRequest],
    ) -> Result<(longfellow_sys::mdoc::MdocProof, Vec<ProofResult>, Vec<String>), (StatusCode, String)> {
        // Parse mdoc
        let (mdoc_bytes, pkx_hex, pky_hex) = parse_mdoc_for_longfellow(credential)?;
        let (mdoc_bytes_parse, pk_x, pk_y) = parse_mdoc_token(credential)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc token: {e}")))?;
        let cred = zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&mdoc_bytes_parse, pk_x, pk_y)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
        let claims = cred.claims().clone();

        // Build attribute list — binding claim FIRST
        let mut attrs: Vec<longfellow_sys::mdoc::AttributeRequest> = Vec::new();

        // 1. Binding claim as first attribute (eq/disclosure on its actual value)
        let binding_cv = claims.get(binding_claim).ok_or_else(|| {
            (StatusCode::BAD_REQUEST, format!("binding claim '{}' not found", binding_claim))
        })?;
        let binding_cbor = claim_to_cbor(binding_cv);
        attrs.push(predicate_to_attribute(binding_claim, "eq", &binding_cbor)?);

        // 2. Predicate attributes
        for p in predicates {
            let cbor_value = match p.op.as_str() {
                "eq" | "disclosure" | "set_member" => {
                    let cv = claims.get(&p.claim).ok_or_else(|| {
                        (StatusCode::BAD_REQUEST, format!("claim '{}' not found", p.claim))
                    })?;
                    claim_to_cbor(cv)
                }
                _ => {
                    let value_str = p.value.as_str()
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| p.value.to_string());
                    let cv = parse_threshold_value(&p.claim, &value_str);
                    claim_to_cbor(&cv)
                }
            };
            attrs.push(predicate_to_attribute(&p.claim, &p.op, &cbor_value)?);
        }

        // Debug: dump binding attrs
        eprintln!("[prove-binding] {} attrs for '{}':", attrs.len(), binding_claim);
        for attr in &attrs {
            eprintln!("  attr: id={} vtype={:?} cbor_hex={}",
                attr.identifier, attr.verify_type, hex::encode(&attr.cbor_value));
        }
        for (name, cv) in &claims {
            let cbor = claim_to_cbor(cv);
            eprintln!("  cred: {} = {:?} → cbor={}", name, cv, hex::encode(&cbor));
        }

        // Get circuit
        let _circuit_ref = get_circuit(state, attrs.len()).await?;

        // Default now
        let now = {
            let d = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let secs = d.as_secs();
            let days = secs / 86400;
            let time_of_day = secs % 86400;
            let hours = time_of_day / 3600;
            let minutes = (time_of_day % 3600) / 60;
            let seconds = time_of_day % 60;
            let (year, month, day) = epoch_days_to_date(days as i64);
            format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
        };

        let num_attrs = attrs.len();
        let state_clone = Arc::clone(state);

        let proof = tokio::task::spawn_blocking(move || {
            unsafe { libc::nice(10) };
            let circuit = state_clone.longfellow_circuits[num_attrs - 1]
                .get()
                .ok_or_else(|| {
                    (StatusCode::INTERNAL_SERVER_ERROR, "circuit not initialized".to_string())
                })?;
            longfellow_sys::mdoc::prove(
                circuit,
                &mdoc_bytes,
                &pkx_hex,
                &pky_hex,
                b"zk-eidas-demo",
                &attrs,
                &now,
                &[0u8; 8],
                &[[0u8; 32]; 8],
            )
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove: {e}")))
        })
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))??;

        // Format results
        let proof_hex = format!("0x{}", hex::encode(&proof.proof_bytes));
        let proof_json = serde_json::json!({
            "proof_bytes": proof.proof_bytes,
            "nullifier_hash": hex::encode(proof.nullifier_hash),
            "binding_hash": hex::encode(proof.binding_hash),
        })
        .to_string();

        let results: Vec<ProofResult> = predicates.iter().map(|p| ProofResult {
            predicate: format!("{} {} {}", p.claim, p.op, p.value),
            proof_json: proof_json.clone(),
            proof_hex: proof_hex.clone(),
            op: p.op.clone(),
        }).collect();

        let hidden_fields: Vec<String> = predicates.iter()
            .filter(|p| p.op == "eq" || p.op == "disclosure")
            .map(|p| p.claim.clone())
            .collect();

        Ok((proof, results, hidden_fields))
    }

    // Acquire semaphore once, prove both in sequence
    let _permit = state.prove_semaphore.acquire().await.map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "proving unavailable".to_string())
    })?;

    let (proof_a, proofs_a, hidden_fields_a) = prove_one_credential(
        &state, &req.credential_a, &req.binding_claim_a, &req.predicates_a,
    ).await?;

    let (proof_b, proofs_b, hidden_fields_b) = prove_one_credential(
        &state, &req.credential_b, &req.binding_claim_b, &req.predicates_b,
    ).await?;

    let binding_verified = proof_a.binding_hash == proof_b.binding_hash;

    Ok(Json(ProveBindingResponse {
        proofs_a,
        proofs_b,
        binding_hash: format!("0x{}", hex::encode(proof_a.binding_hash)),
        binding_verified,
        hidden_fields_a,
        hidden_fields_b,
        cached: false,
    }))
}

// === Proof Export (CBOR) ===

#[derive(Deserialize)]
struct ExportRequest {
    proofs: Vec<ExportProofInput>,
}

#[derive(Deserialize)]
struct ExportProofInput {
    proof_json: String,
    predicate: String,
}

#[derive(Serialize)]
struct ExportResponse {
    cbor_base64: String,
    cbor_size_bytes: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed_cbor_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    compressed_size_bytes: Option<usize>,
}

async fn export_proof(
    Query(params): Query<HashMap<String, String>>,
    Json(req): Json<ExportRequest>,
) -> Result<Json<ExportResponse>, (StatusCode, String)> {
    // Try Longfellow format first (proof_bytes field), fall back to old ZkProof
    let first_proof: serde_json::Value = serde_json::from_str(
        &req.proofs.first().ok_or((StatusCode::BAD_REQUEST, "no proofs".into()))?.proof_json,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid proof JSON: {e}")))?;

    if first_proof.get("proof_bytes").is_some() {
        // Longfellow format: serialize proof envelope as JSON bytes for now
        let envelope = serde_json::json!({
            "version": "longfellow-1",
            "proofs": req.proofs.iter().map(|input| {
                serde_json::json!({
                    "predicate": input.predicate,
                    "proof_json": input.proof_json,
                })
            }).collect::<Vec<_>>(),
        });
        let buf = serde_json::to_vec(&envelope).map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("JSON encode: {e}"))
        })?;
        use base64::Engine;
        return Ok(Json(ExportResponse {
            cbor_base64: base64::engine::general_purpose::STANDARD.encode(&buf),
            cbor_size_bytes: buf.len(),
            compressed_cbor_base64: None,
            compressed_size_bytes: None,
        }));
    }

    // Legacy Groth16 format
    let mut zk_proofs = Vec::new();
    let mut descriptions = Vec::new();
    for input in &req.proofs {
        let proof: zk_eidas_types::proof::ZkProof = serde_json::from_str(&input.proof_json)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid proof JSON: {e}")))?;
        zk_proofs.push(proof);
        descriptions.push(input.predicate.clone());
    }
    let envelope =
        zk_eidas_types::envelope::ProofEnvelope::from_proofs(&zk_proofs, &descriptions);
    let cbor_bytes = envelope.to_bytes().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("CBOR encoding failed: {e}"),
        )
    })?;

    let cbor_size_bytes = cbor_bytes.len();
    use base64::Engine;
    let cbor_base64 = base64::engine::general_purpose::STANDARD.encode(&cbor_bytes);

    let (compressed_cbor_base64, compressed_size_bytes) =
        if params.get("compress").is_some_and(|v| v == "true") {
            let compressed = envelope.to_compressed_bytes().map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, e)
            })?;
            let size = compressed.len();
            (
                Some(base64::engine::general_purpose::STANDARD.encode(&compressed)),
                Some(size),
            )
        } else {
            (None, None)
        };

    Ok(Json(ExportResponse {
        cbor_base64,
        cbor_size_bytes,
        compressed_cbor_base64,
        compressed_size_bytes,
    }))
}

// === Compound Proof Export (CBOR) ===

#[derive(Deserialize)]
struct CompoundExportRequest {
    compound_proof_json: String,
}

async fn export_compound_proof(
    Query(params): Query<HashMap<String, String>>,
    Json(req): Json<CompoundExportRequest>,
) -> Result<Json<ExportResponse>, (StatusCode, String)> {
    let parsed: serde_json::Value =
        serde_json::from_str(&req.compound_proof_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid compound proof JSON: {e}"),
            )
        })?;

    // Longfellow format: compound proof has nullifier_hash field
    if parsed.get("nullifier_hash").is_some() {
        let buf = req.compound_proof_json.as_bytes().to_vec();
        use base64::Engine;
        return Ok(Json(ExportResponse {
            cbor_base64: base64::engine::general_purpose::STANDARD.encode(&buf),
            cbor_size_bytes: buf.len(),
            compressed_cbor_base64: None,
            compressed_size_bytes: None,
        }));
    }

    // Legacy Groth16 compound format
    let compound: zk_eidas_types::proof::CompoundProof =
        serde_json::from_str(&req.compound_proof_json).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid compound proof JSON: {e}"),
            )
        })?;

    let descriptions: Vec<String> = compound
        .proofs()
        .iter()
        .map(|p| format!("{:?}", p.predicate_op()))
        .collect();

    let mut envelope = zk_eidas_types::envelope::ProofEnvelope::from_proofs(compound.proofs(), &descriptions);
    envelope.set_logical_op(Some(compound.op()));

    let cbor_bytes = envelope.to_bytes().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("CBOR encoding failed: {e}"),
        )
    })?;
    let cbor_size_bytes = cbor_bytes.len();

    use base64::Engine;
    let cbor_base64 = base64::engine::general_purpose::STANDARD.encode(&cbor_bytes);

    let (compressed_cbor_base64, compressed_size_bytes) =
        if params.get("compress").is_some_and(|v| v == "true") {
            let compressed = envelope.to_compressed_bytes().map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    e,
                )
            })?;
            let size = compressed.len();
            (
                Some(base64::engine::general_purpose::STANDARD.encode(&compressed)),
                Some(size),
            )
        } else {
            (None, None)
        };

    Ok(Json(ExportResponse {
        cbor_base64,
        cbor_size_bytes,
        compressed_cbor_base64,
        compressed_size_bytes,
    }))
}

// === Contract Prove ===

#[derive(Deserialize)]
struct ContractProveRequest {
    credential: String,
    #[serde(default = "default_format")]
    format: String,
    predicates: Vec<PredicateRequest>,
    contract_terms: String,
    timestamp: String,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    identity_escrow: Option<EscrowRequest>,
}

#[derive(Serialize)]
struct ContractProveResponse {
    compound_proof_json: String,
    op: String,
    sub_proofs_count: usize,
    hidden_fields: Vec<String>,
    nullifier: String,
    contract_hash: String,
    salt: String,
    role: String,
}

async fn contract_prove(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContractProveRequest>,
) -> Result<Json<ContractProveResponse>, (StatusCode, String)> {
    // Longfellow only supports mdoc credentials
    if req.format != "mdoc" {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "SD-JWT proving not implemented — only mdoc is supported".into(),
        ));
    }

    let role_str = req.role.clone().unwrap_or_else(|| "holder".to_string());

    // Compute contract_hash = SHA256(terms || timestamp) → first 8 bytes
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(req.contract_terms.as_bytes());
    hasher.update(req.timestamp.as_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let contract_hash_bytes: [u8; 8] = hash[..8].try_into().unwrap();

    // Parse mdoc credential
    let (mdoc_bytes, pkx_hex, pky_hex) = parse_mdoc_for_longfellow(&req.credential)?;
    let (mdoc_bytes_parse, pk_x, pk_y) = parse_mdoc_token(&req.credential)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc token: {e}")))?;
    let credential = zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&mdoc_bytes_parse, pk_x, pk_y)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
    let claims = credential.claims().clone();

    // Build attribute list from predicates
    let mut attrs: Vec<longfellow_sys::mdoc::AttributeRequest> = Vec::new();
    for p in &req.predicates {
        let cbor_value = match p.op.as_str() {
            "eq" | "disclosure" | "set_member" => {
                let cv = claims.get(&p.claim).ok_or_else(|| {
                    (StatusCode::BAD_REQUEST, format!("claim '{}' not found in credential", p.claim))
                })?;
                claim_to_cbor(cv)
            }
            _ => {
                let value_str = p.value.as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| p.value.to_string());
                let cv = parse_threshold_value(&p.claim, &value_str);
                pad_threshold_cbor(&claim_to_cbor(&cv), &p.claim, &claims)
            }
        };
        attrs.push(predicate_to_attribute(&p.claim, &p.op, &cbor_value)?);
    }

    if attrs.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "at least one predicate is required".into()));
    }

    // Debug: dump attrs and credential claims
    eprintln!("[contract-prove] role={} {} attrs:", role_str, attrs.len());
    for attr in &attrs {
        eprintln!("  attr: id={} vtype={:?} cbor_hex={}",
            attr.identifier, attr.verify_type, hex::encode(&attr.cbor_value));
    }
    for (name, cv) in &claims {
        let cbor = claim_to_cbor(cv);
        eprintln!("  cred: {} = {:?} → cbor={}", name, cv, hex::encode(&cbor));
    }

    // Get or generate the cached circuit
    let _circuit_ref = get_circuit(&state, attrs.len()).await?;

    // Default now
    let now = {
        let d = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let secs = d.as_secs();
        let days = secs / 86400;
        let time_of_day = secs % 86400;
        let hours = time_of_day / 3600;
        let minutes = (time_of_day % 3600) / 60;
        let seconds = time_of_day % 60;
        let (year, month, day) = epoch_days_to_date(days as i64);
        format!("{year:04}-{month:02}-{day:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
    };

    // Pre-compute escrow_fields before spawning (needed by the circuit)
    let (escrow_json_value_opt, escrow_fields_contract) = if let Some(ref escrow_req) = req.identity_escrow {
        let (json_val, fields) = generate_escrow_data(&claims, escrow_req)?;
        (Some(json_val), fields)
    } else {
        (None, [[0u8; 32]; 8])
    };

    // Acquire proving semaphore
    let _permit = state.prove_semaphore.acquire().await.map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "proving unavailable".to_string())
    })?;

    let num_attrs = attrs.len();
    let state_clone = Arc::clone(&state);

    // Longfellow does it all in ONE call: predicates + nullifier
    let proof = tokio::task::spawn_blocking(move || {
        unsafe { libc::nice(10) };
        let circuit = state_clone.longfellow_circuits[num_attrs - 1]
            .get()
            .ok_or_else(|| {
                (StatusCode::INTERNAL_SERVER_ERROR, "circuit not initialized".to_string())
            })?;
        longfellow_sys::mdoc::prove(
            circuit,
            &mdoc_bytes,
            &pkx_hex,
            &pky_hex,
            b"zk-eidas-demo",
            &attrs,
            &now,
            &contract_hash_bytes,
            &escrow_fields_contract,
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("prove: {e}")))
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))??;

    // Format response
    let proof_hex = format!("0x{}", hex::encode(&proof.proof_bytes));
    let nullifier_hex = format!("0x{}", hex::encode(proof.nullifier_hash));

    let proof_json = serde_json::json!({
        "proof_bytes": proof.proof_bytes,
        "nullifier_hash": hex::encode(proof.nullifier_hash),
        "binding_hash": hex::encode(proof.binding_hash),
    })
    .to_string();

    // Build compound proof JSON wrapping the sub-proofs
    let sub_results: Vec<serde_json::Value> = req.predicates.iter().map(|p| {
        serde_json::json!({
            "predicate": format!("{} {} {}", p.claim, p.op, p.value),
            "proof_json": proof_json,
            "proof_hex": proof_hex,
            "op": p.op,
        })
    }).collect();

    let mut compound = serde_json::json!({
        "op": "AND",
        "sub_proofs": sub_results,
        "nullifier_hash": hex::encode(proof.nullifier_hash),
        "contract_hash": hex::encode(&contract_hash_bytes),
        "role": role_str,
        "contract_nullifiers": [{
            "nullifier": proof.nullifier_hash.to_vec(),
            "contract_hash": hex::encode(&contract_hash_bytes),
        }],
    });

    // Identity escrow: attach escrow data including circuit-computed escrow_digest
    if let Some(mut escrow_data) = escrow_json_value_opt {
        escrow_data["escrow_digest"] = serde_json::json!(proof.escrow_digest.to_vec());
        compound["identity_escrow"] = escrow_data;
    }

    let compound_proof_json = compound.to_string();

    let hidden_fields: Vec<String> = req.predicates.iter()
        .filter(|p| p.op == "eq" || p.op == "disclosure")
        .map(|p| p.claim.clone())
        .collect();

    let contract_hash_u64 = u64::from_be_bytes(contract_hash_bytes);

    Ok(Json(ContractProveResponse {
        compound_proof_json,
        op: "AND".to_string(),
        sub_proofs_count: req.predicates.len(),
        hidden_fields,
        nullifier: nullifier_hex,
        contract_hash: format!("0x{:016x}", contract_hash_u64),
        salt: "0x0000000000000000".to_string(),
        role: role_str,
    }))
}

// === Revocation ===

async fn revoke_credential(
    State(state): State<Arc<AppState>>,
    Json(body): Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    let credential_index = body["credential_index"].as_u64().unwrap_or(0) as usize;
    let mut status_list = state.status_list.lock().await;
    let byte_index = credential_index / 8;
    while status_list.len() <= byte_index {
        status_list.push(0);
    }
    status_list[byte_index] |= 1 << (credential_index % 8);
    Json(serde_json::json!({
        "status": "revoked",
        "credential_index": credential_index
    }))
}

async fn revocation_status(
    State(state): State<Arc<AppState>>,
) -> impl axum::response::IntoResponse {
    let status_list = state.status_list.lock().await;
    Json(serde_json::json!({
        "status_list_size": status_list.len(),
        "total_bits": status_list.len() * 8
    }))
}

// === Presentation Request (OpenID4VP) ===

// Minimal OpenID4VP types (inlined from zk-eidas facade, no prover dependency).

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidPresentationDefinition {
    id: String,
    input_descriptors: Vec<OidInputDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidInputDescriptor {
    id: String,
    constraints: Vec<OidFieldConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidFieldConstraint {
    path: String,
    predicate_op: String,
    value: String,
}

async fn presentation_request(
    Json(body): Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    let requirements = body["requirements"].as_array();
    let descriptors: Vec<OidInputDescriptor> = match requirements {
        Some(reqs) => reqs
            .iter()
            .enumerate()
            .map(|(i, req)| OidInputDescriptor {
                id: format!("requirement-{}", i),
                constraints: vec![OidFieldConstraint {
                    path: format!("$.{}", req["claim"].as_str().unwrap_or("")),
                    predicate_op: req["op"].as_str().unwrap_or("gte").to_string(),
                    value: req["value"].as_str().unwrap_or("").to_string(),
                }],
            })
            .collect(),
        None => vec![],
    };

    let id = format!(
        "pd-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    );

    let pd = OidPresentationDefinition {
        id,
        input_descriptors: descriptors,
    };

    Json(serde_json::to_value(&pd).unwrap())
}

// === Proof Cache ===

fn compute_cache_key(req: &CompoundProveRequest) -> String {
    // Hash predicates only (NOT escrow — escrow is credential-specific, generated fresh).
    // For gte/lte ops, omit the value — it's typically epoch_days_today() which
    // drifts over time, causing cache misses against build-time pre-warmed proofs.
    let preds: Vec<serde_json::Value> = req.predicates.iter().map(|p| {
        if matches!(p.op.as_str(), "gte" | "lte") {
            serde_json::json!({"claim": p.claim, "op": p.op})
        } else {
            serde_json::json!({"claim": p.claim, "op": p.op, "value": p.value})
        }
    }).collect();
    let key_material = format!("{}|{}", req.format, serde_json::to_string(&preds).unwrap());
    format!("{:016x}", fnv_hash(key_material.as_bytes()))
}

/// Encrypt credential field values with AES-256-GCM.
fn escrow_encrypt_fields(
    fields: &[(&str, &[u8])],
    key: &[u8; 32],
) -> Result<(Vec<Vec<u8>>, Vec<Vec<u8>>), String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    let cipher = Aes256Gcm::new(key.into());
    let mut ciphertexts = Vec::new();
    let mut tags = Vec::new();
    for (i, (_name, value)) in fields.iter().enumerate() {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[8..12].copy_from_slice(&(i as u32).to_be_bytes());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher.encrypt(nonce, value.as_ref())
            .map_err(|e| format!("AES-GCM encrypt: {e}"))?;
        let (ct_only, tag) = ct.split_at(ct.len() - 16);
        ciphertexts.push(ct_only.to_vec());
        tags.push(tag.to_vec());
    }
    Ok((ciphertexts, tags))
}

/// Derive a deterministic symmetric key from field data and authority pubkey.
fn escrow_derive_key(field_values: &[Vec<u8>], authority_pubkey: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    for v in field_values {
        hasher.update(v);
    }
    hasher.update(authority_pubkey);
    let hash: [u8; 32] = hasher.finalize().into();
    let mut key = [0u8; 32];
    key[1..].copy_from_slice(&hash[..31]);
    key
}

/// Encrypt the symmetric key to the escrow authority's ML-KEM-768 public key.
fn escrow_encrypt_key(key: &[u8; 32], authority_pubkey: &[u8]) -> Result<Vec<u8>, String> {
    use ml_kem::kem::Encapsulate;
    let seed: [u8; 64] = authority_pubkey.try_into()
        .map_err(|_| format!("ML-KEM-768 authority key must be 64-byte seed, got {} bytes", authority_pubkey.len()))?;
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed.into());
    let ek = dk.encapsulation_key().clone();
    let (ct, ss) = ek.encapsulate();
    use sha2::{Sha256, Digest};
    let ss_bytes: &[u8] = ss.as_ref();
    let mask: [u8; 32] = Sha256::digest(ss_bytes).into();
    let mut encrypted_k = [0u8; 32];
    for i in 0..32 { encrypted_k[i] = key[i] ^ mask[i]; }
    let ct_ref: &[u8] = ct.as_ref();
    let mut result = Vec::with_capacity(ct_ref.len() + 32);
    result.extend_from_slice(ct_ref);
    result.extend_from_slice(&encrypted_k);
    Ok(result)
}

/// Generate identity escrow data for the given credential claims and escrow request.
/// Returns the JSON escrow payload and the packed 32-byte field array for the circuit.
fn generate_escrow_data(
    claims: &std::collections::BTreeMap<String, zk_eidas_types::credential::ClaimValue>,
    escrow_req: &EscrowRequest,
) -> Result<(serde_json::Value, [[u8; 32]; 8]), (StatusCode, String)> {
    let authority_pubkey = hex::decode(&escrow_req.authority_pubkey)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid authority_pubkey hex: {e}")))?;
    let mut field_pairs: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut escrow_fields = [[0u8; 32]; 8];
    for (i, name) in escrow_req.field_names.iter().enumerate() {
        if i >= 8 {
            return Err((StatusCode::BAD_REQUEST, "escrow supports at most 8 fields".into()));
        }
        let cv = claims.get(name).ok_or_else(|| {
            (StatusCode::BAD_REQUEST, format!("escrow field '{}' not found in credential", name))
        })?;
        let value_str = match cv {
            zk_eidas_types::credential::ClaimValue::String(s) => s.clone(),
            zk_eidas_types::credential::ClaimValue::Integer(n) => n.to_string(),
            zk_eidas_types::credential::ClaimValue::Boolean(b) => b.to_string(),
            zk_eidas_types::credential::ClaimValue::Date { year, month, day } => format!("{year:04}-{month:02}-{day:02}"),
        };
        let bytes = value_str.as_bytes();
        let copy_len = bytes.len().min(32);
        escrow_fields[i][..copy_len].copy_from_slice(&bytes[..copy_len]);
        field_pairs.push((name.as_str(), value_str.into_bytes()));
    }
    let field_value_bytes: Vec<Vec<u8>> = field_pairs.iter().map(|(_, v)| v.clone()).collect();
    let key = escrow_derive_key(&field_value_bytes, &authority_pubkey);
    let field_refs: Vec<(&str, &[u8])> = field_pairs.iter().map(|(n, v)| (*n, v.as_slice())).collect();
    let (ciphertexts, tags) = escrow_encrypt_fields(&field_refs, &key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("escrow encrypt: {e}")))?;
    let encrypted_key = escrow_encrypt_key(&key, &authority_pubkey)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("escrow key encrypt: {e}")))?;
    Ok((serde_json::json!({
        "ciphertexts": ciphertexts,
        "tags": tags,
        "encrypted_key": encrypted_key,
        "authority_pubkey": authority_pubkey,
        "field_names": escrow_req.field_names,
    }), escrow_fields))
}

fn fnv_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

struct LoadedCache {
    proofs: HashMap<String, CachedProof>,
}

fn load_proof_cache(api_dir: &str) -> LoadedCache {
    let empty = || LoadedCache { proofs: HashMap::new() };

    // Try directory-based cache first
    let dir_candidates = [
        std::env::var("PROOF_CACHE_PATH").ok().map(std::path::PathBuf::from),
        Some(std::path::PathBuf::from("proof-cache")),
        Some(std::path::PathBuf::from(api_dir).join("proof-cache")),
    ];

    if let Some(cache_dir) = dir_candidates.iter().flatten().find(|p| p.is_dir()) {
        return load_proof_cache_dir(cache_dir);
    }

    // Fall back to monolithic JSON file
    let file_candidates = [
        Some(std::path::PathBuf::from("proof-cache.json")),
        Some(std::path::PathBuf::from(api_dir).join("proof-cache.json")),
    ];
    let cache_path = match file_candidates.iter().flatten().find(|p| p.exists()) {
        Some(p) => p.clone(),
        None => {
            eprintln!("[cache] No proof-cache found, running without cache");
            return empty();
        }
    };
    let data = std::fs::read_to_string(&cache_path).unwrap_or_default();
    let parsed: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[cache] Failed to parse proof-cache.json: {e}");
            return empty();
        }
    };
    load_proof_cache_from_value(&parsed, &cache_path.display().to_string())
}

fn load_proof_cache_dir(cache_dir: &std::path::Path) -> LoadedCache {
    let mut proofs = HashMap::new();

    let read_dir_entries = |subdir: &str| -> Vec<(String, serde_json::Value)> {
        let path = cache_dir.join(subdir);
        if !path.is_dir() { return vec![]; }
        let mut entries = vec![];
        if let Ok(dir) = std::fs::read_dir(&path) {
            for entry in dir.flatten() {
                let p = entry.path();
                if p.extension().is_some_and(|e| e == "json") {
                    let key = p.file_stem().unwrap_or_default().to_string_lossy().to_string();
                    if let Ok(data) = std::fs::read_to_string(&p) {
                        if let Ok(val) = serde_json::from_str(&data) {
                            entries.push((key, val));
                        }
                    }
                }
            }
        }
        entries
    };

    for (key, val) in read_dir_entries("predicate") {
        if let Ok(cached) = serde_json::from_value::<CachedProof>(val) {
            proofs.insert(key, cached);
        }
    }

    eprintln!("[cache] Loaded {} cached proofs from {}", proofs.len(), cache_dir.display());
    LoadedCache { proofs }
}

fn load_proof_cache_from_value(parsed: &serde_json::Value, source: &str) -> LoadedCache {
    let mut proofs = HashMap::new();
    if let Some(entries) = parsed["entries"].as_object() {
        for (key, entry) in entries {
            if let Ok(cached) = serde_json::from_value::<CachedProof>(entry.clone()) {
                proofs.insert(key.clone(), cached);
            }
        }
    }
    eprintln!("[cache] Loaded {} cached proofs from {}", proofs.len(), source);
    LoadedCache { proofs }
}

// === Circuit Artifact Serving ===

async fn serve_circuit_artifact(
    State(state): State<Arc<AppState>>,
    AxumPath(rest): AxumPath<String>,
) -> impl axum::response::IntoResponse {
    let file = rest.split('/').last().unwrap_or("");
    let base = std::path::PathBuf::from(&state.circuits_path)
        .canonicalize()
        .unwrap_or_else(|_| std::path::PathBuf::from(&state.circuits_path));
    let path = base.join(&rest);
    // Prevent path traversal: resolved path must stay within circuits dir
    let canonical = match path.canonicalize() {
        Ok(p) if p.starts_with(&base) => p,
        _ => {
            return axum::response::Response::builder()
                .status(404)
                .body(Body::from("Not found"))
                .unwrap();
        }
    };
    match tokio::fs::read(&canonical).await {
        Ok(data) => {
            let content_type = if file.ends_with(".wasm") {
                "application/wasm"
            } else if file.ends_with(".json") {
                "application/json"
            } else {
                "application/octet-stream"
            };
            axum::response::Response::builder()
                .header("content-type", content_type)
                .body(Body::from(data))
                .unwrap()
        }
        Err(_) => axum::response::Response::builder()
            .status(404)
            .body(Body::from("Not found"))
            .unwrap(),
    }
}

/// Decrypt the symmetric key K from ML-KEM-768 ciphertext (inlined from zk-eidas facade).
///
/// `encrypted` is (ciphertext || encrypted_k) as produced by the escrow encrypt path.
/// `secret_key` is the ML-KEM-768 seed (64 bytes).
/// Returns K as a decimal string.
fn escrow_decrypt_key(encrypted: &[u8], secret_key: &[u8]) -> Result<String, String> {
    use ml_kem::kem::TryDecapsulate;
    use num_bigint::BigUint;
    use sha2::{Digest, Sha256};

    let seed: [u8; 64] = secret_key.try_into()
        .map_err(|_| format!("ML-KEM-768 seed must be 64 bytes, got {}", secret_key.len()))?;
    let dk = ml_kem::ml_kem_768::DecapsulationKey::from_seed(seed.into());

    let ct_size = encrypted.len().checked_sub(32)
        .ok_or_else(|| "encrypted data too short".to_string())?;
    let ct_bytes = &encrypted[..ct_size];
    let encrypted_k = &encrypted[ct_size..];

    let ct_array: ml_kem::ml_kem_768::Ciphertext = ct_bytes.try_into()
        .map_err(|_| format!("invalid ML-KEM ciphertext size: {}", ct_bytes.len()))?;
    let ss = dk.try_decapsulate(&ct_array)
        .map_err(|_| "ML-KEM decapsulation failed".to_string())?;

    let ss_bytes: &[u8] = ss.as_ref();
    let mask: [u8; 32] = Sha256::digest(ss_bytes).into();
    let mut k_padded = [0u8; 32];
    for i in 0..32 {
        k_padded[i] = encrypted_k[i] ^ mask[i];
    }

    Ok(BigUint::from_bytes_be(&k_padded).to_string())
}

async fn escrow_decrypt(
    Json(req): Json<EscrowDecryptRequest>,
) -> Result<Json<EscrowDecryptResponse>, (StatusCode, String)> {
    let encrypted_key = hex::decode(&req.encrypted_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid encrypted_key hex: {e}")))?;
    let secret_key = hex::decode(&req.secret_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid secret_key hex: {e}")))?;

    let k = escrow_decrypt_key(&encrypted_key, &secret_key)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("decrypt failed: {e}")))?;

    // Return ciphertext with field names — full Poseidon-CTR decryption
    // requires K and counter logic that happens outside this endpoint.
    // The important part is proving ECIES decryption works.
    let mut fields = std::collections::HashMap::new();
    for (i, name) in req.field_names.iter().enumerate() {
        let ct = req.ciphertext.get(i).cloned().unwrap_or_default();
        fields.insert(name.clone(), ct);
    }

    Ok(Json(EscrowDecryptResponse { fields, key: k }))
}

// === App Builder ===

fn build_cors_layer() -> CorsLayer {
    match std::env::var("CORS_ORIGIN") {
        Ok(origin) => {
            let origin: axum::http::HeaderValue = origin.parse().expect("invalid CORS_ORIGIN");
            CorsLayer::new()
                .allow_origin(AllowOrigin::exact(origin))
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                ])
                .allow_headers([axum::http::header::CONTENT_TYPE])
        }
        Err(_) => CorsLayer::permissive(),
    }
}

// === Longfellow Circuit Cache ===

/// Lazily generate and cache a `MdocCircuit` for the given attribute count (1–4).
async fn get_circuit(
    state: &AppState,
    num_attrs: usize,
) -> Result<&longfellow_sys::mdoc::MdocCircuit, (StatusCode, String)> {
    if num_attrs == 0 || num_attrs > 4 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("num_attrs must be 1-4, got {num_attrs}"),
        ));
    }
    state.longfellow_circuits[num_attrs - 1]
        .get_or_try_init(|| async {
            tokio::task::spawn_blocking(move || {
                longfellow_sys::mdoc::MdocCircuit::generate(num_attrs)
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("circuit gen: {e}")))
            })
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join: {e}")))?
        })
        .await
}

// === Longfellow Demo ===

async fn longfellow_demo(
    State(state): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let total_start = std::time::Instant::now();

    // Generate circuit once (cached across requests)
    let circuit_start = std::time::Instant::now();
    let circuit_bytes = state.longfellow_circuit.get_or_try_init(|| async {
        tokio::task::spawn_blocking(|| {
            longfellow_sys::safe::gen_circuit(0) // 1-attribute v7 circuit
        })
        .await
        .map_err(|e| format!("join error: {e}"))?
        .map_err(|e| format!("circuit gen: {e}"))
    }).await.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    let circuit_ms = circuit_start.elapsed().as_millis();
    let circuit_cached = circuit_ms < 100; // <100ms means it was cached

    // Prove + verify using cached circuit bytes
    let circuit_clone = circuit_bytes.clone();
    let prove_start = std::time::Instant::now();
    let (result, proof_size) = tokio::task::spawn_blocking(move || unsafe {
        let mut proof_ptr: *mut u8 = std::ptr::null_mut();
        let mut proof_len: std::os::raw::c_ulong = 0;
        let ret = longfellow_sys::longfellow_prove_verify_cached(
            circuit_clone.as_ptr(),
            circuit_clone.len() as std::os::raw::c_ulong,
            &mut proof_ptr,
            &mut proof_len,
        );
        let size = proof_len as usize;
        if !proof_ptr.is_null() {
            libc::free(proof_ptr as *mut libc::c_void);
        }
        (ret, size)
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("join error: {e}")))?;
    let prove_ms = prove_start.elapsed().as_millis();

    let total_ms = total_start.elapsed().as_millis();

    if result == 0 {
        Ok(Json(serde_json::json!({
            "status": "success",
            "backend": "longfellow",
            "proving_system": "sumcheck+ligero",
            "quantum_safe": true,
            "trusted_setup": false,
            "test": "age_over_18 on built-in mdoc",
            "circuit_bytes": circuit_bytes.len(),
            "proof_bytes": proof_size,
            "timing": {
                "circuit_gen_ms": circuit_ms,
                "circuit_cached": circuit_cached,
                "prove_verify_ms": prove_ms,
                "total_ms": total_ms,
            }
        })))
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Longfellow smoke test failed with code {result}"),
        ))
    }
}

// === Proof Blob Store ===

async fn store_proof_blob(
    State(state): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(&body);
    let cid = hex::encode(hasher.finalize());
    state
        .proof_blobs
        .write()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("lock poisoned: {e}")))?
        .insert(cid.clone(), body.to_vec());
    Ok(Json(serde_json::json!({ "cid": cid })))
}

async fn get_proof_blob(
    State(state): State<Arc<AppState>>,
    AxumPath(cid): AxumPath<String>,
) -> Result<impl axum::response::IntoResponse, (StatusCode, String)> {
    let bytes = state
        .proof_blobs
        .read()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("lock poisoned: {e}")))?
        .get(&cid)
        .cloned()
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("blob not found: {cid}")))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        bytes,
    ))
}

// === TSP (Trusted Service Provider) ===

async fn tsp_pubkey(
    State(state): State<Arc<AppState>>,
) -> Json<serde_json::Value> {
    use p256::ecdsa::VerifyingKey;
    let vk = VerifyingKey::from(&state.tsp_signing_key);
    let point = vk.to_encoded_point(false);
    Json(serde_json::json!({
        "publicKey": hex::encode(point.as_bytes()),
        "algorithm": "ES256",
        "curve": "P-256",
    }))
}

#[derive(Deserialize)]
struct AttestRequest {
    cid: String,
    predicate: String,
    #[serde(rename = "credentialType")]
    credential_type: String,
}

async fn tsp_attest(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AttestRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    use p256::ecdsa::{signature::Signer, Signature, VerifyingKey};
    use sha2::{Digest, Sha256};

    // 1. Verify proof exists in blob store
    {
        let blobs = state.proof_blobs.read().unwrap();
        blobs.get(&req.cid).ok_or((StatusCode::NOT_FOUND, format!("proof CID {} not found", req.cid)))?;
    };

    // 2. Build W3C VC attestation
    let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let vk = VerifyingKey::from(&state.tsp_signing_key);
    let issuer_pubkey = hex::encode(vk.to_encoded_point(false).as_bytes());

    let vc_without_proof = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", "ProofAttestation"],
        "issuer": format!("did:key:{}", &issuer_pubkey[..32]),
        "issuanceDate": now,
        "credentialSubject": {
            "proofCid": req.cid,
            "predicate": req.predicate,
            "credentialType": req.credential_type,
            "verificationResult": "valid",
            "proofSystem": "longfellow-sumcheck-ligero",
        },
    });

    // 3. Sign: SHA-256(canonical JSON) then ECDSA
    let canonical = serde_json::to_string(&vc_without_proof)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let digest = Sha256::digest(canonical.as_bytes());
    let signature: Signature = state.tsp_signing_key.sign(&digest);
    let sig_hex = hex::encode(signature.to_bytes());

    Ok(Json(serde_json::json!({
        "@context": vc_without_proof["@context"],
        "type": vc_without_proof["type"],
        "issuer": vc_without_proof["issuer"],
        "issuanceDate": vc_without_proof["issuanceDate"],
        "credentialSubject": vc_without_proof["credentialSubject"],
        "proof": {
            "type": "DataIntegrityProof",
            "cryptosuite": "ecdsa-jcs-2019",
            "verificationMethod": issuer_pubkey,
            "proofValue": sig_hex,
        }
    })))
}

pub fn build_app(circuits_path: &str) -> (Router, Arc<AppState>) {
    let api_dir = env!("CARGO_MANIFEST_DIR");
    let loaded = load_proof_cache(api_dir);
    let state = Arc::new(AppState {
        circuits_path: circuits_path.to_string(),
        status_list: Mutex::new(Vec::new()),
        prove_semaphore: Semaphore::new(1),  // one proof at a time
        proof_cache: loaded.proofs,
        longfellow_circuit: tokio::sync::OnceCell::new(),
        longfellow_circuits: std::array::from_fn(|_| tokio::sync::OnceCell::new()),
        proof_blobs: std::sync::RwLock::new(HashMap::new()),
        tsp_signing_key: p256::ecdsa::SigningKey::random(&mut rand::thread_rng()),
    });

    let router = Router::new()
        .route("/issuer/issue", post(issue_credential))
        .route("/holder/prove", post(generate_proof))
        .route("/verifier/verify", post(verify_proof))
        .route("/holder/proof-export", post(export_proof))
        .route("/holder/proof-export-compound", post(export_compound_proof))
        .route("/holder/prove-compound", post(generate_compound_proof))
        .route("/holder/prove-binding", post(prove_binding))
        .route("/verifier/verify-compound", post(verify_compound_proof))
        .route("/holder/contract-prove", post(contract_prove))
        // NOTE: revocation endpoints are unauthenticated.
        // A production deployment MUST add authorization middleware.
        .route("/issuer/revoke", post(revoke_credential))
        .route("/issuer/revocation-status", get(revocation_status))
        .route("/issuer/revocation-root", get(revocation_status))  // backward compat alias
        .route("/circuits/{*rest}", get(serve_circuit_artifact))
        .route("/verifier/presentation-request", post(presentation_request))
        .route("/escrow/decrypt", post(escrow_decrypt))
        .route("/tsp/pubkey", get(tsp_pubkey))
        .route("/tsp/attest", post(tsp_attest))
        .route("/tsp/escrow/decrypt", post(escrow_decrypt))
        .route("/longfellow/demo", get(longfellow_demo))
        .route("/proofs", post(store_proof_blob))
        .route("/proofs/{cid}", get(get_proof_blob))
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB
        .layer(build_cors_layer())
        .with_state(state.clone());
    (router, state)
}

// === Main ===

#[tokio::main]
async fn main() {
    // --generate-circuits <dir>: generate circuit cache files and exit
    let args: Vec<String> = std::env::args().collect();
    if args.len() >= 3 && args[1] == "--generate-circuits" {
        let dir = std::path::PathBuf::from(&args[2]);
        std::fs::create_dir_all(&dir).unwrap();
        for n in 1..=4usize {
            let path = dir.join(format!("mdoc-{n}attr.bin"));
            eprint!("[generate] Circuit {n}-attr... ");
            let t0 = std::time::Instant::now();
            let circuit = longfellow_sys::mdoc::MdocCircuit::generate(n)
                .unwrap_or_else(|e| panic!("circuit {n} failed: {e}"));
            circuit.save(&path).unwrap();
            eprintln!("done in {:.1}s ({} bytes)", t0.elapsed().as_secs_f64(), std::fs::metadata(&path).unwrap().len());
        }
        eprintln!("[generate] All circuits saved to {}", dir.display());
        return;
    }

    let circuits_path = std::env::var("CIRCUITS_PATH").unwrap_or_else(|_| {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let resolved = std::path::PathBuf::from(manifest)
            .join("../../circuits/build");
        if resolved.exists() {
            resolved.to_string_lossy().to_string()
        } else {
            "../../circuits/build".to_string()
        }
    });

    let port = std::env::var("PORT").unwrap_or_else(|_| "3001".to_string());
    let bind_addr = format!("0.0.0.0:{port}");

    let (app, state) = build_app(&circuits_path);

    // Load or generate Longfellow circuits at startup.
    // If cached circuit files exist on disk, loading is instant (~100ms).
    // Otherwise, generate from scratch (~30s each) and save for next startup.
    let cache_dir = std::env::var("CIRCUIT_CACHE_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("circuit-cache"));
    std::fs::create_dir_all(&cache_dir).ok();
    eprintln!("[startup] Loading Longfellow circuits (1-4 attrs)...");
    for n in 1..=4usize {
        let t0 = std::time::Instant::now();
        let cache_path = cache_dir.join(format!("mdoc-{n}attr.bin"));
        let circuit = if cache_path.exists() {
            match longfellow_sys::mdoc::MdocCircuit::load(&cache_path, n) {
                Ok(c) => {
                    eprintln!("[startup] Circuit {n}-attr loaded from cache in {:.0}ms", t0.elapsed().as_millis());
                    c
                }
                Err(e) => {
                    eprintln!("[startup] Circuit {n}-attr cache load failed ({e}), regenerating...");
                    let c = longfellow_sys::mdoc::MdocCircuit::generate(n)
                        .map_err(|e| eprintln!("[startup] Circuit {n}-attr FAILED: {e}")).ok();
                    if let Some(ref c) = c {
                        c.save(&cache_path).ok();
                    }
                    match c { Some(c) => c, None => continue }
                }
            }
        } else {
            eprintln!("[startup] Circuit {n}-attr not cached, generating...");
            let c = tokio::task::spawn_blocking(move || {
                longfellow_sys::mdoc::MdocCircuit::generate(n)
            }).await.ok().and_then(|r| r.ok());
            if let Some(ref c) = c {
                c.save(&cache_path).ok();
                eprintln!("[startup] Circuit {n}-attr generated and saved in {:.1}s", t0.elapsed().as_secs_f64());
            } else {
                eprintln!("[startup] Circuit {n}-attr generation FAILED");
                continue;
            }
            c.unwrap()
        };
        // Store in the OnceCell
        state.longfellow_circuits[n - 1].set(circuit).ok();
    }
    eprintln!("[startup] All circuits ready.");

    let listener = tokio::net::TcpListener::bind(&bind_addr).await.unwrap();
    println!("Demo API running on http://localhost:{port}");
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::sync::OnceLock;

    fn circuits_path() -> String {
        let manifest = env!("CARGO_MANIFEST_DIR");
        let resolved = std::path::PathBuf::from(manifest)
            .join("../../circuits/build");
        resolved.to_string_lossy().to_string()
    }

    struct TestFixture {
        base_url: String,
        credential: String,
        proof_json: String,
        hidden_fields: Vec<String>,
        #[allow(dead_code)]
        nullifier: Option<String>,
    }

    static FIXTURE: OnceLock<TestFixture> = OnceLock::new();
    static FIXTURE_MUTEX: std::sync::Mutex<bool> = std::sync::Mutex::new(false);

    /// Returns a shared test fixture. The server is started once in a background
    /// thread with its own tokio runtime (survives across all test runtimes).
    ///
    /// Uses a mutex to ensure only one thread runs initialization, preventing
    /// races where multiple threads start duplicate servers and prove calls.
    async fn setup() -> &'static TestFixture {
        if let Some(f) = FIXTURE.get() {
            return f;
        }

        // Acquire mutex — other threads block here until init completes.
        // We must drop the guard before any .await, so do the async work
        // in a separate scope that checks the flag.
        let needs_init = {
            let mut guard = FIXTURE_MUTEX.lock().unwrap();
            if !*guard {
                *guard = true;
                true
            } else {
                false
            }
        };

        if needs_init {
            setup_inner().await;
        }

        // Spin-wait for FIXTURE to be set (the initializing thread is doing async work)
        loop {
            if let Some(f) = FIXTURE.get() {
                return f;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    }

    async fn setup_inner() {
        // Start server in a dedicated thread with its own runtime
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let (app, _state) = build_app(&circuits_path());
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://{addr}")).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });

        let base_url = rx.recv().unwrap();

        // Wait for server to be ready
        let client = reqwest::Client::new();
        for _ in 0..50 {
            if client.get(format!("{base_url}/issuer/revocation-status"))
                .send().await.is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        // Issue a PID credential
        let issue_res: serde_json::Value = client
            .post(format!("{base_url}/issuer/issue"))
            .json(&serde_json::json!({
                "credential_type": "pid",
                "claims": {
                    "given_name": "Test",
                    "family_name": "User",
                    "birth_date": "1998-05-14",
                    "age_over_18": "true",
                    "nationality": "UA",
                    "issuing_country": "UA",
                    "document_number": "UA-TEST-001",
                    "issuing_authority": "Test Authority"
                },
                "issuer": "https://test.example.com"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let credential = issue_res["credential"].as_str().unwrap().to_string();

        // Generate a real proof (~15s)
        let prove_resp = client
            .post(format!("{base_url}/holder/prove"))
            .json(&serde_json::json!({
                "credential": credential,
                "format": "mdoc",
                "predicates": [
                    { "claim": "age_over_18", "op": "eq", "value": true }
                ]
            }))
            .send()
            .await
            .unwrap();
        let prove_status = prove_resp.status();
        let prove_text = prove_resp.text().await.unwrap();
        assert_eq!(prove_status.as_u16(), 200, "prove failed ({prove_status}): {prove_text}");
        let prove_res: serde_json::Value = serde_json::from_str(&prove_text)
            .unwrap_or_else(|e| panic!("prove response not JSON: {e}\n{prove_text}"));

        let proof_json = prove_res["proofs"][0]["proof_json"]
            .as_str()
            .unwrap()
            .to_string();
        let hidden_fields: Vec<String> = prove_res["hidden_fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let nullifier = prove_res["nullifier"].as_str().map(|s| s.to_string());

        let _ = FIXTURE.set(TestFixture {
            base_url,
            credential,
            proof_json,
            hidden_fields,
            nullifier,
        }).ok();
    }

    // === Issue ===

    #[tokio::test]
    async fn issue_pid_credential() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/issuer/issue", f.base_url))
            .json(&serde_json::json!({
                "credential_type": "pid",
                "claims": { "given_name": "Alice", "birth_date": "2000-01-01" },
                "issuer": "https://test.example.com"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        let cred = body["credential"].as_str().unwrap();
        assert!(cred.starts_with("mdoc:"), "credential should be mdoc token");
        assert_eq!(body["format"], "mdoc");
        assert_eq!(body["credential_type"], "pid");
    }

    #[tokio::test]
    async fn issue_invalid_type_returns_400() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/issuer/issue", f.base_url))
            .json(&serde_json::json!({
                "credential_type": "unknown_type",
                "claims": { "name": "Test" }
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
    }

    #[tokio::test]
    async fn issue_invalid_claims_returns_400() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/issuer/issue", f.base_url))
            .json(&serde_json::json!({
                "credential_type": "pid",
                "claims": ["not", "an", "object"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
    }

    // === Prove + Verify ===

    #[tokio::test]
    async fn prove_and_verify_round_trip() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/verifier/verify", f.base_url))
            .json(&serde_json::json!({
                "proofs": [{
                    "proof_json": f.proof_json,
                    "predicate": "birth_date >= 18"
                }],
                "hidden_fields": f.hidden_fields
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        let results = body["results"].as_array().unwrap();
        assert!(!results.is_empty());
        assert!(results[0]["valid"].as_bool().unwrap());
    }

    #[tokio::test]
    async fn prove_missing_claim_returns_500() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/prove", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "mdoc",
                "predicates": [
                    { "claim": "nonexistent_field", "op": "gte", "value": 18 }
                ]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 500);
    }

    #[tokio::test]
    async fn prove_invalid_op_returns_400() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/prove", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "mdoc",
                "predicates": [
                    { "claim": "birth_date", "op": "regex", "value": ".*" }
                ]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
    }

    // === Verify edge case ===

    #[tokio::test]
    async fn verify_invalid_proof_json_returns_400() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/verifier/verify", f.base_url))
            .json(&serde_json::json!({
                "proofs": [{
                    "proof_json": "{bad json",
                    "predicate": "test"
                }],
                "hidden_fields": []
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 400);
    }

    // === CBOR Export ===

    #[tokio::test]
    async fn cbor_export() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/proof-export", f.base_url))
            .json(&serde_json::json!({
                "proofs": [{
                    "proof_json": f.proof_json,
                    "predicate": "birth_date >= 18"
                }]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert!(!body["cbor_base64"].as_str().unwrap().is_empty());
        assert!(body["cbor_size_bytes"].as_u64().unwrap() > 0);
    }

    // === Revocation ===

    #[tokio::test]
    #[serial]
    async fn revoke_and_check_status() {
        let f = setup().await;
        let client = reqwest::Client::new();

        // Check initial status
        let res = client
            .get(format!("{}/issuer/revocation-status", f.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert!(body["total_bits"].as_u64().is_some());

        // Revoke credential at index 5
        let res = client
            .post(format!("{}/issuer/revoke", f.base_url))
            .json(&serde_json::json!({ "credential_index": 5 }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["status"], "revoked");
        assert_eq!(body["credential_index"], 5);

        // Status list should now have at least 1 byte (8 bits)
        let res = client
            .get(format!("{}/issuer/revocation-status", f.base_url))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = res.json().await.unwrap();
        assert!(body["total_bits"].as_u64().unwrap() >= 8);
    }

    // === Compound Prove + Verify + Export ===

    #[tokio::test]
    async fn compound_prove_and_verify() {
        let f = setup().await;
        let client = reqwest::Client::new();

        // Prove compound AND: birth_date gte 18 AND nationality in EU
        let res = client
            .post(format!("{}/holder/prove-compound", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "mdoc",
                "predicates": [
                    { "claim": "age_over_18", "op": "eq", "value": true },
                    { "claim": "nationality", "op": "set_member", "value": ["UA", "DE", "FR"] }
                ],
                "op": "and"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["op"], "and");
        assert!(body["sub_proofs_count"].as_u64().unwrap() >= 2);
        let compound_json = body["compound_proof_json"].as_str().unwrap();
        assert!(!compound_json.is_empty());

        // Verify the compound proof
        let res = client
            .post(format!("{}/verifier/verify-compound", f.base_url))
            .json(&serde_json::json!({
                "compound_proof_json": compound_json,
                "hidden_fields": body["hidden_fields"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let verify_body: serde_json::Value = res.json().await.unwrap();
        assert!(verify_body["valid"].as_bool().unwrap());
        assert_eq!(verify_body["op"], "and");

        // Export compound as CBOR
        let res = client
            .post(format!("{}/holder/proof-export-compound", f.base_url))
            .json(&serde_json::json!({
                "compound_proof_json": compound_json
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let export_body: serde_json::Value = res.json().await.unwrap();
        assert!(!export_body["cbor_base64"].as_str().unwrap().is_empty());
        assert!(export_body["cbor_size_bytes"].as_u64().unwrap() > 0);
    }

    // === Holder Binding with different claim names ===

    #[tokio::test]
    async fn holder_binding_different_claim_names() {
        let f = setup().await;
        let client = reqwest::Client::new();

        // Issue a PID with document_number
        let pid_res: serde_json::Value = client
            .post(format!("{}/issuer/issue", f.base_url))
            .json(&serde_json::json!({
                "credential_type": "pid",
                "claims": {
                    "given_name": "Seller",
                    "birth_date": "1990-01-01",
                    "document_number": "SELLER-DOC-001"
                },
                "issuer": "https://test.example.com"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let pid_cred = pid_res["credential"].as_str().unwrap();

        // Issue a vehicle registration with owner_document_number matching the PID
        let vehicle_res: serde_json::Value = client
            .post(format!("{}/issuer/issue", f.base_url))
            .json(&serde_json::json!({
                "credential_type": "vehicle",
                "claims": {
                    "owner_name": "Seller",
                    "owner_document_number": "SELLER-DOC-001",
                    "vin": "WVWZZZ1JZYW000001",
                    "insurance_expiry": "2027-06-15",
                    "make_model": "Volkswagen Golf",
                    "plate_number": "B-MS 2847"
                },
                "issuer": "https://kba.de"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let vehicle_cred = vehicle_res["credential"].as_str().unwrap();

        // Prove binding with different claim names
        let res = client
            .post(format!("{}/holder/prove-binding", f.base_url))
            .json(&serde_json::json!({
                "credential_a": pid_cred,
                "credential_b": vehicle_cred,
                "binding_claim_a": "document_number",
                "binding_claim_b": "owner_document_number",
                "predicates_a": [],
                "predicates_b": []
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200, "prove-binding should succeed");
        let body: serde_json::Value = res.json().await.unwrap();
        assert!(body["binding_verified"].as_bool().unwrap(), "binding hashes should match");
        assert!(!body["binding_hash"].as_str().unwrap().is_empty());

        // Also test mismatched values — issue another vehicle with different owner
        let vehicle2_res: serde_json::Value = client
            .post(format!("{}/issuer/issue", f.base_url))
            .json(&serde_json::json!({
                "credential_type": "vehicle",
                "claims": {
                    "owner_name": "Someone Else",
                    "owner_document_number": "OTHER-DOC-999",
                    "vin": "JTDKN3DU5A0000002",
                    "insurance_expiry": "2027-06-15",
                    "make_model": "Toyota Corolla",
                    "plate_number": "A-BC 1234"
                },
                "issuer": "https://kba.de"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let vehicle2_cred = vehicle2_res["credential"].as_str().unwrap();

        let res = client
            .post(format!("{}/holder/prove-binding", f.base_url))
            .json(&serde_json::json!({
                "credential_a": pid_cred,
                "credential_b": vehicle2_cred,
                "binding_claim_a": "document_number",
                "binding_claim_b": "owner_document_number",
                "predicates_a": [],
                "predicates_b": [],
                "skip_cache": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert!(!body["binding_verified"].as_bool().unwrap(), "mismatched owners should fail binding");
    }

    // === Proof Cache ===

    #[tokio::test]
    async fn compound_prove_returns_cached_false_without_cache() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/prove-compound", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "mdoc",
                "predicates": [
                    { "claim": "age_over_18", "op": "eq", "value": true }
                ],
                "op": "and",
                "skip_cache": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        // With skip_cache, cached should be absent (skip_serializing_if false)
        assert!(body.get("cached").is_none(), "cached field should be absent when false");
        assert!(!body["compound_proof_json"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn compound_prove_skip_cache_works() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/prove-compound", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "mdoc",
                "predicates": [
                    { "claim": "age_over_18", "op": "eq", "value": true }
                ],
                "op": "and",
                "skip_cache": true
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert!(body.get("cached").is_none(), "skip_cache should not return cached=true");
        assert!(!body["compound_proof_json"].as_str().unwrap().is_empty());
    }

    #[test]
    fn cache_key_normalizes_gte_lte_values() {
        let make_req = |op: &str, value: serde_json::Value| CompoundProveRequest {
            credential: String::new(),
            format: "sd-jwt".into(),
            predicates: vec![PredicateRequest {
                claim: "expiry_date".into(),
                op: op.into(),
                value,
            }],
            op: "and".into(),
            skip_cache: false,
            identity_escrow: None,
        };

        // gte/lte: different values should produce the same key
        let k1 = compute_cache_key(&make_req("gte", serde_json::json!(20000)));
        let k2 = compute_cache_key(&make_req("gte", serde_json::json!(20005)));
        assert_eq!(k1, k2, "gte keys should be equal regardless of value");

        let k3 = compute_cache_key(&make_req("lte", serde_json::json!(100)));
        let k4 = compute_cache_key(&make_req("lte", serde_json::json!(999)));
        assert_eq!(k3, k4, "lte keys should be equal regardless of value");

        // eq: different values should produce different keys
        let k5 = compute_cache_key(&make_req("eq", serde_json::json!("A")));
        let k6 = compute_cache_key(&make_req("eq", serde_json::json!("B")));
        assert_ne!(k5, k6, "eq keys should differ when values differ");

        // different ops should produce different keys
        assert_ne!(k1, k3, "gte and lte keys should differ");
        assert_ne!(k1, k5, "gte and eq keys should differ");
    }

    #[test]
    fn cache_key_ignores_escrow_config() {
        let base = CompoundProveRequest {
            credential: String::new(),
            format: "sdjwt".into(),
            predicates: vec![PredicateRequest {
                claim: "birth_date".into(),
                op: "gte".into(),
                value: serde_json::json!(18),
            }],
            op: "and".into(),
            skip_cache: false,
            identity_escrow: None,
        };

        let k_no_escrow = compute_cache_key(&base);

        // With escrow — SAME key (escrow is generated fresh, not cached)
        let with_escrow = CompoundProveRequest {
            identity_escrow: Some(EscrowRequest {
                field_names: vec!["given_name".into(), "family_name".into()],
                authority_pubkey: "aabbcc".into(),
            }),
            ..base.clone()
        };
        assert_eq!(k_no_escrow, compute_cache_key(&with_escrow),
            "escrow should NOT change cache key — escrow is generated fresh per credential");
    }

    // === Test helpers (lightweight server) ===

    static LIGHT_SERVER: OnceLock<String> = OnceLock::new();

    /// Lightweight server setup — no proof generation, just starts the API.
    async fn light_setup() -> &'static str {
        if let Some(url) = LIGHT_SERVER.get() {
            return url;
        }
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let (app, _state) = build_app(&circuits_path());
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://{addr}")).unwrap();
                axum::serve(listener, app).await.unwrap();
            });
        });
        let url = rx.recv().unwrap();
        let client = reqwest::Client::new();
        for _ in 0..50 {
            if client.get(format!("{url}/issuer/revocation-status")).send().await.is_ok() { break; }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        LIGHT_SERVER.get_or_init(|| url)
    }

    /// Helper: issue a credential and return (base_url, credential_string)
    async fn issue_test_credential(claims: serde_json::Value) -> (&'static str, String) {
        let url = light_setup().await;
        let client = reqwest::Client::new();
        let res: serde_json::Value = client
            .post(format!("{url}/issuer/issue"))
            .json(&serde_json::json!({
                "credential_type": "pid",
                "claims": claims,
                "issuer": "https://test.example.com"
            }))
            .send().await.unwrap()
            .json().await.unwrap();
        let cred = res["credential"].as_str().unwrap().to_string();
        (url, cred)
    }

    // === contract-prove endpoint tests ===

    #[tokio::test]
    async fn contract_prove_returns_nullifier_and_proof() {
        let (url, cred) = issue_test_credential(serde_json::json!({
            "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-TEST-001"
        })).await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&serde_json::json!({
                "credential": cred,
                "format": "mdoc",
                "predicates": [{ "claim": "birth_date", "op": "lte", "value": "2008-04-05" }],
                "contract_terms": "test vehicle sale",
                "timestamp": "2026-03-22T18:00:00Z",
            }))
            .send().await.unwrap();
        assert_eq!(res.status().as_u16(), 200, "contract-prove failed: {}", res.text().await.unwrap_or_default());
        let data: serde_json::Value = serde_json::from_str(&res.text().await.unwrap()).unwrap();

        // Must have nullifier, contract_hash, salt
        assert!(data["nullifier"].as_str().unwrap().starts_with("0x"), "nullifier should be hex");
        assert!(data["contract_hash"].as_str().unwrap().starts_with("0x"), "contract_hash should be hex");
        assert!(data["salt"].as_str().unwrap().starts_with("0x"), "salt should be hex");
        assert!(data["compound_proof_json"].is_string(), "must have compound_proof_json");
        assert!(data["sub_proofs_count"].as_u64().unwrap() >= 1);

        // Compound proof must have contract_nullifiers
        let compound: serde_json::Value = serde_json::from_str(data["compound_proof_json"].as_str().unwrap()).unwrap();
        assert!(compound["contract_nullifiers"].is_array(), "compound proof must contain contract_nullifiers");
        assert!(!compound["contract_nullifiers"][0]["nullifier"].as_array().unwrap().is_empty());

        // No document_number in any public output
        let compound_str = data["compound_proof_json"].as_str().unwrap();
        assert!(!compound_str.contains("UA-TEST-001"), "document_number must NOT appear in proof");
    }

    #[tokio::test]
    async fn contract_prove_different_salt_different_nullifier() {
        let (url, cred) = issue_test_credential(serde_json::json!({
            "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-TEST-002"
        })).await;
        let client = reqwest::Client::new();

        let res1: serde_json::Value = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&serde_json::json!({
                "credential": cred, "format": "mdoc",
                "predicates": [{ "claim": "birth_date", "op": "lte", "value": "2008-04-05" }],
                "contract_terms": "contract A", "timestamp": "2026-03-22T18:00:00Z",
            }))
            .send().await.unwrap().json().await.unwrap();

        let res2: serde_json::Value = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&serde_json::json!({
                "credential": cred, "format": "mdoc",
                "predicates": [{ "claim": "birth_date", "op": "lte", "value": "2008-04-05" }],
                "contract_terms": "contract B", "timestamp": "2026-03-22T19:00:00Z",
            }))
            .send().await.unwrap().json().await.unwrap();

        let n1 = res1["nullifier"].as_str().unwrap();
        let n2 = res2["nullifier"].as_str().unwrap();
        assert_ne!(n1, n2, "different contracts must produce different nullifiers");
    }

    #[tokio::test]
    async fn contract_prove_no_predicates_returns_error() {
        let (url, cred) = issue_test_credential(serde_json::json!({
            "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-TEST-003"
        })).await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&serde_json::json!({
                "credential": cred, "format": "mdoc",
                "predicates": [],
                "contract_terms": "test", "timestamp": "2026-03-22",
            }))
            .send().await.unwrap();
        assert_eq!(res.status().as_u16(), 400, "empty predicates should fail");
    }

    #[tokio::test]
    async fn contract_prove_same_terms_same_hash() {
        let (url, cred) = issue_test_credential(serde_json::json!({
            "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-HASH-001"
        })).await;
        let client = reqwest::Client::new();

        let body = serde_json::json!({
            "credential": cred, "format": "mdoc",
            "predicates": [{ "claim": "birth_date", "op": "lte", "value": "2008-04-05" }],
            "contract_terms": "same terms", "timestamp": "2026-03-23T10:00:00Z",
        });

        let res1: serde_json::Value = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&body)
            .send().await.unwrap().json().await.unwrap();

        let res2: serde_json::Value = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&body)
            .send().await.unwrap().json().await.unwrap();

        let h1 = res1["contract_hash"].as_str().unwrap();
        let h2 = res2["contract_hash"].as_str().unwrap();
        assert_eq!(h1, h2, "same (terms, timestamp) must produce same contract_hash");

        // In Longfellow, nullifiers are deterministic: SHA256(e_mso_LE || contract_hash).
        // Same credential + same contract_hash → same nullifier (no random salt).
        let n1 = res1["nullifier"].as_str().unwrap();
        let n2 = res2["nullifier"].as_str().unwrap();
        assert_eq!(n1, n2, "same credential + same contract must produce same nullifier");
    }

    #[tokio::test]
    async fn contract_prove_with_nullifier_field_and_role() {
        let (url, cred) = issue_test_credential(serde_json::json!({
            "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-ROLE-001"
        })).await;
        let client = reqwest::Client::new();
        let res: serde_json::Value = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&serde_json::json!({
                "credential": cred, "format": "mdoc",
                "predicates": [{ "claim": "birth_date", "op": "lte", "value": "2008-04-05" }],
                "contract_terms": "test", "timestamp": "2026-03-23T10:00:00Z",
                "nullifier_field": "document_number",
                "role": "seller",
            }))
            .send().await.unwrap().json().await.unwrap();

        assert_eq!(res["role"].as_str().unwrap(), "seller");
        assert!(res["nullifier"].as_str().unwrap().starts_with("0x"));
    }

    #[tokio::test]
    async fn contract_prove_defaults_role_to_holder() {
        let (url, cred) = issue_test_credential(serde_json::json!({
            "given_name": "Test", "birth_date": "1998-05-14", "document_number": "UA-ROLE-002"
        })).await;
        let client = reqwest::Client::new();
        let res: serde_json::Value = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&serde_json::json!({
                "credential": cred, "format": "mdoc",
                "predicates": [{ "claim": "birth_date", "op": "lte", "value": "2008-04-05" }],
                "contract_terms": "test", "timestamp": "2026-03-23T10:00:00Z",
            }))
            .send().await.unwrap().json().await.unwrap();

        assert_eq!(res["role"].as_str().unwrap(), "holder");
    }

    #[tokio::test]
    async fn contract_prove_route_is_reachable() {
        let url = light_setup().await;
        let client = reqwest::Client::new();
        // Just verify the route exists (not a 404/HTML fallback)
        let res = client
            .post(format!("{url}/holder/contract-prove"))
            .json(&serde_json::json!({
                "credential": "invalid",
                "format": "mdoc",
                "predicates": [{ "claim": "x", "op": "gte", "value": 1 }],
                "contract_terms": "t",
                "timestamp": "2026-03-22",
            }))
            .send().await.unwrap();
        let status = res.status().as_u16();
        let body = res.text().await.unwrap();
        // Should get a parse error, NOT an HTML page
        assert!(status == 400 || status == 500, "expected API error, got {status}");
        assert!(!body.contains("<!DOCTYPE"), "got HTML instead of API response — route not registered");
    }

    // === Proof Blob Store ===

    #[tokio::test]
    async fn blob_store_round_trip() {
        let url = light_setup().await;
        let client = reqwest::Client::new();

        let payload: Vec<u8> = b"fake proof bytes for testing".to_vec();

        // Store the blob
        let store_res = client
            .post(format!("{url}/proofs"))
            .header("content-type", "application/octet-stream")
            .body(payload.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(store_res.status().as_u16(), 200, "store failed");
        let store_json: serde_json::Value = store_res.json().await.unwrap();
        let cid = store_json["cid"].as_str().unwrap().to_string();
        assert_eq!(cid.len(), 64, "CID should be 64 hex chars (SHA-256)");

        // Retrieve the blob
        let get_res = client
            .get(format!("{url}/proofs/{cid}"))
            .send()
            .await
            .unwrap();
        assert_eq!(get_res.status().as_u16(), 200, "get failed");
        let content_type = get_res.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(content_type.contains("application/octet-stream"), "wrong content-type: {content_type}");
        let returned = get_res.bytes().await.unwrap();
        assert_eq!(returned.as_ref(), payload.as_slice(), "returned bytes must match stored bytes");

        // Unknown CID returns 404
        let missing_res = client
            .get(format!("{url}/proofs/deadbeef"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing_res.status().as_u16(), 404, "missing CID should return 404");
    }

    // === Longfellow integration: issue → prove → verify ===

    #[test]
    fn longfellow_issue_prove_verify_round_trip() {
        use longfellow_sys::mdoc::{AttributeRequest, MdocCircuit};
        use longfellow_sys::safe::VerifyType;
        use zk_eidas_types::credential::ClaimValue;

        // Step 1: Issue an mdoc credential
        let (mdoc_bytes, pub_key_x, pub_key_y) =
            zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
                vec![
                    ("given_name", ClaimValue::String("Alice".into())),
                    ("age_over_18", ClaimValue::Boolean(true)),
                ],
                "https://test.example.com",
            );

        // Step 2: Parse claims back via MdocParser
        let cred = zk_eidas_mdoc::MdocParser::parse_with_issuer_key(
            &mdoc_bytes, pub_key_x, pub_key_y,
        ).expect("mdoc parse failed");
        assert_eq!(
            cred.claims().get("age_over_18"),
            Some(&ClaimValue::Boolean(true)),
        );

        // Step 3: Build AttributeRequest for age_over_18 = true (CBOR: 0xf5)
        let attributes = vec![AttributeRequest {
            namespace: "org.iso.18013.5.1".to_string(),
            identifier: "age_over_18".to_string(),
            cbor_value: vec![0xf5], // CBOR true
            verify_type: VerifyType::Eq,
        }];

        // Step 4: Generate circuit for 1 attribute
        let circuit = MdocCircuit::generate(1).expect("circuit generation failed");

        // Step 5: Build public key strings in "0x<hex>" format
        let pkx_hex = format!("0x{}", hex::encode(pub_key_x));
        let pky_hex = format!("0x{}", hex::encode(pub_key_y));

        // Step 6: Prove
        let proof = longfellow_sys::mdoc::prove(
            &circuit,
            &mdoc_bytes,
            &pkx_hex,
            &pky_hex,
            b"zk-eidas-demo",
            &attributes,
            "2026-01-01T00:00:00Z",
            &[0u8; 8],
            &[[0u8; 32]; 8],
        ).expect("prove failed");

        assert!(!proof.proof_bytes.is_empty(), "proof should not be empty");

        // Step 7: Verify
        longfellow_sys::mdoc::verify(
            &circuit,
            &proof,
            &pkx_hex,
            &pky_hex,
            b"zk-eidas-demo",
            &attributes,
            "2026-01-01T00:00:00Z",
            "org.iso.18013.5.1.mDL",
            &[0u8; 8],
        ).expect("verify failed");
    }
}
