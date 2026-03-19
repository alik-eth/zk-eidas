use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, Semaphore};
use tower_http::cors::{AllowOrigin, CorsLayer};
use axum::extract::Path as AxumPath;
use axum::body::Body;

struct AppState {
    circuits_path: String,
    nullifier_registry: Mutex<HashSet<String>>,
    status_list: Mutex<Vec<u8>>,  // bitstring: 0=valid, 1=revoked
    prove_semaphore: Semaphore,  // limit concurrent proof generation
    proof_cache: HashMap<String, CachedProof>,
    binding_cache: HashMap<String, CachedBindingProof>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedProof {
    compound_proof_json: String,
    op: String,
    hidden_fields: Vec<String>,
    sub_proofs_count: usize,
    compressed_cbor_base64: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedBindingProof {
    proofs_a: Vec<CachedProofResult>,
    proofs_b: Vec<CachedProofResult>,
    binding_hash: String,
    binding_verified: bool,
    hidden_fields_a: Vec<String>,
    hidden_fields_b: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CachedProofResult {
    predicate: String,
    proof_json: String,
    proof_hex: String,
    op: String,
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
    "sdjwt".to_string()
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

    let (credential, format) = if req.credential_type == "drivers_license" {
        use zk_eidas_types::credential::ClaimValue;
        let claims_vec: Vec<(String, ClaimValue)> = claims_obj
            .iter()
            .map(|(k, v)| json_value_to_claim(k, v).map(|cv| (k.clone(), cv)))
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
        let token = format!(
            "mdoc:{}:{}:{}",
            base64::engine::general_purpose::STANDARD.encode(&mdoc_bytes),
            hex::encode(pub_key_x),
            hex::encode(pub_key_y),
        );
        (token, "mdoc".to_string())
    } else {
        // Normalize string claim values before embedding in the SD-JWT so the
        // parser stores them with the right type:
        //   - numeric strings → integers (needed for gte/lte/range)
        //   - date strings (except birthdate) → epoch-day integers
        //   - birthdate stays as a string so the parser creates ClaimValue::Date
        let normalized: serde_json::Map<String, serde_json::Value> = claims_obj
            .iter()
            .map(|(k, v)| (k.clone(), normalize_claim_for_sdjwt(k, v)))
            .collect();
        let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
            serde_json::Value::Object(normalized),
            &req.issuer,
        );
        (sdjwt, "sdjwt".to_string())
    };

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
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return Err(format!("expected YYYY-MM-DD, got {s}"));
    }
    let year: u16 = parts[0].parse().map_err(|_| "bad year")?;
    let month: u8 = parts[1].parse().map_err(|_| "bad month")?;
    let day: u8 = parts[2].parse().map_err(|_| "bad day")?;
    Ok(zk_eidas_types::credential::ClaimValue::Date { year, month, day })
}

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

// === Prove ===

#[derive(Deserialize)]
struct ProveRequest {
    credential: String,
    #[serde(default = "default_format")]
    format: String,
    predicates: Vec<PredicateRequest>,
    #[serde(default)]
    nullifier_scope: Option<String>,
}

#[derive(Deserialize)]
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

fn parse_predicate(pred: &PredicateRequest) -> Result<zk_eidas::Predicate, (StatusCode, String)> {
    match pred.op.as_str() {
        "gte" => {
            let v = pred
                .value
                .as_i64()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "gte value must be integer".into()))?;
            Ok(zk_eidas::Predicate::gte(v))
        }
        "lte" => {
            let v = pred
                .value
                .as_i64()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "lte value must be integer".into()))?;
            Ok(zk_eidas::Predicate::lte(v))
        }
        "eq" => {
            let v = pred
                .value
                .as_str()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "eq value must be string".into()))?;
            Ok(zk_eidas::Predicate::eq(v))
        }
        "neq" => {
            let v = pred
                .value
                .as_str()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "neq value must be string".into()))?;
            Ok(zk_eidas::Predicate::neq(v))
        }
        "set_member" => {
            let arr = pred.value.as_array().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "set_member value must be array".into(),
                )
            })?;
            let values: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
            Ok(zk_eidas::Predicate::set_member(values))
        }
        "range" => {
            let arr = pred.value.as_array().ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "range value must be [low, high] array".into(),
                )
            })?;
            if arr.len() != 2 {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "range value must have exactly 2 elements".into(),
                ));
            }
            let low = arr[0]
                .as_i64()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "range low must be integer".into()))?;
            let high = arr[1]
                .as_i64()
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "range high must be integer".into()))?;
            Ok(zk_eidas::Predicate::range(low, high))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("unsupported op: {}", other),
        )),
    }
}

async fn generate_proof(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, (StatusCode, String)> {
    let (mut builder, all_field_names) = if req.format == "mdoc" {
        let (mdoc_bytes, pub_key_x, pub_key_y) = parse_mdoc_token(&req.credential)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc token: {e}")))?;
        let credential =
            zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&mdoc_bytes, pub_key_x, pub_key_y)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
        let names: Vec<String> = credential.claims().keys().cloned().collect();
        (
            zk_eidas::ZkCredential::from_credential(credential, &state.circuits_path),
            names,
        )
    } else {
        let builder = zk_eidas::ZkCredential::from_sdjwt(&req.credential, &state.circuits_path)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("parse error: {e}")))?;
        let names: Vec<String> = builder.credential().claims().keys().cloned().collect();
        (builder, names)
    };

    let mut proven_claims: Vec<String> = Vec::new();
    let mut proof_descriptions: Vec<String> = Vec::new();

    for pred in &req.predicates {
        let predicate = parse_predicate(pred)?;
        let desc = match pred.op.as_str() {
            "gte" => {
                let v = pred.value.as_i64().unwrap_or(0);
                if pred.claim == "birthdate" || pred.claim == "birth_date" {
                    format!("age >= {}", v)
                } else {
                    format!("{} >= {}", pred.claim, v)
                }
            }
            "eq" => format!("{} equals expected value", pred.claim),
            "set_member" => format!("{} in allowed set", pred.claim),
            "neq" => format!("{} != {}", pred.claim, pred.value.as_str().unwrap_or("")),
            "lte" => format!("{} <= {}", pred.claim, pred.value.as_i64().unwrap_or(0)),
            "range" => {
                let arr = pred
                    .value
                    .as_array()
                    .map(|a| {
                        (
                            a.first().and_then(|v| v.as_i64()).unwrap_or(0),
                            a.get(1).and_then(|v| v.as_i64()).unwrap_or(0),
                        )
                    })
                    .unwrap_or((0, 0));
                if pred.claim == "birthdate" || pred.claim == "birth_date" {
                    format!("{} <= age <= {}", arr.0, arr.1)
                } else {
                    format!("{} <= {} <= {}", arr.0, pred.claim, arr.1)
                }
            }
            _ => format!("{} {}", pred.claim, pred.op),
        };
        proof_descriptions.push(desc);
        proven_claims.push(pred.claim.clone());
        builder = builder.predicate(&pred.claim, predicate);
    }

    if let Some(scope) = &req.nullifier_scope {
        builder = builder.nullifier_scope(scope);
    }

    let has_nullifier = req.nullifier_scope.is_some();
    let _permit = state.prove_semaphore.acquire().await.map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "proving unavailable".to_string())
    })?;
    let (zk_proofs, proof_descriptions, proven_claims, all_field_names) =
        tokio::task::spawn_blocking(move || -> Result<_, (StatusCode, String)> {
            unsafe { libc::nice(10); }
            let zk_proofs = builder.prove_all().map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("proving failed: {e}"),
                )
            })?;
            Ok((
                zk_proofs,
                proof_descriptions,
                proven_claims,
                all_field_names,
            ))
        })
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("task join error: {e}"),
            )
        })??;

    let nullifier_hex = if has_nullifier {
        zk_proofs
            .iter()
            .find_map(|p| p.nullifier())
            .map(|n| format!("0x{}", hex::encode(n)))
    } else {
        None
    };

    let proofs: Vec<ProofResult> = zk_proofs
        .iter()
        .zip(proof_descriptions.iter())
        .map(|(proof, desc)| {
            let op = format!("{:?}", proof.predicate_op());
            ProofResult {
                predicate: desc.clone(),
                proof_json: serde_json::to_string(proof).unwrap(),
                proof_hex: format!("0x{}", hex::encode(proof.proof_bytes())),
                op,
            }
        })
        .collect();

    let hidden_fields: Vec<String> = all_field_names
        .iter()
        .filter(|f| !proven_claims.contains(f))
        .cloned()
        .collect();

    Ok(Json(ProveResponse {
        proofs,
        hidden_fields,
        nullifier: nullifier_hex,
    }))
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
    State(state): State<Arc<AppState>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, (StatusCode, String)> {
    let circuits_path = state.circuits_path.clone();
    let hidden_fields = req.hidden_fields;

    // Parse proofs on the async thread (fast), then verify in spawn_blocking
    let mut parsed_proofs = Vec::new();
    for proof_input in &req.proofs {
        let zk_proof: zk_eidas_types::proof::ZkProof =
            serde_json::from_str(&proof_input.proof_json)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid proof JSON: {e}")))?;
        parsed_proofs.push((zk_proof, proof_input.predicate.clone()));
    }

    let results = tokio::task::spawn_blocking(move || -> Result<_, (StatusCode, String)> {
        let verifier = zk_eidas::ZkVerifier::new(&circuits_path);
        let mut results = Vec::new();
        for (zk_proof, predicate) in &parsed_proofs {
            let valid = verifier.verify(zk_proof).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("verification error: {e}"),
                )
            })?;
            results.push(VerifyResult {
                predicate: predicate.clone(),
                valid,
            });
        }
        Ok(results)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("verification task failed: {e}"),
        )
    })??;

    Ok(Json(VerifyResponse {
        results,
        not_disclosed: hidden_fields,
    }))
}

// === Compound Prove ===

#[derive(Deserialize)]
struct CompoundProveRequest {
    credential: String,
    #[serde(default = "default_format")]
    format: String,
    predicates: Vec<PredicateRequest>,
    op: String, // "and" or "or"
    #[serde(default)]
    skip_cache: bool,
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
    // Check proof cache — match by credential content + predicates
    let cache_key = compute_cache_key(&req);
    if !req.skip_cache {
    if let Some(cached) = state.proof_cache.get(&cache_key) {
        eprintln!("[prove-compound] CACHE HIT for key {cache_key}");
        return Ok(Json(CompoundProveResponse {
            compound_proof_json: cached.compound_proof_json.clone(),
            op: cached.op.clone(),
            sub_proofs_count: cached.sub_proofs_count,
            hidden_fields: cached.hidden_fields.clone(),
            cached: true,
        }));
    }
    }
    eprintln!("[prove-compound] {} for key {cache_key}", if req.skip_cache { "CACHE SKIPPED" } else { "CACHE MISS" });


    let (mut builder, all_field_names) = if req.format == "mdoc" {
        let (mdoc_bytes, pub_key_x, pub_key_y) = parse_mdoc_token(&req.credential)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc token: {e}")))?;
        let credential =
            zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&mdoc_bytes, pub_key_x, pub_key_y)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
        let names: Vec<String> = credential.claims().keys().cloned().collect();
        (
            zk_eidas::ZkCredential::from_credential(credential, &state.circuits_path),
            names,
        )
    } else {
        let builder = zk_eidas::ZkCredential::from_sdjwt(&req.credential, &state.circuits_path)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("parse error: {e}")))?;
        let names: Vec<String> = builder.credential().claims().keys().cloned().collect();
        (builder, names)
    };

    // Group predicates by claim name
    let mut claims_predicates: std::collections::BTreeMap<String, Vec<zk_eidas::Predicate>> =
        std::collections::BTreeMap::new();
    let mut proven_claims: Vec<String> = Vec::new();

    for pred in &req.predicates {
        let predicate = parse_predicate(pred)?;
        if !proven_claims.contains(&pred.claim) {
            proven_claims.push(pred.claim.clone());
        }
        claims_predicates
            .entry(pred.claim.clone())
            .or_default()
            .push(predicate);
    }

    // Log what we're about to prove
    eprintln!("[prove-compound] format={} predicates:", req.format);
    for pred in &req.predicates {
        eprintln!("  claim={} op={} value={}", pred.claim, pred.op, pred.value);
    }
    for (claim, subs) in claims_predicates {
        let compound_pred = match req.op.as_str() {
            "or" => zk_eidas::Predicate::or(subs),
            _ => zk_eidas::Predicate::and(subs),
        };
        builder = builder.predicate(&claim, compound_pred);
    }

    let _permit = state.prove_semaphore.acquire().await.map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "proving unavailable".to_string())
    })?;
    let (compound_proof, proven_claims, all_field_names) =
        tokio::task::spawn_blocking(move || -> Result<_, (StatusCode, String)> {
            unsafe { libc::nice(10); }
            let compound_proof = builder.prove_compound().map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("compound proving failed: {e}"),
                )
            })?;
            Ok((compound_proof, proven_claims, all_field_names))
        })
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("task join error: {e}"),
            )
        })??;

    let op_label = format!("{:?}", compound_proof.op());
    let sub_proofs_count = compound_proof.proofs().len();

    let compound_proof_json = serde_json::to_string(&compound_proof).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("serialization failed: {e}"),
        )
    })?;

    let hidden_fields: Vec<String> = all_field_names
        .iter()
        .filter(|f| !proven_claims.contains(f))
        .cloned()
        .collect();

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
    State(state): State<Arc<AppState>>,
    Json(req): Json<CompoundVerifyRequest>,
) -> Result<Json<CompoundVerifyResponse>, (StatusCode, String)> {
    let verifier = zk_eidas::ZkVerifier::new(&state.circuits_path);

    let compound: zk_eidas::CompoundProof = serde_json::from_str(&req.compound_proof_json)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid compound proof JSON: {e}"),
            )
        })?;

    let (valid, op, sub_proofs_verified) = tokio::task::spawn_blocking(move || {
        let valid = verifier.verify_compound(&compound).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("compound verification error: {e}"),
            )
        })?;
        let op = format!("{:?}", compound.op());
        let sub_proofs_verified = compound.proofs().len();
        Ok::<_, (StatusCode, String)>((valid, op, sub_proofs_verified))
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("verification task failed: {e}"),
        )
    })??;

    Ok(Json(CompoundVerifyResponse {
        valid,
        op,
        sub_proofs_verified,
        not_disclosed: req.hidden_fields,
    }))
}

// === Holder Binding ===

#[derive(Deserialize)]
struct ProveBindingRequest {
    sdjwt_a: String,
    sdjwt_b: String,
    binding_claim: String,
    #[serde(default)]
    binding_claim_b: Option<String>,  // if different from binding_claim for credential B
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

fn compute_binding_cache_key(req: &ProveBindingRequest) -> String {
    let claim_b = req.binding_claim_b.as_deref().unwrap_or(&req.binding_claim);
    let key_material = format!("binding|{}|{}", req.binding_claim, claim_b);
    format!("{:016x}", fnv_hash(key_material.as_bytes()))
}

async fn prove_binding(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveBindingRequest>,
) -> Result<Json<ProveBindingResponse>, (StatusCode, String)> {
    // Check binding cache
    let cache_key = compute_binding_cache_key(&req);
    if let Some(cached) = state.binding_cache.get(&cache_key) {
        eprintln!("[prove-binding] CACHE HIT for key {cache_key}");
        return Ok(Json(ProveBindingResponse {
            proofs_a: cached.proofs_a.iter().map(|p| ProofResult {
                predicate: p.predicate.clone(),
                proof_json: p.proof_json.clone(),
                proof_hex: p.proof_hex.clone(),
                op: p.op.clone(),
            }).collect(),
            proofs_b: cached.proofs_b.iter().map(|p| ProofResult {
                predicate: p.predicate.clone(),
                proof_json: p.proof_json.clone(),
                proof_hex: p.proof_hex.clone(),
                op: p.op.clone(),
            }).collect(),
            binding_hash: cached.binding_hash.clone(),
            binding_verified: cached.binding_verified,
            hidden_fields_a: cached.hidden_fields_a.clone(),
            hidden_fields_b: cached.hidden_fields_b.clone(),
            cached: true,
        }));
    }
    eprintln!("[prove-binding] CACHE MISS for key {cache_key}");

    // Build and prove credential A with binding
    let mut builder_a = zk_eidas::ZkCredential::from_sdjwt(&req.sdjwt_a, &state.circuits_path)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("parse error (credential A): {e}"),
            )
        })?;
    let all_fields_a: Vec<String> = builder_a.credential().claims().keys().cloned().collect();
    let mut proven_claims_a: Vec<String> = Vec::new();
    for pred in &req.predicates_a {
        let predicate = parse_predicate(pred)?;
        proven_claims_a.push(pred.claim.clone());
        builder_a = builder_a.predicate(&pred.claim, predicate);
    }
    let _permit = state.prove_semaphore.acquire().await.map_err(|_| {
        (StatusCode::SERVICE_UNAVAILABLE, "proving unavailable".to_string())
    })?;
    let binding_claim_a = req.binding_claim.clone();
    let (zk_proofs_a, binding_hash_a) = tokio::task::spawn_blocking(move || {
        unsafe { libc::nice(10); }
        builder_a.prove_with_binding(&binding_claim_a)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {e}"),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proving A failed: {e}"),
        )
    })?;

    // Build and prove credential B with binding
    let mut builder_b = zk_eidas::ZkCredential::from_sdjwt(&req.sdjwt_b, &state.circuits_path)
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("parse error (credential B): {e}"),
            )
        })?;
    let all_fields_b: Vec<String> = builder_b.credential().claims().keys().cloned().collect();
    let mut proven_claims_b: Vec<String> = Vec::new();
    for pred in &req.predicates_b {
        let predicate = parse_predicate(pred)?;
        proven_claims_b.push(pred.claim.clone());
        builder_b = builder_b.predicate(&pred.claim, predicate);
    }
    let binding_claim_b = req.binding_claim_b.clone().unwrap_or_else(|| req.binding_claim.clone());
    let (zk_proofs_b, binding_hash_b) = tokio::task::spawn_blocking(move || {
        builder_b.prove_with_binding(&binding_claim_b)
    })
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("task join error: {e}"),
        )
    })?
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("proving B failed: {e}"),
        )
    })?;

    let binding_verified = binding_hash_a == binding_hash_b;

    let proofs_a: Vec<ProofResult> = zk_proofs_a
        .iter()
        .map(|proof| ProofResult {
            predicate: format!("{:?}", proof.predicate_op()),
            proof_json: serde_json::to_string(proof).unwrap(),
            proof_hex: format!("0x{}", hex::encode(proof.proof_bytes())),
            op: format!("{:?}", proof.predicate_op()),
        })
        .collect();

    let proofs_b: Vec<ProofResult> = zk_proofs_b
        .iter()
        .map(|proof| ProofResult {
            predicate: format!("{:?}", proof.predicate_op()),
            proof_json: serde_json::to_string(proof).unwrap(),
            proof_hex: format!("0x{}", hex::encode(proof.proof_bytes())),
            op: format!("{:?}", proof.predicate_op()),
        })
        .collect();

    let hidden_fields_a: Vec<String> = all_fields_a
        .iter()
        .filter(|f| !proven_claims_a.contains(f))
        .cloned()
        .collect();
    let hidden_fields_b: Vec<String> = all_fields_b
        .iter()
        .filter(|f| !proven_claims_b.contains(f))
        .cloned()
        .collect();

    Ok(Json(ProveBindingResponse {
        proofs_a,
        proofs_b,
        binding_hash: format!("0x{}", hex::encode(binding_hash_a)),
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
    let mut zk_proofs = Vec::new();
    let mut descriptions = Vec::new();
    for input in &req.proofs {
        let proof: zk_eidas_types::proof::ZkProof = serde_json::from_str(&input.proof_json)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid proof JSON: {e}")))?;
        zk_proofs.push(proof);
        descriptions.push(input.predicate.clone());
    }

    let envelope = zk_eidas::ProofEnvelope::from_proofs(&zk_proofs, &descriptions);

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

// === Compound Proof Export (CBOR) ===

#[derive(Deserialize)]
struct CompoundExportRequest {
    compound_proof_json: String,
}

async fn export_compound_proof(
    Query(params): Query<HashMap<String, String>>,
    Json(req): Json<CompoundExportRequest>,
) -> Result<Json<ExportResponse>, (StatusCode, String)> {
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

    let mut envelope = zk_eidas::ProofEnvelope::from_proofs(compound.proofs(), &descriptions);
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

// === Nullifier Registry ===

#[derive(Deserialize)]
struct NullifierCheckRequest {
    nullifier: String,
}

#[derive(Serialize)]
struct NullifierCheckResponse {
    seen_before: bool,
    nullifier: String,
    registry_size: usize,
}

/// Check if a nullifier has been seen (read-only, does not insert).
fn query_nullifier_in_registry(registry: &HashSet<String>, nullifier: &str) -> bool {
    registry.contains(nullifier)
}

/// Insert a nullifier into the registry (write operation).
fn commit_nullifier_in_registry(registry: &mut HashSet<String>, nullifier: &str) {
    registry.insert(nullifier.to_string());
}

async fn check_nullifier(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NullifierCheckRequest>,
) -> Result<Json<NullifierCheckResponse>, (StatusCode, String)> {
    let registry = state.nullifier_registry.lock().await;
    let seen_before = query_nullifier_in_registry(&registry, &req.nullifier);
    let registry_size = registry.len();
    Ok(Json(NullifierCheckResponse {
        seen_before,
        nullifier: req.nullifier,
        registry_size,
    }))
}

async fn commit_nullifier(
    State(state): State<Arc<AppState>>,
    Json(req): Json<NullifierCheckRequest>,
) -> Result<Json<NullifierCheckResponse>, (StatusCode, String)> {
    let mut registry = state.nullifier_registry.lock().await;
    let seen_before = query_nullifier_in_registry(&registry, &req.nullifier);
    commit_nullifier_in_registry(&mut registry, &req.nullifier);
    let registry_size = registry.len();
    Ok(Json(NullifierCheckResponse {
        seen_before,
        nullifier: req.nullifier,
        registry_size,
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

async fn presentation_request(
    Json(body): Json<serde_json::Value>,
) -> impl axum::response::IntoResponse {
    use zk_eidas::openid4vp::{FieldConstraint, InputDescriptor, PresentationDefinition};

    let requirements = body["requirements"].as_array();
    let descriptors: Vec<InputDescriptor> = match requirements {
        Some(reqs) => reqs
            .iter()
            .enumerate()
            .map(|(i, req)| InputDescriptor {
                id: format!("requirement-{}", i),
                constraints: vec![FieldConstraint {
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

    let pd = PresentationDefinition {
        id,
        input_descriptors: descriptors,
    };

    Json(serde_json::to_value(&pd).unwrap())
}

// === Proof Cache ===

fn compute_cache_key(req: &CompoundProveRequest) -> String {
    // Hash predicates only (credential changes per issue).
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
    bindings: HashMap<String, CachedBindingProof>,
}

fn load_proof_cache(api_dir: &str) -> LoadedCache {
    // Check multiple locations: env var, working dir, CARGO_MANIFEST_DIR
    let candidates = [
        std::env::var("PROOF_CACHE_PATH").ok().map(std::path::PathBuf::from),
        Some(std::path::PathBuf::from("proof-cache.json")),
        Some(std::path::PathBuf::from(api_dir).join("proof-cache.json")),
    ];
    let cache_path = match candidates.iter().flatten().find(|p| p.exists()) {
        Some(p) => p.clone(),
        None => {
            eprintln!("[cache] No proof-cache.json found, running without cache");
            return LoadedCache { proofs: HashMap::new(), bindings: HashMap::new() };
        }
    };
    let data = std::fs::read_to_string(&cache_path).unwrap_or_default();
    let parsed: serde_json::Value = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[cache] Failed to parse proof-cache.json: {e}");
            return LoadedCache { proofs: HashMap::new(), bindings: HashMap::new() };
        }
    };
    let mut proofs = HashMap::new();
    if let Some(entries) = parsed["entries"].as_object() {
        for (key, entry) in entries {
            if let Ok(cached) = serde_json::from_value::<CachedProof>(entry.clone()) {
                proofs.insert(key.clone(), cached);
            }
        }
    }
    let mut bindings = HashMap::new();
    if let Some(entries) = parsed["binding_entries"].as_object() {
        for (key, entry) in entries {
            if let Ok(cached) = serde_json::from_value::<CachedBindingProof>(entry.clone()) {
                bindings.insert(key.clone(), cached);
            }
        }
    }
    eprintln!("[cache] Loaded {} cached proofs + {} bindings from {}",
        proofs.len(), bindings.len(), cache_path.display());
    LoadedCache { proofs, bindings }
}

// === Circuit Artifact Serving ===

async fn serve_circuit_artifact(
    State(state): State<Arc<AppState>>,
    AxumPath((name, file)): AxumPath<(String, String)>,
) -> impl axum::response::IntoResponse {
    let path = std::path::PathBuf::from(&state.circuits_path).join(&name).join(&file);
    match tokio::fs::read(&path).await {
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

// === Prepare Inputs (for browser-side proving) ===

#[derive(Deserialize)]
struct PrepareInputsRequest {
    credential: String,
    format: String,
    predicates: Vec<PredicateRequest>,
}

#[derive(Serialize)]
struct PrepareInputsResponse {
    ecdsa_inputs: serde_json::Value,
    claim_value: String,
    predicates: Vec<PredicateInputSpec>,
}

#[derive(Serialize)]
struct PredicateInputSpec {
    circuit: String,
    claim_value: String,
    #[serde(flatten)]
    extra: serde_json::Value,
}

async fn prepare_inputs(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PrepareInputsRequest>,
) -> Result<Json<PrepareInputsResponse>, (StatusCode, String)> {
    let builder = if req.format == "mdoc" {
        let (mdoc_bytes, pub_key_x, pub_key_y) = parse_mdoc_token(&req.credential)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc token: {e}")))?;
        let credential =
            zk_eidas_mdoc::MdocParser::parse_with_issuer_key(&mdoc_bytes, pub_key_x, pub_key_y)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("mdoc parse: {e}")))?;
        zk_eidas::ZkCredential::from_credential(credential, &state.circuits_path)
    } else {
        zk_eidas::ZkCredential::from_sdjwt(&req.credential, &state.circuits_path)
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("parse error: {e}")))?
    };

    // Use the first predicate's claim for ECDSA input (all predicates share the same ECDSA proof)
    let first_claim = req.predicates.first()
        .map(|p| p.claim.as_str())
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "no predicates".to_string()))?;

    let (ecdsa_json, claim_u64) = builder.ecdsa_input_json(first_claim)
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "credential lacks ECDSA data or claim disclosure".to_string()))?;

    let ecdsa_inputs: serde_json::Value = serde_json::from_str(&ecdsa_json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("input JSON error: {e}")))?;

    let mut predicates = Vec::new();
    for pred in &req.predicates {
        let circuit = match pred.op.as_str() {
            "gte" => {
                // Date claims invert: gte(age) → lte(birthdate)
                let claim_val = builder.credential().claims().get(&pred.claim);
                if claim_val.map(|v| matches!(v, zk_eidas_types::credential::ClaimValue::Date { .. })).unwrap_or(false) {
                    "lte"
                } else {
                    "gte"
                }
            }
            "lte" => {
                let claim_val = builder.credential().claims().get(&pred.claim);
                if claim_val.map(|v| matches!(v, zk_eidas_types::credential::ClaimValue::Date { .. })).unwrap_or(false) {
                    "gte"
                } else {
                    "lte"
                }
            }
            other => other,
        };
        predicates.push(PredicateInputSpec {
            circuit: circuit.to_string(),
            claim_value: claim_u64.to_string(),
            extra: serde_json::json!({
                "op": pred.op,
                "claim": pred.claim,
                "value": pred.value,
            }),
        });
    }

    Ok(Json(PrepareInputsResponse {
        ecdsa_inputs,
        claim_value: claim_u64.to_string(),
        predicates,
    }))
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

pub fn build_app(circuits_path: &str) -> Router {
    let api_dir = env!("CARGO_MANIFEST_DIR");
    let loaded = load_proof_cache(api_dir);
    let state = Arc::new(AppState {
        circuits_path: circuits_path.to_string(),
        nullifier_registry: Mutex::new(HashSet::new()),
        status_list: Mutex::new(Vec::new()),
        prove_semaphore: Semaphore::new(1),  // one proof at a time
        proof_cache: loaded.proofs,
        binding_cache: loaded.bindings,
    });

    Router::new()
        .route("/issuer/issue", post(issue_credential))
        .route("/holder/prove", post(generate_proof))
        .route("/verifier/verify", post(verify_proof))
        .route("/holder/proof-export", post(export_proof))
        .route("/holder/proof-export-compound", post(export_compound_proof))
        .route("/holder/prove-compound", post(generate_compound_proof))
        .route("/holder/prove-binding", post(prove_binding))
        .route("/verifier/verify-compound", post(verify_compound_proof))
        // NOTE: nullifier and revocation endpoints are unauthenticated.
        // A production deployment MUST add authorization middleware.
        .route("/verifier/check-nullifier", post(check_nullifier))
        .route("/verifier/commit-nullifier", post(commit_nullifier))
        .route("/issuer/revoke", post(revoke_credential))
        .route("/issuer/revocation-status", get(revocation_status))
        .route("/issuer/revocation-root", get(revocation_status))  // backward compat alias
        .route("/holder/prepare-inputs", post(prepare_inputs))
        .route("/circuits/{name}/{file}", get(serve_circuit_artifact))
        .route("/verifier/presentation-request", post(presentation_request))
        .layer(build_cors_layer())
        .with_state(state)
}

// === Main ===

#[tokio::main]
async fn main() {
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

    let app = build_app(&circuits_path);
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

    /// Returns a shared test fixture. The server is started once in a background
    /// thread with its own tokio runtime (survives across all test runtimes).
    async fn setup() -> &'static TestFixture {
        if let Some(f) = FIXTURE.get() {
            return f;
        }

        // Start server in a dedicated thread with its own runtime
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                let app = build_app(&circuits_path());
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
                "format": "sdjwt",
                "predicates": [
                    { "claim": "birth_date", "op": "gte", "value": 18 }
                ],
                "nullifier_scope": "test-scope-001"
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
        // Note: nullifier is only generated by prove() (single predicate),
        // not prove_all(). The fixture uses prove_all via the API, so nullifier
        // may be null even when nullifier_scope is set.
        let nullifier = prove_res["nullifier"].as_str().map(|s| s.to_string());

        FIXTURE.set(TestFixture {
            base_url,
            credential,
            proof_json,
            hidden_fields,
            nullifier,
        }).ok();

        FIXTURE.get().unwrap()
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
        assert!(!body["credential"].as_str().unwrap().is_empty());
        assert_eq!(body["format"], "sdjwt");
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
    #[serial]
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
    #[serial]
    async fn prove_missing_claim_returns_500() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/prove", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "sdjwt",
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
    #[serial]
    async fn prove_invalid_op_returns_400() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/prove", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "sdjwt",
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

    // === Nullifier ===

    #[tokio::test]
    #[serial]
    async fn nullifier_check_and_commit() {
        let f = setup().await;
        let client = reqwest::Client::new();
        // Use a synthetic nullifier value (the fixture may not have one due to
        // prove_all not propagating nullifier_scope to sub-proofs)
        let nullifier = "0xdeadbeef00000000000000000000000000000000000000000000000000000001";

        // Check — not seen yet
        let res = client
            .post(format!("{}/verifier/check-nullifier", f.base_url))
            .json(&serde_json::json!({ "nullifier": nullifier }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["seen_before"], false);

        // Commit
        let res = client
            .post(format!("{}/verifier/commit-nullifier", f.base_url))
            .json(&serde_json::json!({ "nullifier": nullifier }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);

        // Check again — seen now
        let res = client
            .post(format!("{}/verifier/check-nullifier", f.base_url))
            .json(&serde_json::json!({ "nullifier": nullifier }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["seen_before"], true);
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
    #[serial]
    async fn compound_prove_and_verify() {
        let f = setup().await;
        let client = reqwest::Client::new();

        // Prove compound AND: birth_date gte 18 AND nationality in EU
        let res = client
            .post(format!("{}/holder/prove-compound", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "sdjwt",
                "predicates": [
                    { "claim": "birth_date", "op": "gte", "value": 18 },
                    { "claim": "nationality", "op": "set_member", "value": ["UA", "DE", "FR"] }
                ],
                "op": "and"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["op"], "And");
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
        assert_eq!(verify_body["op"], "And");

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
    #[serial]
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
        let pid_sdjwt = pid_res["credential"].as_str().unwrap();

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
        let vehicle_sdjwt = vehicle_res["credential"].as_str().unwrap();

        // Prove binding with different claim names
        let res = client
            .post(format!("{}/holder/prove-binding", f.base_url))
            .json(&serde_json::json!({
                "sdjwt_a": pid_sdjwt,
                "sdjwt_b": vehicle_sdjwt,
                "binding_claim": "document_number",
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
        let vehicle2_sdjwt = vehicle2_res["credential"].as_str().unwrap();

        let res = client
            .post(format!("{}/holder/prove-binding", f.base_url))
            .json(&serde_json::json!({
                "sdjwt_a": pid_sdjwt,
                "sdjwt_b": vehicle2_sdjwt,
                "binding_claim": "document_number",
                "binding_claim_b": "owner_document_number",
                "predicates_a": [],
                "predicates_b": []
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
    #[serial]
    async fn compound_prove_returns_cached_false_without_cache() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/prove-compound", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "sdjwt",
                "predicates": [
                    { "claim": "birth_date", "op": "gte", "value": 18 }
                ],
                "op": "and"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(res.status(), 200);
        let body: serde_json::Value = res.json().await.unwrap();
        // Without a cache file, cached should be absent (skip_serializing_if false)
        assert!(body.get("cached").is_none(), "cached field should be absent when false");
        assert!(!body["compound_proof_json"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    #[serial]
    async fn compound_prove_skip_cache_works() {
        let f = setup().await;
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/holder/prove-compound", f.base_url))
            .json(&serde_json::json!({
                "credential": f.credential,
                "format": "sdjwt",
                "predicates": [
                    { "claim": "birth_date", "op": "gte", "value": 18 }
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
}
