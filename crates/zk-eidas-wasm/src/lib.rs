pub mod algebra;
pub mod circuit;
pub mod error;
pub mod field;
pub mod ligero;
pub mod mdoc;
pub mod merkle;
pub mod proof;
pub mod sumcheck;
pub mod transcript;
pub mod zk;

use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
pub struct AttributeInput {
    pub id: String,
    pub cbor_value: Vec<u8>,
    pub verification_type: u8,
}

#[derive(Deserialize)]
pub struct PublicInputs {
    pub issuer_pk_x: String,
    pub issuer_pk_y: String,
    pub transcript: Vec<u8>,
    pub attributes: Vec<AttributeInput>,
    pub now: String,
    pub contract_hash: Vec<u8>,
    pub nullifier_hash: Vec<u8>,
    pub binding_hash: Vec<u8>,
    pub escrow_digest: Vec<u8>,
    pub doc_type: String,
    pub version: usize,
    pub block_enc_hash: usize,
    pub block_enc_sig: usize,
}

#[derive(Serialize)]
pub struct VerifyResult {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[wasm_bindgen]
pub fn verify(
    circuit_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_js: JsValue,
) -> JsValue {
    let inputs: PublicInputs = match serde_wasm_bindgen::from_value(public_inputs_js) {
        Ok(v) => v,
        Err(e) => {
            let result = VerifyResult {
                valid: false,
                error: Some(format!("invalid public inputs: {e}")),
            };
            return serde_wasm_bindgen::to_value(&result).unwrap();
        }
    };

    let attrs: Vec<mdoc::AttributeRequest> = inputs
        .attributes
        .iter()
        .map(|a| mdoc::AttributeRequest {
            id: a.id.clone(),
            cbor_value: a.cbor_value.clone(),
            verification_type: a.verification_type,
        })
        .collect();

    let result = mdoc::mdoc_verify(
        circuit_bytes,
        proof_bytes,
        &inputs.issuer_pk_x,
        &inputs.issuer_pk_y,
        &inputs.transcript,
        &attrs,
        &inputs.now,
        &inputs.contract_hash,
        &inputs.nullifier_hash,
        &inputs.binding_hash,
        &inputs.escrow_digest,
        &inputs.doc_type,
        inputs.version,
        inputs.block_enc_hash,
        inputs.block_enc_sig,
    );

    let out = match result {
        Ok(valid) => VerifyResult { valid, error: None },
        Err(e) => VerifyResult {
            valid: false,
            error: Some(e.to_string()),
        },
    };
    serde_wasm_bindgen::to_value(&out).unwrap()
}
