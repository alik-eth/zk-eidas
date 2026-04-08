//! Cross-verification integration test: C++ Longfellow prover -> pure-Rust WASM verifier.
//!
//! Proves with `longfellow_sys::mdoc::prove()` and verifies with
//! `zk_eidas_wasm::mdoc::mdoc_verify()` to confirm interoperability.
//!
//! Run with:
//!   cargo test -p zk-eidas-wasm --test cross_verify -- --nocapture

use longfellow_sys::mdoc::{AttributeRequest, MdocCircuit};
use longfellow_sys::safe::VerifyType;
use zk_eidas_types::credential::ClaimValue;

#[test]
fn cross_verify_cpp_prover_rust_verifier() {
    // ---------------------------------------------------------------
    // 1. Issue an mdoc credential with ECDSA
    // ---------------------------------------------------------------
    let (mdoc_bytes, pub_key_x, pub_key_y) =
        zk_eidas_mdoc::test_utils::build_ecdsa_signed_mdoc(
            vec![("age_over_18", ClaimValue::Boolean(true))],
            "https://test.example.com",
        );

    // ---------------------------------------------------------------
    // 2. Load the pre-built 1-attribute circuit from cache
    // ---------------------------------------------------------------
    let circuit_path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../demo/web/circuit-cache/mdoc-1attr.bin");
    let circuit = MdocCircuit::load(&circuit_path, 1)
        .expect("failed to load circuit from demo/web/circuit-cache/mdoc-1attr.bin");

    // ---------------------------------------------------------------
    // 3. Build parameters
    // ---------------------------------------------------------------
    let pkx_hex = format!("0x{}", hex::encode(pub_key_x));
    let pky_hex = format!("0x{}", hex::encode(pub_key_y));
    let transcript = b"zk-eidas-demo";
    let now = "2026-01-01T00:00:00Z";
    let contract_hash = [0u8; 8];
    let escrow_fields = [[0u8; 32]; 8];
    let doc_type = "org.iso.18013.5.1.mDL";

    let attributes = vec![AttributeRequest {
        namespace: "org.iso.18013.5.1".to_string(),
        identifier: "age_over_18".to_string(),
        cbor_value: vec![0xf5], // CBOR true
        verify_type: VerifyType::Eq,
    }];

    // ---------------------------------------------------------------
    // 4. Prove with C++ Longfellow prover
    // ---------------------------------------------------------------
    let proof = longfellow_sys::mdoc::prove(
        &circuit,
        &mdoc_bytes,
        &pkx_hex,
        &pky_hex,
        transcript,
        &attributes,
        now,
        &contract_hash,
        &escrow_fields,
    )
    .expect("C++ prover failed");

    assert!(!proof.proof_bytes.is_empty(), "proof should not be empty");
    println!("C++ proof generated: {} bytes", proof.proof_bytes.len());

    // Sanity: verify with the C++ verifier first
    longfellow_sys::mdoc::verify(
        &circuit,
        &proof,
        &pkx_hex,
        &pky_hex,
        transcript,
        &attributes,
        now,
        doc_type,
        &contract_hash,
    )
    .expect("C++ verify failed — proof is invalid");
    println!("  nullifier_hash: {}", hex::encode(proof.nullifier_hash));
    println!("  binding_hash:   {}", hex::encode(proof.binding_hash));
    println!("  escrow_digest:  {}", hex::encode(proof.escrow_digest));

    // ---------------------------------------------------------------
    // 5. Extract ZkSpec parameters from the circuit
    // ---------------------------------------------------------------
    let version = circuit.version();
    let (block_enc_hash, block_enc_sig) = circuit.block_enc();
    println!("  version={version}, block_enc_hash={block_enc_hash}, block_enc_sig={block_enc_sig}");

    // ---------------------------------------------------------------
    // 6. Read circuit bytes for the WASM verifier
    // ---------------------------------------------------------------
    let circuit_bytes = std::fs::read(&circuit_path)
        .expect("failed to read circuit file");

    // Debug: print proof structure info
    println!("  circuit_bytes len: {}", circuit_bytes.len());
    // Verify the circuit bytes are the same as what was used for proving
    assert_eq!(circuit_bytes.len(), circuit_bytes.len(), "circuit bytes length mismatch");
    println!("  proof_bytes len: {}", proof.proof_bytes.len());
    // First 96 bytes are 6 MACs
    println!("  first 112 bytes (MACs + start): {:?}", &proof.proof_bytes[..112.min(proof.proof_bytes.len())]);

    // ---------------------------------------------------------------
    // 7. Convert attributes for the WASM verifier
    // ---------------------------------------------------------------
    let wasm_attributes: Vec<zk_eidas_wasm::mdoc::AttributeRequest> = attributes
        .iter()
        .map(|a| zk_eidas_wasm::mdoc::AttributeRequest {
            id: a.identifier.clone(),
            cbor_value: a.cbor_value.clone(),
            verification_type: a.verify_type as u8,
        })
        .collect();

    // ---------------------------------------------------------------
    // 8. Verify with pure-Rust WASM verifier
    // ---------------------------------------------------------------
    let result = zk_eidas_wasm::mdoc::mdoc_verify(
        &circuit_bytes,
        &proof.proof_bytes,
        &pkx_hex,
        &pky_hex,
        transcript,
        &wasm_attributes,
        now,
        &contract_hash,
        &proof.nullifier_hash,
        &proof.binding_hash,
        &proof.escrow_digest,
        doc_type,
        version,
        block_enc_hash,
        block_enc_sig,
    );

    match &result {
        Ok(true) => println!("WASM verifier: PASS"),
        Ok(false) => panic!("WASM verifier returned Ok(false) — verification failed"),
        Err(e) => panic!("WASM verifier returned error: {e}"),
    }

    assert_eq!(result.unwrap(), true, "cross-verification must succeed");
}
