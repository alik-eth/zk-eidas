fn main() {
    println!("=== zk-eidas Age Verification Demo ===\n");

    let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Oleksandr",
            "family_name": "Kovalenko",
            "birthdate": "2000-06-15",
        }),
        "https://id.diia.gov.ua",
    );
    println!("[Holder] Received ECDSA-signed SD-JWT VC from wallet");
    println!("[Holder] Credential contains: given_name, family_name, birthdate\n");

    println!("[Holder] Generating ZK proof: age >= 18 ...");
    let proof = zk_eidas::ZkCredential::from_sdjwt(&sdjwt, "circuits/predicates")
        .expect("failed to parse SD-JWT")
        .predicate("birthdate", zk_eidas::Predicate::gte(18))
        .prove()
        .expect("proof generation failed");

    println!(
        "[Holder] Proof generated ({} bytes)",
        proof.proof_bytes().len()
    );
    println!("[Holder] No claim values revealed to verifier\n");

    println!("[Verifier] Received proof, verifying ...");
    let valid = zk_eidas::ZkVerifier::new("circuits/predicates")
        .verify(&proof)
        .expect("verification failed");

    if valid {
        println!("[Verifier] VERIFIED: holder is >= 18 years old");
        println!("[Verifier] Learned nothing else about the holder");
    } else {
        println!("[Verifier] REJECTED: proof is invalid");
    }
}
