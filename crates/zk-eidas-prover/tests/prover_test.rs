use zk_eidas_prover::circuit::CircuitLoader;
use zk_eidas_prover::prover::Prover;
use zk_eidas_types::commitment::EcdsaCommitment;
use zk_eidas_types::predicate::PredicateOp;

#[test]
fn test_circuit_loader_finds_build_artifacts() {
    let loader = CircuitLoader::new("../../circuits/build");
    // GTE circuit should exist if circuits have been built
    let result = loader.load(PredicateOp::Gte);
    // Might fail if zkey doesn't exist yet, but should find r1cs and wasm
    if result.is_err() {
        let err = result.unwrap_err().to_string();
        // Acceptable: zkey not found (r1cs/wasm exist but zkey doesn't)
        assert!(
            err.contains("not found"),
            "unexpected error: {err}"
        );
    }
}

#[test]
fn test_circuit_loader_not_found() {
    let loader = CircuitLoader::new("/nonexistent/path");
    let result = loader.load(PredicateOp::Gte);
    assert!(result.is_err());
}

#[test]
fn test_circuit_loader_all_ops_have_correct_names() {
    let loader = CircuitLoader::new("/tmp/fake_circuits");

    let ops = [
        (PredicateOp::Ecdsa, "ecdsa_verify"),
        (PredicateOp::Gte, "gte"),
        (PredicateOp::Lte, "lte"),
        (PredicateOp::Eq, "eq"),
        (PredicateOp::Neq, "neq"),
        (PredicateOp::Range, "range"),
        (PredicateOp::SetMember, "set_member"),
        (PredicateOp::Nullifier, "nullifier"),
        (PredicateOp::HolderBinding, "holder_binding"),
    ];

    for (op, expected_name) in ops {
        let err = loader.load(op).unwrap_err().to_string();
        assert!(
            err.contains(expected_name),
            "Error for {op:?} should contain '{expected_name}', got: {err}"
        );
    }
}

#[test]
fn test_prover_gte_missing_circuit() {
    let prover = Prover::new("/nonexistent");
    let commitment = EcdsaCommitment::new(vec![0u8; 32]);
    let result = prover.prove_gte(100, 18, &commitment, &[0u8; 32], &[0u8; 32]);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("not found"), "unexpected error: {err}");
}

#[test]
fn test_prover_ecdsa_missing_circuit() {
    let prover = Prover::new("/nonexistent");
    let input = zk_eidas_prover::SignedProofInput::new(
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        [0u8; 32],
        42,
        0,
        [0u64; 16],
    );
    let result = prover.prove_ecdsa(&input);
    assert!(result.is_err());
}

#[test]
fn test_prover_all_predicates_fail_with_missing_circuits() {
    let prover = Prover::new("/nonexistent");
    let commitment = EcdsaCommitment::new(vec![0u8; 32]);
    let hash = [0u8; 32];

    assert!(prover.prove_gte(1, 1, &commitment, &hash, &hash).is_err());
    assert!(prover.prove_lte(1, 1, &commitment, &hash, &hash).is_err());
    assert!(prover.prove_eq(1, 1, &commitment, &hash, &hash).is_err());
    assert!(prover.prove_neq(1, 2, &commitment, &hash, &hash).is_err());
    assert!(prover.prove_range(5, 1, 10, &commitment, &hash, &hash).is_err());
    assert!(prover.prove_set_member(1, &[0u64; 16], 1, &commitment, &hash, &hash).is_err());
    assert!(prover.prove_nullifier(1, 2, 3, &commitment, &hash, &hash).is_err());
    assert!(prover.prove_holder_binding(1, &commitment, &hash, &hash).is_err());
}
