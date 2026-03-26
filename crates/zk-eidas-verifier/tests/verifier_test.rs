use zk_eidas_verifier::Verifier;
use zk_eidas_types::predicate::PredicateOp;

#[test]
fn verify_with_missing_circuit_returns_error() {
    let verifier = Verifier::new("/nonexistent");

    let proof = zk_eidas_types::proof::ZkProof::new(
        vec![1, 2, 3],
        vec![],
        vec![4, 5],
        PredicateOp::Gte,
    );

    let result = verifier.verify(&proof);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("circuit load failed"), "unexpected error: {err}");
}

#[test]
fn verify_with_op_missing_circuit_returns_error() {
    let verifier = Verifier::new("/nonexistent");

    let proof = zk_eidas_types::proof::ZkProof::new(
        vec![1, 2, 3],
        vec![],
        vec![],
        PredicateOp::Ecdsa,
    );

    let result = verifier.verify_with_op(&proof, PredicateOp::Ecdsa);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("circuit load failed"), "unexpected error: {err}");
}

#[test]
fn verify_all_ops_fail_gracefully_with_missing_circuits() {
    let verifier = Verifier::new("/nonexistent");
    let ops = [
        PredicateOp::Ecdsa,
        PredicateOp::Gte,
        PredicateOp::Lte,
        PredicateOp::Eq,
        PredicateOp::Neq,
        PredicateOp::Range,
        PredicateOp::SetMember,
        PredicateOp::Nullifier,
        PredicateOp::HolderBinding,
    ];

    for op in ops {
        let proof = zk_eidas_types::proof::ZkProof::new(
            vec![1, 2, 3],
            vec![],
            vec![],
            op,
        );
        let result = verifier.verify(&proof);
        assert!(result.is_err(), "expected error for {:?}", op);
    }
}
