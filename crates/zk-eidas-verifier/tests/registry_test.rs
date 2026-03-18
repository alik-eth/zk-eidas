use zk_eidas_types::predicate::PredicateOp;
use zk_eidas_verifier::{RegistryVerifier, TrustedCircuitRegistry};

#[test]
fn empty_registry_has_no_keys() {
    let registry = TrustedCircuitRegistry::empty();
    assert!(!registry.has(PredicateOp::Gte));
    assert!(!registry.has(PredicateOp::Ecdsa));
    assert!(registry.get(PredicateOp::Gte).is_none());
}

#[test]
fn from_directory_nonexistent_returns_empty() {
    let registry = TrustedCircuitRegistry::from_directory("/nonexistent/path/xyz").unwrap();
    assert!(!registry.has(PredicateOp::Gte));
    assert!(!registry.has(PredicateOp::Ecdsa));
}

#[test]
fn registry_verifier_missing_circuit_returns_error() {
    let registry = TrustedCircuitRegistry::empty();
    let verifier = RegistryVerifier::new(registry);
    let proof = zk_eidas_types::proof::ZkProof::new(
        vec![1, 2, 3],
        vec![],
        vec![],
        PredicateOp::Gte,
    );
    let result = verifier.verify(&proof);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("no trusted circuit"),
        "unexpected error: {err}"
    );
}

#[test]
fn supported_ops_returns_9_operations() {
    let ops = TrustedCircuitRegistry::supported_ops();
    assert_eq!(ops.len(), 9);
    assert!(ops.contains(&PredicateOp::Ecdsa));
    assert!(ops.contains(&PredicateOp::Gte));
    assert!(ops.contains(&PredicateOp::Lte));
    assert!(ops.contains(&PredicateOp::Eq));
    assert!(ops.contains(&PredicateOp::Neq));
    assert!(ops.contains(&PredicateOp::Range));
    assert!(ops.contains(&PredicateOp::SetMember));
    assert!(ops.contains(&PredicateOp::Nullifier));
    assert!(ops.contains(&PredicateOp::HolderBinding));
}
