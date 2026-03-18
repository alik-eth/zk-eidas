use std::collections::BTreeMap;
use zk_eidas_types::credential::{ClaimValue, Credential, SignatureData};
use zk_eidas_types::predicate::{Predicate, PredicateOp};
use zk_eidas_types::proof::ZkProof;
use zk_eidas_types::witness::Witness;

#[test]
fn integer_to_field_element() {
    let bytes = ClaimValue::Integer(18).to_field_element().unwrap();
    assert_eq!(bytes.len(), 8);
    assert_eq!(u64::from_be_bytes(bytes.try_into().unwrap()), 18);
}

#[test]
fn boolean_true_to_field_element() {
    let bytes = ClaimValue::Boolean(true).to_field_element().unwrap();
    assert_eq!(u64::from_be_bytes(bytes.try_into().unwrap()), 1);
}

#[test]
fn boolean_false_to_field_element() {
    let bytes = ClaimValue::Boolean(false).to_field_element().unwrap();
    assert_eq!(u64::from_be_bytes(bytes.try_into().unwrap()), 0);
}

#[test]
fn date_to_field_element() {
    let bytes = ClaimValue::Date {
        year: 2000,
        month: 1,
        day: 15,
    }
    .to_field_element()
    .unwrap();
    assert_eq!(bytes.len(), 8);
    let days = u64::from_be_bytes(bytes.try_into().unwrap());
    assert_eq!(days, 10971);
}

#[test]
fn string_to_field_element_is_sha256() {
    let bytes = ClaimValue::String("active".to_string())
        .to_field_element()
        .unwrap();
    assert_eq!(bytes.len(), 32);
}

#[test]
fn predicate_construction_and_accessors() {
    let pred = Predicate::new("age", PredicateOp::Gte, ClaimValue::Integer(18));
    assert_eq!(pred.claim_name(), "age");
    assert_eq!(pred.op(), PredicateOp::Gte);
    let threshold_bytes = pred.threshold_field().unwrap();
    assert_eq!(u64::from_be_bytes(threshold_bytes.try_into().unwrap()), 18);
}

#[test]
fn predicate_convenience_constructors() {
    let gte = Predicate::gte("age", ClaimValue::Integer(18));
    assert_eq!(gte.op(), PredicateOp::Gte);

    let lte = Predicate::lte("age", ClaimValue::Integer(65));
    assert_eq!(lte.op(), PredicateOp::Lte);

    let eq = Predicate::eq("status", ClaimValue::Boolean(true));
    assert_eq!(eq.op(), PredicateOp::Eq);

    let neq = Predicate::neq("status", ClaimValue::Boolean(false));
    assert_eq!(neq.op(), PredicateOp::Neq);
}

#[test]
fn credential_construction() {
    let mut claims = BTreeMap::new();
    claims.insert("age".to_string(), ClaimValue::Integer(25));
    claims.insert("active".to_string(), ClaimValue::Boolean(true));

    let sig_data = SignatureData::Opaque {
        signature: vec![1, 2, 3],
        public_key: vec![4, 5, 6],
    };

    let cred = Credential::new(claims, "test-issuer".to_string(), sig_data, BTreeMap::new());

    assert_eq!(cred.issuer(), "test-issuer");
    assert!(matches!(
        cred.signature_data(),
        SignatureData::Opaque { .. }
    ));
    assert_eq!(cred.claims().len(), 2);
}

#[test]
fn witness_from_credential_and_predicate_success() {
    let mut claims = BTreeMap::new();
    claims.insert("age".to_string(), ClaimValue::Integer(25));

    let sig_data = SignatureData::Opaque {
        signature: vec![10, 20],
        public_key: vec![30, 40],
    };

    let cred = Credential::new(claims, "issuer".to_string(), sig_data, BTreeMap::new());
    let pred = Predicate::gte("age", ClaimValue::Integer(18));

    let witness = Witness::from_credential_and_predicate(&cred, &pred).unwrap();
    assert_eq!(
        u64::from_be_bytes(witness.claim_field().try_into().unwrap()),
        25
    );
    assert_eq!(
        u64::from_be_bytes(witness.threshold_field().try_into().unwrap()),
        18
    );
    assert!(matches!(
        witness.signature_data(),
        SignatureData::Opaque { .. }
    ));
}

#[test]
fn witness_from_credential_and_predicate_claim_not_found() {
    let claims = BTreeMap::new();
    let sig_data = SignatureData::Opaque {
        signature: vec![],
        public_key: vec![],
    };
    let cred = Credential::new(claims, "issuer".to_string(), sig_data, BTreeMap::new());
    let pred = Predicate::gte("missing", ClaimValue::Integer(0));

    let result = Witness::from_credential_and_predicate(&cred, &pred);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("missing"));
}

#[test]
fn negative_integer_to_field_returns_error() {
    let claim = ClaimValue::Integer(-5);
    let result = claim.to_field_element();
    assert!(result.is_err(), "negative integer should return error");
    assert!(result.unwrap_err().to_string().contains("-5"));
}

#[test]
fn zkproof_construction() {
    let proof = ZkProof::new(
        vec![1, 2, 3],
        vec![vec![4, 5], vec![6, 7]],
        vec![8, 9],
        PredicateOp::Gte,
    );
    assert_eq!(proof.proof_bytes(), &[1, 2, 3]);
    assert_eq!(proof.public_inputs().len(), 2);
    assert_eq!(proof.public_inputs()[0], vec![4, 5]);
    assert_eq!(proof.public_inputs()[1], vec![6, 7]);
    assert_eq!(proof.verification_key(), &[8, 9]);
}

#[test]
fn predicate_op_holder_binding_serializes() {
    use zk_eidas_types::predicate::PredicateOp;
    let op = PredicateOp::HolderBinding;
    let json = serde_json::to_string(&op).unwrap();
    let back: PredicateOp = serde_json::from_str(&json).unwrap();
    assert_eq!(op, back);
}

#[test]
fn zkproof_binding_hash_round_trip() {
    use zk_eidas_types::predicate::PredicateOp;
    use zk_eidas_types::proof::ZkProof;
    let proof = ZkProof::new(
        vec![1, 2, 3],
        vec![],
        vec![4, 5, 6],
        PredicateOp::HolderBinding,
    );
    let hash = [42u8; 32];
    let proof = proof.with_binding_hash(hash);
    assert_eq!(proof.binding_hash(), Some(&hash));
}
