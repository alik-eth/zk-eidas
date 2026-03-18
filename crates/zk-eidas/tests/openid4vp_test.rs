use zk_eidas::openid4vp::{
    FieldConstraint, InputDescriptor, PresentationDefinition, PresentationSubmission,
    SubmissionDescriptor, VPToken,
};
use zk_eidas_types::predicate::PredicateOp;
use zk_eidas_types::proof::ZkProof;

#[test]
fn presentation_definition_serializes() {
    let pd = PresentationDefinition {
        id: "age-check-1".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "age-over-18".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.birthdate".to_string(),
                predicate_op: "gte".to_string(),
                value: "18".to_string(),
            }],
        }],
    };
    let json = serde_json::to_string(&pd).unwrap();
    let back: PresentationDefinition = serde_json::from_str(&json).unwrap();
    assert_eq!(pd.id, back.id);
    assert_eq!(back.input_descriptors.len(), 1);
}

#[test]
fn presentation_definition_to_predicates() {
    let json = r#"{
        "id": "age-nationality-check",
        "input_descriptors": [
            {
                "id": "age-over-18",
                "constraints": [{"path": "$.birthdate", "predicate_op": "gte", "value": "18"}]
            },
            {
                "id": "eu-citizen",
                "constraints": [{"path": "$.nationality", "predicate_op": "set_member", "value": "DE,FR,NL,IT,ES"}]
            }
        ]
    }"#;
    let pd: PresentationDefinition = serde_json::from_str(json).unwrap();
    let predicates = pd.to_predicates().unwrap();
    assert_eq!(predicates.len(), 2);
    assert_eq!(predicates[0].0, "birthdate");
    assert_eq!(predicates[1].0, "nationality");
}

#[test]
fn presentation_definition_unsupported_op_returns_error() {
    let pd = PresentationDefinition {
        id: "test".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "bad".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.foo".to_string(),
                predicate_op: "regex".to_string(),
                value: ".*".to_string(),
            }],
        }],
    };
    assert!(pd.to_predicates().is_err());
}

#[test]
fn vp_token_from_proofs() {
    let pd = PresentationDefinition {
        id: "test-request".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "age-check".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.birthdate".to_string(),
                predicate_op: "gte".to_string(),
                value: "18".to_string(),
            }],
        }],
    };
    let proof = ZkProof::new(vec![1, 2, 3], vec![], vec![4, 5, 6], PredicateOp::Gte);
    let token = VPToken::from_proofs(&pd, &[proof]).unwrap();
    assert_eq!(token.definition_id, "test-request");
    assert_eq!(token.proofs.len(), 1);
    assert_eq!(token.descriptor_map.len(), 1);
    assert_eq!(token.descriptor_map[0].id, "age-check");

    // Round-trip: extract proofs back
    let extracted = token.extract_proofs().unwrap();
    assert_eq!(extracted.len(), 1);
    assert_eq!(extracted[0].predicate_op(), PredicateOp::Gte);
}

#[test]
fn vp_token_not_enough_proofs_returns_error() {
    let pd = PresentationDefinition {
        id: "test".to_string(),
        input_descriptors: vec![
            InputDescriptor {
                id: "a".to_string(),
                constraints: vec![],
            },
            InputDescriptor {
                id: "b".to_string(),
                constraints: vec![],
            },
        ],
    };
    let result = VPToken::from_proofs(&pd, &[]);
    assert!(result.is_err());
}

#[test]
fn presentation_submission_serializes() {
    let submission = PresentationSubmission {
        id: "submission-1".to_string(),
        definition_id: "pd-123".to_string(),
        descriptor_map: vec![SubmissionDescriptor {
            id: "age-check".to_string(),
            format: "zk_proof".to_string(),
            path: "$.proofs[0]".to_string(),
        }],
    };
    let json = serde_json::to_string(&submission).unwrap();
    let back: PresentationSubmission = serde_json::from_str(&json).unwrap();
    assert_eq!(submission.id, back.id);
    assert_eq!(submission.definition_id, back.definition_id);
    assert_eq!(back.descriptor_map.len(), 1);
}
