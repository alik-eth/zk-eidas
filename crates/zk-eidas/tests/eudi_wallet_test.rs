//! End-to-end EUDI wallet integration tests.
//!
//! These tests simulate the OpenID4VP presentation flow between
//! a verifier and a holder wallet using ZK proofs.

mod synthetic;

use zk_eidas::openid4vp::{
    FieldConstraint, InputDescriptor, PresentationDefinition, PresentationSubmission, VPToken,
};
use zk_eidas::{Predicate, ZkCredential, ZkVerifier};

const CIRCUITS: &str = "../../circuits/build";

/// Rebuild a Predicate from a reference (Predicate doesn't implement Clone).
fn rebuild_predicate(p: &Predicate) -> Predicate {
    match p {
        Predicate::Gte(v) => Predicate::gte(*v),
        Predicate::Lte(v) => Predicate::lte(*v),
        Predicate::Eq(v) => Predicate::eq(v),
        Predicate::Neq(v) => Predicate::neq(v),
        Predicate::SetMember(v) => Predicate::set_member(v.iter().map(|s| s.as_str()).collect()),
        _ => panic!("unexpected predicate type from to_predicates()"),
    }
}

/// Simulates the full OpenID4VP flow: verifier request -> holder proof -> verifier verify.
///
/// Scenario: Online alcohol purchase -- verifier requires age >= 18.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_age_verification_single_predicate() {
    // === VERIFIER: Create Presentation Definition ===
    let pd = PresentationDefinition {
        id: "alcohol-purchase-001".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "age-over-18".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.birthdate".to_string(),
                predicate_op: "gte".to_string(),
                value: "18".to_string(),
            }],
        }],
    };

    // Serialize and send to holder (simulates HTTP transport)
    let pd_json = serde_json::to_string(&pd).unwrap();

    // === HOLDER: Parse and process ===
    let received_pd: PresentationDefinition = serde_json::from_str(&pd_json).unwrap();
    let predicates = received_pd.to_predicates().unwrap();
    assert_eq!(predicates.len(), 1);
    assert_eq!(predicates[0].0, "birthdate");

    // Holder has a French PID credential
    let sdjwt = synthetic::pid_credential::french_citizen();
    let mut builder = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS).unwrap();
    for (claim_name, predicate) in &predicates {
        builder = builder.predicate(claim_name, rebuild_predicate(predicate));
    }
    let proofs = builder.prove_all().unwrap();

    // Build VP Token and Presentation Submission
    let vp_token = VPToken::from_proofs(&received_pd, &proofs).unwrap();
    let submission =
        PresentationSubmission::from_definition_and_proofs(&received_pd, &proofs).unwrap();

    // Serialize response (simulates HTTP transport back to verifier)
    let vp_json = serde_json::to_string(&vp_token).unwrap();
    let sub_json = serde_json::to_string(&submission).unwrap();

    // === VERIFIER: Receive and verify ===
    let received_vp: VPToken = serde_json::from_str(&vp_json).unwrap();
    let received_sub: PresentationSubmission = serde_json::from_str(&sub_json).unwrap();

    assert_eq!(received_sub.definition_id, pd.id);
    assert_eq!(received_sub.descriptor_map.len(), 1);

    let extracted_proofs = received_vp.extract_proofs().unwrap();
    let verifier = ZkVerifier::new(CIRCUITS);
    for proof in &extracted_proofs {
        let valid = verifier.verify(proof).unwrap();
        assert!(valid, "Proof verification failed");
    }
}

/// Multi-predicate scenario: age >= 21 AND EU issuing_country.
///
/// Scenario: Cross-border regulated service requiring age 21+ and EU residency.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_multi_predicate_age_and_nationality() {
    // === VERIFIER ===
    let pd = PresentationDefinition {
        id: "regulated-service-001".to_string(),
        input_descriptors: vec![
            InputDescriptor {
                id: "age-over-21".to_string(),
                constraints: vec![FieldConstraint {
                    path: "$.birthdate".to_string(),
                    predicate_op: "gte".to_string(),
                    value: "21".to_string(),
                }],
            },
            InputDescriptor {
                id: "eu-issuing-country".to_string(),
                constraints: vec![FieldConstraint {
                    path: "$.issuing_country".to_string(),
                    predicate_op: "set_member".to_string(),
                    value: "DE,FR,NL,IT,ES,PL,UA".to_string(),
                }],
            },
        ],
    };

    let pd_json = serde_json::to_string(&pd).unwrap();

    // === HOLDER: German citizen ===
    let received_pd: PresentationDefinition = serde_json::from_str(&pd_json).unwrap();
    let predicates = received_pd.to_predicates().unwrap();
    assert_eq!(predicates.len(), 2);

    let sdjwt = synthetic::pid_credential::eu_citizen(); // Hans Mueller, DE, born 1985
    let mut builder = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS).unwrap();
    for (claim_name, predicate) in &predicates {
        builder = builder.predicate(claim_name, rebuild_predicate(predicate));
    }
    let proofs = builder.prove_all().unwrap();

    let vp_token = VPToken::from_proofs(&received_pd, &proofs).unwrap();
    let submission =
        PresentationSubmission::from_definition_and_proofs(&received_pd, &proofs).unwrap();

    // === VERIFIER ===
    let vp_json = serde_json::to_string(&vp_token).unwrap();
    let received_vp: VPToken = serde_json::from_str(&vp_json).unwrap();

    assert_eq!(submission.descriptor_map.len(), 2);

    let extracted = received_vp.extract_proofs().unwrap();
    assert_eq!(extracted.len(), 2);
    let verifier = ZkVerifier::new(CIRCUITS);
    for proof in &extracted {
        assert!(verifier.verify(proof).unwrap(), "Proof should be valid");
    }
}

/// Cross-border scenario: Italian credential verified by German service.
///
/// Scenario: Italian citizen accessing a German government portal.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_cross_border_italian_in_germany() {
    let pd = PresentationDefinition {
        id: "de-gov-portal-001".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "age-over-18".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.birthdate".to_string(),
                predicate_op: "gte".to_string(),
                value: "18".to_string(),
            }],
        }],
    };

    let sdjwt = synthetic::pid_credential::italian_citizen();
    let predicates = pd.to_predicates().unwrap();
    let mut builder = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS).unwrap();
    for (claim_name, predicate) in &predicates {
        builder = builder.predicate(claim_name, rebuild_predicate(predicate));
    }
    let proofs = builder.prove_all().unwrap();

    let vp_token = VPToken::from_proofs(&pd, &proofs).unwrap();
    let extracted = vp_token.extract_proofs().unwrap();
    let verifier = ZkVerifier::new(CIRCUITS);
    for proof in &extracted {
        assert!(
            verifier.verify(proof).unwrap(),
            "Cross-border proof should verify"
        );
    }
}

/// Minor wallet should fail age >= 18 through the full OpenID4VP flow.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_minor_fails_age_check() {
    let pd = PresentationDefinition {
        id: "age-check-minor".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "age-over-18".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.birthdate".to_string(),
                predicate_op: "gte".to_string(),
                value: "18".to_string(),
            }],
        }],
    };

    let sdjwt = synthetic::pid_credential::minor_citizen();
    let predicates = pd.to_predicates().unwrap();
    let mut builder = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS).unwrap();
    for (claim_name, predicate) in &predicates {
        builder = builder.predicate(claim_name, rebuild_predicate(predicate));
    }

    // Proof generation should fail because birthdate doesn't satisfy gte(18)
    let result = builder.prove_all();
    assert!(
        result.is_err(),
        "Minor should fail age >= 18 proof generation"
    );
}

/// Full OpenID4VP flow with ECDSA-signed credential.
/// This exercises the signed circuit path where the issuer's ECDSA signature
/// is verified inside the ZK circuit.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_signed_age_verification() {
    let pd = PresentationDefinition {
        id: "signed-age-check-001".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "age-over-18".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.birthdate".to_string(),
                predicate_op: "gte".to_string(),
                value: "18".to_string(),
            }],
        }],
    };

    let sdjwt = synthetic::pid_credential::french_citizen_signed();
    let predicates = pd.to_predicates().unwrap();
    let mut builder = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS).unwrap();
    for (claim_name, predicate) in &predicates {
        builder = builder.predicate(claim_name, rebuild_predicate(predicate));
    }
    let proofs = builder.prove_all().unwrap();

    let vp_token = VPToken::from_proofs(&pd, &proofs).unwrap();
    let extracted = vp_token.extract_proofs().unwrap();

    let verifier = ZkVerifier::new(CIRCUITS);
    for proof in &extracted {
        assert!(
            verifier.verify(proof).unwrap(),
            "Signed proof should verify"
        );
    }
}

/// Signed credential with multiple predicates: age + issuing_country.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_signed_multi_predicate() {
    let pd = PresentationDefinition {
        id: "signed-multi-001".to_string(),
        input_descriptors: vec![
            InputDescriptor {
                id: "age-over-18".to_string(),
                constraints: vec![FieldConstraint {
                    path: "$.birthdate".to_string(),
                    predicate_op: "gte".to_string(),
                    value: "18".to_string(),
                }],
            },
            InputDescriptor {
                id: "eu-citizen".to_string(),
                constraints: vec![FieldConstraint {
                    path: "$.issuing_country".to_string(),
                    predicate_op: "set_member".to_string(),
                    value: "DE,FR,NL,IT,ES".to_string(),
                }],
            },
        ],
    };

    let sdjwt = synthetic::pid_credential::eu_citizen_signed();
    let predicates = pd.to_predicates().unwrap();
    let mut builder = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS).unwrap();
    for (claim_name, predicate) in &predicates {
        builder = builder.predicate(claim_name, rebuild_predicate(predicate));
    }
    let proofs = builder.prove_all().unwrap();
    assert_eq!(proofs.len(), 2);

    let vp_token = VPToken::from_proofs(&pd, &proofs).unwrap();
    let extracted = vp_token.extract_proofs().unwrap();
    assert_eq!(extracted.len(), 2);

    let verifier = ZkVerifier::new(CIRCUITS);
    for proof in &extracted {
        assert!(
            verifier.verify(proof).unwrap(),
            "Signed multi-predicate proof should verify"
        );
    }
}

/// Compound AND: age between 18 and 65 (working age verification).
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_compound_age_range() {
    let sdjwt = synthetic::pid_credential::french_citizen(); // age 30
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate(
            "birthdate",
            Predicate::and(vec![Predicate::gte(18), Predicate::lte(65)]),
        )
        .prove_compound()
        .unwrap();

    let verifier = ZkVerifier::new(CIRCUITS);
    let valid = verifier.verify_compound(&proof).unwrap();
    assert!(valid, "30-year-old should be in working age range 18-65");
}

/// Compound OR: issuing_country is FR or DE — Italian should fail.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_compound_country_or_fails() {
    let sdjwt = synthetic::pid_credential::italian_citizen(); // IT
    let result = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate(
            "issuing_country",
            Predicate::or(vec![Predicate::eq("FR"), Predicate::eq("DE")]),
        )
        .prove_compound();

    // Italian citizen is neither FR nor DE, so proof generation should fail
    assert!(
        result.is_err(),
        "Italian citizen should fail FR-or-DE check"
    );
}

/// Contract nullifier: same credential + same contract_hash + same salt → same nullifier.
/// Different contract_hash or salt → different nullifier.
/// TODO(Task 6): rewrite with actual circuit artifacts and contract_nullifier API
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts — rewrite in Task 6"]
async fn e2e_nullifier_determinism() {
    let sdjwt = synthetic::pid_credential::french_citizen();

    let result = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .contract_nullifier("document_number", 12345, 67890)
        .prove_compound();

    // Will fail without circuit artifacts, but proves the API compiles
    assert!(result.is_err());
}

/// Holder binding: two credentials with matching given_name produce same binding hash.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_holder_binding_same_holder() {
    let (sdjwt_a, _key_a) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Jean",
            "family_name": "Dupont",
            "birthdate": "1995-09-20",
            "nationalities": ["FR"],
            "issuing_authority": "ANTS",
            "issuing_country": "FR",
        }),
        "https://id.france.gouv.fr",
    );
    let (sdjwt_b, _key_b) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
        serde_json::json!({
            "given_name": "Jean",
            "family_name": "Dupont",
            "birthdate": "1995-09-20",
            "nationalities": ["FR"],
            "issuing_authority": "Another Issuer",
            "issuing_country": "FR",
        }),
        "https://another-issuer.fr",
    );

    let (proofs_a, hash_a) = ZkCredential::from_sdjwt(&sdjwt_a, CIRCUITS)
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove_with_binding("given_name")
        .unwrap();

    let (proofs_b, hash_b) = ZkCredential::from_sdjwt(&sdjwt_b, CIRCUITS)
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove_with_binding("given_name")
        .unwrap();

    assert_eq!(
        hash_a, hash_b,
        "Same holder claim should produce same binding hash"
    );

    let verifier = ZkVerifier::new(CIRCUITS);
    assert!(verifier
        .verify_holder_binding(&proofs_a, &proofs_b)
        .unwrap());
}

/// Different holders produce different binding hashes.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_holder_binding_different_holders() {
    let sdjwt_a = synthetic::pid_credential::french_citizen_signed(); // Jean
    let sdjwt_b = synthetic::pid_credential::eu_citizen_signed(); // Hans

    let (_proofs_a, hash_a) = ZkCredential::from_sdjwt(&sdjwt_a, CIRCUITS)
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove_with_binding("given_name")
        .unwrap();

    let (_proofs_b, hash_b) = ZkCredential::from_sdjwt(&sdjwt_b, CIRCUITS)
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove_with_binding("given_name")
        .unwrap();

    assert_ne!(
        hash_a, hash_b,
        "Different holders should produce different binding hashes"
    );
}

/// Edge case: barely adult (turned 18+ recently).
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_barely_adult_passes_age_check() {
    let sdjwt = synthetic::pid_credential::spanish_citizen_barely_adult();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove()
        .unwrap();
    let valid = ZkVerifier::new(CIRCUITS).verify(&proof).unwrap();
    assert!(valid, "Barely-adult citizen should pass age >= 18");
}

/// Equality check: verify issuing_country == "IT".
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_issuing_country_eq() {
    let sdjwt = synthetic::pid_credential::italian_citizen_signed();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("issuing_country", Predicate::eq("IT"))
        .prove()
        .unwrap();
    let valid = ZkVerifier::new(CIRCUITS).verify(&proof).unwrap();
    assert!(
        valid,
        "Italian credential should have issuing_country == IT"
    );
}

/// Neq check: verify issuing_country != "RU".
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_issuing_country_neq() {
    let sdjwt = synthetic::pid_credential::french_citizen_signed();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("issuing_country", Predicate::neq("RU"))
        .prove()
        .unwrap();
    let valid = ZkVerifier::new(CIRCUITS).verify(&proof).unwrap();
    assert!(valid, "French credential should have issuing_country != RU");
}

/// Invalid predicate op in PresentationDefinition should return error.
#[test]
fn e2e_invalid_predicate_op_rejected() {
    let pd = PresentationDefinition {
        id: "bad-request".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "bad".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.birthdate".to_string(),
                predicate_op: "contains".to_string(),
                value: "1990".to_string(),
            }],
        }],
    };
    let result = pd.to_predicates();
    assert!(
        result.is_err(),
        "Unsupported predicate op should be rejected"
    );
}

/// VPToken with mismatched proof count should fail.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_vp_token_proof_count_mismatch() {
    let pd = PresentationDefinition {
        id: "two-requirements".to_string(),
        input_descriptors: vec![
            InputDescriptor {
                id: "req-1".to_string(),
                constraints: vec![FieldConstraint {
                    path: "$.birthdate".to_string(),
                    predicate_op: "gte".to_string(),
                    value: "18".to_string(),
                }],
            },
            InputDescriptor {
                id: "req-2".to_string(),
                constraints: vec![FieldConstraint {
                    path: "$.issuing_country".to_string(),
                    predicate_op: "set_member".to_string(),
                    value: "DE,FR".to_string(),
                }],
            },
        ],
    };

    // Only generate one proof for two requirements
    let sdjwt = synthetic::pid_credential::french_citizen();
    let proof = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove()
        .unwrap();

    let result = VPToken::from_proofs(&pd, &[proof]);
    assert!(
        result.is_err(),
        "Should fail when proof count < descriptor count"
    );
}

/// Full JSON round-trip: serialize everything, deserialize, verify proofs still valid.
#[tokio::test]
#[ignore = "requires compiled Circom circuit artifacts"]
async fn e2e_full_json_roundtrip() {
    let pd = PresentationDefinition {
        id: "roundtrip-test".to_string(),
        input_descriptors: vec![InputDescriptor {
            id: "age-check".to_string(),
            constraints: vec![FieldConstraint {
                path: "$.birthdate".to_string(),
                predicate_op: "gte".to_string(),
                value: "18".to_string(),
            }],
        }],
    };

    let sdjwt = synthetic::pid_credential::adult_citizen();
    let proofs = ZkCredential::from_sdjwt(&sdjwt, CIRCUITS)
        .unwrap()
        .predicate("birthdate", Predicate::gte(18))
        .prove_all()
        .unwrap();

    let vp_token = VPToken::from_proofs(&pd, &proofs).unwrap();
    let submission = PresentationSubmission::from_definition_and_proofs(&pd, &proofs).unwrap();

    // Serialize everything to a single JSON envelope
    let envelope = serde_json::json!({
        "presentation_definition": serde_json::to_value(&pd).unwrap(),
        "vp_token": serde_json::to_value(&vp_token).unwrap(),
        "presentation_submission": serde_json::to_value(&submission).unwrap(),
    });

    let envelope_str = serde_json::to_string_pretty(&envelope).unwrap();

    // Deserialize from the envelope
    let parsed: serde_json::Value = serde_json::from_str(&envelope_str).unwrap();
    let pd_back: PresentationDefinition =
        serde_json::from_value(parsed["presentation_definition"].clone()).unwrap();
    let vp_back: VPToken = serde_json::from_value(parsed["vp_token"].clone()).unwrap();
    let sub_back: PresentationSubmission =
        serde_json::from_value(parsed["presentation_submission"].clone()).unwrap();

    // Verify structural integrity
    assert_eq!(pd_back.id, "roundtrip-test");
    assert_eq!(sub_back.definition_id, "roundtrip-test");
    assert_eq!(vp_back.proofs.len(), 1);
    assert_eq!(sub_back.descriptor_map.len(), 1);

    // Extract and verify proofs
    let extracted = vp_back.extract_proofs().unwrap();
    let verifier = ZkVerifier::new(CIRCUITS);
    for proof in &extracted {
        assert!(
            verifier.verify(proof).unwrap(),
            "Round-tripped proof should still verify"
        );
    }
}
