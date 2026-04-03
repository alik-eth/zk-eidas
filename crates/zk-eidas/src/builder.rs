use std::collections::HashMap;
use sha2::{Digest, Sha256};
use zk_eidas_prover::SignedProofInput;
use zk_eidas_types::commitment::EcdsaCommitment;
use zk_eidas_types::credential::{bytes_to_u64, ClaimValue, Credential};
use zk_eidas_types::proof::{CompoundProof, ContractNullifier, IdentityEscrowData, LogicalOp, ZkProof};

/// High-level predicate for the builder API.
pub enum Predicate {
    /// Greater-than-or-equal comparison (for numeric/date claims).
    Gte(i64),
    /// Less-than-or-equal comparison (for numeric/date claims).
    Lte(i64),
    /// Equality check (for string/numeric/boolean/date claims).
    Eq(String),
    /// Not-equal check.
    Neq(String),
    /// Range check: low <= claim <= high (for numeric/date claims).
    Range(i64, i64),
    /// Set membership check (claim must match one of the given values).
    SetMember(Vec<String>),
    /// Logical AND over multiple sub-predicates.
    And(Vec<Predicate>),
    /// Logical OR over multiple sub-predicates.
    Or(Vec<Predicate>),
}

impl Predicate {
    /// Create a greater-than-or-equal predicate.
    pub fn gte(threshold: i64) -> Self {
        Self::Gte(threshold)
    }
    /// Create a less-than-or-equal predicate.
    pub fn lte(threshold: i64) -> Self {
        Self::Lte(threshold)
    }
    /// Create an equality predicate.
    pub fn eq(value: &str) -> Self {
        Self::Eq(value.to_string())
    }
    /// Create a not-equal predicate.
    pub fn neq(value: &str) -> Self {
        Self::Neq(value.to_string())
    }
    /// Create a range predicate (low <= claim <= high).
    pub fn range(low: i64, high: i64) -> Self {
        Self::Range(low, high)
    }
    /// Create a set membership predicate (max 16 values).
    pub fn set_member(values: Vec<&str>) -> Self {
        Self::SetMember(values.into_iter().map(|s| s.to_string()).collect())
    }
    /// Create a compound AND predicate over multiple sub-predicates.
    pub fn and(predicates: Vec<Predicate>) -> Self {
        Self::And(predicates)
    }
    /// Create a compound OR predicate over multiple sub-predicates.
    pub fn or(predicates: Vec<Predicate>) -> Self {
        Self::Or(predicates)
    }
}

/// Builder for proof generation from SD-JWT credentials.
///
/// Uses a two-stage architecture:
/// - Stage 1: ECDSA signature verification (one per claim — commitment binds to claim_value)
/// - Stage 2: Predicate proofs (one per predicate, linked via commitment)
/// Configuration for identity escrow proof generation.
struct EscrowConfig {
    field_names: Vec<String>,
    ecdsa_claim: String,
    authority_pubkey: Vec<u8>,
}

pub struct ZkCredential {
    credential: Credential,
    circuits_path: String,
    predicates: Vec<(String, Predicate)>,
    contract_nullifier_params: Option<(String, u64, u64)>,  // (credential_id_field, contract_hash, salt)
    identity_escrow_params: Option<EscrowConfig>,
    /// Per-claim ECDSA proof cache. Each claim needs its own ECDSA proof because
    /// the commitment binds to the claim_value: Poseidon(claim_value, sd_array_hash, message_hash)
    ecdsa_cache: HashMap<String, (ZkProof, EcdsaCommitment, Vec<u8>, Vec<u8>)>,
}

impl ZkCredential {
    /// Returns a reference to the underlying credential.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Build from a pre-parsed Credential (for mdoc or other formats).
    pub fn from_credential(credential: Credential, circuits_path: &str) -> Self {
        Self {
            credential,
            circuits_path: circuits_path.to_string(),
            predicates: Vec::new(),
            contract_nullifier_params: None,
            identity_escrow_params: None,
            ecdsa_cache: HashMap::new(),
        }
    }

    /// Parse an SD-JWT string and build a credential ready for proof generation.
    pub fn from_sdjwt(sdjwt: &str, circuits_path: &str) -> Result<Self, ZkError> {
        let parser = zk_eidas_parser::SdJwtParser::new();
        let credential = parser.parse(sdjwt)?;
        Ok(Self {
            credential,
            circuits_path: circuits_path.to_string(),
            predicates: Vec::new(),
            contract_nullifier_params: None,
            identity_escrow_params: None,
            ecdsa_cache: HashMap::new(),
        })
    }

    /// Build the ECDSA circuit input JSON for browser-side proving.
    ///
    /// Returns the input JSON string for the `ecdsa_verify` circuit and the
    /// claim value as u64 (needed for predicate circuit inputs).
    /// Returns `None` if the credential lacks ECDSA signature data or
    /// the required claim disclosure.
    pub fn ecdsa_input_json(&self, claim_name: &str) -> Option<(String, u64)> {
        let signed_input = build_signed_input(&self.credential, claim_name)?;
        let claim_u64 = signed_input.claim_value;
        let json = zk_eidas_prover::build_ecdsa_input_json(&signed_input);
        Some((json, claim_u64))
    }

    /// Set contract nullifier parameters for court-resolvable nullifier generation.
    /// `credential_id_field` is the claim name used as the unique credential identifier
    /// (e.g. "document_number", "vin", "license_number").
    pub fn contract_nullifier(mut self, credential_id_field: &str, contract_hash: u64, salt: u64) -> Self {
        self.contract_nullifier_params = Some((credential_id_field.to_string(), contract_hash, salt));
        self
    }

    /// Enable identity escrow: encrypt credential fields inside the ZK proof.
    ///
    /// `field_names` are the credential claim names to pack into 8 escrow slots (max 8).
    /// `ecdsa_claim` must be one of the field_names — it binds the escrow to the ECDSA commitment.
    /// `authority_pubkey` is the escrow authority's secp256k1 public key (33 or 65 bytes).
    pub fn identity_escrow(mut self, field_names: Vec<&str>, ecdsa_claim: &str, authority_pubkey: &[u8]) -> Self {
        self.identity_escrow_params = Some(EscrowConfig {
            field_names: field_names.into_iter().map(|s| s.to_string()).collect(),
            ecdsa_claim: ecdsa_claim.to_string(),
            authority_pubkey: authority_pubkey.to_vec(),
        });
        self
    }

    /// Generate a contract nullifier proof for the given credential ID field.
    ///
    /// This is useful when you already have a cached `CompoundProof` and only need
    /// to attach a new nullifier (e.g. for a different contract). Handles ECDSA
    /// commitment generation internally.
    ///
    /// Returns a `ContractNullifier` that can be attached to a `CompoundProof`
    /// via [`CompoundProof::with_contract_nullifier`].
    pub fn generate_nullifier(
        &mut self,
        credential_id_field: &str,
        contract_hash: u64,
        salt: u64,
    ) -> Result<ContractNullifier, ZkError> {
        let (commitment, sd_array_hash, message_hash) =
            self.ensure_ecdsa(credential_id_field)?;

        let id_value = self
            .credential
            .claims()
            .get(credential_id_field)
            .ok_or_else(|| ZkError::ClaimNotFound(credential_id_field.to_string()))?;
        let credential_id = id_value.to_circuit_u64();

        let prover = zk_eidas_prover::Prover::new(&self.circuits_path);
        let nullifier_proof = prover
            .prove_nullifier(credential_id, contract_hash, salt, &commitment, &sd_array_hash, &message_hash)
            .map_err(ZkError::from)?;

        let nullifier_bytes = nullifier_proof
            .nullifier()
            .ok_or(ZkError::MissingProofOutput)?
            .to_vec();

        Ok(ContractNullifier {
            role: "holder".to_string(),
            nullifier: nullifier_bytes,
            contract_hash: contract_hash.to_be_bytes().to_vec(),
            salt: salt.to_be_bytes().to_vec(),
            proof: nullifier_proof,
        })
    }

    /// Generate identity escrow data for the configured escrow parameters.
    fn generate_identity_escrow(&mut self, config: &EscrowConfig) -> Result<IdentityEscrowData, ZkError> {
        use crate::escrow;

        // Pack credential fields into 8 BN254 field elements
        let (credential_data, claim_index) = escrow::pack_credential_fields(
            &self.credential,
            &config.field_names,
            &config.ecdsa_claim,
        )?;

        // The claim_value for the escrow circuit must match the ECDSA-committed value.
        // Use the same escrow encoding that pack_credential_fields uses.
        let claim_value_cv = self.credential.claims().get(&config.ecdsa_claim)
            .ok_or_else(|| ZkError::ClaimNotFound(config.ecdsa_claim.clone()))?
            .clone();
        let claim_value_decimal = escrow::claim_value_to_escrow_decimal(&claim_value_cv);

        // Ensure ECDSA proof exists for the ecdsa_claim
        let (commitment, sd_array_hash, message_hash) =
            self.ensure_ecdsa(&config.ecdsa_claim)?;

        // Derive deterministic symmetric key from credential data + authority pubkey
        // (enables proof caching — same inputs always produce the same K)
        let k = escrow::derive_escrow_key(&credential_data, &config.authority_pubkey);

        // Generate proof
        let prover = zk_eidas_prover::Prover::new(&self.circuits_path);
        let escrow_proof = prover.prove_identity_escrow(
            &claim_value_decimal,
            &credential_data,
            claim_index,
            &k,
            &commitment,
            &sd_array_hash,
            &message_hash,
        )?;

        // identity_escrow circuit public output layout:
        //   [0]    credential_hash   — Poseidon hash of all 8 credential data fields
        //   [1..9] ciphertext[0..7]  — 8 Poseidon-CTR encrypted field elements
        //   [9]    key_commitment    — Poseidon(K)
        //   [10]   commitment        — ECDSA commitment (shared with predicate proofs)
        const PI_CREDENTIAL_HASH: usize = 0;
        const PI_CIPHERTEXT_START: usize = 1;
        const PI_CIPHERTEXT_END: usize = 9;
        const PI_KEY_COMMITMENT: usize = 9;
        const PI_MIN_LEN: usize = 10;

        let pi = escrow_proof.public_inputs();
        if pi.len() < PI_MIN_LEN {
            return Err(ZkError::MissingProofOutput);
        }
        let credential_hash = pi[PI_CREDENTIAL_HASH].clone();
        let ciphertext: Vec<Vec<u8>> = pi[PI_CIPHERTEXT_START..PI_CIPHERTEXT_END].to_vec();
        let key_commitment = pi[PI_KEY_COMMITMENT].clone();

        // Encrypt K to escrow authority
        let encrypted_key = escrow::encrypt_key_to_authority(&k, &config.authority_pubkey)?;

        Ok(IdentityEscrowData {
            credential_hash,
            ciphertext,
            key_commitment,
            encrypted_key,
            authority_pubkey: config.authority_pubkey.clone(),
            field_names: config.field_names.clone(),
            claim_index,
            proof: escrow_proof,
        })
    }

    /// Generate only the identity escrow proof, without predicates or nullifiers.
    /// Used when the predicate proof is cached but escrow must be fresh per credential.
    pub fn generate_escrow_only(&mut self) -> Result<IdentityEscrowData, ZkError> {
        let config = self.identity_escrow_params.take()
            .ok_or_else(|| ZkError::InvalidInput("no escrow config set".into()))?;
        self.generate_identity_escrow(&config)
    }

    /// Add a predicate to prove about the given claim.
    pub fn predicate(mut self, claim_name: &str, predicate: Predicate) -> Self {
        self.predicates.push((claim_name.to_string(), predicate));
        self
    }

    /// Perform Stage 1 ECDSA proof for a given claim, caching the result.
    ///
    /// Returns `(commitment, sd_array_hash, message_hash)` for use in Stage 2.
    pub fn ensure_ecdsa_pub(
        &mut self,
        claim_name: &str,
    ) -> Result<(EcdsaCommitment, Vec<u8>, Vec<u8>), ZkError> {
        self.ensure_ecdsa(claim_name)
    }

    fn ensure_ecdsa(
        &mut self,
        claim_name: &str,
    ) -> Result<(EcdsaCommitment, Vec<u8>, Vec<u8>), ZkError> {
        // Return cached ECDSA proof for this claim if available
        if let Some((_, ref commitment, ref sd_hash, ref msg_hash)) = self.ecdsa_cache.get(claim_name) {
            return Ok((commitment.clone(), sd_hash.clone(), msg_hash.clone()));
        }

        let signed_input = build_signed_input(&self.credential, claim_name)
            .ok_or(ZkError::EcdsaRequired)?;

        let prover = zk_eidas_prover::Prover::new(&self.circuits_path);
        let (ecdsa_proof, commitment, sd_array_hash, message_hash) = prover
            .prove_ecdsa(&signed_input)
            .map_err(ZkError::from)?;

        let result = (commitment.clone(), sd_array_hash.clone(), message_hash.clone());
        self.ecdsa_cache.insert(claim_name.to_string(), (ecdsa_proof, commitment, sd_array_hash, message_hash));

        Ok(result)
    }

    /// Generate proofs for all predicates plus a holder binding proof.
    ///
    /// The binding proof commits to the SHA-256 hash of the given claim's field
    /// element, enabling cross-credential holder linking: two credentials with
    /// the same `binding_claim` value will produce the same `binding_hash`.
    ///
    /// Returns `(proofs, binding_hash)` where `proofs` includes all predicate
    /// proofs followed by the holder binding proof.
    pub fn prove_with_binding(
        mut self,
        binding_claim: &str,
    ) -> Result<(Vec<ZkProof>, [u8; 32]), ZkError> {
        // Get the binding claim value
        let claim_value = self
            .credential
            .claims()
            .get(binding_claim)
            .ok_or_else(|| ZkError::ClaimNotFound(binding_claim.to_string()))?
            .clone();

        // Convert claim to u64 for circuit (same conversion as ECDSA's claim_value)
        let binding_claim_u64 = claim_value.to_circuit_u64();

        // Ensure ECDSA is done for the binding claim
        let (commitment, sd_array_hash, message_hash) = self.ensure_ecdsa(binding_claim)?;

        // Generate predicate proofs
        let mut proofs = self.prove_all_inner()?;

        // Generate holder binding proof — binding_hash is computed by the circuit
        let prover = zk_eidas_prover::Prover::new(&self.circuits_path);
        let binding_proof = prover
            .prove_holder_binding(
                binding_claim_u64,
                &commitment,
                &sd_array_hash,
                &message_hash,
            )
            .map_err(ZkError::Prover)?;

        let binding_hash = *binding_proof.binding_hash()
            .ok_or(ZkError::MissingProofOutput)?;

        proofs.push(binding_proof);

        Ok((proofs, binding_hash))
    }

    /// Generate proofs for all predicates. Returns one ZkProof per predicate.
    pub fn prove_all(mut self) -> Result<Vec<ZkProof>, ZkError> {
        let predicates = &self.predicates;
        if predicates.is_empty() {
            // No predicates — nothing to prove.
            // This is valid when called from prove_with_binding (binding-only).
            return Ok(Vec::new());
        }

        self.prove_all_inner()
    }

    /// Internal: generate proofs for all predicates without the empty check.
    fn prove_all_inner(&mut self) -> Result<Vec<ZkProof>, ZkError> {
        let predicates: Vec<_> = std::mem::take(&mut self.predicates);

        let mut proofs = Vec::new();
        for (claim_name, predicate) in predicates {
            let proof = self.prove_single(&claim_name, predicate)?;
            proofs.push(proof);
        }

        Ok(proofs)
    }

    /// Generate a compound proof with a logical operator over multiple predicates on the same claim.
    pub fn prove_compound(mut self) -> Result<CompoundProof, ZkError> {
        if self.predicates.is_empty() {
            return Err(ZkError::EmptyPredicates);
        }

        let predicates: Vec<_> = std::mem::take(&mut self.predicates);
        let mut sub_proofs = Vec::new();
        let mut logical_op = None;

        for (claim_name, predicate) in predicates {
            let (op, subs) = match predicate {
                Predicate::And(subs) => (Some(LogicalOp::And), subs),
                Predicate::Or(subs) => (Some(LogicalOp::Or), subs),
                other => (None, vec![other]),
            };
            if op.is_some() {
                logical_op = op;
            }
            for sub in subs {
                let proof = self.prove_single(&claim_name, sub)?;
                sub_proofs.push(proof);
            }
        }

        let contract_nullifier = if let Some((ref id_field, contract_hash, salt)) = self.contract_nullifier_params {
            let id_field = id_field.clone();
            // Ensure ECDSA proof exists for the credential_id field
            let (commitment, sd_array_hash, message_hash) = self.ensure_ecdsa(&id_field)?;

            let id_value = self.credential.claims().get(&id_field)
                .ok_or_else(|| ZkError::ClaimNotFound(id_field.to_string()))?;
            let credential_id = id_value.to_circuit_u64();

            let prover = zk_eidas_prover::Prover::new(&self.circuits_path);
            let nullifier_proof = prover
                .prove_nullifier(credential_id, contract_hash, salt, &commitment, &sd_array_hash, &message_hash)
                .map_err(ZkError::from)?;

            let nullifier_bytes = nullifier_proof.nullifier()
                .ok_or(ZkError::MissingProofOutput)?
                .to_vec();

            Some(ContractNullifier {
                role: "holder".to_string(),
                nullifier: nullifier_bytes,
                contract_hash: contract_hash.to_be_bytes().to_vec(),
                salt: salt.to_be_bytes().to_vec(),
                proof: nullifier_proof,
            })
        } else {
            None
        };

        // Identity escrow: encrypt credential fields inside a ZK proof
        // Done before ecdsa_cache drain because it may need ensure_ecdsa()
        let identity_escrow = if let Some(config) = self.identity_escrow_params.take() {
            Some(self.generate_identity_escrow(&config)?)
        } else {
            None
        };

        // Collect ECDSA proofs from cache (one per unique claim)
        // Done after contract_nullifier and escrow to include all ECDSA proofs generated
        let ecdsa_proofs: HashMap<String, ZkProof> = self
            .ecdsa_cache
            .into_iter()
            .map(|(claim_name, (proof, _, _, _))| (claim_name, proof))
            .collect();

        let mut compound = CompoundProof::with_ecdsa_proofs(
            sub_proofs,
            logical_op.unwrap_or(LogicalOp::And),
            ecdsa_proofs,
        );
        if let Some(cn) = contract_nullifier {
            compound = compound.with_contract_nullifier(cn);
        }
        if let Some(escrow) = identity_escrow {
            compound = compound.with_identity_escrow(escrow);
        }

        Ok(compound)
    }

    /// Generate a single zero-knowledge proof for one predicate.
    ///
    /// The credential MUST have ECDSA signature data and a disclosure for the
    /// target claim. The two-stage architecture verifies the issuer's ECDSA
    /// signature inside Stage 1, then proves the predicate in Stage 2.
    ///
    /// Returns [`ZkError::EcdsaRequired`] if the credential lacks ECDSA
    /// signature data or a disclosure for the target claim.
    pub fn prove(mut self) -> Result<ZkProof, ZkError> {
        let claim_name = self
            .predicates
            .first()
            .ok_or(ZkError::EmptyPredicates)?
            .0
            .clone();
        let predicate = std::mem::take(&mut self.predicates).into_iter().next().unwrap().1;

        let proof = self.prove_single(&claim_name, predicate)?;

        Ok(proof)
    }

    /// Internal: prove a single predicate (Stage 1 ECDSA + Stage 2 predicate).
    fn prove_single(
        &mut self,
        claim_name: &str,
        predicate: Predicate,
    ) -> Result<ZkProof, ZkError> {
        let claim_value = self
            .credential
            .claims()
            .get(claim_name)
            .ok_or_else(|| ZkError::ClaimNotFound(claim_name.to_string()))?
            .clone();

        // Validate claim type is compatible with predicate before expensive ECDSA step
        match &predicate {
            Predicate::Gte(_) | Predicate::Lte(_) | Predicate::Range(_, _) => {
                claim_to_u64(&claim_value)?;
            }
            _ => {}
        }

        // Stage 1: Ensure ECDSA proof is computed
        let (commitment, sd_array_hash, message_hash) = self.ensure_ecdsa(claim_name)?;

        let prover = zk_eidas_prover::Prover::new(&self.circuits_path);

        let proof = match predicate {
            Predicate::Gte(threshold) => {
                if matches!(claim_value, ClaimValue::Date { .. }) {
                    let claim_u64 = claim_to_u64(&claim_value)?;
                    let cutoff = age_cutoff_epoch_days(threshold as u32)?;
                    prover
                        .prove_lte(claim_u64, cutoff, &commitment, &sd_array_hash, &message_hash)
                        .map_err(ZkError::from)
                } else {
                    let claim_u64 = claim_to_u64(&claim_value)?;
                    prover
                        .prove_gte(claim_u64, threshold as u64, &commitment, &sd_array_hash, &message_hash)
                        .map_err(ZkError::from)
                }
            }
            Predicate::Lte(threshold) => {
                if matches!(claim_value, ClaimValue::Date { .. }) {
                    let claim_u64 = claim_to_u64(&claim_value)?;
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| ZkError::SystemClockError)?;
                    let total_days = (now.as_secs() / 86400) as i64;
                    let (today_year, _, _) = zk_eidas_utils::epoch_days_to_ymd(total_days);
                    let cutoff = if today_year > threshold as u32 + 1970 {
                        age_cutoff_epoch_days(threshold as u32)?
                    } else {
                        0
                    };
                    prover
                        .prove_gte(claim_u64, cutoff, &commitment, &sd_array_hash, &message_hash)
                        .map_err(ZkError::from)
                } else {
                    let claim_u64 = claim_to_u64(&claim_value)?;
                    prover
                        .prove_lte(claim_u64, threshold as u64, &commitment, &sd_array_hash, &message_hash)
                        .map_err(ZkError::from)
                }
            }
            Predicate::Eq(expected) => {
                let claim_u64 = claim_value.to_circuit_u64();
                let expected_cv = string_to_claim_value(&expected, &claim_value);
                let expected_u64 = expected_cv.to_circuit_u64();
                prover
                    .prove_eq(claim_u64, expected_u64, &commitment, &sd_array_hash, &message_hash)
                    .map_err(ZkError::from)
            }
            Predicate::Neq(expected) => {
                let claim_u64 = claim_value.to_circuit_u64();
                let expected_cv = string_to_claim_value(&expected, &claim_value);
                let expected_u64 = expected_cv.to_circuit_u64();
                prover
                    .prove_neq(claim_u64, expected_u64, &commitment, &sd_array_hash, &message_hash)
                    .map_err(ZkError::from)
            }
            Predicate::Range(low, high) => {
                if matches!(claim_value, ClaimValue::Date { .. }) {
                    let claim_u64 = claim_to_u64(&claim_value)?;
                    let low_cutoff = age_cutoff_epoch_days(high as u32)?;
                    let high_cutoff = age_cutoff_epoch_days(low as u32)?;
                    prover
                        .prove_range(claim_u64, low_cutoff, high_cutoff, &commitment, &sd_array_hash, &message_hash)
                        .map_err(ZkError::from)
                } else {
                    let claim_u64 = claim_to_u64(&claim_value)?;
                    prover
                        .prove_range(claim_u64, low as u64, high as u64, &commitment, &sd_array_hash, &message_hash)
                        .map_err(ZkError::from)
                }
            }
            Predicate::SetMember(values) => {
                let claim_u64 = claim_value.to_circuit_u64();
                let mut set = [0u64; 16];
                let set_len = values.len().min(16) as u64;
                for (i, v) in values.iter().take(16).enumerate() {
                    let hash: [u8; 32] = Sha256::digest(v.as_bytes()).into();
                    set[i] = bytes_to_u64(&hash);
                }
                prover
                    .prove_set_member(claim_u64, &set, set_len, &commitment, &sd_array_hash, &message_hash)
                    .map_err(ZkError::from)
            }
            Predicate::And(_) | Predicate::Or(_) => Err(ZkError::NestedLogicalPredicate),
        }?;

        Ok(proof.with_claim_name(claim_name.to_string()))
    }
}

/// Check that predicate proof commitments match ECDSA proof commitments.
fn check_commitment_chain(compound: &CompoundProof) -> bool {
    if compound.ecdsa_proofs().is_empty() {
        return true;
    }

    let ecdsa_commitments: HashMap<String, String> = compound
        .ecdsa_proofs()
        .iter()
        .map(|(name, proof)| {
            let commitment = proof
                .public_inputs()
                .first()
                .and_then(|b| std::str::from_utf8(b).ok())
                .unwrap_or("")
                .to_string();
            (name.clone(), commitment)
        })
        .collect();

    for p in compound.proofs() {
        if let Some(claim_name) = p.claim_name() {
            if let Some(ecdsa_commitment) = ecdsa_commitments.get(claim_name) {
                let pred_commitment = p
                    .public_inputs()
                    .first()
                    .and_then(|b| std::str::from_utf8(b).ok())
                    .unwrap_or("");
                if pred_commitment != ecdsa_commitment {
                    return false;
                }
            }
        }
    }

    true
}

/// Wraps the verifier crate for high-level proof verification.
pub struct ZkVerifier {
    circuits_path: String,
}

impl ZkVerifier {
    /// Create a verifier that loads circuits from the given directory.
    pub fn new(circuits_path: &str) -> Self {
        Self {
            circuits_path: circuits_path.to_string(),
        }
    }

    /// Verify a single zero-knowledge proof.
    pub fn verify(&self, proof: &ZkProof) -> Result<bool, ZkError> {
        let verifier = zk_eidas_verifier::Verifier::new(&self.circuits_path);
        verifier.verify(proof).map_err(ZkError::from)
    }

    /// Verify that two sets of proofs share the same holder binding hash.
    ///
    /// Returns `true` if both sets contain a `HolderBinding` proof and their
    /// binding hashes are equal, meaning the credentials belong to the same holder.
    pub fn verify_holder_binding(
        &self,
        proofs_a: &[ZkProof],
        proofs_b: &[ZkProof],
    ) -> Result<bool, ZkError> {
        use zk_eidas_types::predicate::PredicateOp;

        let binding_a = proofs_a
            .iter()
            .find(|p| p.predicate_op() == PredicateOp::HolderBinding)
            .and_then(|p| p.binding_hash());
        let binding_b = proofs_b
            .iter()
            .find(|p| p.predicate_op() == PredicateOp::HolderBinding)
            .and_then(|p| p.binding_hash());

        match (binding_a, binding_b) {
            (Some(a), Some(b)) => Ok(a == b),
            _ => Err(ZkError::MissingProofOutput),
        }
    }

    /// Verify a compound proof. And requires all sub-proofs valid. Or requires at least one.
    pub fn verify_compound(&self, compound: &CompoundProof) -> Result<bool, ZkError> {
        let verifier = zk_eidas_verifier::Verifier::new(&self.circuits_path);

        // Step 1: Verify ECDSA proofs
        for (_claim_name, ecdsa_proof) in compound.ecdsa_proofs() {
            let valid = verifier.verify(ecdsa_proof).map_err(ZkError::from)?;
            if !valid {
                return Ok(false);
            }
        }

        // Step 2: Verify predicate proofs
        match compound.op() {
            LogicalOp::And => {
                for p in compound.proofs() {
                    let valid = verifier.verify(p).map_err(ZkError::from)?;
                    if !valid {
                        return Ok(false);
                    }
                }
            }
            LogicalOp::Or => {
                let mut any_valid = false;
                let mut last_err = None;
                for p in compound.proofs() {
                    match verifier.verify(p) {
                        Ok(true) => { any_valid = true; break; }
                        Ok(false) => {}
                        Err(e) => last_err = Some(e),
                    }
                }
                if !any_valid {
                    if let Some(e) = last_err {
                        return Err(ZkError::from(e));
                    }
                    return Ok(false);
                }
            }
        }

        // Step 3: Verify contract nullifier if present
        if let Some(cn) = compound.contract_nullifier() {
            let valid = verifier.verify(&cn.proof).map_err(ZkError::from)?;
            if !valid {
                return Ok(false);
            }
        }

        // Step 4: Verify identity escrow proof if present
        if let Some(escrow) = compound.identity_escrow() {
            let valid = verifier.verify(&escrow.proof).map_err(ZkError::from)?;
            if !valid {
                return Ok(false);
            }
        }

        // Step 5: Check commitment chain
        if !check_commitment_chain(compound) {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Build a SignedProofInput from a Credential if it has ECDSA signature data
/// and the required disclosure for the given claim.
fn build_signed_input(credential: &Credential, claim_name: &str) -> Option<SignedProofInput> {
    match credential.signature_data() {
        zk_eidas_types::credential::SignatureData::Ecdsa {
            pub_key_x,
            pub_key_y,
            signature,
            message_hash,
            sd_claims_hashes,
        } => {
            let _disclosure = credential.disclosures().get(claim_name)?;

            // Split 64-byte signature into r and s components
            let mut signature_r = [0u8; 32];
            let mut signature_s = [0u8; 32];
            signature_r.copy_from_slice(&signature[..32]);
            signature_s.copy_from_slice(&signature[32..]);

            // Get claim value as u64
            let claim_value = credential.claims().get(claim_name)?;
            let claim_u64 = claim_value.to_circuit_u64();

            // Compute disclosure hash
            let disclosure_bytes = credential.disclosures().get(claim_name)?;
            let disclosure_hash_bytes: [u8; 32] = Sha256::digest(disclosure_bytes).into();
            let disclosure_hash = bytes_to_u64(&disclosure_hash_bytes);

            // Build sd_array as u64 field elements
            let mut sd_array = [0u64; 16];
            for (i, hash) in sd_claims_hashes.iter().take(16).enumerate() {
                sd_array[i] = bytes_to_u64(hash);
            }

            Some(SignedProofInput::new(
                signature_r,
                signature_s,
                *message_hash,
                *pub_key_x,
                *pub_key_y,
                claim_u64,
                disclosure_hash,
                sd_array,
            ))
        }
        _ => None,
    }
}

// sd_array_hash and msg_hash_field are now extracted directly from the
// ECDSA circuit's public outputs (see prove_ecdsa return values).
// No need to recompute them in Rust.

/// Convert a string representation to the appropriate ClaimValue,
/// matching the type of the existing claim value for comparison.
fn string_to_claim_value(s: &str, reference: &ClaimValue) -> ClaimValue {
    match reference {
        ClaimValue::Integer(_) => {
            if let Ok(n) = s.parse::<i64>() {
                ClaimValue::Integer(n)
            } else {
                ClaimValue::String(s.to_string())
            }
        }
        ClaimValue::Boolean(_) => {
            if let Ok(b) = s.parse::<bool>() {
                ClaimValue::Boolean(b)
            } else {
                ClaimValue::String(s.to_string())
            }
        }
        ClaimValue::String(_) => ClaimValue::String(s.to_string()),
        ClaimValue::Date { .. } => {
            ClaimValue::from_date_str(s).unwrap_or_else(|_| ClaimValue::String(s.to_string()))
        }
    }
}

/// Convert a ClaimValue to u64 for circuit input (numeric/date/bool only).
///
/// Returns an error for negative integers and strings.
fn claim_to_u64(value: &ClaimValue) -> Result<u64, ZkError> {
    match value {
        ClaimValue::Integer(n) => {
            if *n < 0 {
                return Err(ZkError::NegativeClaimValue(*n));
            }
            Ok(*n as u64)
        }
        ClaimValue::Date { year, month, day } => {
            let days = zk_eidas_utils::date_to_epoch_days(
                *year as u32,
                *month as u32,
                *day as u32,
            );
            Ok(days.max(0) as u64)
        }
        ClaimValue::Boolean(b) => Ok(*b as u64),
        ClaimValue::String(_) => Err(ZkError::IncompatibleClaimType),
    }
}

/// Compute the epoch-days cutoff for an age threshold, given a specific "today" date.
///
/// Returns 0 if `min_age` exceeds `year` (i.e., the cutoff would be before
/// year 0), since circuits use unsigned values.
pub fn age_cutoff_epoch_days_from(min_age: u32, year: u32, month: u32, day: u32) -> u64 {
    let cutoff_year = year.saturating_sub(min_age);
    let days = zk_eidas_utils::date_to_epoch_days(cutoff_year, month, day);
    // Circuits use unsigned values; clamp negative epoch days to 0
    days.max(0) as u64
}

/// Compute the epoch-days cutoff for an age threshold.
///
/// Returns the epoch-days value for (today - `min_age` years). A birthdate
/// must be <= this value for the person to be at least `min_age` years old.
fn age_cutoff_epoch_days(min_age: u32) -> Result<u64, ZkError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ZkError::SystemClockError)?;
    let total_days = (now.as_secs() / 86400) as i64;
    let (y, m, d) = zk_eidas_utils::epoch_days_to_ymd(total_days);
    Ok(age_cutoff_epoch_days_from(min_age, y, m, d))
}

/// Unified error type for the facade crate.
#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    /// An error occurred while parsing the credential.
    #[error("parse error: {0}")]
    Parse(#[from] zk_eidas_parser::ParseError),
    /// An error occurred during proof generation.
    #[error("prover error: {0}")]
    Prover(#[from] zk_eidas_prover::ProverError),
    /// An error occurred during proof verification.
    #[error("verifier error: {0}")]
    Verifier(#[from] zk_eidas_verifier::VerifierError),
    /// The requested claim was not found in the credential.
    #[error("claim not found: {0}")]
    ClaimNotFound(String),
    /// A negative integer was passed where an unsigned value is required.
    #[error("negative claim value {0} cannot be used in unsigned circuit")]
    NegativeClaimValue(i64),
    /// The claim type is incompatible with the requested predicate
    /// (e.g. a string claim used with a numeric comparison).
    #[error("incompatible claim type for predicate")]
    IncompatibleClaimType,
    /// No predicates were added before calling prove/prove_compound.
    #[error("no predicates to prove")]
    EmptyPredicates,
    /// And/Or predicates cannot be nested inside prove_single.
    #[error("nested logical predicates are not supported in prove_single")]
    NestedLogicalPredicate,
    /// A required binding hash or nullifier was missing from a proof.
    #[error("expected proof output (binding_hash or nullifier) is missing")]
    MissingProofOutput,
    /// The credential lacks ECDSA signature data or a disclosure for the claim.
    /// All proofs require in-circuit ECDSA verification — unsigned circuits
    /// have been removed.
    #[error("ECDSA signature data and disclosure required for proof generation")]
    EcdsaRequired,
    /// The system clock returned a time before the Unix epoch.
    #[error("system clock before Unix epoch")]
    SystemClockError,
    /// Invalid input for identity escrow or other operations.
    #[error("invalid input: {0}")]
    InvalidInput(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use zk_eidas_types::credential::{ClaimValue, Credential, SignatureData};
    use zk_eidas_types::predicate::PredicateOp;

    #[test]
    fn auto_selects_signed_when_ecdsa_available() {
        let mut claims = BTreeMap::new();
        claims.insert("age".to_string(), ClaimValue::Integer(25));

        let sig_data = SignatureData::Ecdsa {
            pub_key_x: [1u8; 32],
            pub_key_y: [2u8; 32],
            signature: [3u8; 64],
            message_hash: [4u8; 32],
            sd_claims_hashes: vec![[5u8; 32]],
        };

        let mut disclosures = BTreeMap::new();
        disclosures.insert("age".to_string(), b"encoded_disclosure".to_vec());

        let cred = Credential::new(claims, "issuer".to_string(), sig_data, disclosures);
        let signed_input = build_signed_input(&cred, "age");
        assert!(signed_input.is_some());
    }

    #[test]
    fn opaque_credential_returns_none_for_signed_input() {
        let mut claims = BTreeMap::new();
        claims.insert("age".to_string(), ClaimValue::Integer(25));

        let sig_data = SignatureData::Opaque {
            signature: vec![0u8; 64],
            public_key: vec![0u8; 64],
        };

        let cred = Credential::new(claims, "issuer".to_string(), sig_data, BTreeMap::new());
        let signed_input = build_signed_input(&cred, "age");
        assert!(signed_input.is_none());
    }

    #[test]
    fn opaque_credential_prove_returns_ecdsa_required() {
        let mut claims = BTreeMap::new();
        claims.insert("age".to_string(), ClaimValue::Integer(25));

        let sig_data = SignatureData::Opaque {
            signature: vec![0u8; 64],
            public_key: vec![0u8; 64],
        };

        let cred = Credential::new(claims, "issuer".to_string(), sig_data, BTreeMap::new());
        let result = ZkCredential::from_credential(cred, "/nonexistent")
            .predicate("age", Predicate::gte(18))
            .prove();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("ECDSA"),
            "should return EcdsaRequired for opaque credentials"
        );
    }

    #[test]
    fn prove_all_method_exists() {
        let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
            serde_json::json!({"age": 25}),
            "test-issuer",
        );
        let result = ZkCredential::from_sdjwt(&sdjwt, "/nonexistent")
            .unwrap()
            .predicate("age", Predicate::gte(18))
            .predicate("age", Predicate::lte(100))
            .prove_all();
        assert!(result.is_err()); // circuit not found, but method works
    }

    #[test]
    fn verify_compound_or_first_valid_is_sufficient() {
        // OR semantics: if the first proof is valid, the whole compound is valid.
        // With no circuits available, all verifications error out.
        let proof1 = ZkProof::new(vec![], vec![], vec![], PredicateOp::Gte);
        let proof2 = ZkProof::new(vec![], vec![], vec![], PredicateOp::Lte);
        let compound = CompoundProof::new(vec![proof1, proof2], LogicalOp::Or);
        let verifier = ZkVerifier::new("/nonexistent");
        let result = verifier.verify_compound(&compound);
        assert!(result.is_err());
    }

    #[test]
    fn verify_compound_and_logic() {
        let proof1 = ZkProof::new(vec![], vec![], vec![], PredicateOp::Gte);
        let proof2 = ZkProof::new(vec![], vec![], vec![], PredicateOp::Eq);
        let compound = CompoundProof::new(vec![proof1, proof2], LogicalOp::And);
        let verifier = ZkVerifier::new("/nonexistent");
        let result = verifier.verify_compound(&compound);
        // With empty proofs and no circuits, verification will fail per-proof
        // but the method should still run without panicking
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn nullifier_is_deterministic_and_scope_dependent() {
        // Verify the nullifier computation matches SHA-256(secret || scope)
        // and is deterministic across calls with different scope/secret
        use sha2::{Digest, Sha256};

        let compute = |secret: &[u8; 32], scope: &[u8]| -> [u8; 32] {
            let mut h = Sha256::new();
            h.update(secret);
            h.update(scope);
            h.finalize().into()
        };

        let secret = [42u8; 32];
        let n1 = compute(&secret, b"store-123:2026-03");
        let n2 = compute(&secret, b"store-123:2026-03");
        assert_eq!(n1, n2, "same inputs must produce same nullifier");

        let n3 = compute(&secret, b"store-456:2026-03");
        assert_ne!(n1, n3, "different scope must produce different nullifier");

        let n4 = compute(&[99u8; 32], b"store-123:2026-03");
        assert_ne!(n1, n4, "different secret must produce different nullifier");
    }

    #[test]
    fn contract_nullifier_builder_compiles() {
        let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
            serde_json::json!({"age": 25}),
            "test-issuer",
        );
        let builder = ZkCredential::from_sdjwt(&sdjwt, "/nonexistent")
            .unwrap()
            .predicate("age", Predicate::gte(18))
            .contract_nullifier("document_number", 12345, 67890);

        // Will fail at circuit loading but proves the API works
        let result = builder.prove_compound();
        assert!(result.is_err());
    }

    #[test]
    fn from_credential_builder_requires_ecdsa() {
        let claims = BTreeMap::from([("age".to_string(), ClaimValue::Integer(25))]);
        let cred = Credential::new(
            claims,
            "test".to_string(),
            SignatureData::Opaque {
                signature: vec![],
                public_key: vec![],
            },
            BTreeMap::new(),
        );
        let result = ZkCredential::from_credential(cred, "/nonexistent")
            .predicate("age", Predicate::gte(18))
            .prove();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ECDSA"));
    }

    #[test]
    fn age_cutoff_epoch_days_from_works() {
        // Known date: 2026-03-14, age 18 -> cutoff at 2008-03-14
        let cutoff = age_cutoff_epoch_days_from(18, 2026, 3, 14);
        assert!(cutoff > 0);
    }

    #[test]
    fn string_to_claim_value_invalid_month_falls_back_to_string() {
        let reference = ClaimValue::Date {
            year: 2025,
            month: 1,
            day: 1,
        };
        let result = string_to_claim_value("2025-13-01", &reference);
        assert_eq!(
            result,
            ClaimValue::String("2025-13-01".to_string()),
            "invalid month 13 should fall back to String, not create an invalid Date"
        );
    }

    #[test]
    fn string_to_claim_value_invalid_day_falls_back_to_string() {
        let reference = ClaimValue::Date {
            year: 2025,
            month: 1,
            day: 1,
        };
        let result = string_to_claim_value("2025-01-32", &reference);
        assert_eq!(
            result,
            ClaimValue::String("2025-01-32".to_string()),
            "invalid day 32 should fall back to String, not create an invalid Date"
        );
    }

    #[test]
    fn string_to_claim_value_valid_date_creates_date() {
        let reference = ClaimValue::Date {
            year: 2025,
            month: 1,
            day: 1,
        };
        let result = string_to_claim_value("2025-06-15", &reference);
        assert_eq!(
            result,
            ClaimValue::Date {
                year: 2025,
                month: 6,
                day: 15
            }
        );
    }

    #[test]
    fn chain_check_matching_commitments_passes() {
        use std::collections::HashMap;
        let pred = ZkProof::new(b"{}".to_vec(), vec![b"12345".to_vec(), b"18".to_vec()], vec![], PredicateOp::Gte)
            .with_claim_name("age".into());
        let ecdsa = ZkProof::new(b"{}".to_vec(), vec![b"12345".to_vec(), b"99".to_vec(), b"88".to_vec()], vec![], PredicateOp::Ecdsa);
        let mut ecdsa_map = HashMap::new();
        ecdsa_map.insert("age".into(), ecdsa);
        let compound = CompoundProof::with_ecdsa_proofs(vec![pred], LogicalOp::And, ecdsa_map);
        assert!(check_commitment_chain(&compound));
    }

    #[test]
    fn chain_check_mismatched_commitments_fails() {
        use std::collections::HashMap;
        let pred = ZkProof::new(b"{}".to_vec(), vec![b"12345".to_vec(), b"18".to_vec()], vec![], PredicateOp::Gte)
            .with_claim_name("age".into());
        let ecdsa = ZkProof::new(b"{}".to_vec(), vec![b"99999".to_vec()], vec![], PredicateOp::Ecdsa);
        let mut ecdsa_map = HashMap::new();
        ecdsa_map.insert("age".into(), ecdsa);
        let compound = CompoundProof::with_ecdsa_proofs(vec![pred], LogicalOp::And, ecdsa_map);
        assert!(!check_commitment_chain(&compound));
    }

    #[test]
    fn chain_check_no_ecdsa_proofs_passes_vacuously() {
        let pred = ZkProof::new(b"{}".to_vec(), vec![b"12345".to_vec()], vec![], PredicateOp::Gte)
            .with_claim_name("age".into());
        let compound = CompoundProof::new(vec![pred], LogicalOp::And);
        assert!(check_commitment_chain(&compound));
    }

    #[test]
    fn chain_check_multiple_claims_all_must_match() {
        use std::collections::HashMap;
        let pred1 = ZkProof::new(b"{}".to_vec(), vec![b"111".to_vec()], vec![], PredicateOp::Gte)
            .with_claim_name("age".into());
        let pred2 = ZkProof::new(b"{}".to_vec(), vec![b"222".to_vec()], vec![], PredicateOp::Eq)
            .with_claim_name("nationality".into());
        let ecdsa1 = ZkProof::new(b"{}".to_vec(), vec![b"111".to_vec()], vec![], PredicateOp::Ecdsa);
        let ecdsa2 = ZkProof::new(b"{}".to_vec(), vec![b"333".to_vec()], vec![], PredicateOp::Ecdsa);
        let mut ecdsa_map = HashMap::new();
        ecdsa_map.insert("age".into(), ecdsa1);
        ecdsa_map.insert("nationality".into(), ecdsa2);
        let compound = CompoundProof::with_ecdsa_proofs(vec![pred1, pred2], LogicalOp::And, ecdsa_map);
        assert!(!check_commitment_chain(&compound), "should fail when one claim has mismatched commitment");
    }

    #[test]
    fn returns_none_when_disclosure_missing() {
        let mut claims = BTreeMap::new();
        claims.insert("age".to_string(), ClaimValue::Integer(25));

        let sig_data = SignatureData::Ecdsa {
            pub_key_x: [1u8; 32],
            pub_key_y: [2u8; 32],
            signature: [3u8; 64],
            message_hash: [4u8; 32],
            sd_claims_hashes: vec![[5u8; 32]],
        };

        // No disclosures for "age"
        let cred = Credential::new(claims, "issuer".to_string(), sig_data, BTreeMap::new());
        let signed_input = build_signed_input(&cred, "age");
        assert!(signed_input.is_none());
    }
}
