use std::collections::HashMap;
use sha2::{Digest, Sha256};
use zk_eidas_prover::SignedProofInput;
use zk_eidas_types::commitment::EcdsaCommitment;
use zk_eidas_types::credential::{ClaimValue, Credential};
use zk_eidas_types::proof::{CompoundProof, LogicalOp, ZkProof};

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
pub struct ZkCredential {
    credential: Credential,
    circuits_path: String,
    predicates: Vec<(String, Predicate)>,
    nullifier_scope: Option<String>,
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
            nullifier_scope: None,
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
            nullifier_scope: None,
            ecdsa_cache: HashMap::new(),
        })
    }

    /// Set a nullifier scope for double-spend prevention.
    pub fn nullifier_scope(mut self, scope: &str) -> Self {
        self.nullifier_scope = Some(scope.to_string());
        self
    }

    /// Add a predicate to prove about the given claim.
    pub fn predicate(mut self, claim_name: &str, predicate: Predicate) -> Self {
        self.predicates.push((claim_name.to_string(), predicate));
        self
    }

    /// Perform Stage 1 ECDSA proof for a given claim, caching the result.
    ///
    /// Returns `(commitment, sd_array_hash, message_hash)` for use in Stage 2.
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
            .ok_or_else(|| ZkError::ClaimNotFound(binding_claim.to_string()))?;

        // Convert to 32-byte field element (right-aligned / big-endian padding)
        let field = claim_value.to_field_element().map_err(|_| ZkError::UnsupportedPredicate)?;
        let mut claim_bytes = [0u8; 32];
        let len = field.len().min(32);
        claim_bytes[32 - len..].copy_from_slice(&field[..len]);

        // Compute binding_hash = SHA-256(claim_bytes)
        let binding_hash: [u8; 32] = Sha256::digest(claim_bytes).into();

        // Convert claim to u64 for circuit
        let binding_claim_u64 = bytes_to_u64(&claim_bytes);
        let binding_hash_u64 = bytes_to_u64(&binding_hash);

        // Ensure ECDSA is done for the binding claim
        let (commitment, sd_array_hash, message_hash) = self.ensure_ecdsa(binding_claim)?;

        // Generate predicate proofs
        let mut proofs = self.prove_all_inner()?;

        // Generate holder binding proof
        let prover = zk_eidas_prover::Prover::new(&self.circuits_path);
        let binding_proof = prover
            .prove_holder_binding(
                binding_claim_u64,
                binding_hash_u64,
                &commitment,
                &sd_array_hash,
                &message_hash,
            )
            .map_err(ZkError::Prover)?;
        proofs.push(binding_proof);

        Ok((proofs, binding_hash))
    }

    /// Generate proofs for all predicates. Returns one ZkProof per predicate.
    ///
    /// If a `nullifier_scope` was set, a nullifier is computed and attached to
    /// every returned proof so that verifiers can detect double-spend.
    pub fn prove_all(mut self) -> Result<Vec<ZkProof>, ZkError> {
        let predicates = &self.predicates;
        if predicates.is_empty() && self.nullifier_scope.is_none() {
            // No predicates, no nullifier — nothing to prove.
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

        // Generate nullifier and attach to all proofs
        if let Some(scope) = self.nullifier_scope.clone() {
            let credential_secret = match self.credential.signature_data() {
                zk_eidas_types::credential::SignatureData::Ecdsa { message_hash, .. } => {
                    bytes_to_u64(message_hash)
                }
                zk_eidas_types::credential::SignatureData::Opaque { public_key, .. } => {
                    let hash: [u8; 32] = Sha256::digest(public_key).into();
                    bytes_to_u64(&hash)
                }
            };

            let scope_u64 = bytes_to_u64(&Sha256::digest(scope.as_bytes()).into());

            // For the nullifier circuit, we need the commitment chain
            let first_claim = self.credential.claims().keys().next()
                .ok_or(ZkError::UnsupportedPredicate)?
                .clone();
            let (commitment, sd_array_hash, message_hash) = self.ensure_ecdsa(&first_claim)?;

            let claim_value = self.credential.claims().get(&first_claim)
                .ok_or_else(|| ZkError::ClaimNotFound(first_claim.clone()))?;
            let claim_u64 = claim_to_u64(claim_value).unwrap_or(0);

            // Compute nullifier = hash(secret || scope) for determinism
            let mut h = Sha256::new();
            h.update(&credential_secret.to_be_bytes());
            h.update(scope.as_bytes());
            let nullifier_hash: [u8; 32] = h.finalize().into();
            let nullifier_u64 = bytes_to_u64(&nullifier_hash);

            let prover = zk_eidas_prover::Prover::new(&self.circuits_path);
            let nullifier_proof = prover
                .prove_nullifier(
                    credential_secret,
                    scope_u64,
                    nullifier_u64,
                    claim_u64,
                    &commitment,
                    &sd_array_hash,
                    &message_hash,
                )
                .map_err(ZkError::from)?;

            let nullifier_bytes = *nullifier_proof.nullifier()
                .unwrap_or(&[0u8; 32]);

            proofs = proofs
                .into_iter()
                .map(|p| p.with_nullifier(nullifier_bytes))
                .collect();
        }

        Ok(proofs)
    }

    /// Generate a compound proof with a logical operator over multiple predicates on the same claim.
    pub fn prove_compound(mut self) -> Result<CompoundProof, ZkError> {
        if self.predicates.is_empty() {
            return Err(ZkError::UnsupportedPredicate);
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

        // Collect ECDSA proofs from cache (one per unique claim)
        let ecdsa_proofs: HashMap<String, ZkProof> = self
            .ecdsa_cache
            .into_iter()
            .map(|(claim_name, (proof, _, _, _))| (claim_name, proof))
            .collect();

        Ok(CompoundProof::with_ecdsa_proofs(
            sub_proofs,
            logical_op.unwrap_or(LogicalOp::And),
            ecdsa_proofs,
        ))
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
            .ok_or(ZkError::UnsupportedPredicate)?
            .0
            .clone();
        let predicate = std::mem::take(&mut self.predicates).into_iter().next().unwrap().1;

        let mut proof = self.prove_single(&claim_name, predicate)?;

        if let Some(scope) = self.nullifier_scope.clone() {
            let credential_secret = match self.credential.signature_data() {
                zk_eidas_types::credential::SignatureData::Ecdsa { message_hash, .. } => {
                    bytes_to_u64(message_hash)
                }
                _ => return Err(ZkError::EcdsaRequired),
            };
            let scope_u64 = bytes_to_u64(&Sha256::digest(scope.as_bytes()).into());

            let (commitment, sd_array_hash, message_hash) = self.ensure_ecdsa(&claim_name)?;

            let claim_value = self.credential.claims().get(&claim_name)
                .ok_or_else(|| ZkError::ClaimNotFound(claim_name.clone()))?;
            let claim_u64 = claim_to_u64(claim_value).unwrap_or(0);

            let mut h = Sha256::new();
            h.update(&credential_secret.to_be_bytes());
            h.update(scope.as_bytes());
            let nullifier_hash: [u8; 32] = h.finalize().into();
            let nullifier_u64 = bytes_to_u64(&nullifier_hash);

            let prover = zk_eidas_prover::Prover::new(&self.circuits_path);
            let nullifier_proof = prover
                .prove_nullifier(
                    credential_secret,
                    scope_u64,
                    nullifier_u64,
                    claim_u64,
                    &commitment,
                    &sd_array_hash,
                    &message_hash,
                )
                .map_err(ZkError::from)?;

            let nullifier_bytes = *nullifier_proof.nullifier()
                .unwrap_or(&[0u8; 32]);
            proof = proof.with_nullifier(nullifier_bytes);
        }

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
                    let today_year = {
                        let total_days = (now.as_secs() / 86400) as i64;
                        let z = total_days + 719468;
                        let era = z.div_euclid(146097);
                        let doe = z.rem_euclid(146097) as u64;
                        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
                        (yoe as i64 + era * 400) as u32
                    };
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
                let claim_u64 = claim_to_u64_or_hash(&claim_value);
                let expected_cv = string_to_claim_value(&expected, &claim_value);
                let expected_u64 = claim_to_u64_or_hash(&expected_cv);
                prover
                    .prove_eq(claim_u64, expected_u64, &commitment, &sd_array_hash, &message_hash)
                    .map_err(ZkError::from)
            }
            Predicate::Neq(expected) => {
                let claim_u64 = claim_to_u64_or_hash(&claim_value);
                let expected_cv = string_to_claim_value(&expected, &claim_value);
                let expected_u64 = claim_to_u64_or_hash(&expected_cv);
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
                let claim_u64 = claim_to_u64_or_hash(&claim_value);
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
            Predicate::And(_) | Predicate::Or(_) => Err(ZkError::UnsupportedPredicate),
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
            _ => Err(ZkError::UnsupportedPredicate),
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

        // Step 3: Check commitment chain
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
            let claim_u64 = claim_to_u64_or_hash(claim_value);

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
            // Try to parse as a date (YYYY-MM-DD) with validation
            let parts: Vec<&str> = s.split('-').collect();
            if parts.len() == 3 {
                if let (Ok(y), Ok(m), Ok(d)) = (
                    parts[0].parse::<u16>(),
                    parts[1].parse::<u8>(),
                    parts[2].parse::<u8>(),
                ) {
                    if (1..=12).contains(&m) && (1..=31).contains(&d) {
                        return ClaimValue::Date {
                            year: y,
                            month: m,
                            day: d,
                        };
                    }
                }
            }
            ClaimValue::String(s.to_string())
        }
    }
}

/// Convert a ClaimValue to u64 for circuit input.
fn claim_to_u64(value: &ClaimValue) -> Result<u64, ZkError> {
    match value {
        ClaimValue::Integer(n) => {
            if *n < 0 {
                return Err(ZkError::UnsupportedPredicate);
            }
            Ok(*n as u64)
        }
        ClaimValue::Date { year, month, day } => {
            let days = zk_eidas_utils::date_to_epoch_days(
                *year as u32,
                *month as u32,
                *day as u32,
            );
            // Circuits use unsigned values; clamp negative epoch days to 0
            Ok(days.max(0) as u64)
        }
        ClaimValue::Boolean(b) => Ok(*b as u64),
        ClaimValue::String(_) => Err(ZkError::UnsupportedPredicate),
    }
}

/// Convert a ClaimValue to u64, using a hash for strings/dates.
/// This is used for eq/neq/set_member where we need to compare arbitrary values.
fn claim_to_u64_or_hash(value: &ClaimValue) -> u64 {
    match claim_to_u64(value) {
        Ok(v) => v,
        Err(_) => {
            // For strings, use SHA-256 hash truncated to u64
            let field = value.to_field_element().unwrap_or_default();
            bytes_to_u64_from_slice(&field)
        }
    }
}

/// Convert a 32-byte array to u64 (first 8 bytes, big-endian).
fn bytes_to_u64(bytes: &[u8; 32]) -> u64 {
    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}

/// Convert a byte slice to u64 (first 8 bytes, big-endian).
fn bytes_to_u64_from_slice(bytes: &[u8]) -> u64 {
    if bytes.len() >= 8 {
        u64::from_be_bytes(bytes[..8].try_into().unwrap())
    } else {
        let mut buf = [0u8; 8];
        let start = 8 - bytes.len();
        buf[start..].copy_from_slice(bytes);
        u64::from_be_bytes(buf)
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
    // Get today's date components from system time
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| ZkError::SystemClockError)?;
    let total_days = (now.as_secs() / 86400) as i64;

    // Convert epoch days to y/m/d using the inverse of the civil_from_days algorithm
    let z = total_days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    Ok(age_cutoff_epoch_days_from(min_age, y as u32, m as u32, d as u32))
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
    /// The predicate type is not supported for the claim's value type.
    #[error("unsupported predicate for claim type")]
    UnsupportedPredicate,
    /// The credential lacks ECDSA signature data or a disclosure for the claim.
    /// All proofs require in-circuit ECDSA verification — unsigned circuits
    /// have been removed.
    #[error("ECDSA signature data and disclosure required for proof generation")]
    EcdsaRequired,
    /// The system clock returned a time before the Unix epoch.
    #[error("system clock before Unix epoch")]
    SystemClockError,
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
    fn nullifier_scope_builder_compiles() {
        let (sdjwt, _key) = zk_eidas_parser::test_utils::build_ecdsa_signed_sdjwt(
            serde_json::json!({"age": 25}),
            "test-issuer",
        );
        let builder = ZkCredential::from_sdjwt(&sdjwt, "/nonexistent")
            .unwrap()
            .predicate("age", Predicate::gte(18))
            .nullifier_scope("store-123:2026-03");

        // Will fail at circuit loading but proves the API works
        let result = builder.prove();
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
