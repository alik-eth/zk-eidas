//! Host-side verification of the p7s witness.
//!
//! Runs the same cryptographic checks the ZK circuit will eventually
//! perform, but in plain Rust. Used to validate fixtures in CI before
//! any circuit work begins.
//!
//! Verifies:
//!   1. Signer cert is signed by the trust anchor (ECDSA P-256)
//!   2. Signed content is signed by the user's signing key (the cert's SPKI)
//!
//! Note: for now, step 2 is simplified. Real CMS may use signedAttrs
//! (sign over DER-encoded signedAttrs SET instead of raw content).
//! This verifier handles only the "no signedAttrs" case — sufficient
//! for QKB-format documents.

use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{P7sError, P7sWitness};

/// Run host-side verification of the witness against the trust anchor.
pub fn host_verify(witness: &P7sWitness) -> Result<(), P7sError> {
    verify_cert_signature(witness)?;
    verify_content_signature(witness)?;
    Ok(())
}

fn verify_cert_signature(witness: &P7sWitness) -> Result<(), P7sError> {
    let off = &witness.offsets;
    let bytes = &witness.p7s_bytes;

    let tbs = &bytes[off.cert_tbs_start..off.cert_tbs_start + off.cert_tbs_len];
    let sig_der = &bytes[off.cert_sig_start..off.cert_sig_start + off.cert_sig_len];

    let vk = VerifyingKey::from_sec1_bytes(&witness.trust_anchor_pk)
        .map_err(|e| P7sError::BadSignature(string_leak(format!("anchor pk: {e}"))))?;
    let sig = DerSignature::try_from(sig_der)
        .map_err(|e| P7sError::BadSignature(string_leak(format!("cert sig der: {e}"))))?;

    // The signature is over SHA-256(TBS)
    vk.verify(tbs, &sig)
        .map_err(|_| P7sError::BadSignature("cert signature does not verify"))?;

    Ok(())
}

fn verify_content_signature(witness: &P7sWitness) -> Result<(), P7sError> {
    let off = &witness.offsets;
    let bytes = &witness.p7s_bytes;

    let content = &bytes[off.signed_content_start..off.signed_content_start + off.signed_content_len];
    let sig_der = &bytes[off.content_sig_start..off.content_sig_start + off.content_sig_len];
    let user_pk = &bytes[off.user_signing_pk_start..off.user_signing_pk_start + 65];

    let vk = VerifyingKey::from_sec1_bytes(user_pk)
        .map_err(|e| P7sError::BadSignature(string_leak(format!("user pk: {e}"))))?;
    let sig = DerSignature::try_from(sig_der)
        .map_err(|e| P7sError::BadSignature(string_leak(format!("content sig der: {e}"))))?;

    // For QKB documents without signedAttrs, the signature is over SHA-256(content)
    let _digest = Sha256::digest(content);
    vk.verify(content, &sig)
        .map_err(|_| P7sError::BadSignature("content signature does not verify"))?;

    Ok(())
}

/// Leak a String to a &'static str. Used to smuggle dynamic error text
/// through a &'static-str-only error variant. Only used on error paths.
fn string_leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
