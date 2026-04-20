//! Witness and public output types.

use serde::{Deserialize, Serialize};

use crate::{parser, P7sError};

/// The full witness the circuit needs. Owns the raw p7s bytes plus every
/// byte range the circuit must locate.
#[derive(Debug, Clone)]
pub struct P7sWitness {
    /// Full p7s DER bytes (private input to circuit).
    pub p7s_bytes: Vec<u8>,

    /// Offsets into `p7s_bytes` for the circuit's byte-range locator.
    pub offsets: P7sOffsets,

    /// Public context (verifier-chosen scope, binds the nullifier).
    pub context: Vec<u8>,

    /// Trust anchor — the QTSP root public key that issued the signer cert.
    /// Uncompressed P-256 point: `0x04 || X[32] || Y[32]`.
    pub trust_anchor_pk: [u8; 65],
}

/// Byte offsets into the p7s DER bytes that the circuit must locate.
/// All offsets are absolute into `P7sWitness::p7s_bytes`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct P7sOffsets {
    // --- SignedData envelope ---
    /// The signed content (JSON body) that the signer cert signs over.
    pub signed_content_start: usize,
    pub signed_content_len: usize,

    // --- Signer certificate (the user's DIIA qualified cert) ---
    /// Full DER cert bytes.
    pub cert_start: usize,
    pub cert_len: usize,
    /// TBSCertificate portion — what the issuer signed over.
    pub cert_tbs_start: usize,
    pub cert_tbs_len: usize,
    /// Offset of the SPKI SEQUENCE's outer `0x30` tag WITHIN
    /// `cert_tbs`. Equal to `user_signing_pk_start - cert_tbs_start - 26`
    /// (SEC1 0x04 tag sits 26 bytes past the SPKI SEQ header). Host-
    /// witnessed because the subject-DN byte length varies across
    /// DIIA holders; the p7s circuit anchors it via a 26-byte DIIA
    /// P-256 SPKI prefix assertion.
    pub cert_tbs_spki_offset: usize,
    /// Raw (r, s) ECDSA signature bytes over the TBS.
    pub cert_sig_start: usize,
    pub cert_sig_len: usize,

    // --- Inside the signer cert ---
    /// serialNumber attribute value bytes (OID 2.5.4.5) — the stable ID.
    pub subject_sn_start: usize,
    pub subject_sn_len: usize,
    /// Uncompressed P-256 point of the user's signing key
    /// (0x04 || X[32] || Y[32]). 65 bytes.
    pub user_signing_pk_start: usize,

    // --- Signature on signed_content ---
    pub content_sig_start: usize,
    pub content_sig_len: usize,

    // --- CMS signedAttrs (CAdES-BES style) ---
    /// Full DER bytes of signedAttrs as they appear in the p7s (with [0] IMPLICIT tag 0xA0).
    /// For signature verification, rewrite byte 0 from 0xA0 to 0x31 (SET tag) before hashing.
    pub signed_attrs_start: usize,
    pub signed_attrs_len: usize,
    /// The 32-byte digest inside the messageDigest attribute (OID 1.2.840.113549.1.9.4).
    /// Must equal SHA-256(signed_content) — asserted by verify_content_signature.
    pub message_digest_start: usize,
    pub message_digest_len: usize,

    // --- JSON fields inside signed_content ---
    /// Raw hex body of `"pk"` field, 130 hex chars (65 bytes uncompressed SEC1 secp256k1 point: 0x04 || X[32] || Y[32]).
    pub json_pk_start: usize,
    pub json_pk_len: usize,
    /// Raw hex body of `"nonce"` field, 64 hex chars (32 bytes).
    pub json_nonce_start: usize,
    pub json_nonce_len: usize,
    /// Text body of `"context"` field.
    pub json_context_start: usize,
    pub json_context_len: usize,
    /// Text body of `"declaration"` field (raw JSON string contents).
    /// Consumed by the Phase 2 DeclarationWhitelist invariant.
    pub json_declaration_start: usize,
    pub json_declaration_len: usize,
    /// ASCII digits of the `"timestamp"` integer field (no quotes).
    /// Exposed as a public output for frontend-policy anti-replay.
    pub json_timestamp_start: usize,
    pub json_timestamp_len: usize,
}

/// Public outputs the verifier sees after the ZK proof passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P7sPublicOutputs {
    /// secp256k1 pubkey declared in the JSON, uncompressed (0x04 || X || Y).
    pub pk: [u8; 65],
    /// SHA-256(stable_id ‖ context).
    pub nullifier: [u8; 32],
    /// SHA-256(stable_id).
    pub binding_hash: [u8; 32],
    /// Freshness nonce from the JSON (32 raw bytes).
    pub nonce: [u8; 32],
}

/// Parse a p7s and build the witness (offsets + context + trust anchor).
pub fn build_witness(
    p7s_bytes: &[u8],
    context: &[u8],
    trust_anchor_pk: [u8; 65],
) -> Result<P7sWitness, P7sError> {
    let offsets = parser::locate_offsets(p7s_bytes)?;
    Ok(P7sWitness {
        p7s_bytes: p7s_bytes.to_vec(),
        offsets,
        context: context.to_vec(),
        trust_anchor_pk,
    })
}
