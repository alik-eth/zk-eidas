//! Witness blob builder for the p7s circuit.
//!
//! The circuit consumes a witness as a byte blob with a little-endian u32
//! schema version prefix. The authoritative schema lives in
//! `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc` — keep this file in
//! sync with the "schema history" block there.
//!
//! -----------------------------------------------------------------------
//! Schema history
//! -----------------------------------------------------------------------
//! Note: "Transcript seed" lines below record the seed that shipped with
//! each schema version. The *current* seed is whatever the C++ file
//! (`vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.cc`) declares as
//! `kHashTranscriptSeed` — today that's `"p7s-31-hash"`. Older seed names
//! are kept here as history, not as the live value.
//!
//!   v1 (Task 1a, 1b): implicit-typed C args — no blob. Removed in Task 20.
//!
//!   v2 (Task 20) — Witness blob, all little-endian:
//!     u32 version                 = 2
//!     u32 context_len             in [0, 32]
//!     u8  context[32]             zero-padded
//!     u32 signed_content_len      in [0, 1024]
//!     u8  signed_content[1024]    zero-padded
//!     u32 json_pk_offset          relative to signed_content; +130 ≤ 1024
//!     u8  pk_hex[130]             ASCII lowercase hex
//!
//!   v3 (Task 21) — extends v2 with the nonce fields appended:
//!     u32 json_nonce_offset       relative to signed_content; +64 ≤ 1024
//!     u8  nonce_hex[64]           ASCII lowercase hex
//!
//!   v4 (Task 22) — extends v3 with json_context_offset appended:
//!     u32 json_context_offset     relative to signed_content;
//!                                 + MAX_CONTEXT ≤ MAX_SIGNED_CONTENT
//!     (context byte-length is NOT transmitted — it is derived in-circuit
//!      from the SHA-256 padding of context_bytes).
//!
//!   v5 (Task 23) — extends v4 with json_declaration_offset appended:
//!     u32 json_declaration_offset  relative to signed_content;
//!                                  + DECLARATION_LEN ≤ MAX_SIGNED_CONTENT
//!     (declaration length is a compile-time constant; the phrase itself
//!      is a circuit-side literal in sub/declaration_whitelist.cc).
//!
//!   v6 (Task 24) — extends v5 with message_digest appended:
//!     u8  message_digest[32]       prover-claimed SHA-256(signed_content).
//!     The C++ filler SHA-pads both context_bytes and signed_content
//!     off-circuit before pushing into circuit wires, so the raw blob
//!     still carries raw bytes + zero padding for both fields.
//!
//!   v7 (Task 25a) — no blob schema change. The circuit splits into a
//!     hash circuit (GF(2^128)) and a sig circuit (Fp256Base) linked
//!     by a MAC gadget bound to a compile-time sentinel, but the
//!     witness/public blob layouts are identical to v6. Transcript
//!     seed bumps to "p7s-25-hash" for the same cross-version safety
//!     reason.
//!
//!   v8 (Task 29) — invariant 1: real ECDSA verification against the
//!     hardcoded DIIA QTSP 2311 root pubkey, MAC-bound to
//!     `e = SHA-256(cert_tbs)`. Witness blob extends v7 with:
//!     `u32 cert_tbs_len` (in [0, 2039]), `u8 cert_tbs[2048]` (raw +
//!     zero pad; filler SHA-pads 32 blocks), `u8 cert_sig_r[32]`
//!     (big-endian scalar, DER-parsed in Rust), `u8 cert_sig_s[32]`.
//!     Public blob layout unchanged from v7. The DIIA root pubkey is
//!     a compile-time constant baked into the C++ circuit; it is NOT
//!     part of the public blob. The `PublicInputs.root_pk` field is
//!     retained for type-system continuity but is not serialized.
//!     Transcript seed bumps to "p7s-29-hash".
//!
//!   v9 (Task 26, merged with former #30) — invariant 2a + SPKI
//!     binding: the CMS content signature is signed by the holder's
//!     cert SPKI (a P-256 key embedded in cert_tbs's
//!     SubjectPublicKeyInfo), NOT the secp256k1 JSON.pk of invariant
//!     4. The sig circuit gains a second ECDSA VerifyCircuit; the
//!     hash circuit extracts the 65-byte SEC1 point from cert_tbs via
//!     `Routing::shift` at a host-witnessed offset, anchored by a
//!     26-byte DIIA P-256 SPKI DER prefix assertion. Four messages
//!     cross-bind hash→sig via MAC (kMacMessagesCount = 4): `e`, `e2`,
//!     cert SPKI X, cert SPKI Y. Cert SPKI stays PRIVATE — no holder
//!     identity in the public blob.
//!
//! Witness blob extends v8 with: `u32 cert_tbs_spki_offset` (offset of
//! the SPKI SEQUENCE 0x30 tag WITHIN cert_tbs — host-witnessed
//! because DIIA subject-DN byte length varies per holder),
//! `u32 signed_attrs_len` (in [0, 1527]), `u8 signed_attrs[1536]`
//! (raw bytes + zero pad; first byte MUST be 0xA0 — the host filler
//! rewrites byte 0 to 0x31, the CAdES-canonical SET OF tag the
//! content sig signs over, and SHA-pads the canonical buffer before
//! pushing into circuit wires), and `u8 content_sig_r[32]` /
//! `u8 content_sig_s[32]` (big-endian scalars, DER-parsed in Rust).
//! Public blob unchanged from v8. Transcript seed "p7s-26-hash".
//!
//!   v10 (Task 31) — invariant 2c: blob.message_digest is bound to the
//!     32-byte OCTET STRING value embedded in signed_attrs at the CMS
//!     messageDigest attribute. A new host-witnessed u32 wire
//!     `signed_attrs_md_offset` locates the messageDigest Attribute
//!     SEQUENCE tag (0x30) within signed_attrs; the circuit asserts a
//!     17-byte DER anchor at window[0..17] and the 32-byte digest
//!     equality at window[17..49] against the existing
//!     `message_digest[32]` wires (bound by invariant 2b to
//!     SHA-256(signed_content)). Closes the soundness gap where an
//!     attacker with honest (cert, signed_attrs, sigs) could
//!     substitute a fake signed_content + prover-recomputed
//!     message_digest.
//!     Witness blob extends v9 with:
//!       `u32 signed_attrs_md_offset` — offset of messageDigest
//!         Attribute SEQUENCE tag within signed_attrs (absolute
//!         md_value_offset - 17). Both DIIA fixtures measure 60 but
//!         DIIA's BER ordering is non-canonical; host-witnessed.
//!     Public blob unchanged from v9. Transcript seed "p7s-31-hash".
//!
//!   v11 (Task 34) — invariant 7: in-circuit nullifier from the X.520
//!     serialNumber (stable ID) embedded in cert_tbs's Subject DN.
//!     Binds `PublicInputs.nullifier = SHA-256(stable_id[16] ||
//!     context[..ctx_len])`, matching Phase 1's host-side formula in
//!     `crates/zk-eidas-p7s/src/outputs.rs`. The circuit routes the
//!     9+16-byte anchor+value window from cert_tbs, asserts the
//!     `30 17 06 03 55 04 05 13 10` DER prefix, range-checks
//!     `subject_sn_offset_in_tbs > subject_dn_start_offset_in_tbs`
//!     (dual-match protection: the ISSUER DN's serialNumber attribute
//!     — the QTSP's registration code — has the SAME 9-byte prefix,
//!     and without the range check a prover could bind the nullifier
//!     to the issuer's ID instead of the holder's), and computes
//!     `SHA-256(stable_id || context)` over a host-padded 64-byte
//!     buffer.
//!     Witness blob extends v10 with:
//!       `u32 subject_sn_offset_in_tbs`        — host-witnessed offset of
//!                                               the 9-byte anchor within
//!                                               cert_tbs (370 for both
//!                                               DIIA fixtures).
//!       `u32 subject_dn_start_offset_in_tbs`  — host-witnessed offset of
//!                                               the outer Subject DN
//!                                               SEQUENCE within cert_tbs
//!                                               (294 for DIIA fixtures).
//!                                               Used by the in-circuit
//!                                               range check.
//!       `u32 trust_anchor_index`              — selects which
//!                                               `kTrustAnchors[]` entry
//!                                               the cert-sig ECDSA
//!                                               verifies under. Phase
//!                                               2b ships with one entry
//!                                               (DIIA); Task #36 wired
//!                                               both the in-circuit
//!                                               bound check
//!                                               (`vlt(index,
//!                                                kTrustAnchorCount)`)
//!                                               and the host-side
//!                                               parser probe that
//!                                               picks the index by
//!                                               matching the signer
//!                                               cert's issuer DN.
//!     Public blob extends v10 with:
//!       `u8  nullifier[32]`                   — SHA-256(stable_id ||
//!                                               context) public output.
//!       `u32 trust_anchor_index`              — mirror of the witness
//!                                               field.
//!     v1 limitation: stable-ID length is hardcoded to 16 bytes (DIIA
//!     RNOKPP format `TINUA-` + 10 digits). Non-DIIA QTSPs with
//!     different RNOKPP-analog lengths are deferred to Task #37.
//!     Transcript seed bumps "p7s-31-hash" -> "p7s-7-hash".
//!
//! v11 runtime values (Task 43a, 2026-04-21): committed fixtures swapped
//!   from real DIIA to synthetic TestAnchorA; signer-cert PII scrubbed
//!   (generator at `crates/zk-eidas-p7s/src/bin/gen_synthetic_fixtures.rs`).
//!   TSA countersignature region left unchanged — stale after content_sig
//!   was re-signed, but no circuit invariant or test reads the TSA path.
//!   Residual DIIA-branding strings inside the TSA cert are tracked as
//!   Task #45. No schema version bump — v11 layout is unchanged.

use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};

use zk_eidas_p7s::P7sWitness;

use crate::CircuitError;

/// Keep in sync with C++ constants in `p7s_circuit.h` and
/// `sub/declaration_whitelist.h`.
pub const SCHEMA_VERSION: u32 = 11;
pub const MAX_CONTEXT: usize = 32;
pub const MAX_SIGNED_CONTENT: usize = 1024;
pub const PK_HEX_LEN: usize = 130;
pub const PK_BYTES: usize = 65;
pub const NONCE_HEX_LEN: usize = 64;
pub const NONCE_BYTES: usize = 32;
pub const DECLARATION_LEN: usize = 510;
pub const MESSAGE_DIGEST_LEN: usize = 32;

/// Fixed stable-ID value length (DIIA RNOKPP format: `TINUA-` prefix +
/// 10 decimal digits = 16 bytes). Matches the parser's `STABLE_ID_LEN`
/// and the circuit-side `kStableIdLen`. v1 is DIIA-only; Task #37 adds
/// variable-length support for other ETSI QTSPs.
pub const STABLE_ID_LEN: usize = 16;

/// 9-byte X.520 serialNumber attribute DER anchor asserted in-circuit
/// at `cert_tbs[subject_sn_offset..+9]`. SEQUENCE(l=23) + OID 2.5.4.5
/// + PrintableString(l=16).
pub const SUBJECT_SN_ANCHOR_LEN: usize = 9;

/// Nullifier output size (SHA-256 digest).
pub const NULLIFIER_LEN: usize = 32;

/// Maximum signed_content length that fits within 16 SHA blocks after
/// Merkle-Damgård padding: 16 × 64 − 9 = 1015.
pub const MAX_SIGNED_CONTENT_RAW: usize = 1015;

/// 32 SHA blocks × 64 bytes = 2048. Max raw cert_tbs (accounting for
/// the 9-byte SHA padding floor) is 2039.
pub const CERT_TBS_MAX_BYTES: usize = 2048;
pub const CERT_TBS_MAX_RAW: usize = CERT_TBS_MAX_BYTES - 9;

/// 24 SHA blocks × 64 bytes = 1536. Max raw signedAttrs = 1527 (9-byte
/// SHA pad floor). DIIA fixture measures 1387 bytes; 24 blocks gives
/// ~140 bytes of headroom. If a real-world signedAttrs exceeds this,
/// the host layer fails cleanly rather than truncating — the C++
/// constant must be bumped in tandem.
pub const SIGNED_ATTRS_MAX_BYTES: usize = 1536;
pub const SIGNED_ATTRS_MAX_RAW: usize = SIGNED_ATTRS_MAX_BYTES - 9;

#[derive(Debug, Clone)]
pub struct Witness {
    inner: P7sWitness,
}

impl Witness {
    pub fn new(inner: P7sWitness) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &P7sWitness {
        &self.inner
    }

    /// Serialize the witness into the current (v7) blob layout.
    pub fn to_ffi_bytes(&self) -> Result<Vec<u8>, CircuitError> {
        let off = &self.inner.offsets;
        let ctx = &self.inner.context;
        if ctx.len() > MAX_CONTEXT {
            return Err(CircuitError::ContextTooLong {
                got: ctx.len(),
                max: MAX_CONTEXT,
            });
        }

        let sc_end = off
            .signed_content_start
            .checked_add(off.signed_content_len)
            .ok_or_else(|| CircuitError::InvalidWitness(
                "signed_content range overflow".into(),
            ))?;
        if sc_end > self.inner.p7s_bytes.len() {
            return Err(CircuitError::InvalidWitness(
                "signed_content extends past p7s_bytes".into(),
            ));
        }
        let sc = &self.inner.p7s_bytes[off.signed_content_start..sc_end];
        if sc.len() > MAX_SIGNED_CONTENT_RAW {
            return Err(CircuitError::InvalidWitness(format!(
                "signed_content len {} exceeds MAX_SIGNED_CONTENT_RAW {} \
                 (needs to fit in 16 SHA blocks including 9-byte padding)",
                sc.len(),
                MAX_SIGNED_CONTENT_RAW
            )));
        }

        let pk_off_rel = hex_offset_relative(
            off.json_pk_start,
            off.json_pk_len,
            off.signed_content_start,
            sc.len(),
            PK_HEX_LEN,
            "json_pk",
        )?;
        let pk_hex = &self.inner.p7s_bytes[off.json_pk_start..off.json_pk_start + PK_HEX_LEN];

        let nonce_off_rel = hex_offset_relative(
            off.json_nonce_start,
            off.json_nonce_len,
            off.signed_content_start,
            sc.len(),
            NONCE_HEX_LEN,
            "json_nonce",
        )?;
        let nonce_hex =
            &self.inner.p7s_bytes[off.json_nonce_start..off.json_nonce_start + NONCE_HEX_LEN];

        // Context offset uses the in-witness context length (NOT the JSON
        // locator's length — the two should agree for honest witnesses).
        // The in-circuit byte-length comes from SHA padding; a mismatch
        // fails at prove time with a clean ProverFailed.
        if off.json_context_len != ctx.len() {
            return Err(CircuitError::InvalidWitness(format!(
                "json_context_len {} != witness.context.len() {}",
                off.json_context_len,
                ctx.len()
            )));
        }
        let context_off_rel = plain_offset_relative(
            off.json_context_start,
            ctx.len(),
            off.signed_content_start,
            sc.len(),
            MAX_CONTEXT,
            "json_context",
        )?;

        // Declaration is a compile-time constant (DECLARATION_LEN bytes) —
        // only the offset is serialized. The parser's `json_declaration_len`
        // MUST match our constant for the circuit's byte_range_eq to hold.
        if off.json_declaration_len != DECLARATION_LEN {
            return Err(CircuitError::InvalidWitness(format!(
                "json_declaration_len {} != expected DECLARATION_LEN {DECLARATION_LEN}",
                off.json_declaration_len
            )));
        }
        let declaration_off_rel = plain_offset_relative(
            off.json_declaration_start,
            DECLARATION_LEN,
            off.signed_content_start,
            sc.len(),
            DECLARATION_LEN,
            "json_declaration",
        )?;

        // Compute the prover's claimed message_digest = SHA-256(signed_content).
        let message_digest: [u8; MESSAGE_DIGEST_LEN] = Sha256::digest(sc).into();

        // --- cert_tbs + cert_sig extraction (v8) ---
        let cert_tbs_end = off
            .cert_tbs_start
            .checked_add(off.cert_tbs_len)
            .ok_or_else(|| CircuitError::InvalidWitness(
                "cert_tbs range overflow".into(),
            ))?;
        if cert_tbs_end > self.inner.p7s_bytes.len() {
            return Err(CircuitError::InvalidWitness(
                "cert_tbs extends past p7s_bytes".into(),
            ));
        }
        let cert_tbs = &self.inner.p7s_bytes[off.cert_tbs_start..cert_tbs_end];
        if cert_tbs.len() > CERT_TBS_MAX_RAW {
            return Err(CircuitError::InvalidWitness(format!(
                "cert_tbs len {} exceeds CERT_TBS_MAX_RAW {} \
                 (needs to fit in 32 SHA blocks including 9-byte padding)",
                cert_tbs.len(),
                CERT_TBS_MAX_RAW
            )));
        }

        // DER-parse cert_sig to get the raw 32-byte scalars (r, s).
        // `Signature::from_der` normalizes to the fixed-size `r || s`
        // representation (32 bytes each, big-endian, zero-padded).
        let cert_sig_der = &self.inner.p7s_bytes
            [off.cert_sig_start..off.cert_sig_start + off.cert_sig_len];
        let fixed_sig = Signature::from_der(cert_sig_der).map_err(|e| {
            CircuitError::InvalidWitness(format!("cert_sig DER parse: {e}"))
        })?;
        let sig_bytes = fixed_sig.to_bytes();
        let (r_slice, s_slice) = sig_bytes.split_at(32);
        let mut cert_sig_r = [0u8; 32];
        let mut cert_sig_s = [0u8; 32];
        cert_sig_r.copy_from_slice(r_slice);
        cert_sig_s.copy_from_slice(s_slice);

        // --- signedAttrs + content_sig extraction (v9) ---
        let sa_end = off
            .signed_attrs_start
            .checked_add(off.signed_attrs_len)
            .ok_or_else(|| CircuitError::InvalidWitness(
                "signed_attrs range overflow".into(),
            ))?;
        if sa_end > self.inner.p7s_bytes.len() {
            return Err(CircuitError::InvalidWitness(
                "signed_attrs extends past p7s_bytes".into(),
            ));
        }
        let signed_attrs = &self.inner.p7s_bytes[off.signed_attrs_start..sa_end];
        if signed_attrs.len() > SIGNED_ATTRS_MAX_RAW {
            return Err(CircuitError::InvalidWitness(format!(
                "signed_attrs len {} exceeds SIGNED_ATTRS_MAX_RAW {} \
                 (needs to fit in 24 SHA blocks including 9-byte padding)",
                signed_attrs.len(),
                SIGNED_ATTRS_MAX_RAW
            )));
        }
        if signed_attrs.is_empty() || signed_attrs[0] != 0xA0 {
            return Err(CircuitError::InvalidWitness(
                "signed_attrs first byte must be 0xA0 ([0] IMPLICIT tag)".into(),
            ));
        }

        // DER-parse content_sig — same normalization as cert_sig.
        let content_sig_der = &self.inner.p7s_bytes
            [off.content_sig_start..off.content_sig_start + off.content_sig_len];
        let fixed_csig = Signature::from_der(content_sig_der).map_err(|e| {
            CircuitError::InvalidWitness(format!("content_sig DER parse: {e}"))
        })?;
        let csig_bytes = fixed_csig.to_bytes();
        let (cr_slice, cs_slice) = csig_bytes.split_at(32);
        let mut content_sig_r = [0u8; 32];
        let mut content_sig_s = [0u8; 32];
        content_sig_r.copy_from_slice(cr_slice);
        content_sig_s.copy_from_slice(cs_slice);

        let mut out = Vec::with_capacity(
            4 + 4 + MAX_CONTEXT + 4 + MAX_SIGNED_CONTENT + 4 + PK_HEX_LEN
                + 4 + NONCE_HEX_LEN + 4 + 4 + MESSAGE_DIGEST_LEN
                + 4 + 4 + CERT_TBS_MAX_BYTES + 32 + 32  // cert_tbs_len + spki_offset
                + 4 + SIGNED_ATTRS_MAX_BYTES + 32 + 32,
        );
        out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());

        // context
        out.extend_from_slice(&(ctx.len() as u32).to_le_bytes());
        let mut ctx_padded = [0u8; MAX_CONTEXT];
        ctx_padded[..ctx.len()].copy_from_slice(ctx);
        out.extend_from_slice(&ctx_padded);

        // signed_content
        out.extend_from_slice(&(sc.len() as u32).to_le_bytes());
        let mut sc_padded = [0u8; MAX_SIGNED_CONTENT];
        sc_padded[..sc.len()].copy_from_slice(sc);
        out.extend_from_slice(&sc_padded);

        // pk
        out.extend_from_slice(&(pk_off_rel as u32).to_le_bytes());
        out.extend_from_slice(pk_hex);

        // nonce
        out.extend_from_slice(&(nonce_off_rel as u32).to_le_bytes());
        out.extend_from_slice(nonce_hex);

        // context offset
        out.extend_from_slice(&(context_off_rel as u32).to_le_bytes());

        // declaration offset
        out.extend_from_slice(&(declaration_off_rel as u32).to_le_bytes());

        // messageDigest = SHA-256(signed_content)
        out.extend_from_slice(&message_digest);

        // --- v8/v9: cert_tbs witness + v9 spki offset + raw (r, s) ---
        // Blob order matches C++ parse_witness_blob:
        //   u32 cert_tbs_len, u32 cert_tbs_spki_offset,
        //   u8 cert_tbs[2048], u8 cert_sig_r[32], u8 cert_sig_s[32].
        out.extend_from_slice(&(cert_tbs.len() as u32).to_le_bytes());
        let spki_offset_u32 = u32::try_from(off.cert_tbs_spki_offset).map_err(|_| {
            CircuitError::InvalidWitness(format!(
                "cert_tbs_spki_offset {} overflows u32",
                off.cert_tbs_spki_offset
            ))
        })?;
        out.extend_from_slice(&spki_offset_u32.to_le_bytes());
        let mut cert_tbs_padded = [0u8; CERT_TBS_MAX_BYTES];
        cert_tbs_padded[..cert_tbs.len()].copy_from_slice(cert_tbs);
        out.extend_from_slice(&cert_tbs_padded);
        out.extend_from_slice(&cert_sig_r);
        out.extend_from_slice(&cert_sig_s);

        // --- v9/v10: signedAttrs witness + v10 md offset + content_sig raw (r, s) ---
        // Blob order matches C++ parse_witness_blob:
        //   u32 signed_attrs_len, u32 signed_attrs_md_offset,
        //   u8 signed_attrs[1536], u8 content_sig_r[32], u8 content_sig_s[32].
        out.extend_from_slice(&(signed_attrs.len() as u32).to_le_bytes());
        let md_offset_u32 =
            u32::try_from(off.signed_attrs_md_offset).map_err(|_| {
                CircuitError::InvalidWitness(format!(
                    "signed_attrs_md_offset {} overflows u32",
                    off.signed_attrs_md_offset
                ))
            })?;
        out.extend_from_slice(&md_offset_u32.to_le_bytes());
        let mut sa_padded = [0u8; SIGNED_ATTRS_MAX_BYTES];
        sa_padded[..signed_attrs.len()].copy_from_slice(signed_attrs);
        out.extend_from_slice(&sa_padded);
        out.extend_from_slice(&content_sig_r);
        out.extend_from_slice(&content_sig_s);

        // --- v11 (Task 34): stable-ID offsets + trust-anchor index ---
        // Blob tail order matches C++ parse_witness_blob:
        //   u32 subject_sn_offset_in_tbs,
        //   u32 subject_dn_start_offset_in_tbs,
        //   u32 trust_anchor_index.
        // All three are host-witnessed; the circuit's invariant 7
        // anchors them via byte-eq and a range check.
        let sn_offset_u32 =
            u32::try_from(off.subject_sn_offset_in_tbs).map_err(|_| {
                CircuitError::InvalidWitness(format!(
                    "subject_sn_offset_in_tbs {} overflows u32",
                    off.subject_sn_offset_in_tbs
                ))
            })?;
        let dn_offset_u32 =
            u32::try_from(off.subject_dn_start_offset_in_tbs).map_err(|_| {
                CircuitError::InvalidWitness(format!(
                    "subject_dn_start_offset_in_tbs {} overflows u32",
                    off.subject_dn_start_offset_in_tbs
                ))
            })?;
        out.extend_from_slice(&sn_offset_u32.to_le_bytes());
        out.extend_from_slice(&dn_offset_u32.to_le_bytes());
        // v11 / Task #36 — trust-anchor index selected by the parser
        // (`locate_offsets` probes the signer cert's issuer DN for a
        // known QTSP marker). C++ side bound-checks against
        // `kTrustAnchorCount`; the in-circuit `vlt` constraint binds
        // the same relation so a caller passing a higher-than-expected
        // index surfaces as a host-side P7S_INVALID_INPUT before prove.
        out.extend_from_slice(&off.trust_anchor_index.to_le_bytes());

        Ok(out)
    }
}

/// Validate a non-hex field offset/length and return the relative offset.
/// `len` is the actual byte length of the field in the witness;
/// `window_len` is the length of the in-circuit shifter window (≥ `len`
/// for fields whose length varies at runtime, equal for compile-time-
/// fixed fields like the declaration). The C++ deserializer enforces
/// `offset + window_len ≤ MAX_SIGNED_CONTENT`; we mirror that here so
/// Rust-side errors have the same shape as a C++ rejection.
fn plain_offset_relative(
    start: usize,
    len: usize,
    sc_start: usize,
    sc_len: usize,
    window_len: usize,
    label: &str,
) -> Result<usize, CircuitError> {
    if start < sc_start {
        return Err(CircuitError::InvalidWitness(format!(
            "{label}_start precedes signed_content_start"
        )));
    }
    let rel = start - sc_start;
    if rel + len > sc_len {
        return Err(CircuitError::InvalidWitness(format!(
            "{label} window extends past signed_content"
        )));
    }
    if rel + window_len > MAX_SIGNED_CONTENT {
        return Err(CircuitError::InvalidWitness(format!(
            "{label} + window exceeds MAX_SIGNED_CONTENT"
        )));
    }
    Ok(rel)
}

/// Validate a hex-field offset/length pair and return its offset relative
/// to `signed_content_start`. Errors are captioned with `label` so a bad
/// `pk` vs `nonce` locator reports the right field.
fn hex_offset_relative(
    start: usize,
    len: usize,
    sc_start: usize,
    sc_len: usize,
    expected_len: usize,
    label: &str,
) -> Result<usize, CircuitError> {
    if len != expected_len {
        return Err(CircuitError::InvalidWitness(format!(
            "{label}_len {len} != expected {expected_len}"
        )));
    }
    if start < sc_start {
        return Err(CircuitError::InvalidWitness(format!(
            "{label}_start precedes signed_content_start"
        )));
    }
    let rel = start - sc_start;
    if rel + expected_len > sc_len {
        return Err(CircuitError::InvalidWitness(format!(
            "{label} window extends past signed_content"
        )));
    }
    if rel + expected_len > MAX_SIGNED_CONTENT {
        return Err(CircuitError::InvalidWitness(format!(
            "{label} window extends past MAX_SIGNED_CONTENT"
        )));
    }
    Ok(rel)
}
