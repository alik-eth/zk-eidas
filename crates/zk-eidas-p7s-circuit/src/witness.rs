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

use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};

use zk_eidas_p7s::P7sWitness;

use crate::CircuitError;

/// Keep in sync with C++ constants in `p7s_circuit.h` and
/// `sub/declaration_whitelist.h`.
pub const SCHEMA_VERSION: u32 = 8;
pub const MAX_CONTEXT: usize = 32;
pub const MAX_SIGNED_CONTENT: usize = 1024;
pub const PK_HEX_LEN: usize = 130;
pub const PK_BYTES: usize = 65;
pub const NONCE_HEX_LEN: usize = 64;
pub const NONCE_BYTES: usize = 32;
pub const DECLARATION_LEN: usize = 510;
pub const MESSAGE_DIGEST_LEN: usize = 32;

/// Maximum signed_content length that fits within 16 SHA blocks after
/// Merkle-Damgård padding: 16 × 64 − 9 = 1015.
pub const MAX_SIGNED_CONTENT_RAW: usize = 1015;

/// 32 SHA blocks × 64 bytes = 2048. Max raw cert_tbs (accounting for
/// the 9-byte SHA padding floor) is 2039.
pub const CERT_TBS_MAX_BYTES: usize = 2048;
pub const CERT_TBS_MAX_RAW: usize = CERT_TBS_MAX_BYTES - 9;

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

        let mut out = Vec::with_capacity(
            4 + 4 + MAX_CONTEXT + 4 + MAX_SIGNED_CONTENT + 4 + PK_HEX_LEN
                + 4 + NONCE_HEX_LEN + 4 + 4 + MESSAGE_DIGEST_LEN
                + 4 + CERT_TBS_MAX_BYTES + 32 + 32,
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

        // --- v8: cert_tbs witness + raw (r, s) ---
        out.extend_from_slice(&(cert_tbs.len() as u32).to_le_bytes());
        let mut cert_tbs_padded = [0u8; CERT_TBS_MAX_BYTES];
        cert_tbs_padded[..cert_tbs.len()].copy_from_slice(cert_tbs);
        out.extend_from_slice(&cert_tbs_padded);
        out.extend_from_slice(&cert_sig_r);
        out.extend_from_slice(&cert_sig_s);

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
