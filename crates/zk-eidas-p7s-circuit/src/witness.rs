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

use zk_eidas_p7s::P7sWitness;

use crate::CircuitError;

/// v2 constants — keep in sync with C++ constants in `p7s_circuit.h`.
pub const SCHEMA_VERSION: u32 = 2;
pub const MAX_CONTEXT: usize = 32;
pub const MAX_SIGNED_CONTENT: usize = 1024;
pub const PK_HEX_LEN: usize = 130;
pub const PK_BYTES: usize = 65;

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

    /// Serialize the witness into the v2 blob layout.
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
        if sc.len() > MAX_SIGNED_CONTENT {
            return Err(CircuitError::InvalidWitness(format!(
                "signed_content len {} exceeds MAX_SIGNED_CONTENT {}",
                sc.len(),
                MAX_SIGNED_CONTENT
            )));
        }

        if off.json_pk_len != PK_HEX_LEN {
            return Err(CircuitError::InvalidWitness(format!(
                "json_pk_len {} != expected PK_HEX_LEN {}",
                off.json_pk_len, PK_HEX_LEN
            )));
        }
        if off.json_pk_start < off.signed_content_start {
            return Err(CircuitError::InvalidWitness(
                "json_pk_start precedes signed_content_start".into(),
            ));
        }
        let pk_off_rel = off.json_pk_start - off.signed_content_start;
        if pk_off_rel + PK_HEX_LEN > sc.len() {
            return Err(CircuitError::InvalidWitness(
                "json_pk window extends past signed_content".into(),
            ));
        }
        // Also reject offsets the C++ side would reject — keeps the
        // Rust->C++ boundary error consistent.
        if pk_off_rel + PK_HEX_LEN > MAX_SIGNED_CONTENT {
            return Err(CircuitError::InvalidWitness(
                "json_pk window extends past MAX_SIGNED_CONTENT".into(),
            ));
        }

        let pk_hex = &self.inner.p7s_bytes[off.json_pk_start..off.json_pk_start + PK_HEX_LEN];

        let mut out = Vec::with_capacity(
            4 + 4 + MAX_CONTEXT + 4 + MAX_SIGNED_CONTENT + 4 + PK_HEX_LEN,
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

        // json_pk_offset (u32, within MAX_SIGNED_CONTENT)
        out.extend_from_slice(&(pk_off_rel as u32).to_le_bytes());

        // pk_hex
        out.extend_from_slice(pk_hex);

        Ok(out)
    }
}
