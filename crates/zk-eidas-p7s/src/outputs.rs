//! Derivation of the public outputs (pk, nullifier, binding_hash, nonce)
//! from a parsed witness.

use sha2::{Digest, Sha256};

use crate::{P7sError, P7sPublicOutputs, P7sWitness};

/// Compute the public outputs from a parsed witness.
///
/// This derivation must match what the ZK circuit will produce. Any
/// divergence here means the circuit implementation is wrong.
pub fn compute_outputs(witness: &P7sWitness) -> Result<P7sPublicOutputs, P7sError> {
    let off = &witness.offsets;
    let bytes = &witness.p7s_bytes;

    // Extract stable ID (serialNumber attribute value)
    let stable_id = &bytes[off.subject_sn_start..off.subject_sn_start + off.subject_sn_len];

    // Extract pk: JSON field is hex-encoded, decode to 65 bytes
    let pk_hex = &bytes[off.json_pk_start..off.json_pk_start + off.json_pk_len];
    let pk = decode_hex_fixed::<65>(pk_hex)?;

    // Extract nonce: 32 bytes
    let nonce_hex = &bytes[off.json_nonce_start..off.json_nonce_start + off.json_nonce_len];
    let nonce = decode_hex_fixed::<32>(nonce_hex)?;

    // Sanity: the context field in the JSON must match the witness's context input
    let json_context =
        &bytes[off.json_context_start..off.json_context_start + off.json_context_len];
    if json_context != witness.context.as_slice() {
        return Err(P7sError::ContextMismatch {
            witness: witness.context.clone(),
            input: json_context.to_vec(),
        });
    }

    // nullifier = SHA-256(stable_id || context)
    let mut h = Sha256::new();
    h.update(stable_id);
    h.update(&witness.context);
    let nullifier: [u8; 32] = h.finalize().into();

    // binding_hash = SHA-256(stable_id)
    let binding_hash: [u8; 32] = Sha256::digest(stable_id).into();

    Ok(P7sPublicOutputs {
        pk,
        nullifier,
        binding_hash,
        nonce,
    })
}

fn decode_hex_fixed<const N: usize>(hex: &[u8]) -> Result<[u8; N], P7sError> {
    if hex.len() != 2 * N {
        return Err(P7sError::Der(format!(
            "hex length {} != expected {}",
            hex.len(),
            2 * N
        )));
    }
    let mut out = [0u8; N];
    for (i, pair) in hex.chunks_exact(2).enumerate() {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, P7sError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(P7sError::Der(format!("bad hex char: {b:#x}"))),
    }
}
