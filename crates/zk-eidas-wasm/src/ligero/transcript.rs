//! Ligero-specific Fiat-Shamir challenge generation.
//!
//! These functions mirror the C++ `LigeroTranscript` class, generating
//! challenges in the exact order required for proof verification.

use crate::field::Field;
use crate::merkle::MerkleDigest;
use crate::transcript::Transcript;

/// Write Ligero commitment root to Fiat-Shamir transcript.
pub fn write_commitment(root: &MerkleDigest, ts: &mut Transcript) {
    ts.write_bytes(root);
}

/// Write hash_of_llterm to transcript (byte string).
pub fn write_llterm_hash(ts: &mut Transcript, hash: &[u8; 32]) {
    ts.write_bytes(hash);
}

/// Generate u_ldt challenges: nwqrow field elements.
pub fn gen_uldt<F: Field>(ts: &mut Transcript, nwqrow: usize, f: &F) -> Vec<F::Elt> {
    (0..nwqrow).map(|_| ts.elt(f)).collect()
}

/// Generate alphal challenges: nl field elements.
pub fn gen_alphal<F: Field>(ts: &mut Transcript, nl: usize, f: &F) -> Vec<F::Elt> {
    (0..nl).map(|_| ts.elt(f)).collect()
}

/// Generate alphaq challenges: 3*nq field elements as Vec<[Elt; 3]>.
pub fn gen_alphaq<F: Field>(ts: &mut Transcript, nq: usize, f: &F) -> Vec<[F::Elt; 3]> {
    (0..nq).map(|_| [ts.elt(f), ts.elt(f), ts.elt(f)]).collect()
}

/// Generate u_quad challenges: nqtriples field elements.
pub fn gen_uquad<F: Field>(ts: &mut Transcript, nqtriples: usize, f: &F) -> Vec<F::Elt> {
    (0..nqtriples).map(|_| ts.elt(f)).collect()
}

/// Write y_ldt, y_dot, y_quad_0, y_quad_2 arrays to transcript.
pub fn write_y_arrays<F: Field>(
    ts: &mut Transcript,
    y_ldt: &[F::Elt],
    y_dot: &[F::Elt],
    y_quad_0: &[F::Elt],
    y_quad_2: &[F::Elt],
    f: &F,
) {
    ts.write_array::<F>(y_ldt, f);
    ts.write_array::<F>(y_dot, f);
    ts.write_array::<F>(y_quad_0, f);
    ts.write_array::<F>(y_quad_2, f);
}

/// Generate random column indices: nreq distinct values in [0, block_ext).
pub fn gen_idx(ts: &mut Transcript, block_ext: usize, nreq: usize) -> Vec<usize> {
    ts.choose(block_ext, nreq)
}
