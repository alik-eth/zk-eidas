use crate::merkle::MerkleDigest;
use crate::transcript::Transcript;

/// Write Ligero commitment root to Fiat-Shamir transcript.
pub fn write_commitment(root: &MerkleDigest, ts: &mut Transcript) {
    ts.write_bytes(root);
}
