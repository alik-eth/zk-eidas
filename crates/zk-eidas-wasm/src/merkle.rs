use sha2::{Digest, Sha256};

pub const DIGEST_LEN: usize = 32;
pub const NONCE_LEN: usize = 32;

pub type MerkleDigest = [u8; DIGEST_LEN];

pub struct MerkleProof {
    pub nonces: Vec<[u8; NONCE_LEN]>,
    pub path: Vec<MerkleDigest>,
}

/// Build the bitmask of tree nodes that lie on any root-to-leaf path
/// for the given positions. Uses the same 1-indexed layout as the C++:
/// leaves at indices `[n, 2n)`, root at index `1`.
fn compressed_proof_tree(n: usize, positions: &[usize]) -> Vec<bool> {
    let mut tree = vec![false; 2 * n];

    for &p in positions {
        assert!(p < n, "position out of range");
        tree[p + n] = true;
    }

    // Propagate upward: parent is on a path if either child is.
    let mut i = n;
    while i > 1 {
        i -= 1;
        tree[i] = tree[2 * i] || tree[2 * i + 1];
    }

    tree
}

/// Verify that columns at `positions` open correctly against `root`
/// using the compressed Merkle proof format from Longfellow.
///
/// `column_hash_fn(col_idx, hasher)` feeds column data into the hasher
/// for the column at index `col_idx` within the opened set (0-based).
pub fn merkle_verify(
    n: usize,
    root: &MerkleDigest,
    proof: &MerkleProof,
    positions: &[usize],
    column_hash_fn: &dyn Fn(usize, &mut Sha256),
) -> bool {
    let nreq = positions.len();
    assert!(nreq > 0, "need at least one opened position");
    assert!(n > 0, "n must be positive");

    // 1. Compute leaf hashes: leaf = SHA256(nonce || column_data)
    let mut leaves = vec![[0u8; DIGEST_LEN]; nreq];
    for r in 0..nreq {
        let mut sha = Sha256::new();
        sha.update(&proof.nonces[r]);
        column_hash_fn(r, &mut sha);
        leaves[r] = sha.finalize().into();
    }

    // 2. Build the compressed proof tree bitmask
    let tree = compressed_proof_tree(n, positions);

    // 3. Reconstruct layers from proof — mirror C++ verify_compressed_proof
    let mut layers = vec![[0u8; DIGEST_LEN]; 2 * n];
    let mut defined = vec![false; 2 * n];

    // Read proof elements into positions determined by the tree bitmask.
    // Iteration order: i from n-1 down to 1 (same as C++).
    {
        let mut sz = 0usize;
        let mut i = n;
        while i > 1 {
            i -= 1;
            if tree[i] {
                let mut child = 2 * i;
                if tree[child] {
                    child = 2 * i + 1;
                }
                if !tree[child] {
                    if sz >= proof.path.len() {
                        return false;
                    }
                    layers[child] = proof.path[sz];
                    defined[child] = true;
                    sz += 1;
                }
            }
        }
    }

    // 4. Set leaf values
    for (ip, &pos) in positions.iter().enumerate() {
        let l = pos + n;
        layers[l] = leaves[ip];
        defined[l] = true;
    }

    // 5. Recompute inner nodes bottom-up
    {
        let mut i = n;
        while i > 1 {
            i -= 1;
            if defined[2 * i] && defined[2 * i + 1] {
                let mut sha = Sha256::new();
                sha.update(&layers[2 * i]);
                sha.update(&layers[2 * i + 1]);
                layers[i] = sha.finalize().into();
                defined[i] = true;
            }
        }
    }

    // 6. Check root
    defined[1] && layers[1] == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn merkle_verify_trivial() {
        // Tree with 2 leaves, open position 0
        let nonce0 = [0u8; 32];
        let data0 = [1u8; 32];

        let nonce1 = [2u8; 32];
        let data1 = [3u8; 32];

        let leaf0: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&nonce0);
            h.update(&data0);
            h.finalize().into()
        };
        let leaf1: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&nonce1);
            h.update(&data1);
            h.finalize().into()
        };

        let root: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&leaf0);
            h.update(&leaf1);
            h.finalize().into()
        };

        let proof = MerkleProof {
            nonces: vec![nonce0],
            path: vec![leaf1],
        };

        let result = merkle_verify(2, &root, &proof, &[0], &|_col_idx, hasher| {
            hasher.update(&data0);
        });
        assert!(result);
    }

    #[test]
    fn merkle_verify_wrong_root_fails() {
        let nonce0 = [0u8; 32];
        let data0 = [1u8; 32];
        let leaf1 = [0xFF; 32];

        let wrong_root = [0u8; 32];

        let proof = MerkleProof {
            nonces: vec![nonce0],
            path: vec![leaf1],
        };

        let result = merkle_verify(2, &wrong_root, &proof, &[0], &|_col_idx, hasher| {
            hasher.update(&data0);
        });
        assert!(!result);
    }

    #[test]
    fn merkle_verify_both_leaves_opened() {
        // Tree with 2 leaves, open both — path should be empty
        let nonce0 = [0u8; 32];
        let data0 = [1u8; 32];
        let nonce1 = [2u8; 32];
        let data1 = [3u8; 32];

        let leaf0: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&nonce0);
            h.update(&data0);
            h.finalize().into()
        };
        let leaf1: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&nonce1);
            h.update(&data1);
            h.finalize().into()
        };

        let root: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&leaf0);
            h.update(&leaf1);
            h.finalize().into()
        };

        let proof = MerkleProof {
            nonces: vec![nonce0, nonce1],
            path: vec![], // both siblings known, no path needed
        };

        let result = merkle_verify(2, &root, &proof, &[0, 1], &|col_idx, hasher| {
            if col_idx == 0 {
                hasher.update(&data0);
            } else {
                hasher.update(&data1);
            }
        });
        assert!(result);
    }

    #[test]
    fn merkle_verify_4_leaves_open_one() {
        // Tree with 4 leaves, open position 2
        //        root
        //       /    \
        //    n01      n23
        //   /  \     /  \
        // l0   l1  l2   l3
        let nonces: [[u8; 32]; 4] = [
            [10u8; 32],
            [11u8; 32],
            [12u8; 32],
            [13u8; 32],
        ];
        let datas: [[u8; 32]; 4] = [
            [20u8; 32],
            [21u8; 32],
            [22u8; 32],
            [23u8; 32],
        ];

        let mut leaves = [[0u8; 32]; 4];
        for i in 0..4 {
            let mut h = Sha256::new();
            h.update(&nonces[i]);
            h.update(&datas[i]);
            leaves[i] = h.finalize().into();
        }

        let n01: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&leaves[0]);
            h.update(&leaves[1]);
            h.finalize().into()
        };
        let n23: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&leaves[2]);
            h.update(&leaves[3]);
            h.finalize().into()
        };
        let root: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&n01);
            h.update(&n23);
            h.finalize().into()
        };

        // Open position 2.
        // Compressed proof tree: leaf node 2 (index 6), parent node 3 (index 3),
        // root node 1 (index 1).
        // At node 3 (children 6,7): child 6 is in tree, child 7 is not → path gets leaves[3]
        // At node 1 (children 2,3): child 3 is in tree, child 2 is not → path gets n01
        // Iteration i=3: tree[3]=true, child=6 in tree, try 7 not in tree → push leaves[3]
        // Iteration i=2: tree[2]=false, skip
        // Iteration i=1: tree[1]=true, child=2 not in tree → push n01
        // So path = [leaves[3], n01]
        let proof = MerkleProof {
            nonces: vec![nonces[2]],
            path: vec![leaves[3], n01],
        };

        let result = merkle_verify(4, &root, &proof, &[2], &|_col_idx, hasher| {
            hasher.update(&datas[2]);
        });
        assert!(result);
    }

    #[test]
    fn merkle_verify_4_leaves_open_two_different_subtrees() {
        // Open positions 0 and 3 in a 4-leaf tree
        let nonces: [[u8; 32]; 4] = [
            [10u8; 32],
            [11u8; 32],
            [12u8; 32],
            [13u8; 32],
        ];
        let datas: [[u8; 32]; 4] = [
            [20u8; 32],
            [21u8; 32],
            [22u8; 32],
            [23u8; 32],
        ];

        let mut leaves = [[0u8; 32]; 4];
        for i in 0..4 {
            let mut h = Sha256::new();
            h.update(&nonces[i]);
            h.update(&datas[i]);
            leaves[i] = h.finalize().into();
        }

        let n01: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&leaves[0]);
            h.update(&leaves[1]);
            h.finalize().into()
        };
        let n23: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&leaves[2]);
            h.update(&leaves[3]);
            h.finalize().into()
        };
        let root: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(&n01);
            h.update(&n23);
            h.finalize().into()
        };

        // Compressed proof for positions [0, 3]:
        // tree bitmask: leaves 4(pos0),7(pos3) → nodes 2,3,1 all true
        // i=3: tree[3]=true, child=6, tree[6]=false → push leaves[2]
        // i=2: tree[2]=true, child=4, tree[4]=true, try 5, tree[5]=false → push leaves[1]
        // i=1: tree[1]=true, child=2, tree[2]=true, try 3, tree[3]=true → both in tree, no push
        // path = [leaves[2], leaves[1]]
        let proof = MerkleProof {
            nonces: vec![nonces[0], nonces[3]],
            path: vec![leaves[2], leaves[1]],
        };

        let result = merkle_verify(4, &root, &proof, &[0, 3], &|col_idx, hasher| {
            if col_idx == 0 {
                hasher.update(&datas[0]);
            } else {
                hasher.update(&datas[3]);
            }
        });
        assert!(result);
    }
}
