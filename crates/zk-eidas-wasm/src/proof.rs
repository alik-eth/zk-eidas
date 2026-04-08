//! Proof data structures and deserialization from the Longfellow binary format.
//!
//! The binary layout matches C++ `zk_proof.h`: commitment (32 bytes), sumcheck
//! proof (layer evaluations), then Ligero proof (polynomials, nonces,
//! run-length-encoded opened columns, compressed Merkle path).

use crate::algebra::poly::SumcheckPoly;
use crate::circuit::{Circuit, ReadBuf};
use crate::error::VerifyError;
use crate::field::Field;
use crate::merkle::{MerkleDigest, MerkleProof, DIGEST_LEN, NONCE_LEN};

// ---------------------------------------------------------------------------
// LigeroParam
// ---------------------------------------------------------------------------

/// Parameters governing the Ligero proof matrix layout.
///
/// Computed from the circuit size and ZkSpec version info.  The formulas
/// mirror `ligero_param.h` exactly.
pub struct LigeroParam {
    pub nw: usize,
    pub nq: usize,
    pub rateinv: usize,
    pub nreq: usize,
    pub block_enc: usize,
    pub block: usize,
    pub dblock: usize,
    pub block_ext: usize,
    pub r: usize,
    pub w: usize,
    pub nwrow: usize,
    pub nqtriples: usize,
    pub nwqrow: usize,
    pub nrow: usize,
    pub mc_pathlen: usize,
    pub ildt: usize,
    pub idot: usize,
    pub iquad: usize,
    pub iw: usize,
    pub iq: usize,
}

impl LigeroParam {
    /// Construct from pre-computed `block_enc` (the 5-arg constructor in C++).
    pub fn new(
        nw: usize,
        nq: usize,
        rateinv: usize,
        nreq: usize,
        block_enc: usize,
    ) -> Self {
        let r = nreq;
        let block = (block_enc + 1) / (2 + rateinv);
        let w = block - r;
        let dblock = 2 * block - 1;
        let block_ext = block_enc - dblock;

        let nwrow = ceildiv(nw, w);
        let nqtriples = ceildiv(nq, w);
        let nwqrow = nwrow + 3 * nqtriples;
        let nrow = nwqrow + 3; // 3 blinding rows

        let mc_pathlen = merkle_tree_len(block_ext);

        let iw = 3;
        let iq = iw + nwrow;

        LigeroParam {
            nw,
            nq,
            rateinv,
            nreq,
            block_enc,
            block,
            dblock,
            block_ext,
            r,
            w,
            nwrow,
            nqtriples,
            nwqrow,
            nrow,
            mc_pathlen,
            ildt: 0,
            idot: 1,
            iquad: 2,
            iw,
            iq,
        }
    }
}

fn ceildiv(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

/// Merkle tree path length for `n` leaves.
///
/// Mirrors `merkle_tree.h::merkle_tree_len`.
fn merkle_tree_len(n: usize) -> usize {
    let mut r = 1;
    let mut pos = (n - 1) + n; // max leaf position in 1-indexed tree
    while pos > 1 {
        pos >>= 1;
        r += 1;
    }
    r
}

// ---------------------------------------------------------------------------
// pad_size — witness padding per layer
// ---------------------------------------------------------------------------

/// Compute the total witness padding across all layers.
///
/// Matches `ZkCommon::pad_size` (C++ `zk_common.h`).
///
/// Each layer contributes `PadLayout(logw).layer_size()` = `claim_pad(3)`
/// = `poly_pad(2*logw, 0) + 3` = `4*logw + 3`.
pub fn pad_size<F: Field>(circuit: &Circuit<F>) -> usize {
    let mut sz = 0;
    for layer in &circuit.layers {
        // poly_pad(r, 0) = 2*r, so poly_pad(2*logw, 0) = 4*logw
        // claim_pad(3) = poly_pad(2*logw, 0) + 3 = 4*logw + 3
        // layer_size() = claim_pad(3)
        sz += 4 * layer.logw + 3;
    }
    sz
}

// ---------------------------------------------------------------------------
// Proof data structures
// ---------------------------------------------------------------------------

pub struct LigeroCommitment {
    pub root: MerkleDigest,
}

pub struct LigeroProof<F: Field> {
    pub y_ldt: Vec<F::Elt>,
    pub y_dot: Vec<F::Elt>,
    pub y_quad_0: Vec<F::Elt>,
    pub y_quad_2: Vec<F::Elt>,
    /// Opened columns, stored row-major: `req[row * nreq + col]`.
    pub req: Vec<F::Elt>,
    pub merkle: MerkleProof,
}

/// One layer of sumcheck proof.
pub struct LayerProof<F: Field> {
    /// `hp[round] = [hand0_poly, hand1_poly]`.
    /// Each `SumcheckPoly` has evaluations at 0, 1, 2.
    /// `t[1]` is set to zero here; it is reconstructed during verification.
    pub hp: Vec<[SumcheckPoly<F>; 2]>,
    /// Claims for the next layer.
    pub wc: [F::Elt; 2],
}

pub struct ZkProof<F: Field> {
    pub com: LigeroCommitment,
    pub proof: Vec<LayerProof<F>>,
    pub com_proof: LigeroProof<F>,
    pub param: LigeroParam,
}

// ---------------------------------------------------------------------------
// ReadBuf extensions
// ---------------------------------------------------------------------------

impl<'a> ReadBuf<'a> {
    /// Read a 4-byte little-endian u32.
    pub fn read_u32_le(&mut self) -> Result<u32, VerifyError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

// ---------------------------------------------------------------------------
// Deserialization
// ---------------------------------------------------------------------------

const K_MAX_RUN_LEN: usize = 1 << 25;
const K_MAX_NUM_DIGESTS: usize = 1 << 25;

/// Read one full-size field element from the buffer.
fn read_elt<F: Field>(buf: &mut ReadBuf, f: &F) -> Result<F::Elt, VerifyError> {
    let bytes = buf.read_bytes(F::BYTES)?;
    f.of_bytes(bytes)
        .ok_or_else(|| VerifyError::ProofParse("invalid field element".into()))
}

/// Read one subfield element from the buffer.
fn read_subfield_elt<F: Field>(buf: &mut ReadBuf, f: &F) -> Result<F::Elt, VerifyError> {
    let bytes = buf.read_bytes(F::SUBFIELD_BYTES)?;
    f.of_subfield_bytes(bytes)
        .ok_or_else(|| VerifyError::ProofParse("invalid subfield element".into()))
}

impl<F: Field> ZkProof<F> {
    /// Deserialize a proof from binary format.
    ///
    /// `rate` = rateinv, `nreq` = number of opened columns, `block_enc` =
    /// pre-computed encoding block size (all from ZkSpec).
    pub fn read(
        buf: &mut ReadBuf,
        circuit: &Circuit<F>,
        rate: usize,
        nreq: usize,
        block_enc: usize,
        f: &F,
    ) -> Result<Self, VerifyError> {
        let nw = (circuit.ninputs - circuit.npub_in) + pad_size(circuit);
        let nq = circuit.nl;
        let param = LigeroParam::new(nw, nq, rate, nreq, block_enc);

        // 1. Read commitment (32-byte Merkle root)
        let root_bytes = buf.read_bytes(DIGEST_LEN)?;
        let mut root = [0u8; DIGEST_LEN];
        root.copy_from_slice(root_bytes);
        let com = LigeroCommitment { root };

        // 2. Read sumcheck proof (logc must be 0)
        if circuit.logc != 0 {
            return Err(VerifyError::ProofParse("logc must be 0".into()));
        }

        let mut layers = Vec::with_capacity(circuit.nl);
        for i in 0..circuit.nl {
            let logw = circuit.layers[i].logw;
            let mut hp_rounds = Vec::with_capacity(logw);

            for _wi in 0..logw {
                // k=0: read hand0.t[0], hand1.t[0]
                let t0_h0 = read_elt(buf, f)?;
                let t0_h1 = read_elt(buf, f)?;
                // k=1: skipped (set to zero, reconstructed during verify)
                // k=2: read hand0.t[2], hand1.t[2]
                let t2_h0 = read_elt(buf, f)?;
                let t2_h1 = read_elt(buf, f)?;

                hp_rounds.push([
                    SumcheckPoly::new(vec![t0_h0, f.zero(), t2_h0]),
                    SumcheckPoly::new(vec![t0_h1, f.zero(), t2_h1]),
                ]);
            }

            let wc0 = read_elt(buf, f)?;
            let wc1 = read_elt(buf, f)?;

            layers.push(LayerProof {
                hp: hp_rounds,
                wc: [wc0, wc1],
            });
        }

        // 3. Read Ligero proof

        // 3a. y_ldt[0..block]
        let mut y_ldt = Vec::with_capacity(param.block);
        for _ in 0..param.block {
            y_ldt.push(read_elt(buf, f)?);
        }

        // 3b. y_dot[0..dblock]
        let mut y_dot = Vec::with_capacity(param.dblock);
        for _ in 0..param.dblock {
            y_dot.push(read_elt(buf, f)?);
        }

        // 3c. y_quad_0[0..r]
        let mut y_quad_0 = Vec::with_capacity(param.r);
        for _ in 0..param.r {
            y_quad_0.push(read_elt(buf, f)?);
        }

        // 3d. y_quad_2[0..dblock-block]
        let quad2_len = param.dblock - param.block;
        let mut y_quad_2 = Vec::with_capacity(quad2_len);
        for _ in 0..quad2_len {
            y_quad_2.push(read_elt(buf, f)?);
        }

        // 3e. Nonces: nreq x 32 bytes
        let mut nonces = Vec::with_capacity(param.nreq);
        for _ in 0..param.nreq {
            let nonce_bytes = buf.read_bytes(NONCE_LEN)?;
            let mut nonce = [0u8; NONCE_LEN];
            nonce.copy_from_slice(nonce_bytes);
            nonces.push(nonce);
        }

        // 3f. Run-length encoded req[nrow * nreq]
        let total_req = param.nrow * param.nreq;
        let mut req = vec![f.zero(); total_req];
        let mut ci = 0usize;
        let mut subfield_run = false; // first run is NON-subfield (full elements)
        while ci < total_req {
            let runlen = buf.read_u32_le()? as usize;
            if runlen >= K_MAX_RUN_LEN || ci + runlen > total_req {
                return Err(VerifyError::ProofParse(
                    "invalid run length in req encoding".into(),
                ));
            }
            if subfield_run {
                for idx in ci..ci + runlen {
                    req[idx] = read_subfield_elt(buf, f)?;
                }
            } else {
                for idx in ci..ci + runlen {
                    req[idx] = read_elt(buf, f)?;
                }
            }
            ci += runlen;
            subfield_run = !subfield_run;
        }

        // 3g. Merkle path
        let path_size = buf.read_u32_le()? as usize;
        if path_size < param.nreq || path_size >= K_MAX_NUM_DIGESTS {
            return Err(VerifyError::ProofParse(
                "invalid merkle path size".into(),
            ));
        }
        if path_size > param.nreq * param.mc_pathlen {
            return Err(VerifyError::ProofParse(
                "merkle path too large".into(),
            ));
        }
        let mut path = Vec::with_capacity(path_size);
        for _ in 0..path_size {
            let digest_bytes = buf.read_bytes(DIGEST_LEN)?;
            let mut digest = [0u8; DIGEST_LEN];
            digest.copy_from_slice(digest_bytes);
            path.push(digest);
        }

        let com_proof = LigeroProof {
            y_ldt,
            y_dot,
            y_quad_0,
            y_quad_2,
            req,
            merkle: MerkleProof { nonces, path },
        };

        Ok(ZkProof {
            com,
            proof: layers,
            com_proof,
            param,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ceildiv_basic() {
        assert_eq!(ceildiv(10, 3), 4);
        assert_eq!(ceildiv(9, 3), 3);
        assert_eq!(ceildiv(1, 1), 1);
        assert_eq!(ceildiv(0, 5), 0);
        assert_eq!(ceildiv(7, 7), 1);
        assert_eq!(ceildiv(8, 7), 2);
    }

    #[test]
    fn merkle_tree_len_powers_of_two() {
        assert_eq!(merkle_tree_len(1), 1);
        assert_eq!(merkle_tree_len(2), 2);
        assert_eq!(merkle_tree_len(4), 3);
        assert_eq!(merkle_tree_len(8), 4);
        assert_eq!(merkle_tree_len(16), 5);
    }

    #[test]
    fn merkle_tree_len_non_power_of_two() {
        // n=3: max leaf pos = 2+3=5, path: 5->2->1, len=3
        assert_eq!(merkle_tree_len(3), 3);
        // n=5: max leaf pos = 4+5=9, path: 9->4->2->1, len=4
        assert_eq!(merkle_tree_len(5), 4);
    }

    #[test]
    fn ligero_param_basic() {
        // Use realistic v7 parameters: rate=7, nreq=132, block_enc_sig=2945
        let param = LigeroParam::new(1000, 21, 7, 132, 2945);
        assert_eq!(param.r, 132);
        assert_eq!(param.block, (2945 + 1) / (2 + 7)); // = 327
        assert!(param.block > param.r);
        assert_eq!(param.w, param.block - param.r); // = 195
        assert_eq!(param.dblock, 2 * param.block - 1);
        assert_eq!(param.block_ext, param.block_enc - param.dblock);
        assert_eq!(param.nrow, param.nwqrow + 3);
        assert_eq!(param.ildt, 0);
        assert_eq!(param.idot, 1);
        assert_eq!(param.iquad, 2);
        assert_eq!(param.iw, 3);
        assert_eq!(param.iq, 3 + param.nwrow);
        // C++ sanity: nrow == iq + 3*nqtriples
        assert_eq!(param.nrow, param.iq + 3 * param.nqtriples);
    }

    #[test]
    fn ligero_param_from_real_circuit() {
        use crate::circuit::decompress_circuit;
        use crate::field::fp256::Fp256;

        let compressed = include_bytes!("../../../demo/web/circuit-cache/mdoc-1attr.bin");
        let decompressed = decompress_circuit(compressed).unwrap();
        let fp = Fp256;
        let (sig_circuit, _) = Circuit::from_bytes(&decompressed, &fp).unwrap();

        let pad = pad_size(&sig_circuit);
        let nw = (sig_circuit.ninputs - sig_circuit.npub_in) + pad;
        let nq = sig_circuit.nl;

        // pad_size must be positive (every layer contributes at least 3)
        assert!(pad >= 3 * sig_circuit.nl);
        assert!(nw > sig_circuit.ninputs - sig_circuit.npub_in);

        // Construct with v7 sig parameters — must not panic
        let param = LigeroParam::new(nw, nq, 7, 132, 2945);
        assert!(param.block > 0);
        assert!(param.nrow > 3);
        assert_eq!(param.iw, 3);
        assert_eq!(param.iq, 3 + param.nwrow);
        // Sanity: nrow == iq + 3*nqtriples (matches C++ sanity check)
        assert_eq!(param.nrow, param.iq + 3 * param.nqtriples);
    }

    #[test]
    fn pad_size_logw_zero() {
        // A layer with logw=0 contributes 4*0 + 3 = 3
        use crate::circuit::Layer;
        use crate::field::fp256::Fp256;

        let circuit: Circuit<Fp256> = Circuit {
            nv: 1,
            logv: 0,
            nc: 1,
            logc: 0,
            nl: 1,
            ninputs: 10,
            npub_in: 5,
            subfield_boundary: 0,
            layers: vec![Layer {
                nw: 1,
                logw: 0,
                quads: vec![],
            }],
            constants: vec![],
            id: [0u8; 32],
        };

        assert_eq!(pad_size(&circuit), 3);
    }

    #[test]
    fn pad_size_various_logw() {
        use crate::circuit::Layer;
        use crate::field::fp256::Fp256;

        let circuit: Circuit<Fp256> = Circuit {
            nv: 1,
            logv: 0,
            nc: 1,
            logc: 0,
            nl: 3,
            ninputs: 100,
            npub_in: 10,
            subfield_boundary: 0,
            layers: vec![
                Layer { nw: 1, logw: 0, quads: vec![] },
                Layer { nw: 1, logw: 5, quads: vec![] },
                Layer { nw: 1, logw: 10, quads: vec![] },
            ],
            constants: vec![],
            id: [0u8; 32],
        };

        // (4*0+3) + (4*5+3) + (4*10+3) = 3 + 23 + 43 = 69
        assert_eq!(pad_size(&circuit), 69);
    }
}
