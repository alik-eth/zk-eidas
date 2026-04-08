//! ZK Verifier orchestrator.
//!
//! Ports the C++ `ZkVerifier` from `vendor/longfellow-zk/lib/zk/zk_verifier.h`.
//! Coordinates the sumcheck verifier constraints with the Ligero verifier.

use crate::circuit::Circuit;
use crate::field::Field;
use crate::ligero::{self, LinearConstraint, QuadraticConstraint};
use crate::proof::{LigeroParam, ZkProof};
use crate::sumcheck;
use crate::transcript::Transcript;

/// ZK verifier: validates a zero-knowledge proof by deriving sumcheck
/// constraints and delegating to the Ligero verifier.
pub struct ZkVerifier<F: Field> {
    n_witness: usize,
    param: LigeroParam,
    lqc: Vec<QuadraticConstraint>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> ZkVerifier<F> {
    /// Create a new ZK verifier for the given circuit.
    ///
    /// Mirrors C++ `ZkVerifier(circuit, rsf, rate, nreq, block_enc, F)`.
    pub fn new(
        circuit: &Circuit<F>,
        rate: usize,
        nreq: usize,
        block_enc: usize,
    ) -> Self {
        let n_witness = circuit.ninputs - circuit.npub_in;
        let nw = n_witness + sumcheck::pad_size(circuit);
        let nq = circuit.nl;
        let param = LigeroParam::new(nw, nq, rate, nreq, block_enc);
        let lqc = sumcheck::setup_lqc(circuit, n_witness);

        Self {
            n_witness,
            param,
            lqc,
            _marker: std::marker::PhantomData,
        }
    }

    /// Write the Ligero commitment to the transcript.
    pub fn recv_commitment(&self, zk_proof: &ZkProof<F>, ts: &mut Transcript) {
        ligero::write_commitment(&zk_proof.com.root, ts);
    }

    /// Verify the proof.
    ///
    /// Mirrors C++ `ZkVerifier::verify`.
    pub fn verify(
        &self,
        zk_proof: &ZkProof<F>,
        pub_inputs: &[F::Elt],
        ts: &mut Transcript,
        circuit: &Circuit<F>,
        f: &F,
    ) -> bool {
        #[cfg(feature = "timing")]
        let t0 = std::time::Instant::now();

        // 1. Initialize sumcheck Fiat-Shamir transcript
        sumcheck::initialize_sumcheck_fiat_shamir(ts, circuit, pub_inputs, f);

        // 2. Derive constraints on the witness
        let mut a: Vec<LinearConstraint<F::Elt>> = Vec::new();
        let mut b: Vec<F::Elt> = Vec::new();
        let cn = sumcheck::verifier_constraints(
            circuit,
            pub_inputs,
            &zk_proof.proof,
            &mut a,
            &mut b,
            ts,
            self.n_witness,
            f,
        );

        #[cfg(feature = "timing")]
        let t1 = std::time::Instant::now();

        // 3. Ligero verify
        let ok = ligero::ligero_verify(
            &self.param,
            &zk_proof.com,
            &zk_proof.com_proof,
            ts,
            cn,
            &a,
            &b,
            &self.lqc,
            f,
        );

        #[cfg(feature = "timing")]
        {
            let t2 = std::time::Instant::now();
            eprintln!("[timing]   sumcheck: {:?}, ligero: {:?} (field={})", t1 - t0, t2 - t1, F::FIELD_ID);
        }

        ok
    }
}

/// Compute the total witness padding across all layers.
///
/// Re-exports the computation from `proof::pad_size` for use by the ZK verifier.
/// This is a convenience wrapper matching C++ `ZkCommon::pad_size`.
pub fn pad_size<F: Field>(circuit: &Circuit<F>) -> usize {
    crate::proof::pad_size(circuit)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::Layer;
    use crate::field::fp256::Fp256;

    #[test]
    fn zk_verifier_construction() {
        let circuit: Circuit<Fp256> = Circuit {
            nv: 1,
            logv: 0,
            nc: 1,
            logc: 0,
            nl: 2,
            ninputs: 20,
            npub_in: 5,
            subfield_boundary: 0,
            layers: vec![
                Layer {
                    nw: 4,
                    logw: 2,
                    quads: vec![],
                },
                Layer {
                    nw: 8,
                    logw: 3,
                    quads: vec![],
                },
            ],
            constants: vec![],
            id: [0u8; 32],
        };

        let v = ZkVerifier::<Fp256>::new(&circuit, 7, 132, 2945);

        // n_witness = ninputs - npub_in = 15
        assert_eq!(v.n_witness, 15);

        // pad_size = (4*2+3) + (4*3+3) = 11 + 15 = 26
        // nw = 15 + 26 = 41
        assert_eq!(v.param.nw, 41);
        assert_eq!(v.param.nq, 2); // nl = 2

        // lqc should have 2 entries
        assert_eq!(v.lqc.len(), 2);
    }

    #[test]
    fn pad_size_matches_proof() {
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
                nw: 2,
                logw: 1,
                quads: vec![],
            }],
            constants: vec![],
            id: [0u8; 32],
        };

        assert_eq!(pad_size(&circuit), crate::proof::pad_size(&circuit));
    }
}
