//! Ligero verifier: 4-check verification of committed polynomial proofs.
//!
//! The Ligero verifier runs these checks on a proof:
//! 1. **Merkle check** — opened columns match the commitment root
//! 2. **Low-degree test (LDT)** — committed polynomial is low-degree
//! 3. **Dot-product check** — linear constraint satisfaction
//! 4. **Quadratic check** — quadratic constraint satisfaction

pub mod reed_solomon;
pub mod transcript;

// Re-exports
pub use reed_solomon::{batch_invert, interpolate_at_indices, RsPrecomp};
pub use transcript::write_commitment;

use sha2::Digest;

use crate::field::Field;
use crate::merkle::merkle_verify;
use crate::proof::{LigeroCommitment, LigeroParam, LigeroProof};
use crate::transcript::Transcript;

use self::transcript::{
    gen_alphal, gen_alphaq, gen_idx, gen_uldt, gen_uquad, write_llterm_hash, write_y_arrays,
};

// ---------------------------------------------------------------------------
// Constraint types
// ---------------------------------------------------------------------------

/// A[c, w] = k (sparse linear constraint).
pub struct LinearConstraint<E: Copy> {
    /// Constraint index.
    pub c: usize,
    /// Witness index.
    pub w: usize,
    /// Coefficient.
    pub k: E,
}

/// W[z] = W[x] * W[y] (quadratic constraint).
pub struct QuadraticConstraint {
    pub x: usize,
    pub y: usize,
    pub z: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn dot_product<F: Field>(a: &[F::Elt], b: &[F::Elt], f: &F) -> F::Elt {
    a.iter()
        .zip(b.iter())
        .fold(f.zero(), |acc, (ai, bi)| f.add(&acc, &f.mul(ai, bi)))
}

fn sum_elements<F: Field>(elts: &[F::Elt], f: &F) -> F::Elt {
    elts.iter().fold(f.zero(), |acc, e| f.add(&acc, e))
}

/// Interpolate y[0..len] at the extension positions `dblock + idx[i]`.
///
/// The C++ `interpolate_req_columns` evaluates the polynomial defined by
/// `y[0..len]` at positions `dblock + idx[i]` for each opened column.
fn interpolate_at_extension<F: Field>(
    y: &[F::Elt],
    dblock: usize,
    idx: &[usize],
    precomp: &RsPrecomp<F>,
    f: &F,
) -> Vec<F::Elt> {
    let target_positions: Vec<usize> = idx.iter().map(|&i| dblock + i).collect();
    reed_solomon::interpolate_with_precomp(y, &target_positions, precomp, f)
}

// ---------------------------------------------------------------------------
// Individual checks
// ---------------------------------------------------------------------------

/// Merkle check: verify opened columns match the commitment root.
fn merkle_check<F: Field>(
    param: &LigeroParam,
    com: &LigeroCommitment,
    proof: &LigeroProof<F>,
    idx: &[usize],
    f: &F,
) -> bool {
    // Use block_ext directly as the number of leaves (matches C++ MerkleTreeVerifier).
    let n = param.block_ext;

    merkle_verify(
        n,
        &com.root,
        &proof.merkle,
        idx,
        &|col_idx, hasher| {
            // Hash all elements in column col_idx across all rows.
            let mut buf = [0u8; 32]; // max(Fp256::BYTES=32, Gf2::BYTES=16)
            for row in 0..param.nrow {
                let elt = proof.req[row * param.nreq + col_idx];
                f.write_bytes(&elt, &mut buf);
                hasher.update(&buf[..F::BYTES]);
            }
        },
    )
}

/// Low-degree check: verify committed polynomial is low-degree.
fn low_degree_check<F: Field>(
    param: &LigeroParam,
    proof: &LigeroProof<F>,
    idx: &[usize],
    u_ldt: &[F::Elt],
    precomp: &RsPrecomp<F>,
    f: &F,
) -> bool {
    let nreq = param.nreq;

    // yc = blinding row (ildt) + sum_i u_ldt[i] * witness_row[i + iw]
    let mut yc: Vec<F::Elt> = (0..nreq)
        .map(|j| proof.req[param.ildt * nreq + j])
        .collect();

    for i in 0..param.nwqrow {
        for j in 0..nreq {
            let term = f.mul(&u_ldt[i], &proof.req[(i + param.iw) * nreq + j]);
            yc[j] = f.add(&yc[j], &term);
        }
    }

    // Interpolate y_ldt (block evaluations) at extension positions.
    let yp = interpolate_at_extension(&proof.y_ldt, param.dblock, idx, precomp, f);

    yp == yc
}

/// Build the inner-product vector A from linear and quadratic constraints.
fn inner_product_vector<F: Field>(
    param: &LigeroParam,
    _nl: usize,
    linear: &[LinearConstraint<F::Elt>],
    alphal: &[F::Elt],
    quad: &[QuadraticConstraint],
    alphaq: &[[F::Elt; 3]],
    f: &F,
) -> Vec<F::Elt> {
    // A is [nwqrow * w] flattened.
    let mut a = vec![f.zero(); param.nwqrow * param.w];

    // Linear terms: A[term.w] += term.k * alphal[term.c]
    for term in linear {
        let val = f.mul(&term.k, &alphal[term.c]);
        a[term.w] = f.add(&a[term.w], &val);
    }

    // Quadratic routing terms.
    let ax_offset = param.nwrow * param.w;
    let ay_offset = ax_offset + param.nqtriples * param.w;
    let az_offset = ay_offset + param.nqtriples * param.w;

    for i in 0..param.nqtriples {
        for j in 0..param.w {
            let iw = j + i * param.w;
            if iw >= param.nq {
                break;
            }
            let lqc = &quad[iw];

            // Ax[iw] += alphaq[iw][0]; A[lqc.x] -= alphaq[iw][0]
            a[ax_offset + iw] = f.add(&a[ax_offset + iw], &alphaq[iw][0]);
            a[lqc.x] = f.sub(&a[lqc.x], &alphaq[iw][0]);

            // Ay[iw] += alphaq[iw][1]; A[lqc.y] -= alphaq[iw][1]
            a[ay_offset + iw] = f.add(&a[ay_offset + iw], &alphaq[iw][1]);
            a[lqc.y] = f.sub(&a[lqc.y], &alphaq[iw][1]);

            // Az[iw] += alphaq[iw][2]; A[lqc.z] -= alphaq[iw][2]
            a[az_offset + iw] = f.add(&a[az_offset + iw], &alphaq[iw][2]);
            a[lqc.z] = f.sub(&a[lqc.z], &alphaq[iw][2]);
        }
    }

    a
}

/// Dot-product check: verify linear constraint satisfaction.
fn dot_check<F: Field>(
    param: &LigeroParam,
    proof: &LigeroProof<F>,
    idx: &[usize],
    a: &[F::Elt],
    precomp_block: &RsPrecomp<F>,
    precomp_dblock: &RsPrecomp<F>,
    f: &F,
) -> bool {
    let nreq = param.nreq;

    // yc = blinding row (idot)
    let mut yc: Vec<F::Elt> = (0..nreq)
        .map(|j| proof.req[param.idot * nreq + j])
        .collect();

    // Target positions for interpolation (shared across all rows).
    let target_positions: Vec<usize> = idx.iter().map(|&i| param.dblock + i).collect();

    // For each witness+quadratic row i:
    //   Layout A row: [zero(r), A[i*w .. (i+1)*w]]
    //   Interpolate at extension positions
    //   yc += A_interp[j] * W_row[j]
    #[cfg(feature = "parallel")]
    {
        use rayon::prelude::*;

        // Compute all row contributions in parallel, then reduce.
        let row_contributions: Vec<Vec<F::Elt>> = (0..param.nwqrow)
            .into_par_iter()
            .map(|i| {
                let f = f.clone();
                let mut a_block = vec![f.zero(); param.block];
                let a_start = i * param.w;
                let a_end = (a_start + param.w).min(a.len());
                for k in 0..param.w.min(a_end - a_start) {
                    a_block[param.r + k] = a[a_start + k];
                }

                let a_interp = reed_solomon::interpolate_with_precomp(
                    &a_block,
                    &target_positions,
                    precomp_block,
                    &f,
                );

                // Compute a_interp[j] * W_opened[j] for each j
                let mut contrib = vec![f.zero(); nreq];
                for j in 0..nreq {
                    let w_val = proof.req[(i + param.iw) * nreq + j];
                    contrib[j] = f.mul(&a_interp[j], &w_val);
                }
                contrib
            })
            .collect();

        // Sum all contributions into yc
        for contrib in &row_contributions {
            for j in 0..nreq {
                yc[j] = f.add(&yc[j], &contrib[j]);
            }
        }
    }

    #[cfg(not(feature = "parallel"))]
    {
        let mut a_block = vec![f.zero(); param.block];
        for i in 0..param.nwqrow {
            for v in a_block.iter_mut() {
                *v = f.zero();
            }
            let a_start = i * param.w;
            let a_end = (a_start + param.w).min(a.len());
            for k in 0..param.w.min(a_end - a_start) {
                a_block[param.r + k] = a[a_start + k];
            }

            let a_interp = reed_solomon::interpolate_with_precomp(
                &a_block,
                &target_positions,
                precomp_block,
                f,
            );

            for j in 0..nreq {
                let w_val = proof.req[(i + param.iw) * nreq + j];
                let term = f.mul(&a_interp[j], &w_val);
                yc[j] = f.add(&yc[j], &term);
            }
        }
    }

    // Interpolate y_dot (dblock evaluations) at extension positions.
    let yp = interpolate_at_extension(&proof.y_dot, param.dblock, idx, precomp_dblock, f);

    yp == yc
}

/// Quadratic check: verify quadratic constraint satisfaction.
fn quadratic_check<F: Field>(
    param: &LigeroParam,
    proof: &LigeroProof<F>,
    idx: &[usize],
    u_quad: &[F::Elt],
    precomp: &RsPrecomp<F>,
    f: &F,
) -> bool {
    let nreq = param.nreq;

    // yc = blinding row (iquad)
    let mut yc: Vec<F::Elt> = (0..nreq)
        .map(|j| proof.req[param.iquad * nreq + j])
        .collect();

    let iqx = param.iq;
    let iqy = iqx + param.nqtriples;
    let iqz = iqy + param.nqtriples;

    for i in 0..param.nqtriples {
        for j in 0..nreq {
            // tmp = z[i][j] - x[i][j] * y[i][j]
            let z = proof.req[(iqz + i) * nreq + j];
            let x = proof.req[(iqx + i) * nreq + j];
            let y = proof.req[(iqy + i) * nreq + j];
            let xy = f.mul(&x, &y);
            let tmp = f.sub(&z, &xy);

            // yc[j] += u_quad[i] * tmp
            let term = f.mul(&u_quad[i], &tmp);
            yc[j] = f.add(&yc[j], &term);
        }
    }

    // Reconstruct y_quad from two parts.
    let mut yquad = vec![f.zero(); param.dblock];
    yquad[..param.r].copy_from_slice(&proof.y_quad_0);
    // yquad[r..block] stays zero (the w zeros)
    let yq2_len = param.dblock - param.block;
    yquad[param.block..param.block + yq2_len].copy_from_slice(&proof.y_quad_2);

    // Interpolate y_quad at extension positions.
    let yp = interpolate_at_extension(&yquad, param.dblock, idx, precomp, f);

    yp == yc
}

// ---------------------------------------------------------------------------
// Main verifier
// ---------------------------------------------------------------------------

/// Verify a Ligero proof: Merkle check, LDT, dot-product, quadratic.
///
/// Returns `true` if all 4 checks pass.
pub fn ligero_verify<F: Field>(
    param: &LigeroParam,
    com: &LigeroCommitment,
    proof: &LigeroProof<F>,
    ts: &mut Transcript,
    nl: usize,
    linear: &[LinearConstraint<F::Elt>],
    b: &[F::Elt],
    quad: &[QuadraticConstraint],
    f: &F,
) -> bool {
    // 1. Generate challenges in exact order.
    let hash_of_llterm: [u8; 32] = [
        0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0,
    ];
    write_llterm_hash(ts, &hash_of_llterm);

    let u_ldt = gen_uldt(ts, param.nwqrow, f);
    let alphal = gen_alphal(ts, nl, f);
    let alphaq = gen_alphaq(ts, param.nq, f);
    let u_quad = gen_uquad(ts, param.nqtriples, f);

    // Write proof values to transcript.
    write_y_arrays::<F>(
        ts,
        &proof.y_ldt,
        &proof.y_dot,
        &proof.y_quad_0,
        &proof.y_quad_2,
        f,
    );

    // Generate column indices.
    let idx = gen_idx(ts, param.block_ext, param.nreq);

    // Precompute Lagrange interpolation data once for all checks.
    // block-size precomp: used for A-matrix interpolation in dot_check.
    // dblock-size precomp: used for y_ldt, y_dot, y_quad interpolation.
    #[cfg(feature = "timing")]
    let tp0 = std::time::Instant::now();

    let precomp_block = RsPrecomp::new(param.block, f);
    let precomp_dblock = RsPrecomp::new(param.dblock, f);

    #[cfg(feature = "timing")]
    let tp1 = std::time::Instant::now();

    // 2. Merkle check.
    if !merkle_check(param, com, proof, &idx, f) {
        return false;
    }

    #[cfg(feature = "timing")]
    let tp2 = std::time::Instant::now();

    // 3. Low-degree check (y_ldt has param.block elements).
    if !low_degree_check(param, proof, &idx, &u_ldt, &precomp_block, f) {
        return false;
    }

    #[cfg(feature = "timing")]
    let tp3 = std::time::Instant::now();

    // 4. Dot-product check (includes inner product value verification).
    let a_matrix = inner_product_vector(param, nl, linear, &alphal, quad, &alphaq, f);
    if !dot_check(param, proof, &idx, &a_matrix, &precomp_block, &precomp_dblock, f) {
        return false;
    }

    // Verify dot product value: sum(b[i] * alphal[i]) == sum(y_dot[r..r+w]).
    let want_dot = dot_product::<F>(b, &alphal, f);
    let proof_dot = sum_elements::<F>(&proof.y_dot[param.r..param.r + param.w], f);
    if want_dot != proof_dot {
        return false;
    }

    #[cfg(feature = "timing")]
    let tp4 = std::time::Instant::now();

    // 5. Quadratic check.
    if !quadratic_check(param, proof, &idx, &u_quad, &precomp_dblock, f) {
        return false;
    }

    #[cfg(feature = "timing")]
    {
        let tp5 = std::time::Instant::now();
        eprintln!("[timing]     precomp: {:?}, merkle: {:?}, ldt: {:?}, dot: {:?}, quad: {:?}",
            tp1 - tp0, tp2 - tp1, tp3 - tp2, tp4 - tp3, tp5 - tp4);
    }

    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fp256::Fp256;

    #[test]
    fn dot_product_basic() {
        let f = Fp256;
        let a = vec![f.of_scalar(2), f.of_scalar(3)];
        let b = vec![f.of_scalar(4), f.of_scalar(5)];
        assert_eq!(dot_product::<Fp256>(&a, &b, &f), f.of_scalar(23)); // 2*4 + 3*5 = 23
    }

    #[test]
    fn dot_product_empty() {
        let f = Fp256;
        assert_eq!(dot_product::<Fp256>(&[], &[], &f), f.zero());
    }

    #[test]
    fn dot_product_single() {
        let f = Fp256;
        let a = vec![f.of_scalar(7)];
        let b = vec![f.of_scalar(11)];
        assert_eq!(dot_product::<Fp256>(&a, &b, &f), f.of_scalar(77));
    }

    #[test]
    fn sum_elements_basic() {
        let f = Fp256;
        let elts = vec![f.of_scalar(1), f.of_scalar(2), f.of_scalar(3)];
        assert_eq!(sum_elements::<Fp256>(&elts, &f), f.of_scalar(6));
    }

    #[test]
    fn sum_elements_empty() {
        let f = Fp256;
        assert_eq!(sum_elements::<Fp256>(&[], &f), f.zero());
    }

    #[test]
    fn sum_elements_single() {
        let f = Fp256;
        let elts = vec![f.of_scalar(42)];
        assert_eq!(sum_elements::<Fp256>(&elts, &f), f.of_scalar(42));
    }

    #[test]
    fn constraint_types_compile() {
        let f = Fp256;
        let _lc = LinearConstraint {
            c: 0,
            w: 1,
            k: f.of_scalar(5),
        };
        let _qc = QuadraticConstraint {
            x: 0,
            y: 1,
            z: 2,
        };
    }

    #[test]
    fn inner_product_vector_linear_only() {
        let f = Fp256;
        // Minimal param: 2 witness elements, 0 quadratic constraints.
        let param = LigeroParam::new(2, 0, 7, 1, 28);

        let linear = vec![
            LinearConstraint {
                c: 0,
                w: 0,
                k: f.of_scalar(3),
            },
            LinearConstraint {
                c: 0,
                w: 1,
                k: f.of_scalar(5),
            },
        ];
        let alphal = vec![f.of_scalar(2)];
        let quad: Vec<QuadraticConstraint> = vec![];
        let alphaq: Vec<[<Fp256 as Field>::Elt; 3]> = vec![];

        let a = inner_product_vector(&param, 1, &linear, &alphal, &quad, &alphaq, &f);

        // A[0] = 3 * 2 = 6, A[1] = 5 * 2 = 10
        assert_eq!(a[0], f.of_scalar(6));
        assert_eq!(a[1], f.of_scalar(10));
    }

    #[test]
    fn interpolate_at_extension_constant() {
        let f = Fp256;
        // Constant polynomial: all evals = 42.
        let evals = vec![f.of_scalar(42); 4];
        let dblock = 7; // 2*4-1
        let idx = vec![0, 1, 2];
        let precomp = RsPrecomp::new(evals.len(), &f);
        let result = interpolate_at_extension(&evals, dblock, &idx, &precomp, &f);
        // A constant polynomial evaluates to 42 everywhere.
        for r in result {
            assert_eq!(r, f.of_scalar(42));
        }
    }
}
