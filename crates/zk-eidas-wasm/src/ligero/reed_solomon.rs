use crate::field::Field;

/// Precomputed Lagrange interpolation data for a given block size.
/// Build once per `ligero_verify` call and reuse across all checks.
pub struct RsPrecomp<F: Field> {
    pub positions: Vec<F::Elt>,
    pub inv_denoms: Vec<F::Elt>,
}

impl<F: Field> RsPrecomp<F> {
    /// Build precomputed data for block-size `block`.
    /// Cost: O(block^2) field multiplications + 1 inversion.
    pub fn new(block: usize, f: &F) -> Self {
        let positions: Vec<F::Elt> = (0..block).map(|i| f.of_scalar(i as u64)).collect();

        // Compute denominators: denom[i] = prod_{j!=i} (pos[i] - pos[j])
        #[cfg(feature = "parallel")]
        let denoms = {
            use rayon::prelude::*;
            (0..block)
                .into_par_iter()
                .map(|i| {
                    let f = f.clone();
                    let mut denom = f.one();
                    for j in 0..block {
                        if i != j {
                            let diff = f.sub(&positions[i], &positions[j]);
                            denom = f.mul(&denom, &diff);
                        }
                    }
                    denom
                })
                .collect::<Vec<_>>()
        };

        #[cfg(not(feature = "parallel"))]
        let denoms = {
            let mut denoms = Vec::with_capacity(block);
            for i in 0..block {
                let mut denom = f.one();
                for j in 0..block {
                    if i != j {
                        let diff = f.sub(&positions[i], &positions[j]);
                        denom = f.mul(&denom, &diff);
                    }
                }
                denoms.push(denom);
            }
            denoms
        };

        // Batch inversion using Montgomery's trick:
        // 1 inversion + 3*(block-1) multiplications instead of `block` inversions.
        let inv_denoms = batch_invert(&denoms, f);

        Self {
            positions,
            inv_denoms,
        }
    }
}

/// Batch-invert a slice of field elements using Montgomery's trick.
/// Returns inv[i] = 1/elts[i] for each element.
/// Cost: 1 inversion + 3*(n-1) multiplications.
pub fn batch_invert<F: Field>(elts: &[F::Elt], f: &F) -> Vec<F::Elt> {
    let n = elts.len();
    if n == 0 {
        return vec![];
    }
    if n == 1 {
        return vec![f.invert(&elts[0])];
    }

    // Forward pass: acc[i] = elts[0] * elts[1] * ... * elts[i]
    let mut acc = Vec::with_capacity(n);
    acc.push(elts[0]);
    for i in 1..n {
        acc.push(f.mul(&acc[i - 1], &elts[i]));
    }

    // Single inversion of the total product
    let mut inv = f.invert(&acc[n - 1]);

    // Backward pass: recover individual inverses
    let mut result = vec![f.zero(); n];
    for i in (1..n).rev() {
        // result[i] = inv * acc[i-1] = (1 / (elts[i]*...*elts[n-1])) * (elts[0]*...*elts[i-1])
        //           = 1 / elts[i]  (after we've already peeled off elts[i+1..n-1])
        result[i] = f.mul(&inv, &acc[i - 1]);
        inv = f.mul(&inv, &elts[i]);
    }
    result[0] = inv;

    result
}

/// Reed-Solomon interpolation: given evaluations at systematic positions
/// 0..block-1, evaluate the polynomial at the given target indices.
///
/// Uses direct Lagrange interpolation: for each target index t,
///   f(t) = sum_i evals[i] * L_i(t)
/// where L_i is the Lagrange basis polynomial:
///   L_i(t) = prod_{j!=i} (t - j) / (i - j)
///
/// Performance: O(block^2) precomputation + O(block * nreq) evaluation.
/// For block ~ 200-400 and nreq ~ 132 this is well within WASM bounds.
pub fn interpolate_at_indices<F: Field>(
    evals: &[F::Elt],
    indices: &[usize],
    f: &F,
) -> Vec<F::Elt> {
    let precomp = RsPrecomp::new(evals.len(), f);
    interpolate_with_precomp(evals, indices, &precomp, f)
}

/// Interpolate using precomputed Lagrange data. Use this when calling
/// multiple times with the same block size to avoid redundant work.
pub fn interpolate_with_precomp<F: Field>(
    evals: &[F::Elt],
    indices: &[usize],
    precomp: &RsPrecomp<F>,
    f: &F,
) -> Vec<F::Elt> {
    let block = evals.len();
    let mut results = Vec::with_capacity(indices.len());

    // Pre-allocate scratch buffers once, reuse across all target indices.
    let mut t_minus_j = vec![f.zero(); block];
    let mut left = vec![f.zero(); block];
    let mut right = vec![f.zero(); block];

    for &idx in indices {
        // If t is one of the systematic positions, return the evaluation directly
        if idx < block {
            results.push(evals[idx]);
            continue;
        }

        let t = f.of_scalar(idx as u64);

        // Compute (t - pos[j]) for all j.
        for j in 0..block {
            t_minus_j[j] = f.sub(&t, &precomp.positions[j]);
        }

        // Prefix products: left[i] = prod_{j<i} (t-j)
        let mut acc = f.one();
        for j in 0..block {
            left[j] = acc;
            acc = f.mul(&acc, &t_minus_j[j]);
        }

        // Suffix products: right[i] = prod_{j>i} (t-j)
        acc = f.one();
        for j in (0..block).rev() {
            right[j] = acc;
            acc = f.mul(&acc, &t_minus_j[j]);
        }

        let mut result = f.zero();
        for i in 0..block {
            let numerator = f.mul(&left[i], &right[i]);
            let basis = f.mul(&numerator, &precomp.inv_denoms[i]);
            result = f.add(&result, &f.mul(&evals[i], &basis));
        }

        results.push(result);
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{fp256::Fp256, gf2_128::Gf2_128, Field};

    #[test]
    fn interpolate_identity_at_systematic() {
        let f = Fp256;
        let evals: Vec<_> = (0..4).map(|i| f.of_scalar(i)).collect();
        let results = interpolate_at_indices(&evals, &[0, 1, 2, 3], &f);
        for i in 0..4 {
            assert_eq!(results[i], f.of_scalar(i as u64));
        }
    }

    #[test]
    fn interpolate_constant() {
        let f = Fp256;
        let evals = vec![f.of_scalar(42); 4];
        let results = interpolate_at_indices(&evals, &[4, 5, 6, 100], &f);
        for r in results {
            assert_eq!(r, f.of_scalar(42));
        }
    }

    #[test]
    fn interpolate_linear() {
        // f(x) = 2x + 1, evals at 0,1,2,3 = [1, 3, 5, 7]
        let f = Fp256;
        let evals = vec![
            f.of_scalar(1),
            f.of_scalar(3),
            f.of_scalar(5),
            f.of_scalar(7),
        ];
        let results = interpolate_at_indices(&evals, &[4, 10], &f);
        assert_eq!(results[0], f.of_scalar(9)); // 2*4 + 1
        assert_eq!(results[1], f.of_scalar(21)); // 2*10 + 1
    }

    #[test]
    fn interpolate_quadratic() {
        // f(x) = x^2, evals at 0,1,2 = [0, 1, 4]
        let f = Fp256;
        let evals = vec![f.of_scalar(0), f.of_scalar(1), f.of_scalar(4)];
        let results = interpolate_at_indices(&evals, &[3, 5], &f);
        assert_eq!(results[0], f.of_scalar(9)); // 3^2
        assert_eq!(results[1], f.of_scalar(25)); // 5^2
    }

    #[test]
    fn interpolate_gf2_128_constant() {
        let f = Gf2_128;
        let evals = vec![f.of_scalar(0xFF); 4];
        let results = interpolate_at_indices(&evals, &[4, 5, 100], &f);
        for r in results {
            assert_eq!(r, f.of_scalar(0xFF));
        }
    }

    #[test]
    fn interpolate_mixed_systematic_and_extension() {
        // f(x) = 3x + 7, evals at 0,1,2 = [7, 10, 13]
        let f = Fp256;
        let evals = vec![f.of_scalar(7), f.of_scalar(10), f.of_scalar(13)];
        let results = interpolate_at_indices(&evals, &[0, 2, 4], &f);
        assert_eq!(results[0], f.of_scalar(7)); // systematic
        assert_eq!(results[1], f.of_scalar(13)); // systematic
        assert_eq!(results[2], f.of_scalar(19)); // 3*4 + 7
    }

    #[test]
    fn interpolate_single_point() {
        // Constant polynomial with single evaluation
        let f = Fp256;
        let evals = vec![f.of_scalar(99)];
        let results = interpolate_at_indices(&evals, &[0, 1, 50], &f);
        assert_eq!(results[0], f.of_scalar(99));
        assert_eq!(results[1], f.of_scalar(99));
        assert_eq!(results[2], f.of_scalar(99));
    }

    #[test]
    fn interpolate_cubic() {
        // f(x) = x^3, evals at 0,1,2,3 = [0, 1, 8, 27]
        let f = Fp256;
        let evals = vec![
            f.of_scalar(0),
            f.of_scalar(1),
            f.of_scalar(8),
            f.of_scalar(27),
        ];
        let results = interpolate_at_indices(&evals, &[4, 5], &f);
        assert_eq!(results[0], f.of_scalar(64)); // 4^3
        assert_eq!(results[1], f.of_scalar(125)); // 5^3
    }
}
