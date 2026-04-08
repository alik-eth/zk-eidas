use crate::field::Field;

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
    let block = evals.len();
    let mut results = Vec::with_capacity(indices.len());

    // Precompute field-element representations of positions 0..block-1
    let positions: Vec<F::Elt> = (0..block).map(|i| f.of_scalar(i as u64)).collect();

    // Precompute inverse denominators: inv_denom[i] = 1 / prod_{j!=i} (pos[i] - pos[j])
    let mut inv_denoms = Vec::with_capacity(block);
    for i in 0..block {
        let mut denom = f.one();
        for j in 0..block {
            if i != j {
                let diff = f.sub(&positions[i], &positions[j]);
                denom = f.mul(&denom, &diff);
            }
        }
        inv_denoms.push(f.invert(&denom));
    }

    for &idx in indices {
        let t = f.of_scalar(idx as u64);

        // If t is one of the systematic positions, return the evaluation directly
        if idx < block {
            results.push(evals[idx]);
            continue;
        }

        // Compute f(t) via Lagrange interpolation.
        // First compute (t - pos[j]) for all j.
        let mut t_minus_j = Vec::with_capacity(block);
        for j in 0..block {
            t_minus_j.push(f.sub(&t, &positions[j]));
        }

        // f(t) = sum_i evals[i] * grand_prod / (t - i) * inv_denom[i]
        // Use prefix/suffix products to avoid per-element inversion:
        //   prod_{j!=i} (t - j) = left[i] * right[i]
        // where left[i] = prod_{j<i} (t-j), right[i] = prod_{j>i} (t-j)
        let mut left = Vec::with_capacity(block);
        let mut acc = f.one();
        for j in 0..block {
            left.push(acc);
            acc = f.mul(&acc, &t_minus_j[j]);
        }

        let mut right = vec![f.one(); block];
        acc = f.one();
        for j in (0..block).rev() {
            right[j] = acc;
            acc = f.mul(&acc, &t_minus_j[j]);
        }

        let mut result = f.zero();
        for i in 0..block {
            // prod_{j!=i} (t - j) = left[i] * right[i]
            let numerator = f.mul(&left[i], &right[i]);
            let basis = f.mul(&numerator, &inv_denoms[i]);
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
