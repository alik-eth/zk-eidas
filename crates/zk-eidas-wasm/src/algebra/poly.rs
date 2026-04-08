use crate::field::Field;
use crate::ligero::reed_solomon::batch_invert;

/// Polynomial represented by evaluations at 0, 1, ..., N-1.
#[derive(Clone, Debug)]
pub struct SumcheckPoly<F: Field> {
    pub t: Vec<F::Elt>, // t[i] = p(i)
}

impl<F: Field> SumcheckPoly<F> {
    /// Create from evaluation points.
    pub fn new(evals: Vec<F::Elt>) -> Self {
        Self { t: evals }
    }

    /// Degree of the polynomial (number of evaluation points - 1).
    pub fn degree(&self) -> usize {
        self.t.len() - 1
    }

    /// Evaluate polynomial at challenge point r using Lagrange interpolation.
    /// Points are at 0, 1, ..., N-1.
    pub fn eval(&self, r: &F::Elt, f: &F) -> F::Elt {
        let n = self.t.len();

        // Pre-compute denominators: denom[i] = prod_{j!=i} (i - j)
        let mut denoms = Vec::with_capacity(n);
        for i in 0..n {
            let mut denom = f.one();
            for j in 0..n {
                if i != j {
                    let diff = if i > j {
                        f.of_scalar((i - j) as u64)
                    } else {
                        f.neg(&f.of_scalar((j - i) as u64))
                    };
                    denom = f.mul(&denom, &diff);
                }
            }
            denoms.push(denom);
        }
        let inv_denoms = batch_invert(&denoms, f);

        // Lagrange interpolation: p(r) = sum_i t[i] * inv_denom[i] * prod_{j!=i} (r - j)
        let mut result = f.zero();
        for i in 0..n {
            let mut numerator = f.one();
            for j in 0..n {
                if i != j {
                    let r_minus_j = f.sub(r, &f.of_scalar(j as u64));
                    numerator = f.mul(&numerator, &r_minus_j);
                }
            }
            let term = f.mul(&self.t[i], &f.mul(&numerator, &inv_denoms[i]));
            result = f.add(&result, &term);
        }
        result
    }
}
