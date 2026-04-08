use crate::field::Field;

/// Evaluate the multilinear equality polynomial EQ(x, r).
/// For boolean x: EQ(x, r) = prod_i (r_i * x_i + (1 - r_i) * (1 - x_i))
/// This gives 1 when x == r on the boolean hypercube, 0 otherwise.
pub fn eq_eval<F: Field>(x: &[F::Elt], r: &[F::Elt], f: &F) -> F::Elt {
    assert_eq!(x.len(), r.len());
    let one = f.one();
    let mut result = one;
    for i in 0..x.len() {
        let ri = &r[i];
        let xi = &x[i];
        // term = ri * xi + (1 - ri) * (1 - xi)
        let ri_xi = f.mul(ri, xi);
        let one_minus_ri = f.sub(&one, ri);
        let one_minus_xi = f.sub(&one, xi);
        let term = f.add(&ri_xi, &f.mul(&one_minus_ri, &one_minus_xi));
        result = f.mul(&result, &term);
    }
    result
}

/// Bind one variable of a multilinear extension at value r.
/// Given evaluations over {0,1}^n, produce evaluations over {0,1}^{n-1}
/// by setting the first variable to r.
/// new[i] = old[2*i] * (1-r) + old[2*i+1] * r
pub fn bind_variable<F: Field>(evals: &[F::Elt], r: &F::Elt, f: &F) -> Vec<F::Elt> {
    let half = evals.len() / 2;
    let mut result = Vec::with_capacity(half);
    let one_minus_r = f.sub(&f.one(), r);
    for i in 0..half {
        let lo = f.mul(&evals[2 * i], &one_minus_r);
        let hi = f.mul(&evals[2 * i + 1], r);
        result.push(f.add(&lo, &hi));
    }
    result
}
