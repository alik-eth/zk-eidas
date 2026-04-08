//! Sumcheck verifier constraints and helpers.
//!
//! Faithfully ports the C++ `ZkCommon::verifier_constraints`, `PadLayout`,
//! `Expression`, `ConstraintBuilder`, EQ helpers (`filleq`, `raw_eq2`), and
//! `bind_quad` from `vendor/longfellow-zk/lib/zk/zk_common.h`.

use crate::circuit::Circuit;
use crate::field::Field;
use crate::ligero::{LinearConstraint, QuadraticConstraint};
use crate::proof::LayerProof;
use crate::transcript::Transcript;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const K_MAX_BINDINGS: usize = 40;

// ---------------------------------------------------------------------------
// PadLayout
// ---------------------------------------------------------------------------

/// Layout of padding elements in the witness for one circuit layer.
///
/// Mirrors C++ `ZkCommon::PadLayout`.
pub struct PadLayout {
    logw: usize,
}

impl PadLayout {
    pub fn new(logw: usize) -> Self {
        Self { logw }
    }

    // -- Indexing without overlap (relative to poly_pad(0,0)) --

    /// Index of poly pad element at round `r`, evaluation point `point`.
    /// `point` must be 0 or 2.
    pub fn poly_pad(&self, r: usize, point: usize) -> usize {
        debug_assert!(point == 0 || point == 2);
        if point == 0 {
            2 * r
        } else {
            2 * r + 1
        }
    }

    /// Index of claim pad element `n` (0, 1, or 2).
    pub fn claim_pad(&self, n: usize) -> usize {
        self.poly_pad(2 * self.logw, 0) + n
    }

    /// Total number of padding elements for this layer.
    pub fn layer_size(&self) -> usize {
        self.claim_pad(3)
    }

    // -- Indexing with overlap (includes previous layer's claim pad) --

    /// Index of previous layer's claim pad element `n`.
    pub fn ovp_claim_pad_m1(&self, n: usize) -> usize {
        n
    }

    /// Index of poly pad with overlap offset.
    pub fn ovp_poly_pad(&self, r: usize, point: usize) -> usize {
        3 + self.poly_pad(r, point)
    }

    /// Index of current layer's claim pad with overlap offset.
    pub fn ovp_claim_pad(&self, n: usize) -> usize {
        3 + self.claim_pad(n)
    }

    /// Total size of the overlapping layout.
    pub fn ovp_layer_size(&self) -> usize {
        self.ovp_claim_pad(3)
    }
}

// ---------------------------------------------------------------------------
// Expression
// ---------------------------------------------------------------------------

/// Symbolic expression: KNOWN + SUM_i SYMBOLIC[i] * dX[i]
struct Expression<F: Field> {
    known: F::Elt,
    symbolic: Vec<F::Elt>,
}

impl<F: Field> Expression<F> {
    fn new(nvar: usize, f: &F) -> Self {
        Self {
            known: f.zero(),
            symbolic: vec![f.zero(); nvar],
        }
    }

    /// self += k * (known_value + witness[var])
    fn axpy(&mut self, var: usize, known_value: &F::Elt, k: &F::Elt, f: &F) {
        self.known = f.add(&self.known, &f.mul(k, known_value));
        self.symbolic[var] = f.add(&self.symbolic[var], k);
    }

    /// self -= k * (known_value + witness[var])
    fn axmy(&mut self, var: usize, known_value: &F::Elt, k: &F::Elt, f: &F) {
        self.known = f.sub(&self.known, &f.mul(k, known_value));
        self.symbolic[var] = f.sub(&self.symbolic[var], k);
    }

    /// self *= k (scale both known and symbolic parts)
    fn scale(&mut self, k: &F::Elt, f: &F) {
        self.known = f.mul(&self.known, k);
        for s in &mut self.symbolic {
            *s = f.mul(s, k);
        }
    }
}

// ---------------------------------------------------------------------------
// ConstraintBuilder
// ---------------------------------------------------------------------------

/// Builds Ligero linear constraints from the sumcheck protocol.
///
/// Mirrors C++ `ZkCommon::ConstraintBuilder`.
struct ConstraintBuilder<F: Field> {
    expr: Expression<F>,
    pl: PadLayout,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> ConstraintBuilder<F> {
    fn new(pl: PadLayout, f: &F) -> Self {
        let sz = pl.ovp_layer_size();
        Self {
            expr: Expression::new(sz, f),
            pl,
            _marker: std::marker::PhantomData,
        }
    }

    /// Initialize: claim_{-1} = claims[0] + alpha * claims[1]
    fn first(&mut self, alpha: &F::Elt, claims: &[F::Elt; 2], f: &F) {
        let one = f.one();
        self.expr
            .axpy(self.pl.ovp_claim_pad_m1(0), &claims[0], &one, f);
        self.expr
            .axpy(self.pl.ovp_claim_pad_m1(1), &claims[1], alpha, f);
    }

    /// Given claim_{r-1} in expr, compute claim_{r}
    fn next(&mut self, r: usize, lag: &[F::Elt; 3], tr: &[F::Elt], f: &F) {
        let one = f.one();
        // expr = claim_{r-1} - p_r(0) => this is p_r(1)
        self.expr
            .axmy(self.pl.ovp_poly_pad(r, 0), &tr[0], &one, f);

        // claim_r = lag[1] * p_r(1) + lag[0] * p_r(0) + lag[2] * p_r(2)
        self.expr.scale(&lag[1], f);
        self.expr
            .axpy(self.pl.ovp_poly_pad(r, 0), &tr[0], &lag[0], f);
        self.expr
            .axpy(self.pl.ovp_poly_pad(r, 2), &tr[2], &lag[2], f);
    }

    /// Emit the Ligero linear constraint for this layer.
    fn finalize(
        &mut self,
        wc: &[F::Elt; 2],
        eqq: &F::Elt,
        ci: usize,
        ly: usize,
        pi: usize,
        a: &mut Vec<LinearConstraint<F::Elt>>,
        b: &mut Vec<F::Elt>,
        f: &F,
    ) {
        // RHS = eqq * wc[0] * wc[1] - known
        let rhs = f.sub(&f.mul(eqq, &f.mul(&wc[0], &wc[1])), &self.expr.known);

        // LHS = symbolic (clone)
        let mut lhs = self.expr.symbolic.clone();
        // Subtract quadratic constraint terms
        lhs[self.pl.ovp_claim_pad(0)] =
            f.sub(&lhs[self.pl.ovp_claim_pad(0)], &f.mul(eqq, &wc[1]));
        lhs[self.pl.ovp_claim_pad(1)] =
            f.sub(&lhs[self.pl.ovp_claim_pad(1)], &f.mul(eqq, &wc[0]));
        lhs[self.pl.ovp_claim_pad(2)] = f.sub(&lhs[self.pl.ovp_claim_pad(2)], eqq);

        b.push(rhs);

        // Layer 0 does not refer to CLAIM_PAD[layer - 1]
        let i0 = if ly == 0 {
            self.pl.ovp_poly_pad(0, 0)
        } else {
            self.pl.ovp_claim_pad_m1(0)
        };

        for i in i0..lhs.len() {
            // Map from overlap frame to global witness index.
            // In the C++ code: a.push_back(Llc{ci, (pi + i) - pl_.ovp_poly_pad(0, 0), lhs[i]})
            let w = (pi + i) - self.pl.ovp_poly_pad(0, 0);
            a.push(LinearConstraint {
                c: ci,
                w,
                k: lhs[i],
            });
        }
    }
}

// ---------------------------------------------------------------------------
// EQ helpers
// ---------------------------------------------------------------------------

/// Compute eq[i] = EQ(Q, i) for all i in [0, n).
///
/// Mirrors C++ `Eqs::filleq`.
pub fn filleq<F: Field>(logn: usize, n: usize, q: &[F::Elt], f: &F) -> Vec<F::Elt> {
    assert!(n > 0, "filleq: n must be > 0");
    let mut eq = vec![f.zero(); n];
    eq[0] = f.one();

    let mut l = logn;
    while l > 0 {
        l -= 1;
        let nl = ceilshr(n, l);
        let mut i = ceilshr(nl, 1);

        // Special case: don't write eq[2*i+1] if it would overflow
        if 2 * i - 1 >= nl {
            i -= 1;
            let v = eq[i];
            let qv = f.mul(&q[l], &v);
            eq[2 * i] = f.sub(&v, &qv);
        }

        while i > 0 {
            i -= 1;
            let v = eq[i];
            let qv = f.mul(&q[l], &v);
            eq[2 * i] = f.sub(&v, &qv);
            eq[2 * i + 1] = qv;
        }
    }

    eq
}

/// Compute eq[i] = EQ(G0, i) + alpha * EQ(G1, i) for all i in [0, n).
///
/// Mirrors C++ `Eqs::raw_eq2`.
pub fn raw_eq2<F: Field>(
    logn: usize,
    n: usize,
    g0: &[F::Elt],
    g1: &[F::Elt],
    alpha: &F::Elt,
    f: &F,
) -> Vec<F::Elt> {
    let mut eq = vec![f.zero(); n];
    fill_recursive(&mut eq, logn, n, g0, g1, &f.one(), alpha, f);
    eq
}

fn fill_recursive<F: Field>(
    eq: &mut [F::Elt],
    l: usize,
    n: usize,
    g0: &[F::Elt],
    g1: &[F::Elt],
    w0: &F::Elt,
    w1: &F::Elt,
    f: &F,
) {
    if l > 0 {
        let nl = l - 1;
        let s = 1usize << nl;
        let w0hi = f.mul(w0, &g0[nl]);
        let w1hi = f.mul(w1, &g1[nl]);
        let w0lo = f.sub(w0, &w0hi);
        let w1lo = f.sub(w1, &w1hi);
        if n <= s {
            fill_recursive(eq, nl, n, g0, g1, &w0lo, &w1lo, f);
        } else {
            fill_recursive(&mut eq[..s], nl, s, g0, g1, &w0lo, &w1lo, f);
            fill_recursive(&mut eq[s..], nl, n - s, g0, g1, &w0hi, &w1hi, f);
        }
    } else {
        eq[0] = f.add(w0, w1);
    }
}

/// EQ evaluation for copy variables.
///
/// Mirrors C++ `Eq::eval`. When logc=0, this returns F.one().
pub fn eq_eval<F: Field>(
    logn: usize,
    n: usize,
    i_vals: &[F::Elt],
    j_vals: &[F::Elt],
    f: &F,
) -> F::Elt {
    let mut a = f.one();
    let mut b = f.one();
    let mut nn = n;
    let one = f.one();

    for round in 0..logn {
        let i1 = &i_vals[round];
        let j1 = &j_vals[round];
        let i0 = f.sub(&one, i1);
        let j0 = f.sub(&one, j1);
        let i0j0 = f.mul(&i0, &j0);
        let i1j1 = f.mul(i1, j1);

        if (nn & 1) == 0 {
            b = f.add(&f.mul(&b, &i1j1), &f.mul(&a, &i0j0));
        } else {
            b = f.mul(&b, &i0j0);
        }
        a = f.mul(&a, &f.add(&i0j0, &i1j1));
        nn = (nn + 1) / 2;
    }
    b
}

fn ceilshr(a: usize, n: usize) -> usize {
    1 + ((a - 1) >> n)
}

// ---------------------------------------------------------------------------
// Lagrange coefficients
// ---------------------------------------------------------------------------

/// Compute Lagrange coefficients for a degree-2 polynomial evaluated at
/// points 0, 1, 2, at challenge point r.
///
/// Compute Lagrange interpolation coefficients for a degree-2 polynomial
/// evaluated at the field's 3 evaluation points: x0=of_scalar(0)=0,
/// x1=of_scalar(1)=1, x2=of_scalar(2).
///
/// lag[k] = prod_{j!=k} (r - x_j) / (x_k - x_j)
///
/// For Fp (prime fields), x2=2 and the formulas simplify to:
///   lag[0] = (r-1)(r-2)/2, lag[1] = -r(r-2), lag[2] = r(r-1)/2
/// For GF(2^128), x2=g (subfield generator) and the denominators differ.
pub fn lagrange_coefs_3<F: Field>(r: &F::Elt, f: &F) -> [F::Elt; 3] {
    let x0 = f.zero();
    let x1 = f.one();
    let x2 = f.of_scalar(2);

    let r_m0 = f.sub(r, &x0); // = r
    let r_m1 = f.sub(r, &x1);
    let r_m2 = f.sub(r, &x2);

    // Denominators: d_k = prod_{j!=k} (x_k - x_j)
    let d0 = f.mul(&f.sub(&x0, &x1), &f.sub(&x0, &x2)); // (0-1)(0-x2)
    let d1 = f.mul(&f.sub(&x1, &x0), &f.sub(&x1, &x2)); // (1-0)(1-x2)
    let d2 = f.mul(&f.sub(&x2, &x0), &f.sub(&x2, &x1)); // (x2-0)(x2-1)

    let inv_d0 = f.invert(&d0);
    let inv_d1 = f.invert(&d1);
    let inv_d2 = f.invert(&d2);

    let l0 = f.mul(&f.mul(&r_m1, &r_m2), &inv_d0);
    let l1 = f.mul(&f.mul(&r_m0, &r_m2), &inv_d1);
    let l2 = f.mul(&f.mul(&r_m0, &r_m1), &inv_d2);

    [l0, l1, l2]
}

// ---------------------------------------------------------------------------
// bind_quad
// ---------------------------------------------------------------------------

/// Evaluate the quadratic constraints at the challenge points.
///
/// Mirrors C++ `ZkCommon::bind_quad` -> `Quad::bind_gh_all`.
fn bind_quad<F: Field>(
    layer: &crate::circuit::Layer,
    constants: &[F::Elt],
    logv: usize,
    g0: &[F::Elt],
    g1: &[F::Elt],
    alpha: &F::Elt,
    beta: &F::Elt,
    logw: usize,
    hb0: &[F::Elt],
    hb1: &[F::Elt],
    f: &F,
) -> F::Elt {
    let nv = 1usize << logv;
    let eqg = raw_eq2(logv, nv, g0, g1, alpha, f);

    let nw = 1usize << logw;
    let eqh0 = filleq(logw, nw, hb0, f);
    let eqh1 = filleq(logw, nw, hb1, f);

    let mut s = f.zero();
    for qt in &layer.quads {
        let v = &constants[qt.v_idx];
        let dot = &eqg[qt.g];
        let q = prep_v(v, dot, beta, f);
        let q = f.mul(&q, &eqh0[qt.h[0]]);
        let q = f.mul(&q, &eqh1[qt.h[1]]);
        s = f.add(&s, &q);
    }
    s
}

/// Helper: if v == 0, return beta * dot; else return v * dot.
fn prep_v<F: Field>(v: &F::Elt, dot: &F::Elt, beta: &F::Elt, f: &F) -> F::Elt {
    if *v == f.zero() {
        f.mul(beta, dot)
    } else {
        f.mul(v, dot)
    }
}

// ---------------------------------------------------------------------------
// input_constraint
// ---------------------------------------------------------------------------

/// Add the input binding constraint to the Ligero system.
///
/// Mirrors C++ `ZkCommon::input_constraint`.
fn input_constraint<F: Field>(
    logv: usize,
    g0: &[F::Elt],
    g1: &[F::Elt],
    pub_inputs: &[F::Elt],
    npub_in: usize,
    ninputs: usize,
    pi: usize,
    got: &F::Elt,
    alpha: &F::Elt,
    a: &mut Vec<LinearConstraint<F::Elt>>,
    b: &mut Vec<F::Elt>,
    ci: usize,
    f: &F,
) -> usize {
    let eq0 = filleq(logv, ninputs, g0, f);
    let eq1 = filleq(logv, ninputs, g1, f);

    let mut pub_binding = f.zero();
    for i in 0..ninputs {
        let b_i = f.add(&eq0[i], &f.mul(alpha, &eq1[i]));
        if i < npub_in {
            pub_binding = f.add(&pub_binding, &f.mul(&b_i, &pub_inputs[i]));
        } else {
            // Private input: use (i - npub_in) for witness index
            a.push(LinearConstraint {
                c: ci,
                w: i - npub_in,
                k: b_i,
            });
        }
    }

    // Fake layer with logw=0 for claim pad arithmetic
    let pl = PadLayout::new(0);

    let claim_pad_m1 = pi - pl.ovp_poly_pad(0, 0);
    let mone = f.neg(&f.one());
    a.push(LinearConstraint {
        c: ci,
        w: claim_pad_m1,
        k: mone,
    });
    a.push(LinearConstraint {
        c: ci,
        w: claim_pad_m1 + 1,
        k: f.neg(alpha),
    });
    b.push(f.sub(got, &pub_binding));

    ci + 1
}

// ---------------------------------------------------------------------------
// pad_size
// ---------------------------------------------------------------------------

/// Compute the total witness padding across all layers.
///
/// Mirrors C++ `ZkCommon::pad_size`. Equivalent to `crate::proof::pad_size`.
pub fn pad_size<F: Field>(circuit: &Circuit<F>) -> usize {
    let mut sz = 0;
    for layer in &circuit.layers {
        let pl = PadLayout::new(layer.logw);
        sz += pl.layer_size();
    }
    sz
}

// ---------------------------------------------------------------------------
// initialize_sumcheck_fiat_shamir
// ---------------------------------------------------------------------------

/// Append public parameters to the Fiat-Shamir transcript.
///
/// Mirrors C++ `ZkCommon::initialize_sumcheck_fiat_shamir`.
pub fn initialize_sumcheck_fiat_shamir<F: Field>(
    ts: &mut Transcript,
    circuit: &Circuit<F>,
    pub_inputs: &[F::Elt],
    f: &F,
) {
    // Circuit ID (32 bytes)
    ts.write_bytes(&circuit.id);

    // Public inputs
    for i in 0..circuit.npub_in {
        ts.write_field_elt::<F>(&pub_inputs[i], f);
    }

    // Output pro-forma: zero
    ts.write_field_elt::<F>(&f.zero(), f);

    // Correlation intractability padding: one zero byte per quad term
    ts.write_zeros(circuit.nterms());
}

// ---------------------------------------------------------------------------
// setup_lqc
// ---------------------------------------------------------------------------

/// Set up quadratic constraints from the circuit pad layout.
///
/// Mirrors C++ `ZkCommon::setup_lqc`.
pub fn setup_lqc<F: Field>(
    circuit: &Circuit<F>,
    n_witness: usize,
) -> Vec<QuadraticConstraint> {
    let mut lqc = Vec::with_capacity(circuit.nl);
    let mut pi = n_witness;
    for i in 0..circuit.nl {
        let pl = PadLayout::new(circuit.layers[i].logw);
        lqc.push(QuadraticConstraint {
            x: pi + pl.claim_pad(0),
            y: pi + pl.claim_pad(1),
            z: pi + pl.claim_pad(2),
        });
        pi += pl.layer_size();
    }
    lqc
}

// ---------------------------------------------------------------------------
// verifier_constraints
// ---------------------------------------------------------------------------

/// Derive linear and quadratic constraints from the sumcheck proof.
///
/// Returns `(num_constraints)`. The linear constraints (`a`) and RHS (`b`)
/// are appended to the provided vectors.
///
/// Mirrors C++ `ZkCommon::verifier_constraints`.
pub fn verifier_constraints<F: Field>(
    circuit: &Circuit<F>,
    pub_inputs: &[F::Elt],
    proof: &[LayerProof<F>],
    a: &mut Vec<LinearConstraint<F::Elt>>,
    b: &mut Vec<F::Elt>,
    ts: &mut Transcript,
    mut pi: usize,
    f: &F,
) -> usize {
    assert_eq!(circuit.logc, 0, "assuming copies=1");

    // 1. Generate initial challenges: Q[0..40], G[0..40]
    let q = ts.elt_vec(K_MAX_BINDINGS, f);
    let g = ts.elt_vec(K_MAX_BINDINGS, f);

    // Initial claims (all zero for the root)
    let mut cla_logv = circuit.logv;
    let mut cla_claim = [f.zero(), f.zero()];
    let mut cla_q = q.clone();
    let mut cla_g: [Vec<F::Elt>; 2] = [g.clone(), g.clone()];

    let mut ci = 0usize; // constraint index

    // 2. For each layer
    for ly in 0..circuit.nl {
        let clr = &circuit.layers[ly];
        let plr = &proof[ly];

        // Sample layer challenges
        let alpha = ts.elt(f);
        let beta = ts.elt(f);

        assert!(clr.logw > 0, "layer logw must be > 0");

        let pl = PadLayout::new(clr.logw);
        let mut cb = ConstraintBuilder::new(PadLayout::new(clr.logw), f);

        cb.first(&alpha, &cla_claim, f);

        let mut hb: [Vec<F::Elt>; 2] = [
            vec![f.zero(); K_MAX_BINDINGS],
            vec![f.zero(); K_MAX_BINDINGS],
        ];

        // 3. For each sumcheck round
        for round in 0..clr.logw {
            for hand in 0..2usize {
                let r = 2 * round + hand;
                let hp = &plr.hp[round][hand];

                // Write polynomial to transcript (skip t[1])
                ts.write_field_elt::<F>(&hp.t[0], f);
                ts.write_field_elt::<F>(&hp.t[2], f);
                // Sample challenge
                let challenge = ts.elt(f);
                hb[hand][round] = challenge;

                // Compute Lagrange coefficients at the challenge point
                let lag = lagrange_coefs_3(&challenge, f);

                // Reconstruct t[1] for cb.next: t[1] is not stored, it's
                // implicitly claim - t[0], but cb.next handles this via
                // the axmy step.
                cb.next(r, &lag, &hp.t, f);
            }
        }

        // 4. Compute quad binding
        let quad = bind_quad(
            clr,
            &circuit.constants,
            cla_logv,
            &cla_g[0],
            &cla_g[1],
            &alpha,
            &beta,
            clr.logw,
            &hb[0],
            &hb[1],
            f,
        );

        // EQ evaluation for copies: logc=0, nc=1 => always 1
        // (eq_eval with logn=0 returns F.one())
        let eqv = eq_eval(circuit.logc, circuit.nc, &cla_q, &[], f);
        let eqq = f.mul(&eqv, &quad);

        // 5. Finalize constraint
        cb.finalize(&plr.wc, &eqq, ci, ly, pi, a, b, f);
        ci += 1;

        // Write wc to transcript
        ts.write_field_array::<F>(&plr.wc, 1, 2, f);

        // Update claims for next layer
        cla_logv = clr.logw;
        cla_claim = [plr.wc[0], plr.wc[1]];
        // cb_challenges in C++ is challenge.cb — but logc=0, so no cb challenges.
        // The q in claims is updated to be the cb challenges of this layer.
        // Since logc=0, cb[] is empty/unused, but we need to keep the q vector.
        // Looking at C++ code: claims.q = challenge->cb, but with logc=0 there
        // are no copy rounds, so cb is uninitialized/irrelevant. For Eq::eval
        // with logn=0, the I/J arrays are never accessed.
        cla_q = Vec::new(); // logc=0 means q is unused
        cla_g = [
            hb[0][..clr.logw].to_vec(),
            hb[1][..clr.logw].to_vec(),
        ];

        pi += pl.layer_size();
    }

    // 6. Input binding constraint
    let alpha2 = ts.elt(f);
    let plr = &proof[circuit.nl - 1];
    let got = f.add(&plr.wc[0], &f.mul(&alpha2, &plr.wc[1]));

    input_constraint(
        cla_logv,
        &cla_g[0],
        &cla_g[1],
        pub_inputs,
        circuit.npub_in,
        circuit.ninputs,
        pi,
        &got,
        &alpha2,
        a,
        b,
        ci,
        f,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::fp256::Fp256;
    use crate::field::Field;

    #[test]
    fn pad_layout_sizes() {
        assert_eq!(PadLayout::new(1).layer_size(), 7); // 4*1 + 3
        assert_eq!(PadLayout::new(3).layer_size(), 15); // 4*3 + 3
        assert_eq!(PadLayout::new(0).layer_size(), 3); // 4*0 + 3
    }

    #[test]
    fn pad_layout_overlap_sizes() {
        let pl = PadLayout::new(2);
        // ovp_layer_size = 3 + claim_pad(3) = 3 + (4*2 + 3) = 14
        assert_eq!(pl.ovp_layer_size(), 14);
        assert_eq!(pl.ovp_claim_pad_m1(0), 0);
        assert_eq!(pl.ovp_claim_pad_m1(2), 2);
        assert_eq!(pl.ovp_poly_pad(0, 0), 3);
        assert_eq!(pl.ovp_poly_pad(0, 2), 4);
    }

    #[test]
    fn pad_layout_poly_pad() {
        let pl = PadLayout::new(3);
        assert_eq!(pl.poly_pad(0, 0), 0);
        assert_eq!(pl.poly_pad(0, 2), 1);
        assert_eq!(pl.poly_pad(1, 0), 2);
        assert_eq!(pl.poly_pad(1, 2), 3);
        assert_eq!(pl.poly_pad(5, 0), 10);
        assert_eq!(pl.poly_pad(5, 2), 11);
    }

    #[test]
    fn filleq_basic() {
        let f = Fp256;
        // EQ([r], i) for r=half, i in {0, 1}
        // EQ([r], 0) = 1 - r
        // EQ([r], 1) = r
        let half = f.mul(&f.invert(&f.of_scalar(2)), &f.one());
        let eq = filleq(1, 2, &[half], &f);
        assert_eq!(eq[0], f.sub(&f.one(), &half));
        assert_eq!(eq[1], half);
    }

    #[test]
    fn filleq_two_variables() {
        let f = Fp256;
        let r0 = f.of_scalar(3);
        let r1 = f.of_scalar(5);
        // Q = [r0, r1], EQ(Q, i) where bit 0 of i maps to Q[0]=r0
        // i=0 (b0=0,b1=0): (1-r0)(1-r1)
        // i=1 (b0=1,b1=0): r0*(1-r1)
        // i=2 (b0=0,b1=1): (1-r0)*r1
        // i=3 (b0=1,b1=1): r0*r1
        let eq = filleq(2, 4, &[r0, r1], &f);

        let one = f.one();
        let one_m_r0 = f.sub(&one, &r0);
        let one_m_r1 = f.sub(&one, &r1);
        assert_eq!(eq[0], f.mul(&one_m_r0, &one_m_r1)); // (1-r0)(1-r1)
        assert_eq!(eq[1], f.mul(&r0, &one_m_r1)); // r0*(1-r1)
        assert_eq!(eq[2], f.mul(&one_m_r0, &r1)); // (1-r0)*r1
        assert_eq!(eq[3], f.mul(&r0, &r1)); // r0*r1
    }

    #[test]
    fn raw_eq2_basic() {
        let f = Fp256;
        let g0 = vec![f.of_scalar(2)];
        let g1 = vec![f.of_scalar(3)];
        let alpha = f.of_scalar(5);
        // n=2, logn=1
        // eq[i] = EQ(G0, i) + alpha * EQ(G1, i)
        let eq = raw_eq2(1, 2, &g0, &g1, &alpha, &f);

        // EQ([2], 0) = 1 - 2 = -1
        // EQ([2], 1) = 2
        // EQ([3], 0) = 1 - 3 = -2
        // EQ([3], 1) = 3
        let eq_g0 = filleq(1, 2, &g0, &f);
        let eq_g1 = filleq(1, 2, &g1, &f);
        assert_eq!(eq[0], f.add(&eq_g0[0], &f.mul(&alpha, &eq_g1[0])));
        assert_eq!(eq[1], f.add(&eq_g0[1], &f.mul(&alpha, &eq_g1[1])));
    }

    #[test]
    fn lagrange_coefs_3_at_zero() {
        let f = Fp256;
        let [l0, l1, l2] = lagrange_coefs_3(&f.zero(), &f);
        assert_eq!(l0, f.one());
        assert_eq!(l1, f.zero());
        assert_eq!(l2, f.zero());
    }

    #[test]
    fn lagrange_coefs_3_at_one() {
        let f = Fp256;
        let [l0, l1, l2] = lagrange_coefs_3(&f.one(), &f);
        assert_eq!(l0, f.zero());
        assert_eq!(l1, f.one());
        assert_eq!(l2, f.zero());
    }

    #[test]
    fn lagrange_coefs_3_at_two() {
        let f = Fp256;
        let two = f.of_scalar(2);
        let [l0, l1, l2] = lagrange_coefs_3(&two, &f);
        assert_eq!(l0, f.zero());
        assert_eq!(l1, f.zero());
        assert_eq!(l2, f.one());
    }

    #[test]
    fn lagrange_coefs_3_interpolation() {
        // Verify that sum(lag[i] * p(i)) = p(r) for known polynomial
        let f = Fp256;
        let r = f.of_scalar(7);
        let [l0, l1, l2] = lagrange_coefs_3(&r, &f);

        // p(x) = x^2: p(0)=0, p(1)=1, p(2)=4, p(7)=49
        let p0 = f.zero();
        let p1 = f.one();
        let p2 = f.of_scalar(4);

        let result = f.add(&f.mul(&l0, &p0), &f.add(&f.mul(&l1, &p1), &f.mul(&l2, &p2)));
        assert_eq!(result, f.of_scalar(49));
    }

    #[test]
    fn expression_basic() {
        let f = Fp256;
        let mut expr = Expression::<Fp256>::new(3, &f);

        // axpy(0, 5, 2): known += 2*5=10, symbolic[0] += 2
        expr.axpy(0, &f.of_scalar(5), &f.of_scalar(2), &f);
        assert_eq!(expr.known, f.of_scalar(10));
        assert_eq!(expr.symbolic[0], f.of_scalar(2));

        // axmy(1, 3, 1): known -= 1*3=3, symbolic[1] -= 1
        expr.axmy(1, &f.of_scalar(3), &f.one(), &f);
        assert_eq!(expr.known, f.of_scalar(7)); // 10 - 3
        let mone = f.neg(&f.one());
        assert_eq!(expr.symbolic[1], mone); // 0 - 1

        // scale(4): known *= 4, symbolic *= 4
        expr.scale(&f.of_scalar(4), &f);
        assert_eq!(expr.known, f.of_scalar(28)); // 7 * 4
        assert_eq!(expr.symbolic[0], f.of_scalar(8)); // 2 * 4
        assert_eq!(expr.symbolic[1], f.neg(&f.of_scalar(4))); // -1 * 4
    }

    #[test]
    fn eq_eval_logn_zero() {
        // logn=0, n=1 => loop never runs, returns b=1
        let f = Fp256;
        let result = eq_eval(0, 1, &[], &[], &f);
        assert_eq!(result, f.one());
    }

    #[test]
    fn setup_lqc_basic() {
        use crate::circuit::Layer;

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

        let n_witness = 15; // ninputs - npub_in
        let lqc = setup_lqc(&circuit, n_witness);

        assert_eq!(lqc.len(), 2);

        // Layer 0: logw=2, claim_pad(0)=8, claim_pad(1)=9, claim_pad(2)=10
        let pl0 = PadLayout::new(2);
        assert_eq!(lqc[0].x, n_witness + pl0.claim_pad(0));
        assert_eq!(lqc[0].y, n_witness + pl0.claim_pad(1));
        assert_eq!(lqc[0].z, n_witness + pl0.claim_pad(2));

        // Layer 1: starts at n_witness + pl0.layer_size()
        let pl1 = PadLayout::new(3);
        let offset1 = n_witness + pl0.layer_size();
        assert_eq!(lqc[1].x, offset1 + pl1.claim_pad(0));
        assert_eq!(lqc[1].y, offset1 + pl1.claim_pad(1));
        assert_eq!(lqc[1].z, offset1 + pl1.claim_pad(2));
    }

    #[test]
    fn prep_v_zero() {
        let f = Fp256;
        let zero = f.zero();
        let dot = f.of_scalar(7);
        let beta = f.of_scalar(3);
        // v==0 => beta * dot = 21
        assert_eq!(prep_v(&zero, &dot, &beta, &f), f.of_scalar(21));
    }

    #[test]
    fn prep_v_nonzero() {
        let f = Fp256;
        let v = f.of_scalar(5);
        let dot = f.of_scalar(7);
        let beta = f.of_scalar(3);
        // v!=0 => v * dot = 35
        assert_eq!(prep_v(&v, &dot, &beta, &f), f.of_scalar(35));
    }
}
