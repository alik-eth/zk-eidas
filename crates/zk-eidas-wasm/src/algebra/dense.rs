use crate::field::Field;

/// Dense vector of field elements (used for public inputs).
pub struct Dense<F: Field> {
    pub data: Vec<F::Elt>,
    pub npub: usize,
}

/// Builder for constructing dense vectors element by element.
pub struct DenseFiller<F: Field> {
    data: Vec<F::Elt>,
    _marker: std::marker::PhantomData<F>,
}

impl<F: Field> DenseFiller<F> {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Push a single field element.
    pub fn push(&mut self, elt: F::Elt) {
        self.data.push(elt);
    }

    /// Push a vector of elements.
    pub fn push_vec(&mut self, elts: Vec<F::Elt>) {
        self.data.extend(elts);
    }

    /// Push a scalar as individual bit elements (LSB first).
    /// Used for encoding lengths and packed values.
    pub fn push_scalar_bits(&mut self, val: usize, nbits: usize, f: &F) {
        for i in 0..nbits {
            if (val >> i) & 1 == 1 {
                self.data.push(f.one());
            } else {
                self.data.push(f.zero());
            }
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Finalize into a Dense vector.
    pub fn into_dense(self, npub: usize) -> Dense<F> {
        Dense {
            data: self.data,
            npub,
        }
    }
}

impl<F: Field> Default for DenseFiller<F> {
    fn default() -> Self {
        Self::new()
    }
}
