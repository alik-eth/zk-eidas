//! Longfellow-shaped witness (scaffolding — populated in Step 1 / Task 1).

use zk_eidas_p7s::P7sWitness;

#[derive(Debug, Clone)]
pub struct Witness {
    inner: P7sWitness,
}

impl Witness {
    pub fn new(inner: P7sWitness) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &P7sWitness {
        &self.inner
    }
}
