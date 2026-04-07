pub mod fp256;
pub mod gf2_128;

/// Field element trait for the Longfellow verifier.
/// All operations are in the field's internal representation
/// (Montgomery for Fp256, polynomial for GF2_128).
pub trait Field: Clone + Send + Sync + 'static {
    type Elt: Clone + Copy + Default + PartialEq + Eq + std::fmt::Debug;

    const BYTES: usize;
    const SUBFIELD_BYTES: usize;
    const BITS: usize;
    const FIELD_ID: u8;

    fn zero(&self) -> Self::Elt;
    fn one(&self) -> Self::Elt;

    fn add(&self, a: &Self::Elt, b: &Self::Elt) -> Self::Elt;
    fn sub(&self, a: &Self::Elt, b: &Self::Elt) -> Self::Elt;
    fn mul(&self, a: &Self::Elt, b: &Self::Elt) -> Self::Elt;
    fn neg(&self, a: &Self::Elt) -> Self::Elt;
    fn invert(&self, a: &Self::Elt) -> Self::Elt;

    fn of_scalar(&self, s: u64) -> Self::Elt;

    /// Deserialize from BYTES bytes (little-endian). Returns None if invalid.
    fn of_bytes(&self, bytes: &[u8]) -> Option<Self::Elt>;

    /// Serialize to BYTES bytes (little-endian, field-canonical form).
    fn to_bytes(&self, elt: &Self::Elt) -> Vec<u8>;

    /// Deserialize from subfield bytes (for run-length decoding).
    fn of_subfield_bytes(&self, bytes: &[u8]) -> Option<Self::Elt>;

    /// Check if an element fits in the subfield.
    fn is_subfield(&self, elt: &Self::Elt) -> bool;
}
