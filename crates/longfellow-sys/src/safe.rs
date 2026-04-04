//! Safe Rust wrappers for Longfellow FFI types.

use crate::*;

/// Verification type for attribute predicates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyType {
    /// Attribute value must equal the provided value (default).
    Eq = 0,
    /// Attribute value <= provided value (lexicographic).
    /// For age proofs: birth_date <= cutoff_date means age >= N.
    Leq = 1,
    /// Attribute value >= provided value (lexicographic).
    Geq = 2,
    /// Attribute value != provided value.
    Neq = 3,
}

/// Safe wrapper for circuit generation.
pub fn gen_circuit(spec_index: usize) -> Result<Vec<u8>, String> {
    unsafe {
        let base = kZkSpecs.as_ptr();
        let spec = base.add(spec_index);

        let mut circuit: *mut u8 = std::ptr::null_mut();
        let mut circuit_len: std::os::raw::c_ulong = 0;

        let ret = generate_circuit(spec, &mut circuit, &mut circuit_len);
        if ret != CircuitGenerationErrorCode_CIRCUIT_GENERATION_SUCCESS {
            return Err(format!("generate_circuit failed: {ret}"));
        }

        let bytes = std::slice::from_raw_parts(circuit, circuit_len as usize).to_vec();
        libc::free(circuit as *mut libc::c_void);
        Ok(bytes)
    }
}

/// Build a RequestedAttribute for the prover/verifier.
pub fn make_attribute(
    namespace: &str,
    id: &str,
    cbor_value: &[u8],
    verify_type: VerifyType,
) -> RequestedAttribute {
    let mut attr: RequestedAttribute = unsafe { std::mem::zeroed() };

    let ns_bytes = namespace.as_bytes();
    let ns_len = ns_bytes.len().min(64);
    attr.namespace_id[..ns_len].copy_from_slice(&ns_bytes[..ns_len]);
    attr.namespace_len = ns_len as std::os::raw::c_ulong;

    let id_bytes = id.as_bytes();
    let id_len = id_bytes.len().min(32);
    attr.id[..id_len].copy_from_slice(&id_bytes[..id_len]);
    attr.id_len = id_len as std::os::raw::c_ulong;

    let val_len = cbor_value.len().min(64);
    attr.cbor_value[..val_len].copy_from_slice(&cbor_value[..val_len]);
    attr.cbor_value_len = val_len as std::os::raw::c_ulong;

    attr.verification_type = verify_type as u8;

    attr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn make_attribute_eq() {
        let attr = make_attribute(
            "org.iso.18013.5.1",
            "age_over_18",
            &[0xf5], // CBOR true
            VerifyType::Eq,
        );
        assert_eq!(attr.namespace_len, 17);
        assert_eq!(attr.id_len, 11);
        assert_eq!(attr.cbor_value_len, 1);
        assert_eq!(attr.verification_type, 0);
    }

    #[test]
    fn make_attribute_leq() {
        let attr = make_attribute(
            "org.iso.18013.5.1",
            "birth_date",
            b"\x6a2008-01-01", // CBOR text string "2008-01-01"
            VerifyType::Leq,
        );
        assert_eq!(attr.verification_type, 1);
    }

    #[test]
    fn gen_circuit_spec0() {
        let circuit = gen_circuit(0).expect("circuit generation failed");
        assert!(!circuit.is_empty());
        // Compressed circuit should be ~300KB
        assert!(circuit.len() > 100_000);
    }
}
