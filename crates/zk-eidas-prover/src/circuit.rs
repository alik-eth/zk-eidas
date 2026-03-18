use std::path::{Path, PathBuf};
use zk_eidas_types::predicate::PredicateOp;

/// Errors that can occur when loading compiled Circom circuit files.
#[derive(Debug, thiserror::Error)]
pub enum CircuitError {
    /// The expected circuit artifact file does not exist on disk.
    #[error("circuit file not found: {0}")]
    NotFound(PathBuf),
    /// An I/O error occurred while reading circuit files.
    #[error("failed to read circuit: {0}")]
    IoError(#[from] std::io::Error),
}

/// Paths to compiled Circom circuit artifacts for a single circuit.
#[derive(Debug, Clone)]
pub struct CircuitArtifacts {
    pub r1cs_path: PathBuf,
    pub wasm_path: PathBuf,
    pub zkey_path: PathBuf,
    pub vk_json_path: PathBuf,
}

/// Loads compiled Circom circuit artifacts from a base directory.
///
/// Expected directory layout:
/// ```text
/// <base_path>/
///   gte/
///     gte.r1cs
///     gte_js/gte.wasm
///     gte.zkey
///   lte/
///     lte.r1cs
///     lte_js/lte.wasm
///     lte.zkey
///   ecdsa_verify/
///     ecdsa_verify.r1cs
///     ecdsa_verify_js/ecdsa_verify.wasm
///     ecdsa_verify.zkey
///   ...
/// ```
pub struct CircuitLoader {
    base_path: PathBuf,
}

impl CircuitLoader {
    /// Create a loader that reads circuits from the given base directory.
    pub fn new(base_path: impl AsRef<Path>) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }

    /// Returns the base path where circuits are stored.
    pub fn base_path(&self) -> &Path {
        &self.base_path
    }

    /// Loads the paths to compiled Circom circuit artifacts for a given predicate operation.
    ///
    /// Maps each `PredicateOp` to its circuit directory name and returns paths to
    /// the `.r1cs`, `.wasm` (witness generator), and `.zkey` (proving key) files.
    pub fn load(&self, op: PredicateOp) -> Result<CircuitArtifacts, CircuitError> {
        let name = match op {
            PredicateOp::Ecdsa => "ecdsa_verify",
            PredicateOp::Gte => "gte",
            PredicateOp::Lte => "lte",
            PredicateOp::Eq => "eq",
            PredicateOp::Neq => "neq",
            PredicateOp::Range => "range",
            PredicateOp::SetMember => "set_member",
            PredicateOp::Nullifier => "nullifier",
            PredicateOp::HolderBinding => "holder_binding",
        };

        let dir = self.base_path.join(name);
        let r1cs_path = dir.join(format!("{name}.r1cs"));
        let wasm_path = dir.join(format!("{name}_js/{name}.wasm"));
        let zkey_path = dir.join(format!("{name}.zkey"));
        let vk_json_path = dir.join("vk.json");

        // Check that the essential files exist
        if !r1cs_path.exists() {
            return Err(CircuitError::NotFound(r1cs_path));
        }
        if !wasm_path.exists() {
            return Err(CircuitError::NotFound(wasm_path));
        }
        if !zkey_path.exists() {
            return Err(CircuitError::NotFound(zkey_path));
        }
        if !vk_json_path.exists() {
            return Err(CircuitError::NotFound(vk_json_path));
        }

        Ok(CircuitArtifacts {
            r1cs_path,
            wasm_path,
            zkey_path,
            vk_json_path,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_returns_not_found_for_missing_circuit() {
        let loader = CircuitLoader::new("/nonexistent");
        let result = loader.load(PredicateOp::Gte);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn circuit_name_mapping() {
        let loader = CircuitLoader::new("/tmp/circuits");

        // Verify the paths are constructed correctly (they won't exist, but we can
        // check the error message contains the expected path components)
        let ops_and_names = [
            (PredicateOp::Ecdsa, "ecdsa_verify"),
            (PredicateOp::Gte, "gte"),
            (PredicateOp::Lte, "lte"),
            (PredicateOp::Eq, "eq"),
            (PredicateOp::Neq, "neq"),
            (PredicateOp::Range, "range"),
            (PredicateOp::SetMember, "set_member"),
            (PredicateOp::Nullifier, "nullifier"),
            (PredicateOp::HolderBinding, "holder_binding"),
        ];

        for (op, expected_name) in ops_and_names {
            let err = loader.load(op).unwrap_err().to_string();
            assert!(
                err.contains(expected_name),
                "Expected error to contain '{expected_name}' for {op:?}, got: {err}"
            );
        }
    }
}
