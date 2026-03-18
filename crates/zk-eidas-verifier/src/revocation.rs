/// Errors that can occur during revocation status checks.
#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    /// Failed to fetch or decode the status list.
    #[error("failed to fetch status list: {0}")]
    FetchFailed(String),
    /// The credential index is out of bounds for the given status list.
    #[error("invalid credential index: {0}")]
    InvalidIndex(usize),
}

/// Check if a credential is NOT revoked using a bitfield status list.
///
/// The status list is a byte array where each bit represents one credential.
/// A set bit (1) means the credential at that index is revoked.
///
/// Returns `Ok(true)` if the credential is valid (not revoked),
/// `Ok(false)` if it is revoked, or an error if the index is out of bounds.
pub fn check_revocation_status(
    status_list: &[u8],
    credential_index: usize,
) -> Result<bool, RevocationError> {
    let byte_index = credential_index / 8;
    let bit_index = credential_index % 8;
    if byte_index >= status_list.len() {
        return Err(RevocationError::InvalidIndex(credential_index));
    }
    let is_revoked = (status_list[byte_index] >> bit_index) & 1 == 1;
    Ok(!is_revoked)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_revoked_returns_true() {
        // All zeros = no credentials revoked
        let status = vec![0u8; 4];
        assert!(check_revocation_status(&status, 0).unwrap());
        assert!(check_revocation_status(&status, 15).unwrap());
        assert!(check_revocation_status(&status, 31).unwrap());
    }

    #[test]
    fn revoked_returns_false() {
        // Bit 0 of byte 0 is set = credential 0 is revoked
        let status = vec![0b0000_0001, 0, 0, 0];
        assert!(!check_revocation_status(&status, 0).unwrap());
        // Credential 1 is not revoked
        assert!(check_revocation_status(&status, 1).unwrap());
    }

    #[test]
    fn revoked_bit_in_second_byte() {
        // Bit 2 of byte 1 is set = credential 10 is revoked
        let status = vec![0, 0b0000_0100];
        assert!(!check_revocation_status(&status, 10).unwrap());
        assert!(check_revocation_status(&status, 9).unwrap());
        assert!(check_revocation_status(&status, 11).unwrap());
    }

    #[test]
    fn out_of_bounds_returns_error() {
        let status = vec![0u8; 2]; // 16 credentials max
        let result = check_revocation_status(&status, 16);
        assert!(result.is_err());
        match result.unwrap_err() {
            RevocationError::InvalidIndex(idx) => assert_eq!(idx, 16),
            other => panic!("expected InvalidIndex, got {:?}", other),
        }
    }

    #[test]
    fn empty_status_list() {
        let status: Vec<u8> = vec![];
        assert!(check_revocation_status(&status, 0).is_err());
    }

    #[test]
    fn multiple_revoked() {
        // Credentials 0, 3, 7 revoked
        let status = vec![0b1000_1001];
        assert!(!check_revocation_status(&status, 0).unwrap());
        assert!(check_revocation_status(&status, 1).unwrap());
        assert!(check_revocation_status(&status, 2).unwrap());
        assert!(!check_revocation_status(&status, 3).unwrap());
        assert!(check_revocation_status(&status, 4).unwrap());
        assert!(check_revocation_status(&status, 5).unwrap());
        assert!(check_revocation_status(&status, 6).unwrap());
        assert!(!check_revocation_status(&status, 7).unwrap());
    }
}
