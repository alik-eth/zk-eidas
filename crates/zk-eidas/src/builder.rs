/// High-level predicate for the builder API.
pub enum Predicate {
    /// Greater-than-or-equal comparison (for numeric/date claims).
    Gte(i64),
    /// Less-than-or-equal comparison (for numeric/date claims).
    Lte(i64),
    /// Equality check (for string/numeric/boolean/date claims).
    Eq(String),
    /// Not-equal check.
    Neq(String),
    /// Range check: low <= claim <= high (for numeric/date claims).
    Range(i64, i64),
    /// Set membership check (claim must match one of the given values).
    SetMember(Vec<String>),
    /// Logical AND over multiple sub-predicates.
    And(Vec<Predicate>),
    /// Logical OR over multiple sub-predicates.
    Or(Vec<Predicate>),
}

impl Predicate {
    /// Create a greater-than-or-equal predicate.
    pub fn gte(threshold: i64) -> Self {
        Predicate::Gte(threshold)
    }
    /// Create a less-than-or-equal predicate.
    pub fn lte(threshold: i64) -> Self {
        Predicate::Lte(threshold)
    }
    /// Create an equality predicate.
    pub fn eq(value: impl Into<String>) -> Self {
        Predicate::Eq(value.into())
    }
    /// Create a not-equal predicate.
    pub fn neq(value: impl Into<String>) -> Self {
        Predicate::Neq(value.into())
    }
    /// Create a range predicate.
    pub fn range(low: i64, high: i64) -> Self {
        Predicate::Range(low, high)
    }
    /// Create a set membership predicate.
    pub fn set_member(values: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Predicate::SetMember(values.into_iter().map(|v| v.into()).collect())
    }
}

/// Compute the epoch-days cutoff for an age threshold from a specific date.
pub fn age_cutoff_epoch_days_from(min_age: u32, year: u32, month: u32, day: u32) -> u64 {
    let cutoff_year = year.saturating_sub(min_age);
    let days = zk_eidas_utils::date_to_epoch_days(cutoff_year, month, day);
    days.max(0) as u64
}

/// Unified error type for the facade crate.
#[derive(Debug, thiserror::Error)]
pub enum ZkError {
    /// The requested claim was not found in the credential.
    #[error("claim not found: {0}")]
    ClaimNotFound(String),
    /// Invalid input for identity escrow or other operations.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// The system clock returned a time before the Unix epoch.
    #[error("system clock before Unix epoch")]
    SystemClockError,
}
