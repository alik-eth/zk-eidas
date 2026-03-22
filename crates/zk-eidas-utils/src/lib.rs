//! Shared utility functions for the zk-eidas workspace.
//!
//! Currently provides date-to-epoch-days conversion used by both the types
//! crate and the facade builder for age predicate calculations.

/// Convert a date to days since 1970-01-01 (Unix epoch).
///
/// Uses the civil_from_days algorithm. This is the single canonical
/// implementation used by both the types crate and the facade builder.
pub fn date_to_epoch_days(year: u32, month: u32, day: u32) -> i64 {
    let y = if month <= 2 {
        year as i64 - 1
    } else {
        year as i64
    };
    let m = if month <= 2 {
        month as i64 + 9
    } else {
        month as i64 - 3
    };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400) as u64;
    let doy = (153 * m as u64 + 2) / 5 + day as u64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe as i64 - 719468
}

/// Convert days since 1970-01-01 (Unix epoch) to (year, month, day).
///
/// Inverse of [`date_to_epoch_days`]. Uses the civil_from_days algorithm.
pub fn epoch_days_to_ymd(epoch_days: i64) -> (u32, u32, u32) {
    let z = epoch_days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_start() {
        assert_eq!(date_to_epoch_days(1970, 1, 1), 0);
    }

    #[test]
    fn known_date() {
        // 2000-01-15 = 10971 days from epoch
        assert_eq!(date_to_epoch_days(2000, 1, 15), 10971);
    }

    #[test]
    fn leap_year_feb_29() {
        let feb29 = date_to_epoch_days(2024, 2, 29);
        let mar01 = date_to_epoch_days(2024, 3, 1);
        assert_eq!(mar01 - feb29, 1);
    }

    #[test]
    fn end_of_year() {
        let dec31 = date_to_epoch_days(2025, 12, 31);
        let jan01 = date_to_epoch_days(2026, 1, 1);
        assert_eq!(jan01 - dec31, 1);
    }

    #[test]
    fn month_boundaries() {
        let jan31 = date_to_epoch_days(2025, 1, 31);
        let feb01 = date_to_epoch_days(2025, 2, 1);
        assert_eq!(feb01 - jan31, 1);
    }

    #[test]
    fn far_future_date() {
        // 2100 is NOT a leap year (century not divisible by 400)
        let feb28 = date_to_epoch_days(2100, 2, 28);
        let mar01 = date_to_epoch_days(2100, 3, 1);
        assert_eq!(mar01 - feb28, 1);
    }

    #[test]
    fn pre_1970_dates_are_distinct() {
        let d1 = date_to_epoch_days(1960, 1, 1);
        let d2 = date_to_epoch_days(1969, 12, 31);
        assert_ne!(d1, d2, "pre-1970 dates must produce distinct values");
    }

    #[test]
    fn year_2000_is_leap() {
        // 2000 IS a leap year (divisible by 400)
        let feb28 = date_to_epoch_days(2000, 2, 28);
        let feb29 = date_to_epoch_days(2000, 2, 29);
        let mar01 = date_to_epoch_days(2000, 3, 1);
        assert_eq!(feb29 - feb28, 1);
        assert_eq!(mar01 - feb29, 1);
    }

    #[test]
    fn epoch_days_to_ymd_epoch_start() {
        assert_eq!(epoch_days_to_ymd(0), (1970, 1, 1));
    }

    #[test]
    fn epoch_days_to_ymd_known_date() {
        assert_eq!(epoch_days_to_ymd(10971), (2000, 1, 15));
    }

    #[test]
    fn epoch_days_to_ymd_roundtrip() {
        for (y, m, d) in [(1998, 6, 15), (2024, 2, 29), (2100, 3, 1), (1960, 7, 4)] {
            let days = date_to_epoch_days(y, m, d);
            assert_eq!(epoch_days_to_ymd(days), (y, m, d));
        }
    }
}
