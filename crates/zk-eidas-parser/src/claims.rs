use zk_eidas_types::credential::ClaimValue;

pub fn json_to_claim_value(value: &serde_json::Value) -> Option<ClaimValue> {
    match value {
        serde_json::Value::Number(n) => n.as_i64().map(ClaimValue::Integer),
        serde_json::Value::Bool(b) => Some(ClaimValue::Boolean(*b)),
        serde_json::Value::String(s) => {
            if let Some(date) = try_parse_date(s) {
                Some(date)
            } else {
                Some(ClaimValue::String(s.clone()))
            }
        }
        _ => None,
    }
}

fn try_parse_date(s: &str) -> Option<ClaimValue> {
    let parts: Vec<&str> = s.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    let year: u16 = parts[0].parse().ok()?;
    let month: u8 = parts[1].parse().ok()?;
    let day: u8 = parts[2].parse().ok()?;
    if (1..=12).contains(&month) && (1..=31).contains(&day) && year >= 1900 {
        Some(ClaimValue::Date { year, month, day })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn integer_claim() {
        assert_eq!(
            json_to_claim_value(&json!(42)),
            Some(ClaimValue::Integer(42))
        );
    }

    #[test]
    fn negative_integer() {
        assert_eq!(
            json_to_claim_value(&json!(-5)),
            Some(ClaimValue::Integer(-5))
        );
    }

    #[test]
    fn boolean_true() {
        assert_eq!(
            json_to_claim_value(&json!(true)),
            Some(ClaimValue::Boolean(true))
        );
    }

    #[test]
    fn boolean_false() {
        assert_eq!(
            json_to_claim_value(&json!(false)),
            Some(ClaimValue::Boolean(false))
        );
    }

    #[test]
    fn plain_string() {
        assert_eq!(
            json_to_claim_value(&json!("hello")),
            Some(ClaimValue::String("hello".into()))
        );
    }

    #[test]
    fn date_string_parsed() {
        assert_eq!(
            json_to_claim_value(&json!("1990-05-15")),
            Some(ClaimValue::Date {
                year: 1990,
                month: 5,
                day: 15
            })
        );
    }

    #[test]
    fn invalid_date_treated_as_string() {
        assert_eq!(
            json_to_claim_value(&json!("not-a-date")),
            Some(ClaimValue::String("not-a-date".into()))
        );
    }

    #[test]
    fn date_with_invalid_month_treated_as_string() {
        assert_eq!(
            json_to_claim_value(&json!("2000-13-01")),
            Some(ClaimValue::String("2000-13-01".into()))
        );
    }

    #[test]
    fn null_returns_none() {
        assert_eq!(json_to_claim_value(&json!(null)), None);
    }

    #[test]
    fn array_returns_none() {
        assert_eq!(json_to_claim_value(&json!([1, 2, 3])), None);
    }

    #[test]
    fn object_returns_none() {
        assert_eq!(json_to_claim_value(&json!({"nested": true})), None);
    }
}
