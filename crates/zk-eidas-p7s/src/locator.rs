//! Byte-offset locator for JSON fields inside the signed content.
//!
//! The signed content in a QKB document is a JSON object with a fixed
//! schema. Rather than run a JSON parser inside the ZK circuit, we
//! locate each field we care about by pattern-matching the UTF-8 bytes.

/// Locate a hex-encoded field of the form `"<key>":"0x<chars>"`.
///
/// Returns `(start, expected_len)` where `start` points to the first
/// hex character (after `"0x`). `expected_hex_chars` is the length
/// the field must have; if the actual field is shorter, returns None.
pub(crate) fn locate_hex_field(
    json: &[u8],
    key: &[u8],
    expected_hex_chars: usize,
) -> Option<(usize, usize)> {
    let prefix = key_prefix_hex(key);
    let start_relative = find_subslice(json, &prefix)?;
    let body_start = start_relative + prefix.len();
    if body_start + expected_hex_chars > json.len() {
        return None;
    }
    // Sanity check: all chars are hex
    let body = &json[body_start..body_start + expected_hex_chars];
    if !body.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some((body_start, expected_hex_chars))
}

/// Locate a plain string field of the form `"<key>":"<text>"`.
/// Returns `(start, len)` of the text body (excluding the surrounding quotes).
pub(crate) fn locate_string_field(json: &[u8], key: &[u8]) -> Option<(usize, usize)> {
    let prefix = key_prefix_string(key);
    let start_relative = find_subslice(json, &prefix)?;
    let body_start = start_relative + prefix.len();
    let rel_end = json[body_start..].iter().position(|&b| b == b'"')?;
    Some((body_start, rel_end))
}

/// Build `"<key>":"0x` as a byte sequence.
fn key_prefix_hex(key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(key.len() + 8);
    v.push(b'"');
    v.extend_from_slice(key);
    v.extend_from_slice(b"\":\"0x");
    v
}

/// Build `"<key>":"` as a byte sequence.
fn key_prefix_string(key: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(key.len() + 5);
    v.push(b'"');
    v.extend_from_slice(key);
    v.extend_from_slice(b"\":\"");
    v
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = br#"{"pk":"0xdeadbeef","nonce":"0xcafe","context":"0x","scheme":"secp256k1"}"#;

    #[test]
    fn finds_pk_hex() {
        let (start, len) = locate_hex_field(SAMPLE, b"pk", 8).unwrap();
        assert_eq!(&SAMPLE[start..start + len], b"deadbeef");
    }

    #[test]
    fn finds_nonce_hex() {
        let (start, len) = locate_hex_field(SAMPLE, b"nonce", 4).unwrap();
        assert_eq!(&SAMPLE[start..start + len], b"cafe");
    }

    #[test]
    fn finds_context_string() {
        let (start, len) = locate_string_field(SAMPLE, b"context").unwrap();
        assert_eq!(&SAMPLE[start..start + len], b"0x");
    }

    #[test]
    fn missing_key_returns_none() {
        assert!(locate_hex_field(SAMPLE, b"missing", 8).is_none());
        assert!(locate_string_field(SAMPLE, b"missing").is_none());
    }
}
