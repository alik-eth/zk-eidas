//! Cross-validates our parser's subject serialNumber extraction against
//! an independently-derived KAT vector from the identityescroworg project.
//!
//! The KAT JSON was produced by a TypeScript ASN.1 parser (@peculiar/asn1-schema);
//! our Rust parser (cms + x509-cert crates) must produce identical values.

use serde::Deserialize;
use zk_eidas_p7s::build_witness;

const FIXTURE: &[u8] = include_bytes!("../fixtures/binding.qkb.p7s");
const KAT_JSON: &str = include_str!("../fixtures/kat-subject-serial.json");
const DUMMY_ROOT_PK: [u8; 65] = [0x04; 65];

#[derive(Deserialize)]
struct Kat {
    #[serde(rename = "serialNumberValue")]
    serial_number_value: SerialNumberValue,
}

#[derive(Deserialize)]
struct SerialNumberValue {
    #[serde(rename = "asciiValue")]
    ascii_value: String,
    #[serde(rename = "hexValue")]
    hex_value: String,
    #[serde(rename = "contentLength")]
    content_length: usize,
}

#[test]
fn kat_subject_serial_matches_our_extraction() {
    let kat: Kat = serde_json::from_str(KAT_JSON).expect("parse KAT");
    let witness = build_witness(FIXTURE, b"0x", DUMMY_ROOT_PK).expect("parse");
    let off = &witness.offsets;

    // Content length must match KAT declaration
    assert_eq!(
        off.subject_sn_len,
        kat.serial_number_value.content_length,
        "subject_sn_len mismatch"
    );

    // Content bytes (ASCII) must equal KAT ascii value
    let extracted =
        &witness.p7s_bytes[off.subject_sn_start..off.subject_sn_start + off.subject_sn_len];
    assert_eq!(
        extracted,
        kat.serial_number_value.ascii_value.as_bytes(),
        "subject serialNumber ASCII mismatch"
    );

    // Content bytes hex-encoded must equal KAT hex value
    assert_eq!(
        hex::encode(extracted),
        kat.serial_number_value.hex_value,
        "subject serialNumber hex mismatch"
    );
}
