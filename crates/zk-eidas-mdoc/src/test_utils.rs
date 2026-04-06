//! Test utilities for building synthetic ECDSA-signed mdoc credentials.
//!
//! Produces bytes compatible with Google Longfellow's `ParsedMdoc::parse_device_response()`
//! C++ parser, following the ISO 18013-5 DeviceResponse structure.

use ciborium::Value;
use sha2::{Digest, Sha256};
use zk_eidas_types::credential::ClaimValue;

/// CBOR-encode a ciborium Value to bytes.
fn cbor_encode(val: &Value) -> Vec<u8> {
    let mut buf = Vec::new();
    ciborium::into_writer(val, &mut buf).expect("CBOR encoding failed");
    buf
}

/// Build a CBOR Tag(24, bstr(inner_bytes)) — the "encoded CBOR data item" tag.
fn tag24_wrap(inner_bytes: &[u8]) -> Value {
    Value::Tag(24, Box::new(Value::Bytes(inner_bytes.to_vec())))
}

/// Build CBOR Tag(0, text) for tdate encoding.
fn tdate(date_str: &str) -> Value {
    Value::Tag(0, Box::new(Value::Text(date_str.to_string())))
}

/// Build the COSE protected header for ES256: {1: -7} = A1 01 26.
fn es256_protected_header_bytes() -> Vec<u8> {
    // {1: -7} in CBOR = A1 01 26
    cbor_encode(&Value::Map(vec![(
        Value::Integer(1.into()),
        Value::Integer((-7_i64).into()),
    )]))
}

/// Build the COSE Sig_structure for the **issuer** signature:
/// `["Signature1", protected_bytes, "", payload]`
///
/// Uses hand-crafted CBOR to match Longfellow's `kCose1Prefix` constant,
/// which hardcodes a 2-byte bstr length (0x59) for the payload slot.
fn issuer_sig_structure(protected_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    // Match kCose1Prefix from mdoc_constants.h:
    //   84              array(4)
    //   6A "Signature1" text(10)
    //   43 A1 01 26     bstr(3) = protected header {1: -7}
    //   40              bstr(0) = external_aad
    //   59 XX XX ...    bstr with 2-byte length = payload
    let mut buf = Vec::new();
    buf.push(0x84); // array(4)
    buf.push(0x6A); // text(10)
    buf.extend_from_slice(b"Signature1");
    // protected header as bstr
    append_cbor_bstr(&mut buf, protected_bytes);
    // external_aad = empty bstr
    buf.push(0x40);
    // payload — always use 2-byte length (0x59) to match C++ kCose1Prefix
    let plen = payload.len();
    buf.push(0x59);
    buf.push((plen >> 8) as u8);
    buf.push((plen & 0xFF) as u8);
    buf.extend_from_slice(payload);
    buf
}

/// Build the COSE Sig_structure for the **device** signature:
/// `["Signature1", protected_bytes, "", DeviceAuthenticationBytes]`
///
/// Uses hand-crafted CBOR matching `compute_transcript_hash` in
/// `mdoc_witness.h`, which uses `append_bytes_len` (correct minimal CBOR)
/// for the payload slot.
fn device_sig_structure(protected_bytes: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(0x84); // array(4)
    buf.push(0x6A); // text(10)
    buf.extend_from_slice(b"Signature1");
    // protected header as bstr
    append_cbor_bstr(&mut buf, protected_bytes);
    // external_aad = empty bstr
    buf.push(0x40);
    // payload — use correct minimal CBOR encoding (matching C++ append_bytes_len)
    append_cbor_bstr(&mut buf, payload);
    buf
}

/// Encode a bstr with the correct minimal-length CBOR header.
fn append_cbor_bstr(buf: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len < 24 {
        buf.push(0x40 + len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
    buf.extend_from_slice(data);
}

/// Build a synthetic mdoc with real ECDSA (ES256/P-256) signatures, compatible
/// with Google Longfellow's `ParsedMdoc::parse_device_response()` C++ parser.
///
/// The output follows the ISO 18013-5 DeviceResponse structure:
/// ```text
/// Root Map {
///   "documents": Array [
///     Map {
///       "docType": "org.iso.18013.5.1.mDL",
///       "issuerSigned": Map {
///         "issuerAuth": COSE_Sign1 array [protected, unprotected, payload, signature],
///         "nameSpaces": Map { "org.iso.18013.5.1": Array [ Tag(24, item_bytes), ... ] }
///       },
///       "deviceSigned": Map {
///         "deviceAuth": Map {
///           "deviceSignature": COSE_Sign1 array [protected, unprotected, payload, signature]
///         }
///       }
///     }
///   ]
/// }
/// ```
///
/// The device signature is computed over the DeviceAuthentication structure
/// as defined in ISO 18013-5 §9.1.3.6, matching the `compute_transcript_hash`
/// logic in Longfellow's `mdoc_witness.h`.
///
/// Returns `(mdoc_cbor_bytes, issuer_pub_key_x, issuer_pub_key_y)`.
pub fn build_ecdsa_signed_mdoc(
    claims: Vec<(&str, ClaimValue)>,
    _issuer: &str,
) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    build_ecdsa_signed_mdoc_with_transcript(claims, _issuer, b"zk-eidas-demo")
}

/// Same as [`build_ecdsa_signed_mdoc`] but with an explicit session transcript.
pub fn build_ecdsa_signed_mdoc_with_transcript(
    claims: Vec<(&str, ClaimValue)>,
    _issuer: &str,
    transcript: &[u8],
) -> (Vec<u8>, [u8; 32], [u8; 32]) {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand::rngs::OsRng;

    // ── Step 1: Generate issuer P-256 keypair ──────────────────────────
    let issuer_sk = SigningKey::random(&mut OsRng);
    let issuer_vk = issuer_sk.verifying_key();
    let issuer_point = issuer_vk.to_encoded_point(false);
    let pub_key_x: [u8; 32] = issuer_point.x().unwrap().as_slice().try_into().unwrap();
    let pub_key_y: [u8; 32] = issuer_point.y().unwrap().as_slice().try_into().unwrap();

    // ── Step 2: Generate device P-256 keypair ──────────────────────────
    let device_sk = SigningKey::random(&mut OsRng);
    let device_vk = device_sk.verifying_key();
    let device_point = device_vk.to_encoded_point(false);
    let device_pub_x: [u8; 32] = device_point.x().unwrap().as_slice().try_into().unwrap();
    let device_pub_y: [u8; 32] = device_point.y().unwrap().as_slice().try_into().unwrap();

    // ── Step 3: Build IssuerSignedItems, Tag-24 wrap, compute digests ──
    let mut tagged_items = Vec::new();
    let mut value_digests_entries = Vec::new();

    for (i, (name, val)) in claims.iter().enumerate() {
        let random_salt = vec![i as u8; 16]; // deterministic salt for testing
        let cbor_value = claim_to_cbor(val);

        let item = Value::Map(vec![
            (
                Value::Text("digestID".into()),
                Value::Integer((i as i64).into()),
            ),
            (Value::Text("random".into()), Value::Bytes(random_salt)),
            (
                Value::Text("elementIdentifier".into()),
                Value::Text(name.to_string()),
            ),
            (Value::Text("elementValue".into()), cbor_value),
        ]);

        // CBOR-encode the IssuerSignedItem
        let item_bytes = cbor_encode(&item);

        // Wrap in Tag 24 (encoded CBOR data item) as required by ISO 18013-5
        let tagged = tag24_wrap(&item_bytes);
        let tagged_bytes = cbor_encode(&tagged);

        // SHA-256 digest of the Tag(24)-wrapped bytes.
        // The C++ circuit hashes the full tagged item (D8 18 58 XX <content>),
        // NOT just the inner content.
        let digest: [u8; 32] = Sha256::digest(&tagged_bytes).into();
        value_digests_entries.push((
            Value::Integer((i as i64).into()),
            Value::Bytes(digest.to_vec()),
        ));

        tagged_items.push(tagged);
    }

    // ── Step 4: Build MSO (Mobile Security Object) ─────────────────────
    let mso = Value::Map(vec![
        (Value::Text("version".into()), Value::Text("1.0".into())),
        (
            Value::Text("digestAlgorithm".into()),
            Value::Text("SHA-256".into()),
        ),
        (
            Value::Text("validityInfo".into()),
            Value::Map(vec![
                (
                    Value::Text("validFrom".into()),
                    tdate("2024-01-01T00:00:00Z"),
                ),
                (
                    Value::Text("validUntil".into()),
                    tdate("2030-01-01T00:00:00Z"),
                ),
            ]),
        ),
        (
            Value::Text("deviceKeyInfo".into()),
            Value::Map(vec![(
                Value::Text("deviceKey".into()),
                Value::Map(vec![
                    // COSE_Key format with negative integer keys
                    (Value::Integer(1.into()), Value::Integer(2.into())),   // kty: EC2
                    (Value::Integer((-1_i64).into()), Value::Integer(1.into())), // crv: P-256
                    (
                        Value::Integer((-2_i64).into()),
                        Value::Bytes(device_pub_x.to_vec()),
                    ), // x
                    (
                        Value::Integer((-3_i64).into()),
                        Value::Bytes(device_pub_y.to_vec()),
                    ), // y
                ]),
            )]),
        ),
        (
            Value::Text("valueDigests".into()),
            Value::Map(vec![(
                Value::Text("org.iso.18013.5.1".into()),
                Value::Map(value_digests_entries),
            )]),
        ),
    ]);

    let mso_bytes = cbor_encode(&mso);

    // ── Step 5: Tag-24 wrap the MSO ────────────────────────────────────
    // The C++ parser expects D8 18 59 <len_hi> <len_lo> <mso_cbor>
    // (Tag 24 + bstr with 2-byte length). We must ensure the bstr uses
    // the 59 XX XX encoding (2-byte length), which ciborium does
    // automatically for payloads >= 256 bytes. For smaller MSOs we need
    // to manually encode.
    let tagged_mso_bytes = encode_tag24_2byte_len(&mso_bytes);

    // ── Step 6: Build issuerAuth COSE_Sign1 (sign with issuer key) ─────
    let protected_bytes = es256_protected_header_bytes();
    let tbs = issuer_sig_structure(&protected_bytes, &tagged_mso_bytes);
    let issuer_sig: Signature = issuer_sk.sign(&tbs);
    let issuer_sig = issuer_sig.normalize_s().unwrap_or(issuer_sig);

    // issuerAuth = COSE_Sign1 as CBOR Array [protected, unprotected, payload, signature]
    let issuer_auth = Value::Array(vec![
        Value::Bytes(protected_bytes.clone()),
        Value::Map(vec![]), // unprotected header (empty)
        Value::Bytes(tagged_mso_bytes.clone()),
        Value::Bytes(issuer_sig.to_bytes().to_vec()),
    ]);

    // ── Step 7: Build deviceSignature COSE_Sign1 (sign with device key) ──
    // The device signs the DeviceAuthentication structure as defined in
    // ISO 18013-5 §9.1.3.6.  The CBOR encoding here must match exactly
    // what Longfellow's `compute_transcript_hash` produces in
    // `mdoc_witness.h:405-435`.
    //
    // DeviceAuthentication = [
    //   "DeviceAuthentication",       // text(20)
    //   SessionTranscript,            // raw transcript bytes
    //   DocType,                      // "org.iso.18013.5.1.mDL"
    //   DeviceNameSpacesBytes         // Tag(24, bstr(empty_map))
    // ]
    let device_authentication_bytes = {
        let mut da = Vec::new();
        // array(4)
        da.push(0x84);
        // text(20) "DeviceAuthentication"
        da.push(0x74);
        da.extend_from_slice(b"DeviceAuthentication");
        // SessionTranscript = raw transcript bytes (inserted as-is)
        da.extend_from_slice(transcript);
        // DocType = text(21) "org.iso.18013.5.1.mDL"
        da.push(0x75);
        da.extend_from_slice(b"org.iso.18013.5.1.mDL");
        // DeviceNameSpacesBytes = Tag(24, bstr(1 byte = 0xA0 empty map))
        da.push(0xd8); // tag(24)
        da.push(0x18);
        da.push(0x41); // bstr(1)
        da.push(0xa0); // empty map
        da
    };

    // Wrap DeviceAuthentication in Tag(24, bstr(...)) to get DeviceAuthenticationBytes
    let device_authentication_tagged = {
        let len = device_authentication_bytes.len();
        let mut out = Vec::new();
        out.push(0xd8); // tag(24)
        out.push(0x18);
        // Encode bstr length — use 2-byte form (0x59) for consistency with C++
        if len <= 0xFF {
            out.push(0x58); // bstr with 1-byte length
            out.push(len as u8);
        } else {
            out.push(0x59); // bstr with 2-byte length
            out.push((len >> 8) as u8);
            out.push((len & 0xFF) as u8);
        }
        out.extend_from_slice(&device_authentication_bytes);
        out
    };

    // COSE Sig_structure for device signature
    let device_tbs = device_sig_structure(&protected_bytes, &device_authentication_tagged);
    let device_sig: Signature = device_sk.sign(&device_tbs);
    let device_sig = device_sig.normalize_s().unwrap_or(device_sig);

    let device_signature = Value::Array(vec![
        Value::Bytes(protected_bytes),
        Value::Map(vec![]), // unprotected header (empty)
        Value::Null,        // payload is nil for deviceSignature
        Value::Bytes(device_sig.to_bytes().to_vec()),
    ]);

    // ── Step 8: Assemble full DeviceResponse structure ─────────────────
    let doc = Value::Map(vec![
        (
            Value::Text("docType".into()),
            Value::Text("org.iso.18013.5.1.mDL".into()),
        ),
        (
            Value::Text("issuerSigned".into()),
            Value::Map(vec![
                (Value::Text("issuerAuth".into()), issuer_auth),
                (
                    Value::Text("nameSpaces".into()),
                    Value::Map(vec![(
                        Value::Text("org.iso.18013.5.1".into()),
                        Value::Array(tagged_items),
                    )]),
                ),
            ]),
        ),
        (
            Value::Text("deviceSigned".into()),
            Value::Map(vec![(
                Value::Text("deviceAuth".into()),
                Value::Map(vec![(
                    Value::Text("deviceSignature".into()),
                    device_signature,
                )]),
            )]),
        ),
    ]);

    let root = Value::Map(vec![(
        Value::Text("documents".into()),
        Value::Array(vec![doc]),
    )]);

    // ── Step 9: CBOR-encode to bytes ───────────────────────────────────
    let mdoc_bytes = cbor_encode(&root);

    (mdoc_bytes, pub_key_x, pub_key_y)
}

/// Encode Tag(24) with a guaranteed 2-byte bstr length header (59 XX XX).
///
/// The C++ parser always skips exactly 5 bytes for the MSO tag prefix:
/// `D8 18 59 <len_hi> <len_lo>`. ciborium would use `58 XX` for payloads
/// < 256 bytes, so we manually construct the encoding.
fn encode_tag24_2byte_len(inner: &[u8]) -> Vec<u8> {
    let len = inner.len();
    let mut out = Vec::with_capacity(5 + len);
    out.push(0xD8); // Tag major type 6, additional info 24 (1-byte tag number follows)
    out.push(0x18); // Tag number = 24
    out.push(0x59); // bstr major type 2, additional info 25 (2-byte length follows)
    out.push((len >> 8) as u8); // length high byte
    out.push((len & 0xFF) as u8); // length low byte
    out.extend_from_slice(inner);
    out
}

fn claim_to_cbor(val: &ClaimValue) -> Value {
    match val {
        ClaimValue::String(s) => Value::Text(s.clone()),
        ClaimValue::Integer(i) => Value::Integer((*i).into()),
        ClaimValue::Boolean(b) => Value::Bool(*b),
        ClaimValue::Date { year, month, day } => {
            // ISO 18013-5 fulldate: CBOR tag 1004 + text
            Value::Tag(1004, Box::new(Value::Text(format!("{year:04}-{month:02}-{day:02}"))))
        }
    }
}
