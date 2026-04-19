//! CMS/X.509 parser — locates every byte range the circuit needs.
//!
//! Strategy: parse semantically with the `cms` / `x509-cert` crates, then
//! re-encode each sub-structure and locate it in the original DER via
//! byte search. Works because DER encoding is canonical for the fields
//! we care about.

use cms::content_info::ContentInfo;
use cms::signed_data::SignedData;
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::Certificate;

use crate::{locator, P7sError, P7sOffsets};

/// OID 2.5.4.5 — X.520 serialNumber attribute.
const OID_SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");

/// Parse the p7s and locate every byte range of interest.
pub(crate) fn locate_offsets(p7s: &[u8]) -> Result<P7sOffsets, P7sError> {
    // ── ContentInfo + SignedData ──────────────────────────────────────
    let ci = ContentInfo::from_der(p7s)
        .map_err(|e| P7sError::Cms(format!("ContentInfo: {e}")))?;
    let sd_bytes = ci
        .content
        .to_der()
        .map_err(|e| P7sError::Cms(format!("SignedData encode: {e}")))?;
    let sd = SignedData::from_der(&sd_bytes)
        .map_err(|e| P7sError::Cms(format!("SignedData: {e}")))?;

    // ── Signed content (JSON) ─────────────────────────────────────────
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .ok_or(P7sError::Cms("no eContent".into()))?;
    // econtent is an Any wrapping an OCTET STRING — get its inner bytes
    let econtent_der = econtent
        .to_der()
        .map_err(|e| P7sError::Cms(format!("eContent encode: {e}")))?;
    // Skip the outer Any tag+len and the OCTET STRING tag+len to get raw JSON
    let json_bytes = strip_any_octet_string(&econtent_der)?;
    let signed_content_start = find_subslice_unique(p7s, json_bytes)
        .ok_or(P7sError::OffsetNotFound("signed_content (JSON)"))?;
    let signed_content_len = json_bytes.len();

    // ── Signer certificate ────────────────────────────────────────────
    let cert_set = sd
        .certificates
        .as_ref()
        .ok_or(P7sError::NoCerts)?;
    // cms::signed_data::CertificateSet is a SetOfVec<CertificateChoices>
    // Take the first certificate-choice that is a plain Certificate.
    let signer_cert = first_x509_cert(cert_set)?;
    let cert_der = signer_cert
        .to_der()
        .map_err(|e| P7sError::Cms(format!("cert encode: {e}")))?;
    let cert_start = find_subslice_unique(p7s, &cert_der)
        .ok_or(P7sError::OffsetNotFound("cert"))?;
    let cert_len = cert_der.len();

    // TBSCertificate portion
    let tbs_der = signer_cert
        .tbs_certificate
        .to_der()
        .map_err(|e| P7sError::Cms(format!("tbs encode: {e}")))?;
    let cert_tbs_start = cert_start
        + find_subslice_unique(&cert_der, &tbs_der)
            .ok_or(P7sError::OffsetNotFound("tbs"))?;
    let cert_tbs_len = tbs_der.len();

    // Cert signature bytes (BIT STRING content — raw DER-encoded ECDSA SEQUENCE)
    let cert_sig_bitstring = signer_cert.signature.raw_bytes();
    let cert_sig_start = cert_start
        + find_subslice_unique(&cert_der, cert_sig_bitstring)
            .ok_or(P7sError::OffsetNotFound("cert signature"))?;
    let cert_sig_len = cert_sig_bitstring.len();

    // ── Subject serialNumber (stable ID) ──────────────────────────────
    let sn_value = signer_cert
        .tbs_certificate
        .subject
        .0
        .iter()
        .flat_map(|rdn| rdn.0.iter())
        .find(|atv| atv.oid == OID_SERIAL_NUMBER)
        .ok_or(P7sError::NoSerialNumber)?;
    // The value is an Any containing a PrintableString / UTF8String —
    // we want the inner bytes (not the DER tag+length).
    let sn_any_der = sn_value
        .value
        .to_der()
        .map_err(|e| P7sError::Der(format!("sn value: {e}")))?;
    let sn_inner = strip_tag_and_length(&sn_any_der)?;
    let subject_sn_start = cert_start
        + find_subslice_unique(&cert_der, sn_inner)
            .ok_or(P7sError::OffsetNotFound("subject serialNumber"))?;
    let subject_sn_len = sn_inner.len();

    // ── User signing pubkey (P-256 uncompressed point) ────────────────
    let spki_bitstring = signer_cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .raw_bytes();
    if spki_bitstring.len() != 65 || spki_bitstring[0] != 0x04 {
        return Err(P7sError::NotP256);
    }
    let user_signing_pk_start = cert_start
        + find_subslice_unique(&cert_der, spki_bitstring)
            .ok_or(P7sError::OffsetNotFound("user signing pk"))?;

    // ── SignerInfo content signature ──────────────────────────────────
    let signer_info = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or(P7sError::Cms("no SignerInfo".into()))?;
    let content_sig_bytes = signer_info.signature.as_bytes();
    let content_sig_start = find_subslice_unique(p7s, content_sig_bytes)
        .ok_or(P7sError::OffsetNotFound("content signature"))?;
    let content_sig_len = content_sig_bytes.len();

    // ── SignerInfo signedAttrs (CAdES / CMS authenticated attributes) ─
    // DIIA p7s uses signedAttrs, so the signature covers SHA-256 of the
    // DER-encoded signedAttrs SET (with [0] IMPLICIT 0xA0 rewritten to
    // 0x31). Locate its byte range in the p7s.
    let signed_attrs = signer_info
        .signed_attrs
        .as_ref()
        .ok_or(P7sError::Cms("signerInfo has no signedAttrs (not a CAdES-BES doc)".into()))?;
    let signed_attrs_set_der = signed_attrs
        .to_der()
        .map_err(|e| P7sError::Cms(format!("signedAttrs encode: {e}")))?;
    // Rewrite 0x31 (SET) → 0xA0 ([0] IMPLICIT) to match the form in p7s
    let mut signed_attrs_implicit = signed_attrs_set_der.clone();
    if signed_attrs_implicit.is_empty() || signed_attrs_implicit[0] != 0x31 {
        return Err(P7sError::Cms("signedAttrs DER did not start with SET tag".into()));
    }
    signed_attrs_implicit[0] = 0xA0;
    let signed_attrs_start = find_subslice_unique(p7s, &signed_attrs_implicit)
        .ok_or(P7sError::OffsetNotFound("signedAttrs"))?;
    let signed_attrs_len = signed_attrs_implicit.len();

    // Locate the messageDigest attribute value (OCTET STRING content, 32 bytes for SHA-256).
    const OID_MESSAGE_DIGEST: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
    let md_attr = signed_attrs
        .iter()
        .find(|a| a.oid == OID_MESSAGE_DIGEST)
        .ok_or(P7sError::Cms("messageDigest attribute not found in signedAttrs".into()))?;
    // Attribute value is a SET containing one Any wrapping an OCTET STRING.
    let md_value_any = md_attr
        .values
        .iter()
        .next()
        .ok_or(P7sError::Cms("messageDigest has no values".into()))?;
    let md_any_der = md_value_any
        .to_der()
        .map_err(|e| P7sError::Der(format!("messageDigest value encode: {e}")))?;
    // Strip OCTET STRING tag+length to get the 32-byte digest
    let md_bytes = strip_tag_and_length(&md_any_der)?;
    if md_bytes.len() != 32 {
        return Err(P7sError::Cms(format!(
            "messageDigest length {} != 32 (not SHA-256)",
            md_bytes.len()
        )));
    }
    // The 32-byte digest may appear twice (also inside signingCertificateV2).
    // Locate the unique messageDigest attribute DER, then offset to its OCTET STRING content.
    let md_attr_der = md_attr
        .to_der()
        .map_err(|e| P7sError::Cms(format!("messageDigest attr encode: {e}")))?;
    let md_attr_pos = find_subslice_unique(p7s, &md_attr_der)
        .ok_or(P7sError::OffsetNotFound("messageDigest attribute"))?;
    let message_digest_start = md_attr_pos + md_attr_der.len() - md_bytes.len();
    let message_digest_len = md_bytes.len();

    // ── JSON fields inside signed_content ─────────────────────────────
    let (json_pk_start_rel, json_pk_len) = locator::locate_hex_field(json_bytes, b"pk", 130)
        .ok_or(P7sError::JsonFieldMissing("pk"))?;
    let (json_nonce_start_rel, json_nonce_len) =
        locator::locate_hex_field(json_bytes, b"nonce", 64)
            .ok_or(P7sError::JsonFieldMissing("nonce"))?;
    let (json_context_start_rel, json_context_len) =
        locator::locate_string_field(json_bytes, b"context")
            .ok_or(P7sError::JsonFieldMissing("context"))?;
    let (json_declaration_start_rel, json_declaration_len) =
        locator::locate_string_field(json_bytes, b"declaration")
            .ok_or(P7sError::JsonFieldMissing("declaration"))?;
    let (json_timestamp_start_rel, json_timestamp_len) =
        locator::locate_integer_field(json_bytes, b"timestamp")
            .ok_or(P7sError::JsonFieldMissing("timestamp"))?;

    Ok(P7sOffsets {
        signed_content_start,
        signed_content_len,
        cert_start,
        cert_len,
        cert_tbs_start,
        cert_tbs_len,
        cert_sig_start,
        cert_sig_len,
        subject_sn_start,
        subject_sn_len,
        user_signing_pk_start,
        content_sig_start,
        content_sig_len,
        signed_attrs_start,
        signed_attrs_len,
        message_digest_start,
        message_digest_len,
        json_pk_start: signed_content_start + json_pk_start_rel,
        json_pk_len,
        json_nonce_start: signed_content_start + json_nonce_start_rel,
        json_nonce_len,
        json_context_start: signed_content_start + json_context_start_rel,
        json_context_len,
        json_declaration_start: signed_content_start + json_declaration_start_rel,
        json_declaration_len,
        json_timestamp_start: signed_content_start + json_timestamp_start_rel,
        json_timestamp_len,
    })
}

/// Find the first signer certificate that is a plain X.509 Certificate.
fn first_x509_cert(
    set: &cms::signed_data::CertificateSet,
) -> Result<Certificate, P7sError> {
    use cms::cert::CertificateChoices;
    for choice in set.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            return Ok(cert.clone());
        }
    }
    Err(P7sError::NoCerts)
}

/// Given DER of an Any that wraps an OCTET STRING, return the inner bytes.
/// Handles the `[0] EXPLICIT OCTET STRING` pattern used in eContent.
fn strip_any_octet_string(any_der: &[u8]) -> Result<&[u8], P7sError> {
    // An Any wrapping `[0] EXPLICIT OCTET STRING { bytes }`:
    //   A0 <len> 04 <len> <bytes>
    // Or bare OCTET STRING:
    //   04 <len> <bytes>
    let (mut rest, _) = read_tag_and_length(any_der)?;
    // If we see another OCTET STRING tag, strip it too
    if !rest.is_empty() && rest[0] == 0x04 {
        let (inner, _) = read_tag_and_length(rest)?;
        rest = inner;
    }
    Ok(rest)
}

/// Strip the outer ASN.1 tag and length, returning only the value bytes.
fn strip_tag_and_length(der: &[u8]) -> Result<&[u8], P7sError> {
    read_tag_and_length(der).map(|(rest, _tag)| rest)
}

/// Read an ASN.1 DER tag+length prefix. Returns (value, tag).
fn read_tag_and_length(der: &[u8]) -> Result<(&[u8], u8), P7sError> {
    if der.len() < 2 {
        return Err(P7sError::Der("truncated TLV".into()));
    }
    let tag = der[0];
    let len_byte = der[1];
    let (len, header_len) = if len_byte & 0x80 == 0 {
        (len_byte as usize, 2)
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || der.len() < 2 + n {
            return Err(P7sError::Der(format!("bad length byte: {len_byte}")));
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | der[2 + i] as usize;
        }
        (v, 2 + n)
    };
    if der.len() < header_len + len {
        return Err(P7sError::Der("truncated value".into()));
    }
    Ok((&der[header_len..header_len + len], tag))
}

/// Find `needle` in `haystack`. Returns `None` if absent or non-unique.
fn find_subslice_unique(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    let mut first = None;
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            if first.is_some() {
                return None; // non-unique — ambiguous offset
            }
            first = Some(i);
            i += needle.len();
        } else {
            i += 1;
        }
    }
    first
}
