//! Top-level mdoc verifier: public input encoding and two-proof verification.
//!
//! Mirrors C++ `run_mdoc_verifier()` from `vendor/longfellow-zk/lib/circuits/mdoc/mdoc_zk.cc`
//! lines 685-845. Encodes public inputs for both hash and signature circuits,
//! then verifies two proofs sharing a Fiat-Shamir transcript.

use sha2::{Digest, Sha256};

use crate::circuit::{decompress_circuit, Circuit, ReadBuf};
use crate::error::VerifyError;
use crate::field::fp256::{Fp256, Fp256Elt};
use crate::field::gf2_128::{Gf2Elt, Gf2_128};
use crate::field::Field;
use crate::proof::ZkProof;
use crate::transcript::Transcript;
use crate::zk::ZkVerifier;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A requested attribute for verification.
pub struct AttributeRequest {
    /// Element identifier (e.g. "family_name").
    pub id: String,
    /// CBOR-encoded value.
    pub cbor_value: Vec<u8>,
    /// Verification type: 0=EQ, 1=LEQ, 2=GEQ, 3=NEQ.
    pub verification_type: u8,
}

// ---------------------------------------------------------------------------
// CBOR length helpers (matching C++ mdoc_witness.h)
// ---------------------------------------------------------------------------

/// Append CBOR text string length prefix. Handles lengths < 256.
fn append_text_len(buf: &mut Vec<u8>, len: usize) {
    if len < 24 {
        buf.push(0x60 + len as u8);
    } else if len < 256 {
        buf.push(0x78);
        buf.push(len as u8);
    }
}

/// Append CBOR byte string length prefix. Handles lengths < 65536.
fn append_bytes_len(buf: &mut Vec<u8>, len: usize) {
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
}

// ---------------------------------------------------------------------------
// Bit encoding helpers
// ---------------------------------------------------------------------------

/// Fill 8 bit-elements in `v` starting at position `i*8` from byte `b`, LSB first.
/// Matches C++ `fill_byte(v, b, i, F)`.
fn fill_byte_into<F: Field>(v: &mut [F::Elt], b: u8, i: usize, f: &F) {
    for j in 0..8 {
        v[i * 8 + j] = if (b >> j) & 1 == 1 { f.one() } else { f.zero() };
    }
}

/// Encode a byte slice as bit elements, padding with `of_scalar(2)` ("don't care").
/// Matches C++ `fill_bit_string(filler, s, len, max, F)`.
fn fill_bit_string<F: Field>(s: &[u8], len: usize, max: usize, f: &F) -> Vec<F::Elt> {
    let mut v = vec![f.of_scalar(2); max * 8];
    for i in 0..std::cmp::min(len, max) {
        if i < s.len() {
            fill_byte_into::<F>(&mut v, s[i], i, f);
        }
    }
    v
}

/// Encode a 32-byte hash as 256 bit-elements using big-endian byte / LSB-first bit mapping.
/// Matches C++ hash encoding for nullifier, binding, and escrow digest:
/// ```text
/// for j in 0..256:
///     byte_idx = (255 - j) / 8
///     bit_idx = j % 8
///     bits[j] = (hash[byte_idx] >> bit_idx) & 1
/// ```
fn hash_to_bits<F: Field>(hash: &[u8; 32], f: &F) -> Vec<F::Elt> {
    let mut bits = vec![f.zero(); 256];
    for j in 0..256 {
        let byte_idx = (255 - j) / 8;
        let bit_idx = j % 8;
        bits[j] = if (hash[byte_idx] >> bit_idx) & 1 == 1 {
            f.one()
        } else {
            f.zero()
        };
    }
    bits
}

/// Expand a scalar as `nbits` bit-elements, LSB first.
/// Matches C++ `DenseFiller::push_back(uint64_t x, size_t bits, Field F)`.
fn scalar_bits<F: Field>(x: u64, nbits: usize, f: &F) -> Vec<F::Elt> {
    let mut v = Vec::with_capacity(nbits);
    for i in 0..nbits {
        v.push(f.of_scalar((x >> i) & 1));
    }
    v
}

// ---------------------------------------------------------------------------
// Attribute encoding (version >= 7)
// ---------------------------------------------------------------------------

/// Encode a single attribute for the hash circuit public inputs.
/// Mirrors C++ `fill_attribute(filler, attr, F, version)` from mdoc_witness.h:467-535.
fn fill_attribute<F: Field>(
    out: &mut Vec<F::Elt>,
    attr: &AttributeRequest,
    f: &F,
    version: usize,
) -> Result<(), VerifyError> {
    // 768 bit positions (96 bytes * 8 bits)
    let mut v = vec![f.zero(); 96 * 8];

    if version >= 7 {
        // First 32 bytes: "<text_len(id_len)> <id>" zero-padded
        let mut id_buf = Vec::new();
        append_text_len(&mut id_buf, attr.id.len());
        id_buf.extend_from_slice(attr.id.as_bytes());

        for j in 0..std::cmp::min(id_buf.len(), 32) {
            fill_byte_into::<F>(&mut v, id_buf[j], j, f);
        }

        // Next 64 bytes: CBOR value
        for j in 0..std::cmp::min(attr.cbor_value.len(), 64) {
            fill_byte_into::<F>(&mut v, attr.cbor_value[j], 32 + j, f);
        }

        out.extend_from_slice(&v);

        // Packed identifier length: 1 + 17 + 1 + id_len
        let id_packed = (1 + 17 + 1 + attr.id.len()) as u64;
        out.extend(scalar_bits(id_packed, 8, f));

        // Packed value length with verification_type in bits 6-7
        let vlen = attr.cbor_value.len() + 12 + 1;
        let packed = vlen as u64 | (((attr.verification_type & 0x3) as u64) << 6);
        out.extend(scalar_bits(packed, 8, f));
    } else {
        // version < 7
        let mut vbuf = Vec::new();
        append_text_len(&mut vbuf, attr.id.len());
        vbuf.extend_from_slice(attr.id.as_bytes());
        append_text_len(&mut vbuf, 12); // len of "elementValue"
        vbuf.extend_from_slice(b"elementValue");
        vbuf.extend_from_slice(&attr.cbor_value);

        if vbuf.len() > 96 {
            return Err(VerifyError::InvalidInput("attribute too long".into()));
        }

        let len = std::cmp::min(vbuf.len(), 96);
        for j in 0..len {
            fill_byte_into::<F>(&mut v, vbuf[j], j, f);
        }
        out.extend_from_slice(&v);
        out.extend(scalar_bits(len as u64, 8, f));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Hash circuit public inputs
// ---------------------------------------------------------------------------

/// Fill all hash circuit public inputs (GF2_128).
/// Order: one, attributes, timestamp, contract_hash, nullifier, binding, escrow, MACs, av.
fn fill_hash_public_inputs(
    gf: &Gf2_128,
    attributes: &[AttributeRequest],
    now: &[u8],
    contract_hash: &[u8],
    nullifier_hash: &[u8; 32],
    binding_hash: &[u8; 32],
    escrow_digest: &[u8; 32],
    macs: &[Gf2Elt; 6],
    av: Gf2Elt,
    version: usize,
) -> Result<Vec<Gf2Elt>, VerifyError> {
    let mut pub_in: Vec<Gf2Elt> = Vec::new();

    // 1. one
    pub_in.push(gf.one());

    // 2. Per attribute
    for attr in attributes {
        fill_attribute(&mut pub_in, attr, gf, version)?;
    }

    // 3. Timestamp: fill_bit_string(now, 20, 20)
    pub_in.extend(fill_bit_string::<Gf2_128>(now, 20, 20, gf));

    // 4. Contract hash: fill_bit_string(contract_hash, 8, 8)
    pub_in.extend(fill_bit_string::<Gf2_128>(contract_hash, 8, 8, gf));

    // 5. Nullifier hash: 256 bit elements
    pub_in.extend(hash_to_bits(nullifier_hash, gf));

    // 6. Binding hash: 256 bit elements
    pub_in.extend(hash_to_bits(binding_hash, gf));

    // 7. Escrow digest: 256 bit elements
    pub_in.extend(hash_to_bits(escrow_digest, gf));

    // 8. 6 MAC elements (each pushed directly as one GF2_128 element)
    for mac in macs {
        pub_in.push(*mac);
    }

    // 9. MAC key (av)
    pub_in.push(av);

    Ok(pub_in)
}

// ---------------------------------------------------------------------------
// Signature circuit public inputs
// ---------------------------------------------------------------------------

/// Expand a GF2_128 element to 128 individual bit-elements in Fp256.
/// Matches C++ `fill_gf2k<GF2_128, Fp256Base>`.
fn fill_gf2k_as_bits(mac: &Gf2Elt, fp: &Fp256) -> Vec<Fp256Elt> {
    let mut v = Vec::with_capacity(128);
    for i in 0..128 {
        v.push(if mac.bit(i) { fp.one() } else { fp.zero() });
    }
    v
}

/// Fill all signature circuit public inputs (Fp256).
/// Order: one, pkX, pkY, e2, MACs (expanded), av (expanded).
fn fill_sig_public_inputs(
    fp: &Fp256,
    pk_x: Fp256Elt,
    pk_y: Fp256Elt,
    e2: Fp256Elt,
    macs: &[Gf2Elt; 6],
    av: Gf2Elt,
) -> Vec<Fp256Elt> {
    let mut pub_in: Vec<Fp256Elt> = Vec::new();

    // 1. one
    pub_in.push(fp.one());

    // 2-3. Issuer public key
    pub_in.push(pk_x);
    pub_in.push(pk_y);

    // 4. Transcript hash
    pub_in.push(e2);

    // 5. 6 MACs expanded to 128 bits each
    for mac in macs {
        pub_in.extend(fill_gf2k_as_bits(mac, fp));
    }

    // 6. av expanded to 128 bits
    pub_in.extend(fill_gf2k_as_bits(&av, fp));

    pub_in
}

// ---------------------------------------------------------------------------
// Transcript hash (DeviceAuthenticationBytes -> COSE Signature1 -> SHA-256)
// ---------------------------------------------------------------------------

/// Compute the transcript hash as a SHA-256 of the COSE Signature1 encoding of
/// DeviceAuthenticationBytes.
///
/// Mirrors C++ `compute_transcript_hash()` from mdoc_witness.h:394-442.
fn compute_transcript_hash(transcript: &[u8], doc_type: &str) -> [u8; 32] {
    // DeviceAuthentication CBOR array header + "DeviceAuthentication" text
    let mut da = vec![
        0x84, 0x74, // array(4), text(20)
        b'D', b'e', b'v', b'i', b'c', b'e', b'A', b'u', b't', b'h', b'e', b'n', b't', b'i',
        b'c', b'a', b't', b'i', b'o', b'n',
    ];
    da.extend_from_slice(transcript);

    // DocType as CBOR text
    let mut dt = Vec::new();
    append_text_len(&mut dt, doc_type.len());
    dt.extend_from_slice(doc_type.as_bytes());
    da.extend(dt);

    // DeviceNameSpacesBytes
    da.extend_from_slice(&[0xD8, 0x18, 0x41, 0xA0]);

    // COSE Signature1 wrapping
    let mut cose1 = vec![
        0x84, 0x6A, // array(4), text(10)
        0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31, // "Signature1"
        0x43, 0xA1, 0x01, 0x26, // bytes(3), {1: -7}
        0x40, // bytes(0) - external_aad
    ];

    let l1 = da.len();
    let l2 = l1 + if l1 < 256 { 4 } else { 5 }; // tagged bstr overhead
    append_bytes_len(&mut cose1, l2);
    cose1.extend_from_slice(&[0xD8, 0x18]); // tag(24)
    append_bytes_len(&mut cose1, l1);
    cose1.extend(da);

    // SHA-256
    let hash = Sha256::digest(&cose1);
    let mut result = [0u8; 32];
    result.copy_from_slice(&hash);
    result
}

/// Compute the transcript hash and convert to Fp256 Montgomery form.
fn compute_transcript_hash_fp256(transcript: &[u8], doc_type: &str, fp: &Fp256) -> Fp256Elt {
    let hash = compute_transcript_hash(transcript, doc_type);
    fp.of_bytes_be(&hash)
}

// ---------------------------------------------------------------------------
// MAC key generation
// ---------------------------------------------------------------------------

/// Derive the MAC verification key from the Fiat-Shamir transcript.
/// Matches C++ `generate_mac_key(Transcript& t)`.
fn generate_mac_key(ts: &mut Transcript, gf: &Gf2_128) -> Gf2Elt {
    let bytes = ts.bytes(16);
    gf.of_bytes(&bytes).expect("16 bytes always valid for GF2_128")
}

// ---------------------------------------------------------------------------
// Main verification entry point
// ---------------------------------------------------------------------------

/// Verify an mdoc zero-knowledge proof consisting of two sub-proofs
/// (hash circuit over GF2_128, signature circuit over Fp256) sharing a
/// Fiat-Shamir transcript.
///
/// This is the Rust equivalent of C++ `run_mdoc_verifier()`.
#[allow(clippy::too_many_arguments)]
pub fn mdoc_verify(
    circuit_bytes: &[u8],
    proof_bytes: &[u8],
    issuer_pk_x: &str,
    issuer_pk_y: &str,
    transcript: &[u8],
    attributes: &[AttributeRequest],
    now: &str,
    contract_hash: &[u8],
    nullifier_hash: &[u8],
    binding_hash: &[u8],
    escrow_digest: &[u8],
    doc_type: &str,
    version: usize,
    block_enc_hash: usize,
    block_enc_sig: usize,
) -> Result<bool, VerifyError> {
    let fp = Fp256;
    let gf = Gf2_128;

    // 1. Decompress and parse circuits
    let decompressed = decompress_circuit(circuit_bytes)?;
    let (c_sig, consumed) = Circuit::from_bytes(&decompressed, &fp)?;
    let (c_hash, _) = Circuit::from_bytes(&decompressed[consumed..], &gf)?;

    // 2. Parse proof
    let rate = if version < 7 { 4 } else { 7 };
    let nreq = if version < 7 { 128 } else { 132 };

    let mut rb = ReadBuf::new(proof_bytes);
    let mut macs = [gf.zero(); 6];
    for mac in &mut macs {
        let bytes = rb.read_bytes(16)?;
        *mac = gf
            .of_bytes(bytes)
            .ok_or(VerifyError::ProofParse("invalid MAC element".into()))?;
    }

    let pr_hash = ZkProof::read(&mut rb, &c_hash, rate, nreq, block_enc_hash, &gf)?;
    let pr_sig = ZkProof::read(&mut rb, &c_sig, rate, nreq, block_enc_sig, &fp)?;

    if rb.remaining() != 0 {
        return Err(VerifyError::ProofParse(format!(
            "extra bytes in proof: {}",
            rb.remaining()
        )));
    }

    // 3. Create verifiers
    let hash_v = ZkVerifier::<Gf2_128>::new(&c_hash, rate, nreq, block_enc_hash);
    let sig_v = ZkVerifier::<Fp256>::new(&c_sig, rate, nreq, block_enc_sig);

    // 4. Shared Fiat-Shamir transcript
    let mut tv = Transcript::new(transcript, version);

    // 5. Receive commitments into transcript
    hash_v.recv_commitment(&pr_hash, &mut tv);
    sig_v.recv_commitment(&pr_sig, &mut tv);

    // 6. Generate MAC key
    let av = generate_mac_key(&mut tv, &gf);

    // 7. Fill public inputs
    let null_hash: &[u8; 32] = nullifier_hash
        .try_into()
        .map_err(|_| VerifyError::InvalidInput("nullifier_hash must be 32 bytes".into()))?;
    let bind_hash: &[u8; 32] = binding_hash
        .try_into()
        .map_err(|_| VerifyError::InvalidInput("binding_hash must be 32 bytes".into()))?;
    let esc_digest: &[u8; 32] = escrow_digest
        .try_into()
        .map_err(|_| VerifyError::InvalidInput("escrow_digest must be 32 bytes".into()))?;

    let pub_hash = fill_hash_public_inputs(
        &gf,
        attributes,
        now.as_bytes(),
        contract_hash,
        null_hash,
        bind_hash,
        esc_digest,
        &macs,
        av,
        version,
    )?;

    let pk_x = fp
        .of_string(issuer_pk_x)
        .ok_or(VerifyError::InvalidInput("pkX".into()))?;
    let pk_y = fp
        .of_string(issuer_pk_y)
        .ok_or(VerifyError::InvalidInput("pkY".into()))?;
    let e2 = compute_transcript_hash_fp256(transcript, doc_type, &fp);

    let pub_sig = fill_sig_public_inputs(&fp, pk_x, pk_y, e2, &macs, av);

    // Validate public input sizes
    if pub_hash.len() != c_hash.npub_in {
        return Err(VerifyError::InvalidInput(format!(
            "hash public input count mismatch: got {}, expected {}",
            pub_hash.len(),
            c_hash.npub_in
        )));
    }
    if pub_sig.len() != c_sig.npub_in {
        return Err(VerifyError::InvalidInput(format!(
            "sig public input count mismatch: got {}, expected {}",
            pub_sig.len(),
            c_sig.npub_in
        )));
    }

    // 8. Verify both proofs
    let ok1 = hash_v.verify(&pr_hash, &pub_hash, &mut tv, &c_hash, &gf);
    let ok2 = sig_v.verify(&pr_sig, &pub_sig, &mut tv, &c_sig, &fp);

    Ok(ok1 && ok2)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::gf2_128::Gf2_128;

    #[test]
    fn fill_byte_encoding() {
        let f = Gf2_128;
        let mut v = vec![f.zero(); 8];
        fill_byte_into::<Gf2_128>(&mut v, 0b10110001, 0, &f);
        assert_eq!(v[0], f.one()); // bit 0 = 1
        assert_eq!(v[1], f.zero()); // bit 1 = 0
        assert_eq!(v[2], f.zero()); // bit 2 = 0
        assert_eq!(v[3], f.zero()); // bit 3 = 0
        assert_eq!(v[4], f.one()); // bit 4 = 1
        assert_eq!(v[5], f.one()); // bit 5 = 1
        assert_eq!(v[6], f.zero()); // bit 6 = 0
        assert_eq!(v[7], f.one()); // bit 7 = 1
    }

    #[test]
    fn fill_byte_encoding_fp256() {
        let f = Fp256;
        let mut v = vec![f.zero(); 8];
        fill_byte_into::<Fp256>(&mut v, 0xAB, 0, &f);
        // 0xAB = 1010_1011
        assert_eq!(v[0], f.one()); // bit 0
        assert_eq!(v[1], f.one()); // bit 1
        assert_eq!(v[2], f.zero()); // bit 2
        assert_eq!(v[3], f.one()); // bit 3
        assert_eq!(v[4], f.zero()); // bit 4
        assert_eq!(v[5], f.one()); // bit 5
        assert_eq!(v[6], f.zero()); // bit 6
        assert_eq!(v[7], f.one()); // bit 7
    }

    #[test]
    fn fill_byte_at_offset() {
        let f = Gf2_128;
        let mut v = vec![f.zero(); 24]; // 3 bytes worth
        fill_byte_into::<Gf2_128>(&mut v, 0xFF, 1, &f);
        // Byte 0 should be all zeros
        for j in 0..8 {
            assert_eq!(v[j], f.zero());
        }
        // Byte 1 should be all ones
        for j in 8..16 {
            assert_eq!(v[j], f.one());
        }
        // Byte 2 should be all zeros
        for j in 16..24 {
            assert_eq!(v[j], f.zero());
        }
    }

    #[test]
    fn hash_to_bits_encoding() {
        let f = Gf2_128;
        let mut hash = [0u8; 32];
        hash[31] = 1; // least significant byte = 1, bit 0 set
        let bits = hash_to_bits(&hash, &f);
        assert_eq!(bits.len(), 256);
        // byte_idx for j=0: (255-0)/8 = 31, bit_idx = 0%8 = 0
        // hash[31] = 1, bit 0 = 1
        assert_eq!(bits[0], f.one());
        // All other bits should be zero
        for j in 1..256 {
            // j=1: byte_idx=31, bit_idx=1 => hash[31]=1 => bit 1 = 0
            let byte_idx = (255 - j) / 8;
            let bit_idx = j % 8;
            let expected = if (hash[byte_idx] >> bit_idx) & 1 == 1 {
                f.one()
            } else {
                f.zero()
            };
            assert_eq!(bits[j], expected, "mismatch at bit {j}");
        }
    }

    #[test]
    fn hash_to_bits_msb_byte() {
        let f = Gf2_128;
        let mut hash = [0u8; 32];
        hash[0] = 0x80; // Most significant byte, bit 7 set
        let bits = hash_to_bits(&hash, &f);
        // j=255: byte_idx=(255-255)/8=0, bit_idx=255%8=7 => hash[0]=0x80 => bit 7 = 1
        assert_eq!(bits[255], f.one());
        // j=248: byte_idx=(255-248)/8=0, bit_idx=248%8=0 => hash[0]=0x80 => bit 0 = 0
        assert_eq!(bits[248], f.zero());
    }

    #[test]
    fn append_text_len_small() {
        let mut buf = Vec::new();
        append_text_len(&mut buf, 5);
        assert_eq!(buf, vec![0x60 + 5]);
    }

    #[test]
    fn append_text_len_medium() {
        let mut buf = Vec::new();
        append_text_len(&mut buf, 30);
        assert_eq!(buf, vec![0x78, 30]);
    }

    #[test]
    fn append_text_len_zero() {
        let mut buf = Vec::new();
        append_text_len(&mut buf, 0);
        assert_eq!(buf, vec![0x60]);
    }

    #[test]
    fn append_text_len_23() {
        let mut buf = Vec::new();
        append_text_len(&mut buf, 23);
        assert_eq!(buf, vec![0x60 + 23]);
    }

    #[test]
    fn append_text_len_24() {
        let mut buf = Vec::new();
        append_text_len(&mut buf, 24);
        assert_eq!(buf, vec![0x78, 24]);
    }

    #[test]
    fn append_bytes_len_small() {
        let mut buf = Vec::new();
        append_bytes_len(&mut buf, 5);
        assert_eq!(buf, vec![0x40 + 5]);
    }

    #[test]
    fn append_bytes_len_medium() {
        let mut buf = Vec::new();
        append_bytes_len(&mut buf, 100);
        assert_eq!(buf, vec![0x58, 100]);
    }

    #[test]
    fn append_bytes_len_large() {
        let mut buf = Vec::new();
        append_bytes_len(&mut buf, 300);
        assert_eq!(buf, vec![0x59, 1, 44]); // 300 = 0x012C
    }

    #[test]
    fn transcript_hash_deterministic() {
        let hash1 = compute_transcript_hash(&[1, 2, 3], "org.iso.18013.5.1.mDL");
        let hash2 = compute_transcript_hash(&[1, 2, 3], "org.iso.18013.5.1.mDL");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]); // not all zeros
    }

    #[test]
    fn transcript_hash_different_input() {
        let hash1 = compute_transcript_hash(&[1, 2, 3], "org.iso.18013.5.1.mDL");
        let hash2 = compute_transcript_hash(&[4, 5, 6], "org.iso.18013.5.1.mDL");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn transcript_hash_different_doctype() {
        let hash1 = compute_transcript_hash(&[1, 2, 3], "org.iso.18013.5.1.mDL");
        let hash2 = compute_transcript_hash(&[1, 2, 3], "eu.europa.ec.eudi.pid.1");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn fill_bit_string_padding() {
        let f = Gf2_128;
        let data = [0xFF, 0x00];
        let bits = fill_bit_string::<Gf2_128>(&data, 2, 4, &f);
        assert_eq!(bits.len(), 32); // 4 * 8
        // First byte: all ones
        for j in 0..8 {
            assert_eq!(bits[j], f.one(), "bit {j} should be one");
        }
        // Second byte: all zeros
        for j in 8..16 {
            assert_eq!(bits[j], f.zero(), "bit {j} should be zero");
        }
        // Remaining bytes: padded with of_scalar(2)
        let two = f.of_scalar(2);
        for j in 16..32 {
            assert_eq!(bits[j], two, "bit {j} should be padding (2)");
        }
    }

    #[test]
    fn scalar_bits_encoding() {
        let f = Gf2_128;
        let bits = scalar_bits(0b10110, 5, &f);
        assert_eq!(bits.len(), 5);
        assert_eq!(bits[0], f.zero()); // bit 0
        assert_eq!(bits[1], f.one()); // bit 1
        assert_eq!(bits[2], f.one()); // bit 2
        assert_eq!(bits[3], f.zero()); // bit 3
        assert_eq!(bits[4], f.one()); // bit 4
    }

    #[test]
    fn fill_attribute_v7_element_count() {
        let f = Gf2_128;
        let attr = AttributeRequest {
            id: "family_name".to_string(),
            cbor_value: vec![0x65, b'S', b'm', b'i', b't', b'h'], // CBOR text "Smith"
            verification_type: 0,
        };
        let mut out = Vec::new();
        fill_attribute(&mut out, &attr, &f, 7).unwrap();
        // Should be: 768 (bit fields) + 8 (id packed len) + 8 (value packed len) = 784
        assert_eq!(out.len(), 768 + 8 + 8);
    }

    #[test]
    fn fill_attribute_v6_element_count() {
        let f = Gf2_128;
        let attr = AttributeRequest {
            id: "family_name".to_string(),
            cbor_value: vec![0x65, b'S', b'm', b'i', b't', b'h'],
            verification_type: 0,
        };
        let mut out = Vec::new();
        fill_attribute(&mut out, &attr, &f, 6).unwrap();
        // Should be: 768 (bit fields) + 8 (len) = 776
        assert_eq!(out.len(), 768 + 8);
    }

    #[test]
    fn fill_gf2k_as_bits_zero() {
        let fp = Fp256;
        let zero = Gf2Elt::default();
        let bits = fill_gf2k_as_bits(&zero, &fp);
        assert_eq!(bits.len(), 128);
        for bit in &bits {
            assert_eq!(*bit, fp.zero());
        }
    }

    #[test]
    fn fill_gf2k_as_bits_one() {
        let fp = Fp256;
        let gf = Gf2_128;
        let one = gf.one();
        let bits = fill_gf2k_as_bits(&one, &fp);
        assert_eq!(bits.len(), 128);
        assert_eq!(bits[0], fp.one()); // bit 0 should be 1
        for bit in &bits[1..] {
            assert_eq!(*bit, fp.zero()); // rest should be 0
        }
    }

    #[test]
    fn hash_public_inputs_count() {
        let gf = Gf2_128;
        let attrs = vec![AttributeRequest {
            id: "family_name".to_string(),
            cbor_value: vec![0x65, b'S', b'm', b'i', b't', b'h'],
            verification_type: 0,
        }];
        let now = b"2026-04-08T00:00:00Z";
        let contract_hash = [0u8; 8];
        let nullifier_hash = [0u8; 32];
        let binding_hash = [0u8; 32];
        let escrow_digest = [0u8; 32];
        let macs = [gf.zero(); 6];
        let av = gf.zero();

        let pub_in = fill_hash_public_inputs(
            &gf,
            &attrs,
            now,
            &contract_hash,
            &nullifier_hash,
            &binding_hash,
            &escrow_digest,
            &macs,
            av,
            7,
        )
        .unwrap();

        // 1 (one) + 784 (attr) + 160 (timestamp) + 64 (contract) + 256 (null) + 256 (bind) + 256 (escrow) + 6 (macs) + 1 (av)
        let expected = 1 + 784 + 160 + 64 + 256 + 256 + 256 + 6 + 1;
        assert_eq!(pub_in.len(), expected);
    }

    #[test]
    fn sig_public_inputs_count() {
        let fp = Fp256;
        let gf = Gf2_128;
        let macs = [gf.zero(); 6];
        let av = gf.zero();

        let pub_in = fill_sig_public_inputs(
            &fp,
            fp.zero(),
            fp.zero(),
            fp.zero(),
            &macs,
            av,
        );

        // 1 (one) + 1 (pkX) + 1 (pkY) + 1 (e2) + 6*128 (macs) + 128 (av)
        let expected = 4 + 6 * 128 + 128;
        assert_eq!(pub_in.len(), expected);
    }

    #[test]
    fn of_bytes_be_zero() {
        let fp = Fp256;
        let bytes = [0u8; 32];
        let elt = fp.of_bytes_be(&bytes);
        assert_eq!(elt, fp.zero());
    }

    #[test]
    fn of_bytes_be_one() {
        let fp = Fp256;
        let mut bytes = [0u8; 32];
        bytes[31] = 1; // big-endian 1
        let elt = fp.of_bytes_be(&bytes);
        assert_eq!(elt, fp.one());
    }

    #[test]
    fn of_bytes_be_handles_ge_p() {
        // All 0xFF bytes = 2^256 - 1 > p. Should still produce a valid element.
        let fp = Fp256;
        let bytes = [0xFF; 32];
        let elt = fp.of_bytes_be(&bytes);
        // The result should be (2^256 - 1) mod p in Montgomery form.
        // Just verify it's not zero (since 2^256-1 != 0 mod p).
        assert_ne!(elt, fp.zero());
    }

    #[test]
    fn generate_mac_key_deterministic() {
        let gf = Gf2_128;
        let mut t1 = Transcript::new(&[0x42], 7);
        let mut t2 = Transcript::new(&[0x42], 7);
        t1.write_bytes(&[1, 2, 3]);
        t2.write_bytes(&[1, 2, 3]);
        let k1 = generate_mac_key(&mut t1, &gf);
        let k2 = generate_mac_key(&mut t2, &gf);
        assert_eq!(k1, k2);
    }
}
