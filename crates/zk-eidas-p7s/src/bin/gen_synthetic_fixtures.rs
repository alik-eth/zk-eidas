//! Deterministic synthetic-fixture generator (Task 43a).
//!
//! Rewrites the committed DIIA `.p7s` fixtures by:
//!   1. In-place, length-preserving substitutions in the signer cert's
//!      issuer + subject DNs (removes PII — see `DN_SUBS` table below).
//!   2. Re-signing the cert's TBSCertificate with a deterministic
//!      synthetic root key (`TestAnchorA`), splicing the new
//!      `signatureValue` into the cert's BIT STRING.
//!   3. Recomputing the SHA-256(cert) digest embedded in the CMS
//!      `signing-certificate-v2` (ESSCertIDv2) attribute inside
//!      signedAttrs.
//!   4. Re-signing the canonicalized `signedAttrs` (byte 0 rewritten
//!      from `0xA0` to `0x31`) with a deterministic synthetic signer
//!      key, splicing the new `signatureValue` into the SignerInfo.
//!
//! TSA countersignature bytes are LEFT AS-IS — by design the new
//! content_sig no longer matches the TSA's `message_imprint`, but no
//! circuit invariant or test reads the TSA path (scope decision for
//! Task 43a; TSA surgery is tracked as Task #45).
//!
//! ## Determinism
//!
//! All signing uses RFC 6979 (p256's `SigningKey::sign` default). Root
//! and signer secret keys are derived from fixed seed strings via
//! SHA-256 → scalar reduction. The `(signer_seed_nonce, serial_tweak)`
//! retry loop iterates in a fixed order. Running the generator twice
//! with no code changes produces byte-identical output — verified by
//! `--output-dir` + `diff -rq` in CI.
//!
//! ## Usage
//!
//! ```bash
//! # Safe: write to a temp dir, compare, then overwrite.
//! cargo run --release --bin gen_synthetic_fixtures -- --output-dir /tmp/syn-a/
//! cargo run --release --bin gen_synthetic_fixtures -- --output-dir /tmp/syn-b/
//! diff -rq /tmp/syn-a /tmp/syn-b   # must be empty
//! cp /tmp/syn-a/*.p7s crates/zk-eidas-p7s/fixtures/
//!
//! # Overwrite in place (used once the output has been verified).
//! cargo run --release --bin gen_synthetic_fixtures -- --in-place
//! ```
//!
//! The final output SHA-256s are logged on success; any drift in
//! future runs surfaces as a visible diff.

use std::path::PathBuf;

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

// ── Scope guards (handoff §8 trap 1) ─────────────────────────────────
//
// These constants pin the DIIA fixture layout. Any drift means the
// current fixtures aren't the ones this generator was designed for and
// the surgery would corrupt them. Changing these requires re-auditing
// the whole surgery plan.

/// Total length of the outer signer cert SEQUENCE (bytes), including
/// its 4-byte DER header.
const CERT_LEN_TOTAL: usize = 1292;
/// Offset of the outer cert SEQ's `0x30` tag within the p7s.
const CERT_START: usize = 917;
/// Offset of the TBSCertificate `0x30` tag within the p7s.
const CERT_TBS_START: usize = 921;
/// TBSCertificate total length (header + body).
const CERT_TBS_LEN_TOTAL: usize = 1203;
/// Offset of the cert's BIT STRING signature value's 70-byte payload
/// (the ECDSA `30 44 02 20 r 02 20 s` SEQ). Precedent: `03 47 00` hdr
/// starts at `CERT_END - 73`, payload starts at `CERT_END - 70`.
const CERT_SIG_START: usize = 2139;
const CERT_SIG_LEN: usize = 70;

/// Offset of the 20-byte cert serial number value (INTEGER content,
/// past the `02 14` header inside the `[0] EXPLICIT { INTEGER 2 }`
/// version anchor).
const SERIAL_START: usize = 932;
const SERIAL_LEN: usize = 20;

/// Offset of the signer cert SPKI's 65-byte SEC1 uncompressed point
/// (leading `0x04` byte). The 26-byte DIIA P-256 SPKI DER prefix that
/// precedes it is unchanged (same OID bytes for every P-256 QTSP, so
/// the in-circuit prefix anchor stays valid for the synthetic anchor).
const SPKI_PK_START: usize = 1355;
const SPKI_PK_LEN: usize = 65;

/// Offset of the 32-byte SHA-256(cert) value inside the CMS
/// `signing-certificate-v2` (ESSCertIDv2) attribute in signedAttrs.
/// Fixed because every DN/pk/sig substitution above is length-
/// preserving; the ESSCertIDv2 location doesn't shift.
const ESS_DIGEST_START: usize = 2634;
const ESS_DIGEST_LEN: usize = 32;

/// Offset of the signedAttrs `[0] IMPLICIT` tag within the p7s. The
/// body length is read from the `30 82 ll ll` header at runtime
/// because the two DIIA fixtures differ by one byte of signedAttrs
/// body length (`binding.qkb.p7s` vs `admin-binding.qkb.p7s`).
const SIGNED_ATTRS_START: usize = 2477;

/// Offset of the primary content_sig's 70-byte ECDSA SEQ value. Note:
/// the two DIIA fixtures differ — `binding.qkb.p7s` has it at 3878,
/// `admin-binding.qkb.p7s` at 3879 (one-byte shift from the longer
/// signedAttrs body). The generator locates this from the signedAttrs
/// end rather than hardcoding.
#[allow(dead_code)]
const CONTENT_SIG_LEN: usize = 70;

// ── Length-preserving DN substitution table (handoff §3.2) ───────────
//
// Each (needle, replacement) pair is byte-identical in length. Order
// matters only for overlap avoidance — longer needles first so we
// don't accidentally match a shorter needle inside a longer one.

const DN_SUBS: &[(&[u8], &[u8])] = &[
    // 41-byte pair (longer than the 23-byte "State enterprise" variant,
    // which is a substring of nothing else — but longer first is cheap
    // insurance).
    (
        b"\"DIIA\". Qualified Trust Services Provider",
        b"\"Test\". Synthetic Trust Services Provider",
    ),
    // 39-byte pair.
    (
        b"Department of Electronic Trust Services",
        b"Synthetic Electronic Trust Services Dpt",
    ),
    // 23-byte pair.
    (
        b"State enterprise \"DIIA\"",
        b"Synthetic Test QTSP Inc",
    ),
    // 20-byte pair (subject DN commonName — note trailing space).
    (b"Vovkotrub Oleksandr ", b"Test Holder Subject "),
    // 16-byte pair (QTSP reg-code — the marker `TRUST_ANCHOR_PROBES`
    // uses to identify TestAnchorA).
    (b"UA-43395033-2311", b"TQSA-00000000-01"),
    // 16-byte pair (subject stable-ID).
    (b"TINUA-3627506575", b"TINUA-1111111111"),
    // 14-byte pair (legal entity reg code).
    (b"NTRUA-43395033", b"NTRUA-00000000"),
    // 10-byte pair (subject givenName — trailing space).
    (b"Oleksandr ", b"TestHoldr "),
    // 9-byte pair (subject surname).
    (b"Vovkotrub", b"TestHoldX"),
    // 4-byte pair (locality).
    (b"Kyiv", b"Test"),
];

// ── Deterministic key derivation ─────────────────────────────────────

/// Root-CA seed — hashed with SHA-256 to produce the scalar that
/// becomes `TestAnchorA`'s root signing key.
const ROOT_SEED: &[u8] = b"zk-eidas-test-anchor-A-root-v1";

/// Signer seed base — the per-fixture signer key is derived by
/// hashing `SIGNER_SEED_BASE || signer_seed_nonce.to_le_bytes()`.
const SIGNER_SEED_BASE: &[u8] = b"zk-eidas-test-anchor-A-signer-v1";

/// Derive a P-256 signing key deterministically from a 32-byte seed.
/// If the reduced scalar is zero, bump the seed and retry (vanishingly
/// rare for a SHA-256 output, but handled for paranoia).
fn derive_key(mut seed: [u8; 32]) -> SigningKey {
    loop {
        match SigningKey::from_bytes(&seed.into()) {
            Ok(sk) => return sk,
            Err(_) => {
                seed = Sha256::digest(seed).into();
            }
        }
    }
}

fn derive_root_key() -> SigningKey {
    derive_key(Sha256::digest(ROOT_SEED).into())
}

fn derive_signer_key(nonce: u32) -> SigningKey {
    let mut h = Sha256::new();
    h.update(SIGNER_SEED_BASE);
    h.update(nonce.to_le_bytes());
    derive_key(h.finalize().into())
}

fn sec1_uncompressed(sk: &SigningKey) -> [u8; 65] {
    let pt = sk.verifying_key().to_encoded_point(false);
    pt.as_bytes().try_into().expect("SEC1 uncompressed P-256 is 65 bytes")
}

// ── Byte surgery helpers ─────────────────────────────────────────────

/// Replace every occurrence of `needle` in `buf` with `rep`. Requires
/// `needle.len() == rep.len()` (length-preserving).
fn replace_all(buf: &mut [u8], needle: &[u8], rep: &[u8]) {
    assert_eq!(needle.len(), rep.len(), "replace_all requires equal lengths");
    if needle.is_empty() {
        return;
    }
    let n = needle.len();
    let mut i = 0;
    let mut hits = 0;
    while i + n <= buf.len() {
        if &buf[i..i + n] == needle {
            buf[i..i + n].copy_from_slice(rep);
            hits += 1;
            i += n;
        } else {
            i += 1;
        }
    }
    eprintln!(
        "  replace_all: {} hits for needle len {} ({:?} → {:?})",
        hits,
        n,
        String::from_utf8_lossy(needle),
        String::from_utf8_lossy(rep)
    );
}

/// Read the DER body length for a tag whose length field starts at
/// `pos + 1` (long-form `0x82` assumed — the signer cert, its TBS,
/// and signedAttrs all use 2-byte length encoding). Returns
/// `(header_len, body_len)`.
fn read_long_form_len(buf: &[u8], pos: usize) -> (usize, usize) {
    assert_eq!(
        buf[pos + 1],
        0x82,
        "expected long-form length at {pos:+1} (got {:#x})",
        buf[pos + 1]
    );
    let body_len = ((buf[pos + 2] as usize) << 8) | (buf[pos + 3] as usize);
    (4, body_len)
}

/// Locate the primary SignerInfo content_sig within the p7s. We walk
/// forward from `signed_attrs_end` looking for the signerInfo's
/// `signatureAlgorithm` AlgId (`30 0A 06 08 2A 86 48 CE 3D 04 03 02`),
/// then the immediately following `04 46 <70-byte ECDSA SEQ>`. This is
/// more robust than hardcoding the offset because the two DIIA
/// fixtures differ by one byte of signedAttrs body length.
fn locate_content_sig(buf: &[u8], signed_attrs_end: usize) -> usize {
    const ECDSA_ALG: &[u8] = &[
        0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
    ];
    const SIG_HDR: &[u8] = &[0x04, 0x46]; // OCTET STRING len 70

    let alg_idx = buf[signed_attrs_end..]
        .windows(ECDSA_ALG.len())
        .position(|w| w == ECDSA_ALG)
        .expect("signerInfo ecdsa-with-SHA256 AlgId not found after signedAttrs")
        + signed_attrs_end;
    let after_alg = alg_idx + ECDSA_ALG.len();
    assert_eq!(
        &buf[after_alg..after_alg + SIG_HDR.len()],
        SIG_HDR,
        "expected OCTET STRING 04 46 immediately after signerInfo AlgId at {after_alg}",
    );
    after_alg + SIG_HDR.len()
}

// ── Core: regenerate one fixture ─────────────────────────────────────

fn generate_synthetic(orig: &[u8]) -> Vec<u8> {
    assert!(
        orig.len() > CERT_START + CERT_LEN_TOTAL + 2500,
        "input too small to be a DIIA p7s fixture"
    );
    let mut buf = orig.to_vec();

    // Scope-guard: cert layout constants match the input.
    let (cert_hl, cert_body_len) = read_long_form_len(&buf, CERT_START);
    assert_eq!(
        cert_hl + cert_body_len,
        CERT_LEN_TOTAL,
        "unexpected cert outer SEQ length"
    );
    let (tbs_hl, tbs_body_len) = read_long_form_len(&buf, CERT_TBS_START);
    assert_eq!(
        tbs_hl + tbs_body_len,
        CERT_TBS_LEN_TOTAL,
        "unexpected TBSCertificate length"
    );

    // Locate signedAttrs end (body length varies per fixture).
    let (sa_hl, sa_body_len) = read_long_form_len(&buf, SIGNED_ATTRS_START);
    let signed_attrs_total = sa_hl + sa_body_len;
    let signed_attrs_end = SIGNED_ATTRS_START + signed_attrs_total;
    let content_sig_start = locate_content_sig(&buf, signed_attrs_end);
    eprintln!(
        "  signed_attrs: start={}, body_len={}, end={}",
        SIGNED_ATTRS_START, sa_body_len, signed_attrs_end
    );
    eprintln!("  content_sig_start: {}", content_sig_start);

    // Step 1: length-preserving DN substitutions.
    eprintln!("Step 1: DN substitutions");
    for (needle, rep) in DN_SUBS {
        replace_all(&mut buf, needle, rep);
    }

    // Step 2: splice synthetic signer SPKI (SEC1 uncompressed).
    eprintln!("Step 2: retry loop (signer_seed × serial_tweak)");
    let root_sk = derive_root_key();
    let root_pk = sec1_uncompressed(&root_sk);

    let (signer_seed, serial_tweak, signer_sk) =
        retry_until_both_sigs_fit(&mut buf, &root_sk, content_sig_start);

    let signer_pk = sec1_uncompressed(&signer_sk);

    eprintln!(
        "  converged: signer_seed={} serial_tweak={}",
        signer_seed, serial_tweak
    );
    eprintln!(
        "  synthetic signer SPKI X: {}",
        hex::encode(&signer_pk[1..33])
    );
    eprintln!(
        "  TestAnchorA root pk X (hex BE): {}",
        hex::encode(&root_pk[1..33])
    );
    eprintln!(
        "  TestAnchorA root pk Y (hex BE): {}",
        hex::encode(&root_pk[33..65])
    );
    eprintln!(
        "  TestAnchorA root pk X (decimal): {}",
        be_bytes_to_decimal(&root_pk[1..33])
    );
    eprintln!(
        "  TestAnchorA root pk Y (decimal): {}",
        be_bytes_to_decimal(&root_pk[33..65])
    );

    // Sanity: verify the spliced cert_sig verifies under the root.
    let tbs = &buf[CERT_TBS_START..CERT_TBS_START + CERT_TBS_LEN_TOTAL];
    let cert_sig_bytes = &buf[CERT_SIG_START..CERT_SIG_START + CERT_SIG_LEN];
    let parsed_cert_sig = Signature::from_der(cert_sig_bytes)
        .expect("spliced cert_sig must parse");
    use p256::ecdsa::signature::Verifier;
    VerifyingKey::from(&root_sk)
        .verify(tbs, &parsed_cert_sig)
        .expect("spliced cert_sig must verify under root_pk (sanity)");

    // Sanity: verify the spliced content_sig verifies under the signer pk
    // over the canonicalized signedAttrs.
    let canonical_sa = canonicalize_signed_attrs(&buf, signed_attrs_end);
    let content_sig_bytes = &buf[content_sig_start..content_sig_start + CERT_SIG_LEN];
    let parsed_content_sig = Signature::from_der(content_sig_bytes)
        .expect("spliced content_sig must parse");
    VerifyingKey::from(&signer_sk)
        .verify(&canonical_sa, &parsed_content_sig)
        .expect("spliced content_sig must verify under signer_pk (sanity)");

    buf
}

/// Canonicalize signedAttrs for signing: rewrite byte 0 from
/// `0xA0` (the [0] IMPLICIT tag) to `0x31` (the SET OF CAdES-canonical
/// tag), keeping everything else unchanged.
fn canonicalize_signed_attrs(buf: &[u8], signed_attrs_end: usize) -> Vec<u8> {
    let mut sa = buf[SIGNED_ATTRS_START..signed_attrs_end].to_vec();
    assert_eq!(sa[0], 0xA0, "signedAttrs must start with [0] IMPLICIT tag");
    sa[0] = 0x31;
    sa
}

/// Nested retry loop. For each `(signer_seed_nonce, serial_tweak)`
/// pair, compute the synthetic cert + signatures, splice them in, and
/// check both the cert_sig DER length and the content_sig DER length
/// match the original (72 bytes = 2B hdr + 70B body). Returns the
/// winning `(signer_seed, serial_tweak, signer_sk)` on convergence.
fn retry_until_both_sigs_fit(
    buf: &mut [u8],
    root_sk: &SigningKey,
    content_sig_start: usize,
) -> (u32, u32, SigningKey) {
    // The DIIA fixture's cert_sig region is 70 bytes of raw DER (a
    // complete ECDSA SEQ `30 44 02 20 r[32] 02 20 s[32]` — the leading
    // `30 44` IS the outer SEQ header, not a sibling). So any
    // `to_der()` call whose output is exactly 70 bytes fits
    // byte-for-byte into the region; anything longer (71+ bytes) means
    // r or s needed an extra leading-zero padding byte and we retry.
    const ORIG_DER_LEN: usize = CERT_SIG_LEN;

    for signer_seed_nonce in 0u32.. {
        if signer_seed_nonce > 10_000 {
            panic!("retry loop exceeded 10,000 seeds without convergence — bug?");
        }

        let signer_sk = derive_signer_key(signer_seed_nonce);
        let signer_pk_sec1 = sec1_uncompressed(&signer_sk);
        buf[SPKI_PK_START..SPKI_PK_START + SPKI_PK_LEN]
            .copy_from_slice(&signer_pk_sec1);

        for serial_tweak in 0u32..256 {
            // Tweak last 4 bytes of the 20-byte serial (LE u32 counter).
            buf[SERIAL_START + SERIAL_LEN - 4..SERIAL_START + SERIAL_LEN]
                .copy_from_slice(&serial_tweak.to_le_bytes());

            // Sign cert_tbs with root.
            let tbs = &buf[CERT_TBS_START..CERT_TBS_START + CERT_TBS_LEN_TOTAL];
            let cert_sig: Signature = root_sk.sign(tbs);
            let cert_sig_der = cert_sig.to_der();
            let cert_sig_der_bytes = cert_sig_der.as_bytes();
            if cert_sig_der_bytes.len() != ORIG_DER_LEN {
                continue;
            }

            // Splice cert_sig (skip 2-byte DER SEQ hdr — cert_sig region
            // holds only the inner r||s SEQ body prefixed by 30 44).
            buf[CERT_SIG_START..CERT_SIG_START + CERT_SIG_LEN]
                .copy_from_slice(cert_sig_der_bytes);

            // Recompute SHA-256(cert) and splice into ESSCertIDv2.
            let cert = &buf[CERT_START..CERT_START + CERT_LEN_TOTAL];
            let cert_digest = Sha256::digest(cert);
            buf[ESS_DIGEST_START..ESS_DIGEST_START + ESS_DIGEST_LEN]
                .copy_from_slice(&cert_digest);

            // Canonicalize signedAttrs, compute e2, sign with signer.
            let (sa_hl, sa_body_len) = read_long_form_len(buf, SIGNED_ATTRS_START);
            let signed_attrs_end = SIGNED_ATTRS_START + sa_hl + sa_body_len;
            let canonical_sa = {
                let mut sa = buf[SIGNED_ATTRS_START..signed_attrs_end].to_vec();
                sa[0] = 0x31;
                sa
            };
            let content_sig: Signature = signer_sk.sign(&canonical_sa);
            let content_sig_der = content_sig.to_der();
            let content_sig_der_bytes = content_sig_der.as_bytes();
            if content_sig_der_bytes.len() != ORIG_DER_LEN {
                continue;
            }

            // Splice content_sig (70-byte DER SEQ).
            buf[content_sig_start..content_sig_start + CERT_SIG_LEN]
                .copy_from_slice(content_sig_der_bytes);

            return (signer_seed_nonce, serial_tweak, signer_sk);
        }
    }
    unreachable!("u32::MAX signer seeds exhausted")
}

/// Big-endian 32-byte integer → decimal string (for submodule constant
/// regeneration). Each "digit" is a base-10^9 chunk; u64 arithmetic
/// keeps the inner `d * 256 + carry` expression from overflowing for
/// 256-bit inputs.
fn be_bytes_to_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u64> = vec![0];
    for &b in bytes {
        let mut carry = b as u64;
        for d in digits.iter_mut() {
            let v = *d * 256 + carry;
            *d = v % 1_000_000_000;
            carry = v / 1_000_000_000;
        }
        while carry > 0 {
            digits.push(carry % 1_000_000_000);
            carry /= 1_000_000_000;
        }
    }
    let mut out = String::new();
    let mut first = true;
    for d in digits.iter().rev() {
        if first {
            out.push_str(&format!("{}", d));
            first = false;
        } else {
            out.push_str(&format!("{:09}", d));
        }
    }
    if out.is_empty() {
        "0".into()
    } else {
        out
    }
}

// ── CLI ──────────────────────────────────────────────────────────────

const FIXTURE_FILES: &[&str] = &["binding.qkb.p7s", "admin-binding.qkb.p7s"];

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut output_dir: Option<PathBuf> = None;
    let mut in_place = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--output-dir" => {
                i += 1;
                output_dir = Some(PathBuf::from(&args[i]));
            }
            "--in-place" => {
                in_place = true;
            }
            "--help" | "-h" => {
                eprintln!(
                    "Usage: gen_synthetic_fixtures [--output-dir PATH | --in-place]\n\
                     \n\
                     Default (no flags): prints the generated SHA-256s but does not write.\n\
                     --output-dir PATH: writes regenerated fixtures into PATH/.\n\
                     --in-place: overwrites crates/zk-eidas-p7s/fixtures/*.p7s.\n"
                );
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
        i += 1;
    }

    if in_place && output_dir.is_some() {
        eprintln!("--output-dir and --in-place are mutually exclusive");
        std::process::exit(2);
    }

    let repo_root = repo_root();
    let fixtures_dir = repo_root.join("crates/zk-eidas-p7s/fixtures");

    if let Some(out) = &output_dir {
        std::fs::create_dir_all(out).expect("output dir");
    }

    for fname in FIXTURE_FILES {
        let src = fixtures_dir.join(fname);
        eprintln!("=== processing {} ===", fname);
        let orig = std::fs::read(&src).expect("read fixture");
        let syn = generate_synthetic(&orig);
        let digest = Sha256::digest(&syn);
        eprintln!("  output SHA-256: {}", hex::encode(digest));

        let dst: PathBuf = if let Some(out) = &output_dir {
            out.join(fname)
        } else if in_place {
            src
        } else {
            // Default: dry-run. Print only.
            eprintln!("  dry-run (no write)");
            continue;
        };
        std::fs::write(&dst, &syn).expect("write output");
        eprintln!("  wrote {}", dst.display());
    }
}

fn repo_root() -> PathBuf {
    // Run from anywhere in the workspace — locate by finding the
    // parent dir that contains a top-level Cargo.toml with [workspace].
    let mut cur = std::env::current_dir().expect("cwd");
    loop {
        let cargo = cur.join("Cargo.toml");
        if cargo.is_file() {
            let contents = std::fs::read_to_string(&cargo).unwrap_or_default();
            if contents.contains("[workspace]") {
                return cur;
            }
        }
        if !cur.pop() {
            panic!("could not locate workspace root");
        }
    }
}
