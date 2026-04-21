//! Deterministic synthetic-fixture generator.
//!
//! Supports N≥2 trust anchors as parameterized `SyntheticAnchorParams`
//! entries. Each anchor produces a pair of re-signed `.p7s` fixtures
//! derived from the committed baseline. TestAnchorA (`ANCHORS[0]`) keeps
//! its existing output byte-identical — its seeds, DN substitutions, and
//! output filenames are fixed. TestAnchorB (`ANCHORS[1]`, added in
//! Task #44) differs in seed strings (yielding a distinct root pk),
//! DN-org text, and reg-code / stable-ID markers (yielding a distinct
//! `TRUST_ANCHOR_PROBES` match), and emits output to `testanchor-b-*.p7s`.
//!
//! Surgery steps per anchor:
//!   1. Apply the universal `TSA_SUBS` table (TSA region branding;
//!      same for every anchor).
//!   2. Apply the anchor's `dn_subs` table (DN-identifying text +
//!      QTSP reg-code + stable-ID — length-preserving).
//!   3. Re-sign the cert_tbs with the anchor's root key, splice the
//!      signature into the cert BIT STRING.
//!   4. Recompute SHA-256(cert), splice into ESSCertIDv2.
//!   5. Re-sign the canonicalized signedAttrs with the anchor's
//!      signer key, splice into the primary content_sig.
//!
//! TSA countersignature bytes are LEFT AS-IS for both anchors — no
//! circuit invariant reads the TSA path (#43a scope decision; TSA
//! surgery tracked by #45, already merged upstream of this task).
//!
//! ## Determinism
//!
//! All signing uses RFC 6979 (p256's `SigningKey::sign` default). Root
//! and signer secret keys are derived from fixed seed strings via
//! SHA-256 → scalar reduction. The `(signer_seed_nonce, serial_tweak)`
//! retry loop iterates in a fixed order. Running the generator twice
//! with no code changes produces byte-identical output for EVERY anchor
//! — verified by `--output-dir` + `diff -rq` in CI.
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

use std::path::PathBuf;

use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

// ── Scope guards ─────────────────────────────────────────────────────
//
// These constants pin the baseline fixture layout. Any drift means the
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
/// (leading `0x04` byte). The 26-byte P-256 SPKI DER prefix that
/// precedes it is unchanged (same OID bytes for every P-256 QTSP, so
/// the in-circuit prefix anchor stays valid for every synthetic anchor).
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
/// because the two baseline fixtures differ by one byte of signedAttrs
/// body length (`binding.qkb.p7s` vs `admin-binding.qkb.p7s`).
const SIGNED_ATTRS_START: usize = 2477;

/// Offset of the primary content_sig's 70-byte ECDSA SEQ value. Note:
/// the two baseline fixtures differ — `binding.qkb.p7s` has it at 3878,
/// `admin-binding.qkb.p7s` at 3879 (one-byte shift from the longer
/// signedAttrs body). The generator locates this from the signedAttrs
/// end rather than hardcoding.
#[allow(dead_code)]
const CONTENT_SIG_LEN: usize = 70;

// ── Length-preserving TSA region substitution table (Task 45) ────────
//
// These strings appear exclusively in (or primarily in) the TSA
// countersignature region. They are applied globally like `dn_subs` for
// EVERY anchor — the TSA region is neutralized once and shared across
// anchors. Any occurrences inside the signer cert TBS or signedAttrs
// are covered by the subsequent per-anchor re-signing steps (cert_sig
// + content_sig), so the output remains self-consistent.

const TSA_SUBS: &[(&[u8], &[u8])] = &[
    // 22-byte pair: TSA cert common name.
    (
        b"TSA-server QTSP \"DIIA\"",
        b"TSA-server QTSP \"TSYN\"",
    ),
    // 45-byte pair: TSA issuer organisation.
    (
        b"Ministry of digital transformation of Ukraine",
        b"Ukrainian Test TSA Authority (fixture only)  ",
    ),
    // 16-byte pair: TSA cert serialNumber UA-43395033-2552 (QTSP TSA).
    (b"UA-43395033-2552", b"TQSA-00000000-02"),
    // 16-byte pair: TSA cert serialNumber UA-43395033-2506 (TSA root).
    (b"UA-43395033-2506", b"TQSA-00000000-03"),
    // 14-byte pair: TSA CA hostname (rfc822Name + URI host).
    (b"ca.diia.gov.ua", b"ca.synth.local"),
    // 14-byte pair: TSA CA email in Subject Alternative Name.
    (b"ca@diia.gov.ua", b"ca@synth.local"),
    // 10-byte pair: certificate bundle filename inside a URI extension.
    (b"diia_ecdsa", b"test_ecdsa"),
];

// ── TestAnchorA DN substitution table ────────────────────────────────
//
// Each (needle, replacement) pair is byte-identical in length. Applied
// to the signer cert TBS + signedAttrs region for TestAnchorA. Order
// matters only for overlap avoidance — longer needles first so we
// don't accidentally match a shorter needle inside a longer one.
//
// The reg-code `TQSA-00000000-01` is the marker the host-side
// `TRUST_ANCHOR_PROBES` uses to identify TestAnchorA.

const DN_SUBS_TESTANCHOR_A: &[(&[u8], &[u8])] = &[
    // 41-byte pair.
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
    //
    // NOTE: the subject-DN PII substitutions (commonName / stable-ID /
    // givenName / surname) were removed from this table after the
    // Phase 2b push because the committed fixture is already
    // post-substitution — the generator finds zero matches for those
    // needles and the entries were dead code carrying source-side PII.
    // The table below covers the non-PII, publicly-registered QTSP
    // identifiers only. To re-derive a TestAnchorA fixture from a
    // pristine DIIA p7s, restore those four entries out-of-tree.
    //
    // 16-byte pair (QTSP reg-code — the TRUST_ANCHOR_PROBES marker).
    (b"UA-43395033-2311", b"TQSA-00000000-01"),
    // 14-byte pair (legal entity reg code).
    (b"NTRUA-43395033", b"NTRUA-00000000"),
    // 4-byte pair (locality).
    (b"Kyiv", b"Test"),
];

// ── TestAnchorB DN substitution table (Task #44) ─────────────────────
//
// The committed baseline fixture is ALREADY post-TestAnchorA-substitution
// (the pre-A DIIA form is not stored in the tree). So the TestAnchorB
// generator reads the A-shaped fixture and performs a *delta* rewrite
// from TestAnchorA text to TestAnchorB text — the needles below are
// A's replacements, not DIIA originals.
//
// Same length constraints as TestAnchorA. The DN-identifying strings
// differ so the two anchors are distinguishable to a human reader and
// so the `TRUST_ANCHOR_PROBES` marker is unique per anchor. The
// QTSP reg-code is `TQSB-00000000-02` (16 bytes) — B for "second
// synthetic anchor", distinct from A's `TQSA-00000000-01`.
//
// Invariant: every (needle, replacement) must be byte-identical in
// length. Order: longer needles first.

const DN_SUBS_TESTANCHOR_B: &[(&[u8], &[u8])] = &[
    // 41-byte pair.
    (
        b"\"Test\". Synthetic Trust Services Provider",
        b"\"TstB\". Fixture-B Trust Services Provider",
    ),
    // 39-byte pair.
    (
        b"Synthetic Electronic Trust Services Dpt",
        b"Fixture-B Electronic Trust Services Dpt",
    ),
    // 23-byte pair.
    (
        b"Synthetic Test QTSP Inc",
        b"Fixture-B Test QTSP Inc",
    ),
    // 20-byte pair (subject DN commonName — note trailing space).
    (b"Test Holder Subject ", b"FixtureB Holder Sub "),
    // 16-byte pair (QTSP reg-code — the TRUST_ANCHOR_PROBES marker).
    (b"TQSA-00000000-01", b"TQSB-00000000-02"),
    // 16-byte pair (subject stable-ID).
    (b"TINUA-1111111111", b"TINUB-2222222222"),
    // 14-byte pair (legal entity reg code).
    (b"NTRUA-00000000", b"NTRUB-00000000"),
    // 10-byte pair (subject givenName — trailing space).
    (b"TestHoldr ", b"TestHoldB "),
    // 9-byte pair (subject surname).
    (b"TestHoldX", b"FixtrHldB"),
    // 4-byte pair (locality) — A rewrote Kyiv→Test, so B needle is Test.
    //
    // CAVEAT: "Test" is a very common 4-byte substring; `replace_all` is
    // indiscriminate, so some non-locality occurrences may flip too.
    // Safe because the surgery re-signs the cert after the substitution
    // (any incidental flips are absorbed into the new cert_sig and
    // content_sig). The only region not re-signed is the TSA
    // countersignature, which already has stale bytes by design
    // (#43a / #45).
    (b"Test", b"TstB"),
];

// ── Parameterized anchor spec ────────────────────────────────────────
//
// One `SyntheticAnchorParams` value per distinct trust anchor. The
// generator iterates `ANCHORS[]` and emits the full `{binding,
// admin-binding}` pair for each — prefixed by `output_prefix` so
// outputs don't collide. TestAnchorA uses the empty prefix for
// backwards compatibility with the already-committed filenames.

struct SyntheticAnchorParams {
    /// Human-readable name for logging.
    name: &'static str,
    /// Seed string fed to SHA-256 to derive the root CA signing key.
    root_seed: &'static [u8],
    /// Seed base for signer keys. Per-fixture key is derived by
    /// hashing `signer_seed_base || signer_seed_nonce.to_le_bytes()`.
    signer_seed_base: &'static [u8],
    /// Length-preserving DN substitution table for this anchor.
    dn_subs: &'static [(&'static [u8], &'static [u8])],
    /// Output filename prefix (e.g. `""` or `"testanchor-b-"`). The
    /// baseline filenames from `FIXTURE_FILES` get concatenated after
    /// the prefix, so `testanchor-b-binding.qkb.p7s` etc.
    output_prefix: &'static str,
}

const ANCHORS: &[SyntheticAnchorParams] = &[
    SyntheticAnchorParams {
        name: "TestAnchorA",
        root_seed: b"zk-eidas-test-anchor-A-root-v1",
        signer_seed_base: b"zk-eidas-test-anchor-A-signer-v1",
        dn_subs: DN_SUBS_TESTANCHOR_A,
        output_prefix: "",
    },
    SyntheticAnchorParams {
        name: "TestAnchorB",
        root_seed: b"zk-eidas-p7s-testanchor-b-root-v1",
        signer_seed_base: b"zk-eidas-p7s-testanchor-b-signer-v1",
        dn_subs: DN_SUBS_TESTANCHOR_B,
        output_prefix: "testanchor-b-",
    },
];

// ── Deterministic key derivation ─────────────────────────────────────

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

fn derive_root_key(root_seed: &[u8]) -> SigningKey {
    derive_key(Sha256::digest(root_seed).into())
}

fn derive_signer_key(signer_seed_base: &[u8], nonce: u32) -> SigningKey {
    let mut h = Sha256::new();
    h.update(signer_seed_base);
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
/// more robust than hardcoding the offset because the two baseline
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

// ── Core: regenerate one fixture for one anchor ──────────────────────

fn generate_synthetic(orig: &[u8], anchor: &SyntheticAnchorParams) -> Vec<u8> {
    assert!(
        orig.len() > CERT_START + CERT_LEN_TOTAL + 2500,
        "input too small to be a baseline p7s fixture"
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

    // Step 1a: length-preserving TSA region substitutions (Task 45).
    eprintln!("Step 1a: TSA region substitutions");
    for (needle, rep) in TSA_SUBS {
        replace_all(&mut buf, needle, rep);
    }

    // Step 1b: length-preserving DN substitutions (per-anchor).
    eprintln!("Step 1b: DN substitutions ({})", anchor.name);
    for (needle, rep) in anchor.dn_subs {
        replace_all(&mut buf, needle, rep);
    }

    // Step 2: splice synthetic signer SPKI (SEC1 uncompressed).
    eprintln!("Step 2: retry loop (signer_seed × serial_tweak)");
    let root_sk = derive_root_key(anchor.root_seed);
    let root_pk = sec1_uncompressed(&root_sk);

    let (signer_seed, serial_tweak, signer_sk) = retry_until_both_sigs_fit(
        &mut buf,
        &root_sk,
        anchor.signer_seed_base,
        content_sig_start,
    );

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
        "  {} root pk X (hex BE): {}",
        anchor.name,
        hex::encode(&root_pk[1..33])
    );
    eprintln!(
        "  {} root pk Y (hex BE): {}",
        anchor.name,
        hex::encode(&root_pk[33..65])
    );
    eprintln!(
        "  {} root pk X (decimal): {}",
        anchor.name,
        be_bytes_to_decimal(&root_pk[1..33])
    );
    eprintln!(
        "  {} root pk Y (decimal): {}",
        anchor.name,
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
    signer_seed_base: &[u8],
    content_sig_start: usize,
) -> (u32, u32, SigningKey) {
    const ORIG_DER_LEN: usize = CERT_SIG_LEN;

    for signer_seed_nonce in 0u32.. {
        if signer_seed_nonce > 10_000 {
            panic!("retry loop exceeded 10,000 seeds without convergence — bug?");
        }

        let signer_sk = derive_signer_key(signer_seed_base, signer_seed_nonce);
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

    for anchor in ANCHORS {
        eprintln!("======== anchor: {} ========", anchor.name);
        for fname in FIXTURE_FILES {
            let src = fixtures_dir.join(fname);
            let out_fname = format!("{}{}", anchor.output_prefix, fname);
            eprintln!("=== processing {} → {} ===", fname, out_fname);
            let orig = std::fs::read(&src).expect("read baseline fixture");
            let syn = generate_synthetic(&orig, anchor);
            let digest = Sha256::digest(&syn);
            eprintln!("  output SHA-256: {}", hex::encode(digest));

            let dst: PathBuf = if let Some(out) = &output_dir {
                out.join(&out_fname)
            } else if in_place {
                fixtures_dir.join(&out_fname)
            } else {
                // Default: dry-run. Print only.
                eprintln!("  dry-run (no write)");
                continue;
            };
            std::fs::write(&dst, &syn).expect("write output");
            eprintln!("  wrote {}", dst.display());
        }
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
