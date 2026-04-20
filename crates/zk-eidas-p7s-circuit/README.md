# zk-eidas-p7s-circuit

Rust facade over the Longfellow circuit that proves Phase-2a invariants on an
eIDAS 1 DIIA-QSTP-signed `.p7s` (PKCS#7 SignedData) witness. The crate wraps
the FFI surface exposed by `longfellow-sys::p7s` and handles witness blob
serialisation, public-input construction, and proof/verify plumbing.

## What the circuit proves

Given a DIIA qualified-binding-key PKCS#7 envelope (`fixtures/binding.qkb.p7s`)
and a verifier-chosen `context`, the prover produces a zero-knowledge proof
that the holder signed the bound JSON body (declaration + pk + nonce) under a
DIIA-issued qualified certificate, without revealing either the certificate
or the signed document. See `whitepaper/sections/evaluation.tex` for the
academic framing and paper-section invariant table.

## Invariants landed in Phase 2a

The eleven binding invariants enumerated in the umbrella design
(`docs/superpowers/specs/2026-04-20-eidas1-p7s-umbrella-design.md`) split
across Phase 2a (landed here) and Phase 2b (deferred). Eleven landed:

| # | Invariant | Task | What it binds |
|---|-----------|------|---------------|
| 1  | DIIA root cert signature | #29 | `cert_tbs` verifies under the compile-time-pinned DIIA QTSP 2311 root pubkey, MAC-bound to `e = SHA-256(cert_tbs)`. |
| 2a | Content signature | #26 | `signed_attrs` (CAdES-rewritten `0xA0`→`0x31`) verifies under the cert's SPKI, MAC-bound via SPKI X/Y. |
| 2b | messageDigest SHA-256 | #24 | `message_digest[32] == SHA-256(signed_content)`. |
| 2c | messageDigest ↔ signedAttrs | #31 | Anchored 17-byte DER prefix + 32-byte digest equality between `message_digest[]` and the OCTET STRING embedded in `signed_attrs` at the CMS messageDigest attribute. Closes the "honest cert + sigs, fake signed_content" substitution gap. |
| 4  | JSON pk byte equality | #20 | `signed_content[pk_offset..]` matches JSON-hex-decoded holder pk (= `public.pk`). |
| 5  | JSON nonce byte equality | #21 | `signed_content[nonce_offset..]` matches JSON-hex-decoded freshness nonce (= `public.nonce`). |
| 6  | JSON context byte equality | #22 | `signed_content[ctx_offset..]` matches host-supplied `context_bytes`. |
| 9  | context_hash SHA-256 | #28 | `public.context_hash == SHA-256(context_bytes)`. |
| 10 | Declaration whitelist | #23 | `signed_content[decl_offset..]` equals the compile-time DeclarationWhitelist phrase (N=1 today). |
| 11 | SPKI binding (cert_tbs ↔ JSON pk) | #26 (merged) | SEC1 uncompressed point embedded in cert_tbs's SubjectPublicKeyInfo byte-equals `public.pk`, anchored by a 26-byte DIIA P-256 SPKI DER prefix assertion. |

## Architecture

The circuit is **dual-field** (Task 25a) — two sub-circuits linked by a
cross-field MAC gadget:

- **Hash circuit over GF(2^128).** Carries every SHA-256 / byte-equality /
  whitelist-comparison invariant (2b, 2c, 4, 5, 6, 9, 10, 11). Cheap per
  gate, fast to commit, but cannot express P-256 scalar arithmetic.
- **Sig circuit over Fp256Base.** Runs two `VerifyCircuit` instances — one
  under the DIIA root (invariant 1), one under the cert's SPKI (invariant
  2a). `Fp256Base` is the base field of NIST P-256, matching the ECDSA
  verifier's native arithmetic.
- **MAC binding** (4 messages × 2 values = 8 GF(2^128) scalars) cross-binds
  the two circuits: `e`, `e2` (the two SHA-256 digests the signatures sign
  over) and the cert SPKI X, Y coordinates. Private values to both
  circuits, visible only via the MAC shares in the proof header.

The dual proof is framed as `u32 schema_version ‖ u8 macs_b[64] ‖ hash_zk ‖
sig_zk`, with each `ZkProof` component self-delimited per
`ZkProof::read`. Reference: `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.h`.

## Benchmark results

Reference run on a 2.6 GHz Intel, 8C/16T, 31 GB RAM, Linux 6.19,
`binding.qkb.p7s` fixture. Captured by `cargo run --release --bin
p7s_benchmark`; full output in `whitepaper/data/p7s-benchmark.log`,
machine-readable baseline in `whitepaper/data/p7s-benchmark.json`.

| Metric | p7s | mdoc 1-attr (reference) |
|---|---|---|
| Prove (cold, includes circuit setup) | ~28 s | ~13 s (hash only) + 1.3 s prove |
| Prove (warm, median of 5) | ~1.5 s | ~1.3 s |
| Verify (median of 5) | ~570 ms | ~470 ms |
| Proof size (total) | ~1040 KB | ~372 KB |
| Proof header (schema + macs_b) | 68 B | 68 B |
| Witness blob size | 5038 B | n/a (typed args) |
| Peak RSS (post-call) | ~1234 MB | ~1283 MB |

p7s is **~12% slower warm-prove** than mdoc 1-attr (expected: two ECDSA
`VerifyCircuit` instances vs one) and **~2.8× larger proof** (expected:
dual `ZkProof` payload — hash_zk over GF(2^128) + sig_zk over Fp256Base).
Cold prove is dominated by circuit setup for both sub-circuits; warm prove
matches the steady-state production model (circuits pre-generated at
build time per deployment notes).

RSS is the `VmRSS` read immediately after the FFI call returns, not a
true peak — the same shortcut mdoc's bench uses (handoff §7.3). Longfellow
emits `[INFO][+Nms]` stderr lines during each prove/verify that give a
cleaner per-phase breakdown (commit, sumcheck, constraints); those are
captured verbatim in `p7s-benchmark.log`.

QR delivery: at 2945 useful bytes per QR V40 low-ECC chunk (see
`demo/web/app/lib/qr-chunking.ts`), the ~1040 KB proof fits in **~361
chunks**, vs mdoc's ~127.

## How to run

```sh
# Human-readable table
cargo run -p zk-eidas-p7s-circuit --release --bin p7s_benchmark

# Machine-readable baseline (pipe to whitepaper/data/p7s-benchmark.json)
cargo run -p zk-eidas-p7s-circuit --release --bin p7s_benchmark -- --json
```

Single-threaded by design. Parallelising prove invocations OOMs a 32 GB
machine (ECDSA sig-circuit is memory-heavy).

## Known caveats

- **DER re-encode on cert_sig / content_sig — permanent deferral.** The
  Rust host DER-parses both P-256 signatures and supplies raw (r, s)
  scalars to the circuit. The circuit proves "some (r, s) verifies"; it
  does not bind the raw DER bytes to (r, s). Downstream callers that
  commit to the raw p7s bytes via another channel are unaffected
  (`PublicInputs` does not expose those bytes). Documented at
  `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.h:112-118`.
- **DIIA-only trust anchor.** The DIIA QTSP 2311 root pubkey is a
  compile-time constant in the C++ sig circuit
  (`sub/p7s_signature.h`). Other QTSPs require a fresh circuit build —
  trust-anchor agility is a Phase 2b concern.
- **Same-holder fixtures.** Both bundled fixtures share a subject and
  therefore a SPKI offset. SPKI-offset variance coverage is
  host-witnessed and structurally exercised by #26's soundness
  negatives (wrong_spki_offset rejected by the 26-byte prefix anchor);
  a cross-holder fixture would add an empirical third data point and
  is tracked as a test-coverage follow-up, not blocking Phase 2a exit.
- **No circuit caching.** Each `prove()` call reconstructs the circuit
  FFI-side. The ~28 s cold-prove includes setup; warm numbers
  approximate steady-state but a proper pre-built-and-mmap-cached
  layer is a Phase 2b / deployment-track task.
- **Regression guards deferred.** The baseline JSON
  (`whitepaper/data/p7s-benchmark.json`) is one data point from one
  machine. Two or three additional independent runs are needed before
  soft / hard regression thresholds can be set with real noise data.
  Tracked as a future task, not blocking Phase 2a exit (handoff §5 /
  §8 Q5).
- **In-circuit SPKI / messageDigest anchors are single-defence.** The
  ECDSA invariants (1, 2a) are defended twice over: both by the
  in-circuit verifier and by the host DER parse. The anchor-only
  invariants (11 SPKI prefix, 2c messageDigest prefix) rely on the
  26-byte / 17-byte prefix equality plus host witnessing. Test
  coverage for the anchor-only paths lives in `tests/invariant_2a.rs`
  and `tests/invariant_2c.rs` via the `test-bypass-host-anchors`
  feature-gated FFI; adding feature-gated tests for the ECDSA paths
  is tracked for Phase 2b.

## What Phase 2b inherits

- **Invariant 3** — DER structural validation (structured walker over
  `cert_tbs` / `signed_content` rather than host-witnessed offsets).
- **Invariant 7** — nullifier derivation. Requires stable-id
  commitment (binding_hash) plumbed in-circuit against the signer
  cert's `subject.serialNumber`.
- **Invariant 8** — holder binding. Requires the stable-id path
  above plus a session-bound ephemeral pk commitment.
- **DER re-encode cost bound.** Replace host DER parsing with
  span-tracking so `cert_sig` / `content_sig` DER bytes are bound
  in-circuit (closes the permanent-deferral caveat above).
- **Trust-anchor agility.** Make the DIIA root a runtime input
  instead of a compile-time constant so multi-QTSP deployments don't
  require per-QTSP circuit builds.
- **In-circuit anchor-only test coverage.** Feature-gated negative
  tests for invariants 11 and 2c paired against invariants 1 and 2a
  (the asymmetry reviewer flagged in #31).

## Architecture pointers

- Umbrella design: `docs/superpowers/specs/2026-04-20-eidas1-p7s-umbrella-design.md`
- Phase 2a circuit design: `docs/superpowers/specs/2026-04-20-phase2a-circuit-design.md`
- Dual-circuit bring-up: `docs/superpowers/specs/handoff-25a-dual-circuit.md`
- SPKI binding: `docs/superpowers/specs/handoff-30-spki-binding.md`
- messageDigest binding: `docs/superpowers/specs/handoff-31-messagedigest-binding.md`
- Bench handoff: `docs/superpowers/specs/handoff-27-bench.md`
- Paper evaluation: `whitepaper/sections/evaluation.tex`
