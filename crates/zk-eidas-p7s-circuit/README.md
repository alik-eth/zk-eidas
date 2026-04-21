# zk-eidas-p7s-circuit

Rust facade over the Longfellow circuit that proves Phase 2b invariants on
an eIDAS 1 CAdES-BES `.p7s` (PKCS#7 SignedData) witness. The crate wraps
the FFI surface exposed by `longfellow-sys::p7s` and handles witness blob
serialisation, public-input construction, and proof/verify plumbing.

## What the circuit proves

Given a CAdES-BES qualified-binding-key PKCS#7 envelope (for example,
`fixtures/binding.qkb.p7s` — a synthetic TestAnchorA fixture derived from
a real DIIA QKB and PII-scrubbed in Task #43a) and a verifier-chosen
`context`, the prover produces a zero-knowledge proof that the holder
signed the bound JSON body (declaration + pk + nonce + timestamp) under
a qualified certificate issued by one of the trust anchors in the
compile-time `kTrustAnchors[]` table. Neither the certificate nor the
signed document is revealed. See `whitepaper/sections/evaluation.tex`
for the academic framing.

## Invariants landed in Phase 2b

Thirteen binding invariants are enumerated in the umbrella design
(`docs/superpowers/specs/2026-04-20-eidas1-p7s-umbrella-design.md`).
Phase 2a landed ten (invariants 1, 2a, 2b, 2c, 4, 5, 6, 9, 10, 11).
Phase 2b adds invariants 7 (nullifier) and 8 (holder binding), leaving
invariant 3 (DER structural validation) deferred to Phase 2c — see the
DER-walker handoff below.

| # | Invariant | Task | What it binds |
|---|-----------|------|---------------|
| 1  | Trust-anchor cert signature | #29, #36, #44 | `cert_tbs` verifies under the compile-time-pinned QTSP root selected from `kTrustAnchors[]` by the public `trust_anchor_index`, MAC-bound to `e = SHA-256(cert_tbs)`. Phase 2b ships N=2 (TestAnchorA + TestAnchorB) with a real in-circuit multiplexer. |
| 2a | Content signature | #26 | `signed_attrs` (CAdES-rewritten `0xA0`→`0x31`) verifies under the cert's SPKI, MAC-bound via SPKI X/Y. |
| 2b | messageDigest SHA-256 | #24 | `message_digest[32] == SHA-256(signed_content)`. |
| 2c | messageDigest ↔ signedAttrs | #31 | Anchored 17-byte DER prefix + 32-byte digest equality between `message_digest[]` and the OCTET STRING embedded in `signed_attrs` at the CMS messageDigest attribute. Closes the "honest cert + sigs, fake signed_content" substitution gap. |
| 4  | JSON pk byte equality | #20 | `signed_content[pk_offset..]` matches JSON-hex-decoded holder pk (= `public.pk`). |
| 5  | JSON nonce byte equality | #21 | `signed_content[nonce_offset..]` matches JSON-hex-decoded freshness nonce (= `public.nonce`). |
| 6  | JSON context byte equality | #22 | `signed_content[ctx_offset..]` matches host-supplied `context_bytes`. |
| 7  | Nullifier from stable-ID | #34, #41 | `public.nullifier == SHA-256(stable_id ‖ context)`, where `stable_id` is extracted from the signer cert's `subject.serialNumber` attribute. Anchored by a 9-byte X.520 serialNumber DER prefix and a range-checked `subject_sn_offset > subject_dn_start_offset` in-circuit to reject issuer-DN collisions. |
| 8  | Holder binding | #35, #40 | `public.binding_hash` commits to `SHA-256(stable_id)` (out-of-circuit in Phase 2b — in-circuit wiring is tracked for Phase 2c when the ephemeral-key binding lands). |
| 9  | context_hash SHA-256 | #28 | `public.context_hash == SHA-256(context_bytes)`. |
| 10 | Declaration whitelist | #23 | `signed_content[decl_offset..]` equals the compile-time DeclarationWhitelist phrase (N=1 today). |
| 11 | SPKI binding (cert_tbs ↔ JSON pk) | #26 (merged) | SEC1 uncompressed point embedded in cert_tbs's SubjectPublicKeyInfo byte-equals `public.pk`, anchored by a 26-byte P-256 SPKI DER prefix assertion. |

**Deferred:** invariant 3 (DER structural validation) requires a
general-purpose in-circuit DER walker that materially changes the
cost profile. The research handoff (`docs/superpowers/specs/
handoff-33-der-walker.md`, Task #33) recommended deferral to Phase 2c;
Task #38 formally records the deferral. Today's host-witnessed offsets
are defended by the in-circuit prefix anchors (2c, 7, 11) plus
host-side DER parsing, which together close the "lying-offset"
soundness gap for the specific attributes the circuit reads.

## Architecture

The circuit is **dual-field** (Task 25a) — two sub-circuits linked by a
cross-field MAC gadget:

- **Hash circuit over GF(2^128).** Carries every SHA-256 / byte-equality /
  whitelist-comparison / nullifier invariant (2b, 2c, 4, 5, 6, 7, 9, 10, 11).
  Cheap per gate, fast to commit, but cannot express P-256 scalar
  arithmetic.
- **Sig circuit over Fp256Base.** Runs two `VerifyCircuit` instances — one
  under the trust-anchor root selected from `kTrustAnchors[]` (invariant
  1), one under the cert's SPKI (invariant 2a). `Fp256Base` is the base
  field of NIST P-256, matching the ECDSA verifier's native arithmetic.
- **MAC binding** (4 messages × 2 values = 8 GF(2^128) scalars) cross-binds
  the two circuits: `e`, `e2` (the two SHA-256 digests the signatures sign
  over) and the cert SPKI X, Y coordinates. Private values to both
  circuits, visible only via the MAC shares in the proof header.

The dual proof is framed as `u32 schema_version ‖ u8 macs_b[64] ‖ hash_zk ‖
sig_zk`, with each `ZkProof` component self-delimited per
`ZkProof::read`. Reference: `vendor/longfellow-zk/lib/circuits/p7s/p7s_zk.h`.

### N=2 trust-anchor multiplexer (Task #44)

`kTrustAnchors[]` is a compile-time array of `(root_pk_x, root_pk_y)`
pairs in `vendor/longfellow-zk/lib/circuits/p7s/sub/p7s_signature.h`.
The public `trust_anchor_index` u32 selects which entry the cert-sig
ECDSA verifies under. Two independent guards pin the valid range:

1. **Hash-circuit bound check.** `lc.assert1(lc.vlt(trust_anchor_index,
   kTrustAnchorCount))` — a v32 range check that rejects any index
   ≥ `kTrustAnchorCount` regardless of what the prover claims.
2. **Sig-circuit 2-way mux.** The sig circuit receives the index as a
   public Fp256Base EltW and constrains it with `idx * (idx - 1) == 0`
   (the canonical "bit" predicate), then computes
   `root_pk_x = k0_x + idx * (k1_x - k0_x)` and symmetric for Y.
   For N=2 this is an exact one-hot linear interpolation; N>2 would
   replace it with a generic Σᵢ Lagrangeᵢ(idx) · kᵢ construction and
   tighten the range constraint (flagged by a `static_assert` in
   `build_sig_circuit`).

Cross-binding between the two sides is **by construction, not by
MAC**: the verifier parses one public blob and pushes the SAME u32
into both circuits. If a malicious prover tried to make the two sides
disagree, the ZK-proof framing — in which both circuits share the same
transcript — would surface the inconsistency as a rejected commitment.

Phase 2b ships with two synthetic anchors (TestAnchorA + TestAnchorB,
Task #44) so the multiplexer is a real 2-way branch rather than a
degenerate "always entry 0" shortcut. Real QTSP anchors arrive with
Task #37 once non-PII production fixtures land; the mux generalises
cleanly.

### Verifier posture (trust model)

The circuit today is **off-chain verifier** only. A verifier runs
`longfellow-sys::p7s::verify(&proof, &public)`, which calls the Rust
FFI, which calls the Longfellow C++ `p7s_verify` and returns a
bool. There is no on-chain equivalent yet — the proof framing
(`~1 MB` dual-ZkProof) and the verifier cost (≈700 ms per proof,
dominated by Sumcheck re-evaluation and Ligero proximity checks) are
both orders of magnitude above what an EVM precompile could
accommodate.

On-chain verification (Solidity / Move / Risc0-in-EVM) is a
**Phase 3** deliverable. The current design makes no irrevocable
commitment to the off-chain path: the public blob is a stable u32
+ 32-byte values that can be passed to any future verifier
implementation, and the transcript seed (`p7s-v11-hash-seed-*`)
will bump to signal a verifier-incompatible change.

## Benchmark results

Reference run on a 2.6 GHz Intel, 8C/16T, 31 GB RAM, Linux 6.19, all
four committed fixtures. Captured by `cargo run --release --bin
p7s_benchmark`; full output in `whitepaper/data/p7s-benchmark.log`,
machine-readable baseline in `whitepaper/data/p7s-benchmark.json`.

Bench walks each fixture in order; only the first fixture incurs the
one-time in-FFI circuit build (~28 s cold prove). Every subsequent
fixture sees a warm circuit on its "first prove" and is labelled
accordingly.

| Metric | TestAnchorA (binding) | TestAnchorA (admin) | TestAnchorB (binding) | TestAnchorB (admin) |
|---|---|---|---|---|
| Trust-anchor index | 0 | 0 | 1 | 1 |
| First prove | 28.50 s (cold circuit) | 1.91 s (warm) | 2.05 s (warm) | 1.84 s (warm) |
| Prove (warm, median of 5) | 2.00 s | 1.85 s | 1.87 s | 1.86 s |
| Verify (median of 5) | 738 ms | 743 ms | 732 ms | 742 ms |
| Proof size (total) | 1046 KB | 1047 KB | 1046 KB | 1046 KB |
| Proof header (schema + macs_b) | 68 B | 68 B | 68 B | 68 B |
| Witness blob size | 5050 B | 5050 B | 5050 B | 5050 B |
| Public blob size | 169 B | 169 B | 169 B | 169 B |
| QR chunks (V40 low-ECC) | 364 | 365 | 364 | 364 |
| Peak RSS (post-call) | 1253 MB | 1253 MB | 1253 MB | 1253 MB |

The per-fixture timing is within run-to-run noise: proof size,
circuit shape, and witness/public blob layouts are identical across
anchors because the N=2 mux evaluates a linear combination whose cost
is independent of which branch is selected. This is the expected
behaviour — the multiplexer is functionally transparent to bench
metrics. The ~5% spread on warm-prove median across fixtures reflects
measurement noise on a multi-process Linux system, not an
anchor-dependent cost.

**Phase 2b vs Phase 2a deltas.** Warm prove moves from ~1.48 s →
~1.85 s (+25%) and verify from ~567 ms → ~738 ms (+30%), driven
primarily by the additional SHA-256 for invariant 7 (nullifier) plus
the two new MAC-bound coordinates for SPKI-X / SPKI-Y binding in the
hash circuit. Proof size grows from ~1038 KB → ~1046 KB (+8 KB,
+0.8%), dominated by the extra 32×v8 wires for the nullifier public
output. RSS is unchanged.

QR delivery: at 2945 useful bytes per QR V40 low-ECC chunk (see
`demo/web/app/lib/qr-chunking.ts`), each ~1046 KB proof fits in
**364 chunks**.

## How to run

```sh
# Human-readable table per fixture
cargo run -p zk-eidas-p7s-circuit --release --bin p7s_benchmark

# Machine-readable baseline (pipe to whitepaper/data/p7s-benchmark.json)
cargo run -p zk-eidas-p7s-circuit --release --bin p7s_benchmark -- --json \
  > whitepaper/data/p7s-benchmark.json \
  2> whitepaper/data/p7s-benchmark.log
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
- **Synthetic trust anchors only.** Phase 2b ships with TestAnchorA and
  TestAnchorB, both produced by
  `crates/zk-eidas-p7s/src/bin/gen_synthetic_fixtures.rs`. Real QTSP
  anchors require non-PII production fixtures and are tracked as
  Task #37. Adding a third anchor is purely additive on both the
  circuit side (append to `kTrustAnchors[]`) and the host side
  (append to `TRUST_ANCHOR_PROBES` in `crates/zk-eidas-p7s/src/
  parser.rs`), with the mux generalisation note above.
- **Same-holder fixtures per anchor.** Both TestAnchorA fixtures share
  a subject SPKI offset, and both TestAnchorB fixtures share a
  (different) subject SPKI offset. SPKI-offset variance coverage is
  host-witnessed and structurally exercised by #26's soundness
  negatives (wrong_spki_offset rejected by the 26-byte prefix anchor);
  a cross-holder fixture within each anchor would add an empirical
  third data point and is tracked as a test-coverage follow-up.
- **No circuit caching.** Each `prove()` call reconstructs the circuit
  FFI-side. The ~27 s cold-prove includes setup; warm numbers
  approximate steady-state. A proper pre-built-and-mmap-cached layer
  is a deployment-track task.
- **Regression guards deferred.** The baseline JSON
  (`whitepaper/data/p7s-benchmark.json`) is one data point from one
  machine. Two or three additional independent runs are needed before
  soft / hard regression thresholds can be set with real noise data.
- **In-circuit DER structural validation (invariant 3).** Deferred to
  Phase 2c pending the DER walker design (handoff #33).
- **Invariant 8 is out-of-circuit in Phase 2b.** Holder binding today
  is enforced by the host committing to `SHA-256(stable_id)` via
  `PublicInputs.binding_hash`; the in-circuit ephemeral-key binding
  is tracked for Phase 2c.
- **Off-chain verifier only.** See "Verifier posture" above.

## What Phase 2c inherits

- **Invariant 3** — DER structural validation via an in-circuit DER
  walker (handoff-33 recommends a gated research→implement path).
- **Invariant 8 in-circuit binding.** Promote the ephemeral-key +
  nonce commitment from host-witnessed to circuit-enforced.
- **DER re-encode cost bound.** Replace host DER parsing with
  span-tracking so `cert_sig` / `content_sig` DER bytes are bound
  in-circuit (closes the permanent-deferral caveat above).
- **Real QTSP fixtures.** Task #37 — add a third trust-anchor entry
  keyed to a production QTSP once non-PII fixtures are obtainable.
- **On-chain verifier path.** Compile the Longfellow verifier into a
  size- and gas-tractable target (candidate: Risc0-in-EVM, or a
  hand-translated Solidity verifier for a restricted circuit subset).
- **Cross-holder fixture coverage.** Per-anchor holder diversity
  under the same trust anchor.

## Architecture pointers

- Umbrella design: `docs/superpowers/specs/2026-04-20-eidas1-p7s-umbrella-design.md`
- Phase 2a circuit design: `docs/superpowers/specs/2026-04-20-phase2a-circuit-design.md`
- Phase 2b plan: `docs/superpowers/plans/2026-04-20-phase2b.md`
- Dual-circuit bring-up: `docs/superpowers/specs/handoff-25a-dual-circuit.md`
- SPKI binding: `docs/superpowers/specs/handoff-30-spki-binding.md`
- messageDigest binding: `docs/superpowers/specs/handoff-31-messagedigest-binding.md`
- DER walker research: `docs/superpowers/specs/handoff-33-der-walker.md`
- Bench handoff: `docs/superpowers/specs/handoff-27-bench.md`
- Paper evaluation: `whitepaper/sections/evaluation.tex`

## Schema history

- **v9 — Phase 2a bring-up.** Invariants 1, 2a, 2b, 2c, 4, 5, 6, 9,
  10, 11 landed; dual-circuit MAC plumbing; JSON body fields
  (pk / nonce / context / declaration) bound.
- **v10 — messageDigest ↔ signedAttrs.** Added `signed_attrs_md_offset`
  to the witness blob and the 17-byte CMS messageDigest DER anchor.
- **v11 — Phase 2b.** Added `nullifier` (32 B) and `trust_anchor_index`
  (u32) to the public blob, and `subject_sn_offset_in_tbs` +
  `subject_dn_start_offset_in_tbs` to the witness blob. The N=2
  trust-anchor mux (Task #44) is an internal sig-circuit layout change
  that does NOT bump the public-blob schema version.
