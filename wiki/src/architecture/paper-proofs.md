# Paper Proofs & QR Transport

## The Idea

Zero-knowledge proofs can be printed on paper and verified offline with a phone camera. No internet, no app store, no institutional infrastructure. A contract with embedded QR codes is a self-contained cryptographic document — the paper IS the proof.

## Chunked QR Protocol

The `cbor-print` crate implements a binary protocol for splitting proof payloads across multiple QR codes:

### Header Structure (8 bytes)

```
[version:1][proof_id:2][seq:1][total:1][part_index:1][part_count:1][flags:1]
```

| Field | Bytes | Purpose |
|-------|-------|---------|
| `version` | 1 | Protocol version (currently 1) |
| `proof_id` | 2 | Links chunks belonging to the same document |
| `seq` | 1 | Chunk sequence number (0-indexed) |
| `total` | 1 | Total chunks for this document |
| `part_index` | 1 | Document position in a multi-document set |
| `part_count` | 1 | Total documents in set |
| `flags` | 1 | Bit 0: compressed. Bits 1-2: logical op (00=single, 01=AND, 10=OR) |

### Constraints

- QR Version 40, Low ECC, binary mode: max **2953 bytes** per QR
- Max payload per chunk: 2953 - 8 = **2945 bytes**
- Max chunks per document: **255**
- Compression: **deflate-raw** (RFC 1951)

A typical Longfellow proof (~350 KB) would need ~120 QR codes — too many. That's where the blob store comes in.

## Proof Blob Store

For proofs that exceed practical QR capacity, the demo server provides a content-addressed store:

- `POST /proofs` — stores raw proof bytes, returns SHA-256 hex CID
- `GET /proofs/{cid}` — retrieves proof by CID

The QR code on the paper document contains just the CID (~60 bytes) — a single compact QR. The verifier scans it, fetches the proof from the store, and verifies.

For small payloads (escrow envelopes, contract terms, metadata), the chunked protocol works directly — these typically fit in 1-2 QR codes.

## Multi-Document Sets

Compound proofs (AND/OR over multiple predicates) produce multiple sub-proofs. The protocol supports multi-document sets:

- Each sub-proof gets its own `proof_id`
- `part_index` and `part_count` track position in the set
- `flags` bits 1-2 encode the logical operation (AND/OR/single)
- The scanner accumulates chunks across all documents and reassembles when complete

## Reserved Identifiers

Special `proof_id` ranges carry non-proof data:

| Range | Purpose |
|-------|---------|
| `0x0000–0xFEFF` | Regular proof chunks |
| `0xFE` (part_index) | Contract terms QR |
| `0xFF` (part_index) | Contract metadata QR (hash, parties, nullifiers) |
| `0xFFF0–0xFFFD` (proof_id) | Identity escrow envelopes (one per credential) |

## Scanning and Verification

The verify page (`/verify`) is a PWA with a QR scanner:

1. Camera scans QR codes one at a time
2. `ChunkCollector` accumulates chunks, shows progress ("P 3/8, E 1/2")
3. When all chunks for a document arrive, it reassembles and decompresses
4. Three-stage verification pipeline: proof verification → contract hash cross-check → party nullifier summary
5. If escrow QRs are present, a "Decrypt as Authority" button appears

### Offline Verification

The verify page works offline after first load (service worker caches assets). QEAA attestations are verified purely client-side via Web Crypto API — no server needed. Raw proof verification requires the server API, but the plan is to eventually embed a Longfellow WASM verifier.

## Visual Distinction

On printed documents:
- **Proof QRs**: standard black-on-white, grouped in 2x2 grids with predicate labels
- **Escrow QRs**: double-line amber border with lock icon, authority info and SHA-256 fingerprint printed below
- **CID QRs**: compact single QR with "Scan to verify" label
