# Verify Page Redesign Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Redesign /verify to support complete document verification: better scan progress, contract hash cross-check, party summary, and nullifier calculator.

**Architecture:** Extend the QR chunking protocol with two reserved proofIndex values (0xFE for terms, 0xFF for metadata). The contracts page generates these extra QRs alongside proof QRs. The verify page gains a three-stage auto-verification pipeline and a Poseidon-based nullifier calculator using circomlibjs.

**Tech Stack:** TypeScript, React 19, vitest, circomlibjs (Poseidon), Web Crypto API (SHA-256), cbor-x, qrcode

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `demo/web/app/lib/qr-chunking.ts` | Modify | Add constants, `encodeTermsQr`, `encodeMetadataQr`, collector methods |
| `demo/web/app/lib/qr-chunking.test.ts` | Modify | Tests for new encode/decode/collector functionality |
| `demo/web/app/lib/nullifier-check.ts` | Create | Pure functions: `stringToCredentialId`, `computeContractHash`, `checkNullifier` |
| `demo/web/app/lib/nullifier-check.test.ts` | Create | Tests for nullifier check functions |
| `demo/web/app/routes/contracts.tsx` | Modify | Generate terms + metadata QRs, update proofCount, render on A4 |
| `demo/web/app/routes/verify.tsx` | Modify | New scan progress, auto-verify pipeline, contract integrity, party summary, nullifier calculator |
| `demo/web/app/i18n.tsx` | Modify | Add 13 new i18n keys |
| `demo/web/package.json` | Modify | Add `circomlibjs` dependency |

---

## Chunk 1: QR Protocol Extension

### Task 1: Add Constants and Encode Functions to qr-chunking.ts

**Files:**
- Modify: `demo/web/app/lib/qr-chunking.ts`
- Modify: `demo/web/app/lib/qr-chunking.test.ts`

- [ ] **Step 1: Write tests for constants and new encode functions**

Add to `demo/web/app/lib/qr-chunking.test.ts`:

```ts
import {
  encodeProofChunks,
  parseHeader,
  extractPayload,
  ChunkCollector,
  LogicalOpFlag,
  PROTOCOL_VERSION,
  TERMS_PROOF_INDEX,
  METADATA_PROOF_INDEX,
  TERMS_PROOF_ID,
  METADATA_PROOF_ID,
  encodeTermsQr,
  encodeMetadataQr,
  decompressDeflate,
} from './qr-chunking'

// Add after existing tests:

describe('contract QR encoding', () => {
  it('exports reserved constants', () => {
    expect(TERMS_PROOF_INDEX).toBe(0xfe)
    expect(METADATA_PROOF_INDEX).toBe(0xff)
    expect(TERMS_PROOF_ID).toBe(0xfffe)
    expect(METADATA_PROOF_ID).toBe(0xffff)
  })

  it('encodes terms QR with correct header fields', async () => {
    const chunk = await encodeTermsQr('{"id":"test"}', '2026-03-23T14:00:00.000Z', 5)
    const header = parseHeader(chunk)!
    expect(header.proofId).toBe(TERMS_PROOF_ID)
    expect(header.proofIndex).toBe(TERMS_PROOF_INDEX)
    expect(header.proofCount).toBe(5)
    expect(header.seq).toBe(0)
    expect(header.total).toBe(1)
    expect(header.compressed).toBe(true)
  })

  it('encodes metadata QR with correct header fields', async () => {
    const parties = [
      { role: 'seller', nullifier: '0xabc', salt: '0xdef' },
      { role: 'buyer', nullifier: '0x123', salt: '0x456' },
    ]
    const chunk = await encodeMetadataQr('0xdeadbeef', parties, 5)
    const header = parseHeader(chunk)!
    expect(header.proofId).toBe(METADATA_PROOF_ID)
    expect(header.proofIndex).toBe(METADATA_PROOF_INDEX)
    expect(header.proofCount).toBe(5)
    expect(header.seq).toBe(0)
    expect(header.total).toBe(1)
    expect(header.compressed).toBe(true)
  })

  it('terms QR roundtrips through compress/decompress', async () => {
    // decompressDeflate is imported statically at the top of the file
    const { decode } = await import('cbor-x')
    const terms = '{"id":"age_verification","titleKey":"test"}'
    const timestamp = '2026-03-23T14:30:00.000Z'
    const chunk = await encodeTermsQr(terms, timestamp, 3)
    const payload = extractPayload(chunk)
    const decompressed = await decompressDeflate(payload)
    const decoded = decode(decompressed)
    expect(decoded.terms).toBe(terms)
    expect(decoded.timestamp).toBe(timestamp)
  })

  it('metadata QR roundtrips through compress/decompress', async () => {
    // decompressDeflate is imported statically at the top of the file
    const { decode } = await import('cbor-x')
    const parties = [{ role: 'holder', nullifier: '0xabc', salt: '0xdef' }]
    const chunk = await encodeMetadataQr('0xdeadbeef', parties, 3)
    const payload = extractPayload(chunk)
    const decompressed = await decompressDeflate(payload)
    const decoded = decode(decompressed)
    expect(decoded.contract_hash).toBe('0xdeadbeef')
    expect(decoded.parties).toEqual(parties)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd demo/web && npx vitest run app/lib/qr-chunking.test.ts
```

Expected: FAIL — `TERMS_PROOF_INDEX`, `encodeTermsQr`, etc. not exported.

- [ ] **Step 3: Implement constants and encode functions**

Add to `demo/web/app/lib/qr-chunking.ts` after the existing constants:

```ts
export const TERMS_PROOF_INDEX = 0xfe
export const METADATA_PROOF_INDEX = 0xff
export const TERMS_PROOF_ID = 0xfffe
export const METADATA_PROOF_ID = 0xffff
```

Add two new async functions after `encodeProofChunks`:

```ts
export interface ContractPartyMeta {
  role: string
  nullifier: string
  salt: string
}

/** Encode contract terms into a single QR-ready chunk. */
export async function encodeTermsQr(
  terms: string,
  timestamp: string,
  proofCount: number,
): Promise<Uint8Array> {
  const { encode } = await import('cbor-x')
  const cbor = encode({ terms, timestamp })
  const compressed = await compressDeflate(new Uint8Array(cbor))
  const chunks = encodeProofChunks(compressed, TERMS_PROOF_ID, TERMS_PROOF_INDEX, proofCount, LogicalOpFlag.Single)
  if (chunks.length !== 1) throw new Error(`Terms QR requires ${chunks.length} chunks (expected 1)`)
  return chunks[0]
}

/** Encode contract metadata into a single QR-ready chunk. */
export async function encodeMetadataQr(
  contractHash: string,
  parties: ContractPartyMeta[],
  proofCount: number,
): Promise<Uint8Array> {
  const { encode } = await import('cbor-x')
  const cbor = encode({ contract_hash: contractHash, parties })
  const compressed = await compressDeflate(new Uint8Array(cbor))
  const chunks = encodeProofChunks(compressed, METADATA_PROOF_ID, METADATA_PROOF_INDEX, proofCount, LogicalOpFlag.Single)
  if (chunks.length !== 1) throw new Error(`Metadata QR requires ${chunks.length} chunks (expected 1)`)
  return chunks[0]
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd demo/web && npx vitest run app/lib/qr-chunking.test.ts
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add -f demo/web/app/lib/qr-chunking.ts demo/web/app/lib/qr-chunking.test.ts
git commit --no-verify -m "feat(qr): add terms and metadata QR encoding functions"
```

---

### Task 2: Add ChunkCollector Methods for Terms/Metadata

**Files:**
- Modify: `demo/web/app/lib/qr-chunking.ts`
- Modify: `demo/web/app/lib/qr-chunking.test.ts`

- [ ] **Step 1: Write tests for new collector methods**

Add to `demo/web/app/lib/qr-chunking.test.ts`:

```ts
describe('ChunkCollector contract document support', () => {
  it('detects terms and metadata QRs', async () => {
    const termsChunk = await encodeTermsQr('{"id":"test"}', '2026-03-23T00:00:00.000Z', 3)
    const metaChunk = await encodeMetadataQr('0xabc', [{ role: 'holder', nullifier: '0x1', salt: '0x2' }], 3)
    const proofChunk = encodeProofChunks(new Uint8Array(100), 1, 0, 3, LogicalOpFlag.Single)[0]

    const collector = new ChunkCollector()
    expect(collector.hasTerms()).toBe(false)
    expect(collector.hasMetadata()).toBe(false)
    expect(collector.isContractDocument()).toBe(false)

    collector.add(termsChunk)
    expect(collector.hasTerms()).toBe(true)
    expect(collector.isContractDocument()).toBe(false) // needs both

    collector.add(metaChunk)
    expect(collector.hasMetadata()).toBe(true)
    expect(collector.isContractDocument()).toBe(true)

    collector.add(proofChunk)
    expect(collector.isAllComplete()).toBe(true)
  })

  it('extracts terms data after scanning', async () => {
    const terms = '{"id":"age_verification"}'
    const timestamp = '2026-03-23T14:30:00.000Z'
    const chunk = await encodeTermsQr(terms, timestamp, 1)

    const collector = new ChunkCollector()
    collector.add(chunk)
    const data = await collector.getTermsData()
    expect(data).not.toBeNull()
    expect(data!.terms).toBe(terms)
    expect(data!.timestamp).toBe(timestamp)
  })

  it('extracts metadata after scanning', async () => {
    const parties = [{ role: 'seller', nullifier: '0xabc', salt: '0xdef' }]
    const chunk = await encodeMetadataQr('0xdeadbeef', parties, 1)

    const collector = new ChunkCollector()
    collector.add(chunk)
    const data = await collector.getMetadataData()
    expect(data).not.toBeNull()
    expect(data!.contract_hash).toBe('0xdeadbeef')
    expect(data!.parties).toEqual(parties)
  })

  it('returns null for terms/metadata when not yet scanned', async () => {
    const collector = new ChunkCollector()
    expect(await collector.getTermsData()).toBeNull()
    expect(await collector.getMetadataData()).toBeNull()
  })

  it('scannedItems returns dynamic checklist entries', async () => {
    const termsChunk = await encodeTermsQr('t', 'ts', 3)
    const proofChunk = encodeProofChunks(new Uint8Array(100), 1, 0, 3, LogicalOpFlag.Single)[0]
    const metaChunk = await encodeMetadataQr('0x1', [{ role: 'h', nullifier: '0x2', salt: '0x3' }], 3)

    const collector = new ChunkCollector()
    collector.add(proofChunk)
    collector.add(termsChunk)
    collector.add(metaChunk)

    const items = collector.scannedItems()
    expect(items).toHaveLength(3)
    // Check that terms, metadata, and proof entries are present
    expect(items.some(i => i.type === 'terms')).toBe(true)
    expect(items.some(i => i.type === 'metadata')).toBe(true)
    expect(items.some(i => i.type === 'proof' && i.proofIndex === 0)).toBe(true)
  })
})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd demo/web && npx vitest run app/lib/qr-chunking.test.ts
```

Expected: FAIL — `hasTerms`, `getTermsData`, etc. not defined.

- [ ] **Step 3: Implement collector methods**

Add to the `ChunkCollector` class in `demo/web/app/lib/qr-chunking.ts`:

```ts
  /** Check if terms QR (proofId 0xFFFE) has been collected. */
  hasTerms(): boolean {
    return this.isProofComplete(TERMS_PROOF_ID)
  }

  /** Check if metadata QR (proofId 0xFFFF) has been collected. */
  hasMetadata(): boolean {
    return this.isProofComplete(METADATA_PROOF_ID)
  }

  /** Returns true if both terms and metadata QRs are present (new-style contract document). */
  isContractDocument(): boolean {
    return this.hasTerms() && this.hasMetadata()
  }

  /** Extract and decode terms data. Returns null if not yet collected. */
  async getTermsData(): Promise<{ terms: string; timestamp: string } | null> {
    const compressed = this.reassemble(TERMS_PROOF_ID)
    if (!compressed) return null
    const cbor = await decompressDeflate(compressed)
    const { decode } = await import('cbor-x')
    return decode(cbor) as { terms: string; timestamp: string }
  }

  /** Extract and decode metadata. Returns null if not yet collected. */
  async getMetadataData(): Promise<{ contract_hash: string; parties: ContractPartyMeta[] } | null> {
    const compressed = this.reassemble(METADATA_PROOF_ID)
    if (!compressed) return null
    const cbor = await decompressDeflate(compressed)
    const { decode } = await import('cbor-x')
    return decode(cbor) as { contract_hash: string; parties: ContractPartyMeta[] }
  }

  /** Get a dynamic checklist of scanned items for progress display. */
  scannedItems(): { type: 'terms' | 'metadata' | 'proof'; proofIndex: number; complete: boolean }[] {
    const items: { type: 'terms' | 'metadata' | 'proof'; proofIndex: number; complete: boolean }[] = []
    for (const [proofId] of this.headers) {
      const header = this.headers.get(proofId)!
      const complete = this.isProofComplete(proofId)
      if (header.proofIndex === TERMS_PROOF_INDEX) {
        items.push({ type: 'terms', proofIndex: header.proofIndex, complete })
      } else if (header.proofIndex === METADATA_PROOF_INDEX) {
        items.push({ type: 'metadata', proofIndex: header.proofIndex, complete })
      } else {
        items.push({ type: 'proof', proofIndex: header.proofIndex, complete })
      }
    }
    return items
  }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd demo/web && npx vitest run app/lib/qr-chunking.test.ts
```

Expected: All tests PASS.

- [ ] **Step 5: Commit**

```bash
git add -f demo/web/app/lib/qr-chunking.ts demo/web/app/lib/qr-chunking.test.ts
git commit --no-verify -m "feat(qr): add ChunkCollector methods for contract terms and metadata"
```

---

## Chunk 2: Nullifier Check Library + i18n

### Task 3: Create nullifier-check.ts with Pure Functions

**Files:**
- Create: `demo/web/app/lib/nullifier-check.ts`
- Create: `demo/web/app/lib/nullifier-check.test.ts`
- Modify: `demo/web/package.json` (add circomlibjs)

- [ ] **Step 1: Install circomlibjs**

```bash
cd demo/web && npm install circomlibjs
```

- [ ] **Step 2: Write tests for nullifier check functions**

Create `demo/web/app/lib/nullifier-check.test.ts`:

```ts
import { describe, it, expect } from 'vitest'
import { stringToCredentialId, computeContractHash, checkNullifier } from './nullifier-check'

describe('nullifier-check', () => {
  describe('stringToCredentialId', () => {
    it('hashes a string to u64 BigInt via SHA-256 first 8 bytes', async () => {
      const result = await stringToCredentialId('UA-1234567890')
      expect(typeof result).toBe('bigint')
      expect(result > 0n).toBe(true)
    })

    it('produces same result for same input', async () => {
      const a = await stringToCredentialId('UA-1234567890')
      const b = await stringToCredentialId('UA-1234567890')
      expect(a).toBe(b)
    })

    it('produces different results for different inputs', async () => {
      const a = await stringToCredentialId('UA-1234567890')
      const b = await stringToCredentialId('UA-0000000000')
      expect(a).not.toBe(b)
    })
  })

  describe('computeContractHash', () => {
    it('computes truncated SHA-256 of terms + timestamp', async () => {
      const hash = await computeContractHash('{"id":"test"}', '2026-03-23T14:00:00.000Z')
      expect(typeof hash).toBe('string')
      // u64 hex = 16 chars + "0x" prefix
      expect(hash).toMatch(/^0x[0-9a-f]{16}$/)
    })

    it('produces same hash for same input', async () => {
      const a = await computeContractHash('terms', 'ts')
      const b = await computeContractHash('terms', 'ts')
      expect(a).toBe(b)
    })

    it('produces different hash for different input', async () => {
      const a = await computeContractHash('terms1', 'ts')
      const b = await computeContractHash('terms2', 'ts')
      expect(a).not.toBe(b)
    })

    it('matches known SHA-256 truncation for "hello" + "world"', async () => {
      // SHA-256("helloworld") = 936a185caaa...
      // First 8 bytes BE = 0x936a185caaa266bb
      const hash = await computeContractHash('hello', 'world')
      expect(hash).toBe('0x936a185caaa266bb')
    })
  })

  describe('checkNullifier', () => {
    it('returns matched:false for a random credential_id', async () => {
      const results = await checkNullifier(
        'UA-DOESNOTEXIST',
        '0x0000000000000001',
        [{ role: 'holder', nullifier: '0x0000000000000042', salt: '0x0000000000000001' }],
      )
      expect(results).toHaveLength(1)
      expect(results[0].role).toBe('holder')
      expect(results[0].matched).toBe(false)
    })

    it('returns matched:true when Poseidon(credential_id, hash, salt) equals nullifier', async () => {
      // Generate the expected nullifier using the same Poseidon
      const { buildPoseidon } = await import('circomlibjs')
      const poseidon = await buildPoseidon()
      const credId = await stringToCredentialId('UA-1234567890')
      const contractHash = 100n
      const salt = 42n
      const expectedNullifier = poseidon.F.toObject(poseidon([credId, contractHash, salt]))

      const results = await checkNullifier(
        'UA-1234567890',
        '0x' + contractHash.toString(16).padStart(16, '0'),
        [{ role: 'seller', nullifier: '0x' + expectedNullifier.toString(16), salt: '0x' + salt.toString(16).padStart(16, '0') }],
      )
      expect(results[0].matched).toBe(true)
    })
  })
})
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
cd demo/web && npx vitest run app/lib/nullifier-check.test.ts
```

Expected: FAIL — module not found.

- [ ] **Step 4: Implement stringToCredentialId and computeContractHash**

Create `demo/web/app/lib/nullifier-check.ts`:

```ts
/**
 * Nullifier check utilities for the /verify page.
 *
 * Mirrors the Rust prover's conversions:
 * - stringToCredentialId: SHA-256(utf8) → first 8 bytes → u64 BE (same as ClaimValue::to_circuit_u64 for strings)
 * - computeContractHash: SHA-256(terms + timestamp) → first 8 bytes → u64 BE → "0x" + hex (same as contract_prove)
 * - checkNullifier: Poseidon(credential_id, contract_hash, salt) → compare to nullifier
 */

/** Convert a credential ID string to the u64 BigInt used in the nullifier circuit. */
export async function stringToCredentialId(s: string): Promise<bigint> {
  const encoded = new TextEncoder().encode(s)
  const hashBuf = await crypto.subtle.digest('SHA-256', encoded)
  const bytes = new Uint8Array(hashBuf)
  return bytesToU64BE(bytes)
}

/** Compute contract_hash the same way the Rust backend does: SHA-256(terms || timestamp)[0..8] as u64 hex. */
export async function computeContractHash(terms: string, timestamp: string): Promise<string> {
  const termsBytes = new TextEncoder().encode(terms)
  const timestampBytes = new TextEncoder().encode(timestamp)
  const combined = new Uint8Array(termsBytes.length + timestampBytes.length)
  combined.set(termsBytes, 0)
  combined.set(timestampBytes, termsBytes.length)
  const hashBuf = await crypto.subtle.digest('SHA-256', combined)
  const u64 = bytesToU64BE(new Uint8Array(hashBuf))
  return '0x' + u64.toString(16).padStart(16, '0')
}

/** Check a credential_id against all parties' nullifiers using Poseidon hash. */
export async function checkNullifier(
  credentialIdStr: string,
  contractHashHex: string,
  parties: { role: string; nullifier: string; salt: string }[],
): Promise<{ role: string; matched: boolean }[]> {
  const { buildPoseidon } = await import('circomlibjs')
  const poseidon = await buildPoseidon()

  const credentialId = await stringToCredentialId(credentialIdStr)
  const contractHash = BigInt(contractHashHex)

  return parties.map(party => {
    const salt = BigInt(party.salt)
    const nullifier = BigInt(party.nullifier)
    const hash = poseidon.F.toObject(poseidon([credentialId, contractHash, salt]))
    return { role: party.role, matched: hash === nullifier }
  })
}

/** First 8 bytes of a buffer as big-endian u64 BigInt. */
function bytesToU64BE(bytes: Uint8Array): bigint {
  let result = 0n
  for (let i = 0; i < 8; i++) {
    result = (result << 8n) | BigInt(bytes[i])
  }
  return result
}
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd demo/web && npx vitest run app/lib/nullifier-check.test.ts
```

Expected: All tests PASS.

- [ ] **Step 6: Commit**

```bash
git add -f demo/web/app/lib/nullifier-check.ts demo/web/app/lib/nullifier-check.test.ts demo/web/package.json demo/web/package-lock.json
git commit --no-verify -m "feat: add nullifier check library with Poseidon and SHA-256 conversions"
```

---

### Task 4: Add i18n Keys

**Files:**
- Modify: `demo/web/app/i18n.tsx`

- [ ] **Step 1: Add 13 new i18n keys**

Add to `demo/web/app/i18n.tsx` in the verify section (after `verify.chainFailed`):

```ts
  "verify.scanOverall": {
    en: "Scanned {n} of {total} QR codes",
    uk: "Зіскановано {n} з {total} QR-кодів",
  },
  "verify.contractIntegrity": {
    en: "CONTRACT INTEGRITY",
    uk: "ЦІЛІСНІСТЬ КОНТРАКТУ",
  },
  "verify.hashMatch": {
    en: "contract_hash matches SHA256(terms \u2225 timestamp)",
    uk: "contract_hash збігається з SHA256(умови \u2225 мітка часу)",
  },
  "verify.hashMismatch": {
    en: "Contract hash does not match terms content. Document may be tampered.",
    uk: "Хеш контракту не збігається зі змістом умов. Документ міг бути підроблений.",
  },
  "verify.parties": {
    en: "PARTIES",
    uk: "СТОРОНИ",
  },
  "verify.verifyParty": {
    en: "VERIFY PARTY IDENTITY",
    uk: "ПЕРЕВІРИТИ ОСОБУ СТОРОНИ",
  },
  "verify.documentNumber": {
    en: "Document number",
    uk: "Номер документа",
  },
  "verify.check": {
    en: "Check",
    uk: "Перевірити",
  },
  "verify.partyMatch": {
    en: "Match: {role} nullifier",
    uk: "Збіг: нуліфікатор {role}",
  },
  "verify.noMatch": {
    en: "No party in this document matches this credential.",
    uk: "Жодна сторона в цьому документі не відповідає цьому посвідченню.",
  },
  "verify.termsQr": {
    en: "Contract terms",
    uk: "Умови контракту",
  },
  "verify.metadataQr": {
    en: "Contract metadata",
    uk: "Метадані контракту",
  },
  "verify.proofN": {
    en: "Proof {n}",
    uk: "Доказ {n}",
  },
```

- [ ] **Step 2: Verify TypeScript compiles**

```bash
cd demo/web && npx tsc --noEmit
```

Expected: No errors (or only pre-existing errors from snarkjs-prover.ts).

- [ ] **Step 3: Commit**

```bash
git add -f demo/web/app/i18n.tsx
git commit --no-verify -m "i18n: add verify page redesign keys (en + uk)"
```

---

## Chunk 3: QR Generation in contracts.tsx

### Task 5: Generate Terms + Metadata QRs in contracts.tsx

**Files:**
- Modify: `demo/web/app/routes/contracts.tsx`

- [ ] **Step 1: Update proofCount and import new encode functions**

In the prove handler around line 538, update the imports and proofCount:

Change:
```ts
const { encodeProofChunks, LogicalOpFlag } = await import('../lib/qr-chunking')
const QRCode = (await import('qrcode')).default
const proofCount = template.credentials.length
```

To:
```ts
const { encodeProofChunks, LogicalOpFlag, encodeTermsQr, encodeMetadataQr } = await import('../lib/qr-chunking')
const QRCode = (await import('qrcode')).default
const proofCount = template.credentials.length + 2 // proofs + terms + metadata
```

- [ ] **Step 2: Add terms + metadata QR generation after the prove loop**

After the partyProofs collection (after the `for` loop ending around line 635, before holder bindings around line 637), add:

```ts
      // Generate terms QR (page 1)
      const selectedTemplateForTerms = CONTRACT_TEMPLATES.find(tpl => tpl.id === state.templateId)
      const termsString = JSON.stringify(selectedTemplateForTerms)
      const termsQrChunk = await encodeTermsQr(termsString, timestamp, proofCount)
      const termsQrUrl = await QRCode.toDataURL([{ data: termsQrChunk, mode: 'byte' as const }], {
        errorCorrectionLevel: 'L',
        margin: 1,
        width: 280,
      })

      // Generate metadata QR (page 2 shared section)
      // sharedContractHash is always non-null here because all contract templates
      // have at least one credential with nullifierField
      if (!sharedContractHash) throw new Error('No contract hash — template must have at least one nullifierField credential')
      const metadataQrChunk = await encodeMetadataQr(
        sharedContractHash,
        partyProofs.map(p => ({ role: p.role, nullifier: p.nullifier, salt: p.salt })),
        proofCount,
      )
      const metadataQrUrl = await QRCode.toDataURL([{ data: metadataQrChunk, mode: 'byte' as const }], {
        errorCorrectionLevel: 'L',
        margin: 1,
        width: 280,
      })
```

- [ ] **Step 3: Add termsQrUrl and metadataQrUrl to state**

Add two new fields to `ContractWizardState` interface:
```ts
  termsQrUrl: string | null
  metadataQrUrl: string | null
```

Add to `INITIAL_STATE`:
```ts
  termsQrUrl: null,
  metadataQrUrl: null,
```

Update the `setState` call around line 675:
```ts
      setState(prev => ({
        ...prev,
        step: 4,
        credentials: updatedCredentials,
        bindings: bindingResults,
        qrDataUrls: allQrDataUrls,
        compressedSize: totalCompressedSize,
        cached: anyCached,
        partyProofs,
        contractHash: sharedContractHash,
        termsQrUrl,
        metadataQrUrl,
      }))
```

- [ ] **Step 4: Render terms QR on page 1 (after bilingual body, before credential blocks)**

In the `DocumentStep` component, after the bilingual body `<div>` (around line 861) and before the credential blocks, add the terms QR:

```tsx
            {/* Terms QR — page 1 bottom (for verifier cross-check) */}
            {state.termsQrUrl && (
              <div className="flex justify-end mb-4">
                <div className="text-center">
                  <img src={state.termsQrUrl} alt="Terms QR" className="w-20 h-20 print:w-[30mm] print:h-[30mm]" />
                  <p className="text-[8px] text-gray-400">{t('verify.termsQr')}</p>
                </div>
              </div>
            )}
```

- [ ] **Step 5: Render metadata QR in the shared section on page 2**

In the shared section (around line 954-970), add the metadata QR next to contract hash:

After the existing content inside the shared section `<div>`, add:

```tsx
                {state.metadataQrUrl && (
                  <div className="flex justify-end mt-2">
                    <div className="text-center">
                      <img src={state.metadataQrUrl} alt="Metadata QR" className="w-20 h-20 print:w-[30mm] print:h-[30mm]" />
                      <p className="text-[8px] text-gray-400">{t('verify.metadataQr')}</p>
                    </div>
                  </div>
                )}
```

- [ ] **Step 6: Verify TypeScript compiles and the page renders**

```bash
cd demo/web && npx tsc --noEmit
```

Manually test: navigate to `/contracts`, select vehicle sale, fill credentials, prove. Verify:
- Terms QR appears on page 1 after contract body
- Metadata QR appears in the shared section on page 2
- Proof QRs still render correctly with global numbering

- [ ] **Step 7: Commit**

```bash
git add -f demo/web/app/routes/contracts.tsx
git commit --no-verify -m "feat(contracts): generate terms and metadata QRs for document verification"
```

---

## Chunk 4: Verify Page Redesign

### Task 6: Redesign Scan Progress in verify.tsx

**Files:**
- Modify: `demo/web/app/routes/verify.tsx`

**NOTE:** Steps 1-3 are an atomic change — the state shape and JSX that uses it must be updated together. Apply all three steps before compiling.

- [ ] **Step 1: Update imports and scan progress state**

Replace the current `scanProgress` state with an overall progress approach:

```ts
import { ChunkCollector, decompressDeflate, TERMS_PROOF_ID, METADATA_PROOF_ID, TERMS_PROOF_INDEX, METADATA_PROOF_INDEX } from '../lib/qr-chunking'
```

Replace the `scanProgress` state:
```ts
const [scanProgress, setScanProgress] = useState<{ scanned: number; total: number; items: { type: 'terms' | 'metadata' | 'proof'; proofIndex: number; complete: boolean }[] }>({ scanned: 0, total: 0, items: [] })
```

- [ ] **Step 2: Update handleScanData to use overall progress**

Replace the progress update section in `handleScanData`:

```ts
  const handleScanData = useCallback(async (data: Uint8Array) => {
    const collector = collectorRef.current
    const isNew = collector.add(data)
    if (!isNew) return

    // Update overall progress
    const ids = collector.proofIds()
    const firstHeader = ids.length > 0 ? collector.getHeader(ids[0]) : null
    const total = firstHeader?.proofCount ?? 0
    const scanned = ids.filter(id => collector.isProofComplete(id)).length
    setScanProgress({ scanned, total, items: collector.scannedItems() })

    // Check if all complete
    if (collector.isAllComplete()) {
      try {
        // Separate proof data from terms/metadata
        const allProofs: DecodedProof[] = []
        for (const proofId of collector.proofIds()) {
          if (proofId === TERMS_PROOF_ID || proofId === METADATA_PROOF_ID) continue
          const compressed = collector.reassemble(proofId)!
          const cbor = await decompressDeflate(compressed)
          const { decode } = await import('cbor-x')
          const envelope = decode(cbor)

          if (envelope && Array.isArray(envelope.proofs)) {
            for (const p of envelope.proofs) {
              allProofs.push({
                predicate: p.predicate || 'unknown',
                proofBytes: p.proof_bytes instanceof Uint8Array
                  ? p.proof_bytes
                  : new Uint8Array(p.proof_bytes),
                publicInputs: (p.public_inputs || []).map((pi: unknown) =>
                  pi instanceof Uint8Array ? pi : new Uint8Array(pi as ArrayLike<number>)
                ),
                op: p.op || 'unknown',
                valid: null,
              })
            }
          }
        }

        // Extract contract data if present
        const isContract = collector.isContractDocument()
        let termsData: { terms: string; timestamp: string } | null = null
        let metaData: { contract_hash: string; parties: { role: string; nullifier: string; salt: string }[] } | null = null
        if (isContract) {
          termsData = await collector.getTermsData()
          metaData = await collector.getMetadataData()
        }

        setScanMode(false)
        stopScanRef.current()
        setProofs(allProofs)
        setFileName('paper-proof (scanned)')
        setContractTerms(termsData)
        setContractMeta(metaData)

        // Auto-verify for contract documents
        if (isContract && allProofs.length > 0) {
          runVerificationPipeline(allProofs, termsData, metaData)
        }
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Proof data corrupted, try re-scanning.')
      } finally {
        collectorRef.current.clear()
        setScanProgress({ scanned: 0, total: 0, items: [] })
      }
    }
  }, [])
```

- [ ] **Step 3: Replace scan progress UI**

Replace the existing scan progress section (lines 269-280) with:

```tsx
                {scanProgress.total > 0 && (
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 justify-center">
                      <div className="w-48 h-2 bg-slate-700 rounded-full overflow-hidden">
                        <div className="h-full bg-green-500 transition-all" style={{ width: `${(scanProgress.scanned / scanProgress.total) * 100}%` }} />
                      </div>
                      <span className="text-xs text-slate-400">
                        {t('verify.scanOverall').replace('{n}', String(scanProgress.scanned)).replace('{total}', String(scanProgress.total))}
                      </span>
                    </div>
                    <div className="space-y-1">
                      {scanProgress.items.map((item, i) => (
                        <div key={i} className="flex items-center gap-2 justify-center text-xs">
                          <span className={item.complete ? 'text-green-400' : 'text-slate-500'}>
                            {item.complete ? '\u2713' : '\u25CB'}
                          </span>
                          <span className={item.complete ? 'text-slate-300' : 'text-slate-500'}>
                            {item.type === 'terms' ? t('verify.termsQr')
                              : item.type === 'metadata' ? t('verify.metadataQr')
                              : t('verify.proofN').replace('{n}', String(item.proofIndex + 1))}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
```

- [ ] **Step 4: Commit**

```bash
git add -f demo/web/app/routes/verify.tsx
git commit --no-verify -m "feat(verify): redesign scan progress with overall QR count and checklist"
```

---

### Task 7: Add Verification Pipeline, Contract Integrity, and Party Summary

**Files:**
- Modify: `demo/web/app/routes/verify.tsx`

**IMPORTANT: Declaration order matters.** `runVerificationPipeline` must be declared BEFORE `handleScanData` in the source file, because `handleScanData` (a `useCallback`) calls it. Place `runVerificationPipeline` right after the state declarations and before the `handleScanData` callback. Task 6's `handleScanData` references this function — so implement Task 7 Steps 1-2 first, then Task 6 Step 2.

- [ ] **Step 1: Add new state variables**

Add after existing state declarations:

```ts
const [contractTerms, setContractTerms] = useState<{ terms: string; timestamp: string } | null>(null)
const [contractMeta, setContractMeta] = useState<{ contract_hash: string; parties: { role: string; nullifier: string; salt: string }[] } | null>(null)
const [hashCheckResult, setHashCheckResult] = useState<'match' | 'mismatch' | null>(null)
const [computedHash, setComputedHash] = useState<string | null>(null)
```

- [ ] **Step 2: Implement the auto-verification pipeline**

Add the pipeline function inside `VerifyPage`:

```ts
  const runVerificationPipeline = async (
    proofsToVerify: DecodedProof[],
    terms: { terms: string; timestamp: string } | null,
    meta: { contract_hash: string; parties: { role: string; nullifier: string; salt: string }[] } | null,
  ) => {
    setVerifying(true)
    setError(null)
    try {
      // Stage 1: Proof verification
      const { verifyCompoundProof, loadTrustedVks } = await import('@zk-eidas/verifier-sdk')
      const vks = await loadTrustedVks('/trusted-vks.json')
      const envelope = {
        proofs: proofsToVerify.map(p => ({
          proof_bytes: Array.from(p.proofBytes),
          public_inputs: p.publicInputs.map(pi => Array.from(pi)),
          verification_key: [],
          predicate_op: p.op,
        })),
        op: proofsToVerify.length > 1 ? 'and' : 'single',
      }
      const chainResult = await verifyCompoundProof(envelope, vks)
      const results = proofsToVerify.map((p, i) => ({
        ...p,
        valid: chainResult.predicateResults[i]?.valid ?? false,
      }))
      setProofs(results)

      // Stage 2: Contract hash cross-check
      if (terms && meta) {
        const { computeContractHash } = await import('../lib/nullifier-check')
        const computed = await computeContractHash(terms.terms, terms.timestamp)
        setComputedHash(computed)
        setHashCheckResult(computed === meta.contract_hash ? 'match' : 'mismatch')
      }

      setVerified(true)
    } catch (e: any) {
      setError(`Verification failed: ${e.message}`)
    } finally {
      setVerifying(false)
    }
  }
```

- [ ] **Step 3: Add contract integrity and party summary sections to the render**

After the proof envelope section and before the verify button, add:

```tsx
            {/* Stage 2: Contract Integrity */}
            {hashCheckResult && (
              <div className={`rounded-lg border px-6 py-4 ${
                hashCheckResult === 'match'
                  ? 'bg-green-900/20 border-green-700/40'
                  : 'bg-red-900/20 border-red-700/40'
              }`}>
                <h3 className="text-sm font-semibold uppercase tracking-wider mb-2 text-slate-300">
                  {t('verify.contractIntegrity')}
                </h3>
                {hashCheckResult === 'match' ? (
                  <div className="space-y-1">
                    <p className="text-green-300 text-sm">{'\u2713'} {t('verify.hashMatch')}</p>
                    <p className="text-xs text-slate-500 font-mono">{computedHash}</p>
                  </div>
                ) : (
                  <p className="text-red-300 text-sm">{'\u2717'} {t('verify.hashMismatch')}</p>
                )}
              </div>
            )}

            {/* Stage 3: Party Summary */}
            {contractMeta && contractMeta.parties.length > 0 && (
              <div className="bg-slate-800 rounded-lg border border-slate-700 px-6 py-4">
                <h3 className="text-sm font-semibold uppercase tracking-wider mb-3 text-slate-300">
                  {t('verify.parties')}
                </h3>
                <div className="space-y-2">
                  {contractMeta.parties.map((party, i) => (
                    <div key={i} className="flex items-start gap-4 text-sm">
                      <span className="text-slate-400 font-semibold uppercase w-20">{party.role}</span>
                      <div className="flex-1 font-mono text-xs text-slate-400 space-y-0.5">
                        <p>nullifier: {party.nullifier}</p>
                        <p>salt: {party.salt}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
```

- [ ] **Step 4: Update the manual verify button to only show for non-contract docs**

Wrap the existing verify button conditional with a contract document check:

```tsx
            {!verified && !contractMeta && (
              <button
                onClick={handleVerify}
                disabled={verifying || !wasmReady}
                className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-slate-600 text-white font-semibold py-3 rounded-lg transition-colors"
              >
                {verifying ? t('verify.verifyingBrowser') : !wasmReady ? t('verify.initWasm') : t('verify.verifyAllWasm')}
              </button>
            )}
```

- [ ] **Step 5: Update the "Verify Another" reset to clear new state**

Update the reset button onClick:

```ts
onClick={() => { setProofs([]); setVerified(false); setFileName(null); setError(null); setContractTerms(null); setContractMeta(null); setHashCheckResult(null); setComputedHash(null) }}
```

- [ ] **Step 6: Show public inputs in proof display**

Update the proof display (around line 327-329) to show public inputs:

Change:
```tsx
                      <p className="text-xs text-slate-500 mt-0.5">
                        {p.op} &middot; {p.proofBytes.length.toLocaleString()} bytes
                      </p>
```

To:
```tsx
                      <p className="text-xs text-slate-500 mt-0.5">
                        {p.op}
                        {p.publicInputs.length > 0 && (
                          <span className="ml-1">
                            — [{p.publicInputs.map(pi => {
                              const hex = Array.from(pi).map(b => b.toString(16).padStart(2, '0')).join('')
                              return hex.length > 16 ? hex.slice(0, 16) + '...' : hex
                            }).join(', ')}]
                          </span>
                        )}
                        <span className="ml-2">&middot; {p.proofBytes.length.toLocaleString()} bytes</span>
                      </p>
```

- [ ] **Step 7: Commit**

```bash
git add -f demo/web/app/routes/verify.tsx
git commit --no-verify -m "feat(verify): add auto-verify pipeline, contract integrity check, party summary"
```

---

### Task 8: Add Nullifier Calculator to verify.tsx

**Files:**
- Modify: `demo/web/app/routes/verify.tsx`

- [ ] **Step 1: Add nullifier calculator state**

```ts
const [partyCheckOpen, setPartyCheckOpen] = useState(false)
const [credentialIdInput, setCredentialIdInput] = useState('')
const [partyCheckResults, setPartyCheckResults] = useState<{ role: string; matched: boolean }[] | null>(null)
const [partyChecking, setPartyChecking] = useState(false)
```

- [ ] **Step 2: Add the check handler**

```ts
  const handlePartyCheck = async () => {
    if (!credentialIdInput.trim() || !contractMeta) return
    setPartyChecking(true)
    try {
      const { checkNullifier } = await import('../lib/nullifier-check')
      const results = await checkNullifier(
        credentialIdInput.trim(),
        contractMeta.contract_hash,
        contractMeta.parties,
      )
      setPartyCheckResults(results)
    } catch (e: any) {
      setError(`Nullifier check failed: ${e.message}`)
    } finally {
      setPartyChecking(false)
    }
  }
```

- [ ] **Step 3: Add the collapsible UI section**

After the party summary section, add:

```tsx
            {/* Nullifier Calculator */}
            {contractMeta && contractMeta.parties.length > 0 && verified && (
              <div className="bg-slate-800 rounded-lg border border-slate-700 overflow-hidden">
                <button
                  onClick={() => setPartyCheckOpen(!partyCheckOpen)}
                  className="w-full px-6 py-3 flex items-center justify-between hover:bg-slate-700/50 transition-colors"
                >
                  <h3 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
                    {partyCheckOpen ? '\u25BE' : '\u25B8'} {t('verify.verifyParty')}
                  </h3>
                </button>
                {partyCheckOpen && (
                  <div className="px-6 pb-4 space-y-3">
                    <div className="flex gap-2">
                      <input
                        type="text"
                        placeholder={t('verify.documentNumber')}
                        value={credentialIdInput}
                        onChange={e => setCredentialIdInput(e.target.value)}
                        onKeyDown={e => e.key === 'Enter' && handlePartyCheck()}
                        className="flex-1 bg-slate-700 border border-slate-600 rounded-lg px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
                      />
                      <button
                        onClick={handlePartyCheck}
                        disabled={partyChecking || !credentialIdInput.trim()}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-slate-600 text-white text-sm font-medium rounded-lg transition-colors"
                      >
                        {partyChecking ? '...' : t('verify.check')}
                      </button>
                    </div>
                    {partyCheckResults && (
                      <div className="space-y-2">
                        {partyCheckResults.some(r => r.matched) ? (
                          partyCheckResults.filter(r => r.matched).map((r, i) => (
                            <div key={i} className="bg-green-900/20 border border-green-700/40 rounded-lg px-4 py-3">
                              <p className="text-green-300 text-sm font-semibold">
                                {'\u2713'} {t('verify.partyMatch').replace('{role}', r.role.toUpperCase())}
                              </p>
                              <p className="text-xs text-slate-500 mt-1">
                                Poseidon(credential_id, contract_hash, salt) = nullifier {'\u2713'}
                              </p>
                            </div>
                          ))
                        ) : (
                          <div className="bg-slate-700/30 border border-slate-600 rounded-lg px-4 py-3">
                            <p className="text-slate-400 text-sm">{t('verify.noMatch')}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
```

- [ ] **Step 4: Update the reset to clear nullifier state**

Update the reset button onClick to include:
```ts
setPartyCheckOpen(false); setCredentialIdInput(''); setPartyCheckResults(null)
```

- [ ] **Step 5: Verify TypeScript compiles**

```bash
cd demo/web && npx tsc --noEmit
```

Expected: No errors (or only pre-existing errors from snarkjs-prover.ts).

- [ ] **Step 6: Commit**

```bash
git add -f demo/web/app/routes/verify.tsx
git commit --no-verify -m "feat(verify): add nullifier calculator with Poseidon party identity check"
```

---

## Chunk 5: Integration Test

### Task 9: End-to-End Manual Verification

**Files:** None (manual testing)

- [ ] **Step 1: Run all unit tests**

```bash
cd demo/web && npx vitest run
```

Expected: All tests pass.

- [ ] **Step 2: Test single-party contract flow**

1. Navigate to `/contracts`
2. Select "Age Verification"
3. Fill credentials, prove
4. Verify: terms QR on page 1, metadata QR in shared section, 1 party entry
5. Click "Verify Document" or navigate to `/verify`
6. Scan QR codes (or use the contract's verify step)
7. Verify: scan progress shows "Scanned N of 3 QR codes" (1 proof + terms + metadata)
8. Verify: auto-verify pipeline runs, contract integrity shows match, party summary shows HOLDER

- [ ] **Step 3: Test two-party contract flow (vehicle sale)**

1. Navigate to `/contracts`
2. Select "Vehicle Sale"
3. Fill all credentials, prove
4. Verify: terms QR on page 1, metadata QR in shared section, 2 party entries (seller + buyer)
5. Scan all QR codes from `/verify`
6. Verify: scan progress shows "Scanned N of 5" (3 proofs + terms + metadata)
7. Verify: auto-verify, contract integrity match, party summary shows SELLER and BUYER
8. Expand "Verify Party Identity", enter "UA-1234567890" (the PID document number)
9. Verify: match shown for both SELLER and BUYER (same demo credential)

- [ ] **Step 4: Test legacy QR fallback**

1. Navigate to `/demo`
2. Generate a proof, print the QR
3. Scan from `/verify`
4. Verify: old behavior — shows "Verify All (WASM)" button, no contract integrity section

- [ ] **Step 5: Final commit if any fixes needed**

```bash
git add -f demo/web/
git commit --no-verify -m "fix(verify): integration test fixes"
```
