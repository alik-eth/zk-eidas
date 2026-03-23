/**
 * Chunked QR protocol for paper-based ZK proofs.
 *
 * Header (8 bytes):
 * [version:1][proof_id:2][seq:1][total:1][proof_index:1][proof_count:1][flags:1]
 *
 * Flags: bit 0 = compressed (deflate-raw), bits 1-2 = logical op (00=single, 01=AND, 10=OR)
 */

const HEADER_SIZE = 8
const QR_MAX_BINARY = 2953 // QR V40, Low ECC
const MAX_PAYLOAD = QR_MAX_BINARY - HEADER_SIZE // 2945

export const PROTOCOL_VERSION = 1

export const TERMS_PROOF_INDEX = 0xfe
export const METADATA_PROOF_INDEX = 0xff
export const TERMS_PROOF_ID = 0xfffe
export const METADATA_PROOF_ID = 0xffff

export const enum LogicalOpFlag {
  Single = 0b00,
  And = 0b01,
  Or = 0b10,
}

export interface ChunkHeader {
  version: number
  proofId: number
  seq: number
  total: number
  proofIndex: number
  proofCount: number
  compressed: boolean
  logicalOp: LogicalOpFlag
}

export interface ProofChunk {
  header: ChunkHeader
  payload: Uint8Array
}

export interface ContractPartyMeta {
  role: string
  nullifier: string
  salt: string
}

/** Encode a header into 8 bytes. */
function encodeHeader(h: ChunkHeader): Uint8Array {
  const buf = new Uint8Array(HEADER_SIZE)
  buf[0] = h.version
  buf[1] = (h.proofId >> 8) & 0xff
  buf[2] = h.proofId & 0xff
  buf[3] = h.seq
  buf[4] = h.total
  buf[5] = h.proofIndex
  buf[6] = h.proofCount
  buf[7] = (h.compressed ? 1 : 0) | ((h.logicalOp & 0x03) << 1)
  return buf
}

/** Parse 8-byte header from raw QR data. Returns null if invalid. */
export function parseHeader(data: Uint8Array): ChunkHeader | null {
  if (data.length < HEADER_SIZE) return null
  const version = data[0]
  if (version !== PROTOCOL_VERSION) return null
  return {
    version,
    proofId: (data[1] << 8) | data[2],
    seq: data[3],
    total: data[4],
    proofIndex: data[5],
    proofCount: data[6],
    compressed: (data[7] & 0x01) !== 0,
    logicalOp: ((data[7] >> 1) & 0x03) as LogicalOpFlag,
  }
}

/** Extract payload (everything after the 8-byte header). */
export function extractPayload(data: Uint8Array): Uint8Array {
  return data.slice(HEADER_SIZE)
}

/** Split compressed CBOR bytes into QR-ready chunks for one proof. */
export function encodeProofChunks(
  compressedCbor: Uint8Array,
  proofId: number,
  proofIndex: number,
  proofCount: number,
  logicalOp: LogicalOpFlag,
): Uint8Array[] {
  const totalChunks = Math.ceil(compressedCbor.length / MAX_PAYLOAD)
  if (totalChunks > 255) throw new Error(`Proof too large: needs ${totalChunks} chunks (max 255)`)

  const chunks: Uint8Array[] = []
  for (let i = 0; i < totalChunks; i++) {
    const start = i * MAX_PAYLOAD
    const end = Math.min(start + MAX_PAYLOAD, compressedCbor.length)
    const payload = compressedCbor.slice(start, end)

    const header = encodeHeader({
      version: PROTOCOL_VERSION,
      proofId,
      seq: i,
      total: totalChunks,
      proofIndex,
      proofCount,
      compressed: true,
      logicalOp,
    })

    const chunk = new Uint8Array(HEADER_SIZE + payload.length)
    chunk.set(header, 0)
    chunk.set(payload, HEADER_SIZE)
    chunks.push(chunk)
  }
  return chunks
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

/** Compress bytes using browser's DeflateRaw (matches Rust flate2 deflate). */
export async function compressDeflate(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('deflate-raw')
  const writer = cs.writable.getWriter()
  // Copy into a plain ArrayBuffer to satisfy strict lib types
  const plain = new Uint8Array(new ArrayBuffer(data.length))
  plain.set(data)
  writer.write(plain)
  writer.close()
  const reader = cs.readable.getReader()
  const chunks: Uint8Array[] = []
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
  }
  const totalLen = chunks.reduce((s, c) => s + c.length, 0)
  const result = new Uint8Array(totalLen)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}

/** Decompress deflate-raw bytes using browser's DecompressionStream. */
export async function decompressDeflate(data: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream('deflate-raw')
  const writer = ds.writable.getWriter()
  // Copy into a plain ArrayBuffer to satisfy strict lib types
  const plain = new Uint8Array(new ArrayBuffer(data.length))
  plain.set(data)
  writer.write(plain)
  writer.close()
  const reader = ds.readable.getReader()
  const chunks: Uint8Array[] = []
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
  }
  const totalLen = chunks.reduce((s, c) => s + c.length, 0)
  const result = new Uint8Array(totalLen)
  let offset = 0
  for (const chunk of chunks) {
    result.set(chunk, offset)
    offset += chunk.length
  }
  return result
}

/** Collector: accumulates scanned chunks and reassembles when complete. */
export class ChunkCollector {
  // proofId → Map<seq, payload>
  private chunks = new Map<number, Map<number, Uint8Array>>()
  private totals = new Map<number, number>()
  private headers = new Map<number, ChunkHeader>()

  /** Add a scanned chunk. Returns true if this was a new chunk. */
  add(data: Uint8Array): boolean {
    const header = parseHeader(data)
    if (!header) return false

    const { proofId, seq, total } = header

    if (!this.chunks.has(proofId)) {
      this.chunks.set(proofId, new Map())
      this.totals.set(proofId, total)
      this.headers.set(proofId, header)
    }

    const existing = this.chunks.get(proofId)!
    if (existing.has(seq)) return false // duplicate

    // Reject conflicting total
    if (this.totals.get(proofId) !== total) return false

    existing.set(seq, extractPayload(data))
    return true
  }

  /** Check if all chunks for a given proofId have been collected. */
  isProofComplete(proofId: number): boolean {
    const chunks = this.chunks.get(proofId)
    const total = this.totals.get(proofId)
    if (!chunks || total === undefined) return false
    return chunks.size === total
  }

  /** Reassemble a complete proof's compressed bytes. */
  reassemble(proofId: number): Uint8Array | null {
    if (!this.isProofComplete(proofId)) return null
    const chunks = this.chunks.get(proofId)!
    const total = this.totals.get(proofId)!
    const parts: Uint8Array[] = []
    for (let i = 0; i < total; i++) {
      const chunk = chunks.get(i)
      if (!chunk) return null
      parts.push(chunk)
    }
    const totalLen = parts.reduce((s, p) => s + p.length, 0)
    const result = new Uint8Array(totalLen)
    let offset = 0
    for (const part of parts) {
      result.set(part, offset)
      offset += part.length
    }
    return result
  }

  /** Get header for a proofId (for reading proofCount, logicalOp). */
  getHeader(proofId: number): ChunkHeader | null {
    return this.headers.get(proofId) ?? null
  }

  /** Get all known proofIds. */
  proofIds(): number[] {
    return [...this.chunks.keys()]
  }

  /** Get scan progress for a proofId: [scanned, total]. */
  progress(proofId: number): [number, number] {
    const chunks = this.chunks.get(proofId)
    const total = this.totals.get(proofId)
    if (!chunks || total === undefined) return [0, 0]
    return [chunks.size, total]
  }

  /** Check if all expected proofs are complete. */
  isAllComplete(): boolean {
    if (this.chunks.size === 0) return false
    const firstHeader = this.headers.values().next().value
    if (!firstHeader) return false
    const expectedCount = firstHeader.proofCount
    if (this.chunks.size !== expectedCount) return false
    for (const proofId of this.chunks.keys()) {
      if (!this.isProofComplete(proofId)) return false
    }
    return true
  }

  /** Reset the collector. */
  clear() {
    this.chunks.clear()
    this.totals.clear()
    this.headers.clear()
  }

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
}
