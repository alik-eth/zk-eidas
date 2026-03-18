import { describe, it, expect } from 'vitest'
import {
  encodeProofChunks,
  parseHeader,
  extractPayload,
  ChunkCollector,
  LogicalOpFlag,
  PROTOCOL_VERSION,
} from './qr-chunking'

describe('qr-chunking', () => {
  describe('header encode/decode', () => {
    it('roundtrips a header through encodeProofChunks + parseHeader', () => {
      const data = new Uint8Array(100)
      const chunks = encodeProofChunks(data, 0x1234, 0, 1, LogicalOpFlag.Single)
      expect(chunks.length).toBe(1)
      const header = parseHeader(chunks[0])
      expect(header).not.toBeNull()
      expect(header!.version).toBe(PROTOCOL_VERSION)
      expect(header!.proofId).toBe(0x1234)
      expect(header!.seq).toBe(0)
      expect(header!.total).toBe(1)
      expect(header!.proofIndex).toBe(0)
      expect(header!.proofCount).toBe(1)
      expect(header!.compressed).toBe(true)
      expect(header!.logicalOp).toBe(LogicalOpFlag.Single)
    })

    it('rejects data shorter than header', () => {
      expect(parseHeader(new Uint8Array(5))).toBeNull()
    })

    it('rejects unknown version', () => {
      const data = new Uint8Array(8)
      data[0] = 99
      expect(parseHeader(data)).toBeNull()
    })
  })

  describe('chunking', () => {
    it('splits large data into multiple chunks', () => {
      const data = new Uint8Array(6000) // > 2945 max payload
      const chunks = encodeProofChunks(data, 1, 0, 1, LogicalOpFlag.Single)
      expect(chunks.length).toBe(3) // ceil(6000/2945)
      const payloads = chunks.map(c => extractPayload(c))
      const total = payloads.reduce((s, p) => s + p.length, 0)
      expect(total).toBe(6000)
    })

    it('handles single-chunk data', () => {
      const data = new Uint8Array(100)
      const chunks = encodeProofChunks(data, 1, 0, 1, LogicalOpFlag.Single)
      expect(chunks.length).toBe(1)
    })

    it('encodes AND logical op in flags', () => {
      const chunks = encodeProofChunks(new Uint8Array(10), 1, 0, 2, LogicalOpFlag.And)
      const header = parseHeader(chunks[0])!
      expect(header.logicalOp).toBe(LogicalOpFlag.And)
      expect(header.proofCount).toBe(2)
    })
  })

  describe('ChunkCollector', () => {
    it('collects and reassembles chunks', () => {
      const data = new Uint8Array(6000)
      for (let i = 0; i < data.length; i++) data[i] = i % 256
      const chunks = encodeProofChunks(data, 1, 0, 1, LogicalOpFlag.Single)

      const collector = new ChunkCollector()
      for (const chunk of chunks) {
        collector.add(chunk)
      }

      expect(collector.isProofComplete(1)).toBe(true)
      const result = collector.reassemble(1)!
      expect(result.length).toBe(6000)
      expect(result).toEqual(data)
    })

    it('deduplicates chunks', () => {
      const chunks = encodeProofChunks(new Uint8Array(100), 1, 0, 1, LogicalOpFlag.Single)
      const collector = new ChunkCollector()
      expect(collector.add(chunks[0])).toBe(true)
      expect(collector.add(chunks[0])).toBe(false)
    })

    it('tracks progress', () => {
      const chunks = encodeProofChunks(new Uint8Array(6000), 1, 0, 1, LogicalOpFlag.Single)
      const collector = new ChunkCollector()
      collector.add(chunks[0])
      expect(collector.progress(1)).toEqual([1, chunks.length])
    })

    it('handles compound proofs with multiple proofIds', () => {
      const chunks1 = encodeProofChunks(new Uint8Array(100), 1, 0, 2, LogicalOpFlag.And)
      const chunks2 = encodeProofChunks(new Uint8Array(100), 2, 1, 2, LogicalOpFlag.And)

      const collector = new ChunkCollector()
      for (const c of chunks1) collector.add(c)
      expect(collector.isAllComplete()).toBe(false)
      for (const c of chunks2) collector.add(c)
      expect(collector.isAllComplete()).toBe(true)
    })

    it('rejects chunks with conflicting totals', () => {
      const collector = new ChunkCollector()
      const chunk1 = encodeProofChunks(new Uint8Array(6000), 1, 0, 1, LogicalOpFlag.Single)
      collector.add(chunk1[0])

      const fake = new Uint8Array(20)
      fake[0] = PROTOCOL_VERSION
      fake[1] = 0; fake[2] = 1
      fake[3] = 1
      fake[4] = 99 // different total
      expect(collector.add(fake)).toBe(false)
    })
  })
})
