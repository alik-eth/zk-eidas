import { describe, it, expect } from 'vitest'
import { computeContractHash, matchNullifier } from './nullifier-check'

describe('nullifier-check', () => {
  describe('computeContractHash', () => {
    it('computes truncated SHA-256 of terms + timestamp', async () => {
      const hash = await computeContractHash('{"id":"test"}', '2026-03-23T14:00:00.000Z')
      expect(typeof hash).toBe('string')
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
      // SHA-256("helloworld") = 936a185caaa266bb...
      // First 8 bytes BE = 0x936a185caaa266bb
      const hash = await computeContractHash('hello', 'world')
      expect(hash).toBe('0x936a185caaa266bb')
    })
  })

  describe('matchNullifier', () => {
    it('returns matched:false for non-matching nullifier', () => {
      const results = matchNullifier(
        '0xaabbccdd',
        [{ role: 'holder', nullifier: '0x11223344' }],
      )
      expect(results).toHaveLength(1)
      expect(results[0].role).toBe('holder')
      expect(results[0].matched).toBe(false)
    })

    it('returns matched:true for matching nullifier (case-insensitive)', () => {
      const results = matchNullifier(
        '0xAABBCCDD',
        [
          { role: 'seller', nullifier: '0xaabbccdd' },
          { role: 'buyer', nullifier: '0x11223344' },
        ],
      )
      expect(results[0].matched).toBe(true)
      expect(results[1].matched).toBe(false)
    })

    it('matches with or without 0x prefix', () => {
      const results = matchNullifier(
        'aabbccdd',
        [{ role: 'holder', nullifier: '0xaabbccdd' }],
      )
      expect(results[0].matched).toBe(true)
    })
  })
})
