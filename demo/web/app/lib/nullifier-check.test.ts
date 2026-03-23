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
