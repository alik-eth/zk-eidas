/**
 * Full client-side identity escrow decryption (post-quantum safe).
 *
 * 1. ML-KEM-768 decapsulate: recover shared secret from ciphertext using authority's seed
 * 2. XOR decrypt: recover symmetric key K = encrypted_k XOR SHA-256(shared_secret)
 * 3. Poseidon-CTR decrypt: plaintext[i] = ciphertext[i] - Poseidon(K, i) in BN254 field
 */

import { Buffer } from 'buffer'
if (typeof globalThis.Buffer === 'undefined') {
  globalThis.Buffer = Buffer
}

// BN254 scalar field order
const BN254_ORDER = 21888242871839275222246405745257275088548364400416034343698204186575808495617n

/**
 * Full escrow decryption — ML-KEM key recovery + Poseidon-CTR decrypt.
 *
 * @param encryptedKey - ML-KEM ciphertext || encrypted_K (byte array from proof)
 * @param secretKey - escrow authority's ML-KEM-768 seed (hex string, 64 bytes = 128 hex chars)
 * @param ciphertextFields - 8 ciphertext values as byte arrays (from proof public_inputs)
 * @param fieldNames - names of the encrypted fields
 * @returns map of field name → decrypted value string
 */
export interface DecryptResult {
  fields: Record<string, string>
  integrityValid: boolean
}

export async function decryptEscrow(
  encryptedKey: number[],
  secretKey: string,
  ciphertextFields: number[][],
  fieldNames: string[],
  expectedCredentialHash?: number[],
): Promise<DecryptResult> {
  // Step 1: ML-KEM-768 decapsulate to recover K
  const { MlKem768 } = await import('mlkem')
  const mlkem = new MlKem768()

  const seedBytes = hexToBytes(secretKey)
  // Reconstruct the keypair from seed to get the decapsulation key
  // The seed is used to deterministically generate dk + ek
  const [_ek, dk] = await mlkem.deriveKeyPair(seedBytes)

  // Split encrypted data: ML-KEM ciphertext (1088 bytes) + encrypted_K (32 bytes)
  const allBytes = new Uint8Array(encryptedKey)
  const ctSize = allBytes.length - 32
  const mlkemCt = allBytes.slice(0, ctSize)
  const encryptedK = allBytes.slice(ctSize)

  // Decapsulate to get shared secret
  const ss = await mlkem.decap(mlkemCt, dk)

  // Decrypt K: XOR with SHA-256(shared_secret)
  const maskBuf = await crypto.subtle.digest('SHA-256', new Uint8Array(ss) as unknown as ArrayBuffer)
  const mask = new Uint8Array(maskBuf)
  const kPadded = new Uint8Array(32)
  for (let i = 0; i < 32; i++) {
    kPadded[i] = encryptedK[i] ^ mask[i]
  }
  const K = bytesToBigInt(kPadded)

  // Step 2: Poseidon-CTR decrypt
  const { buildPoseidon } = await import('circomlibjs')
  const poseidon = await buildPoseidon()
  const F = poseidon.F

  const result: Record<string, string> = {}
  const plaintexts: bigint[] = []
  // Decrypt ALL 8 ciphertext slots (circuit always uses 8).
  // Named fields get human-readable output; unnamed slots are only used for hash.
  for (let i = 0; i < ciphertextFields.length; i++) {
    // Convert ciphertext bytes to BigInt (decimal string encoded as UTF-8 bytes)
    const ctStr = new TextDecoder().decode(new Uint8Array(ciphertextFields[i]))
    const ct = BigInt(ctStr)

    // keystream[i] = Poseidon(K, i)
    const keystream = F.toObject(poseidon([K, BigInt(i)]))

    // plaintext = ciphertext - keystream (mod BN254 order)
    const plaintext = ((ct - keystream) % BN254_ORDER + BN254_ORDER) % BN254_ORDER

    if (i < fieldNames.length) {
      result[fieldNames[i]] = fieldElementToValue(plaintext)
    }
    plaintexts.push(plaintext)
  }

  // Integrity check: Poseidon(plaintext[0..7]) should match credential_hash
  let integrityValid = false
  if (expectedCredentialHash && plaintexts.length === 8) {
    const integrityHasher = poseidon(plaintexts)
    const computed = F.toObject(integrityHasher).toString()
    const expected = new TextDecoder().decode(new Uint8Array(expectedCredentialHash))
    integrityValid = computed === expected
  }

  return { fields: result, integrityValid }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = ''
  for (const b of bytes) hex += b.toString(16).padStart(2, '0')
  return BigInt('0x' + hex)
}

/**
 * Convert a BN254 field element back to a human-readable value.
 *
 * Escrow encoding (ClaimValue::to_escrow_field):
 * - Strings: raw UTF-8 bytes, zero-padded to 31 bytes
 * - Integers: i64 big-endian in last 8 bytes of 31-byte buffer
 * - Dates: epoch days as u64 big-endian in last 8 bytes
 * - Booleans: 0 or 1 in last byte
 */
function fieldElementToValue(plaintext: bigint): string {
  if (plaintext === 0n) return '0'

  // Convert to 31-byte big-endian buffer
  const hex = plaintext.toString(16).padStart(62, '0')
  const bytes = new Uint8Array(31)
  for (let i = 0; i < 31; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }

  // Try as UTF-8 string (strip trailing zeros)
  let nonZeroEnd = -1
  for (let i = bytes.length - 1; i >= 0; i--) {
    if (bytes[i] !== 0) { nonZeroEnd = i; break }
  }
  if (nonZeroEnd >= 0) {
    const strBytes = bytes.slice(0, nonZeroEnd + 1)
    const isPrintable = strBytes.every((b: number) => (b >= 0x20 && b < 0x7f) || b >= 0x80)
    if (isPrintable && strBytes.length > 0) {
      try {
        const decoded = new TextDecoder('utf-8', { fatal: true }).decode(strBytes)
        if (decoded.length > 0) return decoded
      } catch { /* not valid UTF-8, fall through */ }
    }
  }

  // Try as numeric: last 8 bytes as i64 big-endian
  const numBytes = bytes.slice(23, 31)
  const view = new DataView(numBytes.buffer, numBytes.byteOffset, 8)
  const num = view.getBigInt64(0)

  // If it's a plausible date (epoch days), convert
  if (num > 0n && num < 100000n) {
    const date = new Date(Number(num) * 86400 * 1000)
    return date.toISOString().split('T')[0]
  }

  return num.toString()
}
