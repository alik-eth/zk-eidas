/**
 * Full client-side identity escrow decryption (post-quantum safe).
 *
 * 1. ML-KEM-768 decapsulate: recover shared secret from ciphertext using authority's seed
 * 2. XOR decrypt: recover symmetric key K = encrypted_k XOR SHA-256(shared_secret)
 * 3. AES-256-GCM decrypt each field using K and a per-field nonce (counter-based)
 */

export interface DecryptResult {
  fields: Record<string, string>
  integrityValid: boolean
}

/**
 * Full escrow decryption — ML-KEM key recovery + AES-256-GCM decrypt.
 *
 * @param encryptedKey - ML-KEM ciphertext || encrypted_K (byte array from proof)
 * @param secretKey - escrow authority's ML-KEM-768 seed (hex string, 64 bytes = 128 hex chars)
 * @param ciphertextFields - ciphertext byte arrays per field (from proof public_inputs)
 * @param tags - AES-GCM authentication tags per field (16 bytes each)
 * @param fieldNames - names of the encrypted fields
 * @param expectedBindingHash - optional hex SHA-256 hash of the first field value for integrity check
 * @returns map of field name → decrypted value string, plus integrityValid flag
 */
export async function decryptEscrow(
  encryptedKey: number[],
  secretKey: string,
  ciphertextFields: number[][],
  tags: number[][],
  fieldNames: string[],
  expectedBindingHash?: string,
): Promise<DecryptResult> {
  // Step 1: ML-KEM-768 decapsulate to recover K
  const { MlKem768 } = await import('mlkem')
  const mlkem = new MlKem768()
  const seedBytes = hexToBytes(secretKey)
  const [_ek, dk] = await mlkem.deriveKeyPair(seedBytes)

  const mlkemCtSize = encryptedKey.length - 32
  const mlkemCt = new Uint8Array(encryptedKey.slice(0, mlkemCtSize))
  const encryptedK = new Uint8Array(encryptedKey.slice(mlkemCtSize))

  const sharedSecret = await mlkem.decap(mlkemCt, dk)
  const mask = new Uint8Array(await crypto.subtle.digest('SHA-256', sharedSecret as unknown as ArrayBuffer))
  const keyBytes = new Uint8Array(32)
  for (let i = 0; i < 32; i++) keyBytes[i] = encryptedK[i] ^ mask[i]

  // Step 2: AES-256-GCM decrypt each field
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']
  )

  const fields: Record<string, string> = {}
  for (let i = 0; i < ciphertextFields.length && i < fieldNames.length; i++) {
    const nonce = new Uint8Array(12)
    new DataView(nonce.buffer).setUint32(8, i, false) // big-endian counter in last 4 bytes

    // AES-GCM expects ciphertext || tag concatenated
    const ctWithTag = new Uint8Array([...ciphertextFields[i], ...tags[i]])

    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce }, cryptoKey, ctWithTag
    )
    fields[fieldNames[i]] = new TextDecoder().decode(plaintext)
  }

  // Step 3: Verify binding hash if provided (SHA-256 of first field value, zero-padded to 32 bytes)
  let integrityValid = true
  if (expectedBindingHash && fieldNames.length > 0) {
    const firstFieldName = fieldNames[0]
    const bindingFieldBytes = new TextEncoder().encode(fields[firstFieldName] || '')
    const padded = new Uint8Array(32)
    padded.set(bindingFieldBytes.slice(0, 32))
    const hashBuf = await crypto.subtle.digest('SHA-256', padded)
    const hashHex = Array.from(new Uint8Array(hashBuf))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
    integrityValid = hashHex === expectedBindingHash
  }

  return { fields, integrityValid }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return bytes
}
