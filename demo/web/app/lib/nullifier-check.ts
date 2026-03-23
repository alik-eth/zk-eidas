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
