/**
 * Nullifier check utilities for the /verify page.
 *
 * Longfellow nullifiers are SHA-256(credential_cbor_bytes || contract_hash),
 * computed inside the ZK circuit. The verifier cannot recompute them without
 * the original credential bytes — they can only compare nullifier values.
 *
 * - computeContractHash: SHA-256(terms || timestamp)[0..8] as u64 hex (cross-checks contract binding)
 * - matchNullifier: compares a known nullifier against each party's nullifier (string equality)
 */

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

/** Match a nullifier value against contract parties by string comparison. */
export function matchNullifier(
  nullifierHex: string,
  parties: { role: string; nullifier: string }[],
): { role: string; matched: boolean }[] {
  const normalized = nullifierHex.toLowerCase().replace(/^0x/, '')
  return parties.map(party => {
    const partyNorm = party.nullifier.toLowerCase().replace(/^0x/, '')
    return { role: party.role, matched: normalized === partyNorm }
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
