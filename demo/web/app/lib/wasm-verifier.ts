/**
 * WASM-based ZK proof verification in the browser.
 *
 * Loads the zk-eidas-wasm package and circuit files on demand,
 * then delegates to the Rust/WASM verifier for real Sumcheck+Ligero
 * verification of mdoc proofs.
 */

let wasmModule: any = null

async function loadWasm() {
  if (!wasmModule) {
    // Dynamic import of the WASM package (built via wasm-pack)
    const wm = await import('zk-eidas-wasm')
    await wm.default() // init WASM
    wasmModule = wm
  }
  return wasmModule
}

const circuitCache = new Map<number, Uint8Array>()

async function loadCircuit(numAttrs: number): Promise<Uint8Array> {
  if (!circuitCache.has(numAttrs)) {
    const resp = await fetch(`/circuit-cache/mdoc-${numAttrs}attr.bin`)
    if (!resp.ok) throw new Error(`Failed to load circuit: ${resp.status}`)
    circuitCache.set(numAttrs, new Uint8Array(await resp.arrayBuffer()))
  }
  return circuitCache.get(numAttrs)!
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex
  const bytes = new Uint8Array(clean.length / 2)
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16)
  }
  return bytes
}

export async function verifyInBrowser(
  compoundProofJson: string,
  verificationInputs: any,
): Promise<{ valid: boolean; error?: string }> {
  try {
    const wasm = await loadWasm()
    const proof = JSON.parse(compoundProofJson)
    const numAttrs = verificationInputs.num_attributes
    const circuit = await loadCircuit(numAttrs)

    const proofBytes = new Uint8Array(proof.proof_bytes)

    // Determine nullifier/binding hashes — may be hex strings or byte arrays
    const nullifierHash = typeof proof.nullifier_hash === 'string'
      ? hexToBytes(proof.nullifier_hash)
      : new Uint8Array(proof.nullifier_hash)
    const bindingHash = typeof proof.binding_hash === 'string'
      ? hexToBytes(proof.binding_hash)
      : new Uint8Array(proof.binding_hash)

    // Escrow digest from identity_escrow if present
    const escrowDigest = proof.identity_escrow?.escrow_digest
      ? new Uint8Array(proof.identity_escrow.escrow_digest)
      : new Uint8Array(32)

    const result = wasm.verify(circuit, proofBytes, {
      issuer_pk_x: verificationInputs.issuer_pk_x,
      issuer_pk_y: verificationInputs.issuer_pk_y,
      transcript: new Uint8Array(verificationInputs.transcript),
      attributes: verificationInputs.attributes.map((a: any) => ({
        id: a.id,
        cbor_value: new Uint8Array(a.cbor_value),
        verification_type: a.verification_type,
      })),
      now: verificationInputs.now,
      contract_hash: new Uint8Array(verificationInputs.contract_hash),
      nullifier_hash: nullifierHash,
      binding_hash: bindingHash,
      escrow_digest: escrowDigest,
      doc_type: verificationInputs.doc_type,
      version: verificationInputs.version,
      block_enc_hash: verificationInputs.block_enc_hash,
      block_enc_sig: verificationInputs.block_enc_sig,
    })

    return result
  } catch (e: any) {
    return { valid: false, error: e.message ?? String(e) }
  }
}
