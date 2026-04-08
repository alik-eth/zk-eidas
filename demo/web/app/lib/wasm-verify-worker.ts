/**
 * Web Worker for WASM ZK proof verification.
 * Runs Sumcheck+Ligero verification off the main thread.
 */

let wasmModule: any = null

async function loadWasm() {
  if (!wasmModule) {
    const wm = await import('zk-eidas-wasm')
    await wm.default()
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

self.onmessage = async (e: MessageEvent) => {
  const { id, compoundProofJson, verificationInputs } = e.data
  try {
    const wasm = await loadWasm()
    const proof = JSON.parse(compoundProofJson)
    const numAttrs = verificationInputs.num_attributes
    const circuit = await loadCircuit(numAttrs)

    const proofBytes = new Uint8Array(proof.proof_bytes)

    const nullifierHash = typeof proof.nullifier_hash === 'string'
      ? hexToBytes(proof.nullifier_hash)
      : new Uint8Array(proof.nullifier_hash)
    const bindingHash = typeof proof.binding_hash === 'string'
      ? hexToBytes(proof.binding_hash)
      : new Uint8Array(proof.binding_hash)

    // Escrow digest: top-level first, then identity_escrow, then zeros
    const rawDigest = proof.escrow_digest ?? proof.identity_escrow?.escrow_digest
    const escrowDigest = rawDigest ? new Uint8Array(rawDigest) : new Uint8Array(32)

    const attrs = verificationInputs.attributes.map((a: any) => ({
      id: a.id,
      cbor_value: new Uint8Array(a.cbor_value),
      verification_type: a.verification_type,
    }))
    self.postMessage({ id, type: 'log', msg: `start: ${numAttrs} attrs, proof ${proofBytes.length}b, circuit ${circuit.length}b` })
    const t0 = performance.now()
    const result = wasm.verify(circuit, proofBytes, {
      issuer_pk_x: verificationInputs.issuer_pk_x,
      issuer_pk_y: verificationInputs.issuer_pk_y,
      transcript: new Uint8Array(verificationInputs.transcript),
      attributes: attrs,
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

    self.postMessage({ id, type: 'log', msg: `done: ${(performance.now() - t0).toFixed(0)}ms, valid=${result.valid}${result.error ? ', error=' + result.error : ''}` })
    self.postMessage({ id, type: 'result', ...result })
  } catch (e: any) {
    self.postMessage({ id, type: 'result', valid: false, error: e.message ?? String(e) })
  }
}
