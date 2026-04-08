/**
 * WASM-based ZK proof verification in the browser.
 *
 * Spawns one Web Worker per proof for parallel Sumcheck+Ligero verification.
 */

function spawnWorker(): Worker {
  const w = new Worker(new URL('./wasm-verify-worker.ts', import.meta.url), { type: 'module' })
  return w
}

export function verifyInBrowser(
  compoundProofJson: string,
  verificationInputs: any,
): Promise<{ valid: boolean; error?: string }> {
  return new Promise((resolve) => {
    const w = spawnWorker()
    w.onmessage = (e: MessageEvent) => {
      const { type, ...rest } = e.data
      if (type === 'log') {
        console.log(`[wasm-verify] ${rest.msg}`)
        return
      }
      resolve(rest)
      w.terminate()
    }
    w.onerror = (e) => {
      resolve({ valid: false, error: e.message })
      w.terminate()
    }
    w.postMessage({ id: 1, compoundProofJson, verificationInputs })
  })
}
