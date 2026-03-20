// Web Worker for snarkjs Groth16 proving
// Runs in a separate thread so the UI stays responsive
importScripts("https://cdn.jsdelivr.net/npm/snarkjs@0.7.6/build/snarkjs.min.js");

self.onmessage = async (e) => {
  const { type, circuitName, inputs, wasmUrl, zkeyUrl, vkUrl } = e.data;

  if (type !== "prove") return;

  try {
    // Download WASM into memory (small, ~19MB)
    self.postMessage({ type: "progress", detail: `Downloading ${circuitName} WASM...` });
    const wasmResp = await fetch(wasmUrl);
    if (!wasmResp.ok) throw new Error(`Failed to fetch WASM: ${wasmResp.status}`);
    const wasmBuffer = new Uint8Array(await wasmResp.arrayBuffer());

    // Pass zkey URL as string — snarkjs fetches it internally.
    // This avoids holding both the fetch response AND the Uint8Array copy in memory.
    self.postMessage({ type: "progress", detail: `Generating ${circuitName} proof...` });
    const proveStart = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      wasmBuffer,
      zkeyUrl
    );
    const provingTimeMs = performance.now() - proveStart;

    // Verify
    self.postMessage({ type: "progress", detail: `Verifying ${circuitName} proof...` });
    const vkResp = await fetch(vkUrl);
    const vk = await vkResp.json();
    const verifyStart = performance.now();
    const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const verificationTimeMs = performance.now() - verifyStart;

    self.postMessage({
      type: "result",
      proof,
      publicSignals,
      provingTimeMs,
      verified,
      verificationTimeMs,
    });
  } catch (err) {
    self.postMessage({ type: "error", message: err.message || String(err) });
  }
};
