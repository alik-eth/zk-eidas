// Web Worker for snarkjs Groth16 proving (chunked fork)
// Uses sampritipanda/snarkjs fork that reads zkey sections from localforage (IndexedDB).
// Runs in a separate thread so the UI stays responsive.
importScripts("/snarkjs-chunked.min.js");

self.onmessage = async (e) => {
  const { type, circuitName, inputs, wasmUrl, zkeyUrl, vkUrl } = e.data;

  if (type !== "prove") return;

  try {
    // Download WASM into memory (small, ~19MB)
    console.log(`[worker] Fetching WASM for ${circuitName}...`);
    self.postMessage({ type: "progress", detail: `Downloading ${circuitName} WASM...` });
    const wasmResp = await fetch(wasmUrl);
    if (!wasmResp.ok) throw new Error(`Failed to fetch WASM: ${wasmResp.status}`);
    const wasmBuffer = new Uint8Array(await wasmResp.arrayBuffer());
    console.log(`[worker] WASM loaded (${(wasmBuffer.byteLength / 1024 / 1024).toFixed(1)} MB)`);

    // The chunked fork's groth16.fullProve reads zkey sections from localforage
    // using the circuit name (e.g. "ecdsa_verify.zkey"). Section files must already
    // be stored in localforage by the chunked-zkey-loader before this worker runs.
    console.log(`[worker] Starting groth16.fullProve for ${circuitName} (zkeyUrl=${zkeyUrl})...`);
    self.postMessage({ type: "progress", detail: `Generating ${circuitName} proof...` });
    const proveStart = performance.now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      inputs,
      wasmBuffer,
      zkeyUrl
    );
    const provingTimeMs = performance.now() - proveStart;
    console.log(`[worker] Proof generated for ${circuitName} in ${(provingTimeMs / 1000).toFixed(1)}s`);

    // Verify
    console.log(`[worker] Verifying ${circuitName} proof...`);
    self.postMessage({ type: "progress", detail: `Verifying ${circuitName} proof...` });
    const vkResp = await fetch(vkUrl);
    const vk = await vkResp.json();
    const verifyStart = performance.now();
    const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const verificationTimeMs = performance.now() - verifyStart;
    console.log(`[worker] Verification: ${verified ? "PASS" : "FAIL"} (${(verificationTimeMs / 1000).toFixed(1)}s)`);

    self.postMessage({
      type: "result",
      proof,
      publicSignals,
      provingTimeMs,
      verified,
      verificationTimeMs,
    });
  } catch (err) {
    console.error(`[worker] Error proving ${circuitName}:`, err);
    self.postMessage({ type: "error", message: err.message || String(err) });
  }
};
