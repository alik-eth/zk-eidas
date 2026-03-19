// @ts-expect-error snarkjs doesn't have type declarations
import * as snarkjs from "snarkjs";

export interface BrowserProofResult {
  proof: unknown;
  publicSignals: string[];
  provingTimeMs: number;
  verified: boolean;
  verificationTimeMs: number;
}

export interface BrowserCompoundResult {
  ecdsaProof: BrowserProofResult;
  predicateProofs: BrowserProofResult[];
  totalTimeMs: number;
}

type ProgressCallback = (stage: string, detail: string) => void;

const ARTIFACT_CACHE_NAME = "zk-eidas-circuits-v1";

/** Fetch a circuit artifact with Cache API caching. */
async function fetchCached(url: string, onProgress?: ProgressCallback): Promise<Uint8Array> {
  const cache = await caches.open(ARTIFACT_CACHE_NAME);
  const cached = await cache.match(url);
  if (cached) {
    onProgress?.("cache", `Using cached ${url.split("/").pop()}`);
    return new Uint8Array(await cached.arrayBuffer());
  }

  onProgress?.("download", `Downloading ${url.split("/").pop()}...`);
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to fetch ${url}: ${resp.status}`);

  // Clone before consuming — one for cache, one for us
  const clone = resp.clone();
  await cache.put(url, clone);

  return new Uint8Array(await resp.arrayBuffer());
}

/** Load circuit artifacts (wasm + zkey + vk) with caching. */
async function loadCircuit(
  circuitName: string,
  apiBaseUrl: string,
  onProgress?: ProgressCallback,
) {
  const wasmUrl = `${apiBaseUrl}/circuits/${circuitName}/${circuitName}_js/${circuitName}.wasm`;
  const zkeyUrl = `${apiBaseUrl}/circuits/${circuitName}/${circuitName}.zkey`;
  const vkUrl = `${apiBaseUrl}/circuits/${circuitName}/vk.json`;

  onProgress?.("loading", `Loading ${circuitName} circuit artifacts...`);

  const [wasmBuffer, zkeyBuffer] = await Promise.all([
    fetchCached(wasmUrl, onProgress),
    fetchCached(zkeyUrl, onProgress),
  ]);

  const vk = await (await fetch(vkUrl)).json();

  return { wasmBuffer, zkeyBuffer, vk };
}

/** Prove a single circuit in-browser. */
export async function proveInBrowser(
  circuitName: string,
  inputs: Record<string, string | string[]>,
  apiBaseUrl: string,
  onProgress?: ProgressCallback,
): Promise<BrowserProofResult> {
  const { wasmBuffer, zkeyBuffer, vk } = await loadCircuit(circuitName, apiBaseUrl, onProgress);

  onProgress?.("proving", `Generating ${circuitName} proof...`);
  const proveStart = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    wasmBuffer,
    zkeyBuffer
  );
  const provingTimeMs = performance.now() - proveStart;

  onProgress?.("verifying", `Verifying ${circuitName} proof...`);
  const verifyStart = performance.now();
  const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
  const verificationTimeMs = performance.now() - verifyStart;

  return { proof, publicSignals, provingTimeMs, verified, verificationTimeMs };
}

/**
 * Two-stage browser proving: ECDSA → predicate(s).
 *
 * 1. Calls /holder/prepare-inputs to get circuit inputs from the server
 * 2. Proves ECDSA circuit in-browser (heavy, ~2-5min)
 * 3. Extracts commitment from ECDSA public outputs
 * 4. Proves each predicate circuit in-browser (fast, <1s each)
 */
export async function proveCompoundInBrowser(
  credential: string,
  format: string,
  predicates: Array<{ claim: string; op: string; value: unknown }>,
  apiBaseUrl: string,
  onProgress?: ProgressCallback,
): Promise<BrowserCompoundResult> {
  const totalStart = performance.now();

  // Step 1: Get circuit inputs from server
  onProgress?.("preparing", "Preparing circuit inputs...");
  const prepResp = await fetch(`${apiBaseUrl}/holder/prepare-inputs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ credential, format, predicates }),
  });
  if (!prepResp.ok) {
    const err = await prepResp.text();
    throw new Error(`Failed to prepare inputs: ${err}`);
  }
  const prepData = await prepResp.json();

  // Step 2: Prove ECDSA circuit (heavy)
  onProgress?.("ecdsa", "Downloading ECDSA circuit (1.2 GB on first run, cached after)...");
  const ecdsaResult = await proveInBrowser(
    "ecdsa_verify",
    prepData.ecdsa_inputs,
    apiBaseUrl,
    (stage, detail) => onProgress?.(`ecdsa-${stage}`, detail),
  );

  if (!ecdsaResult.verified) {
    throw new Error("ECDSA proof failed verification");
  }

  // Extract public outputs: [0]=commitment, [1]=sd_array_hash, [2]=msg_hash_field
  const commitment = ecdsaResult.publicSignals[0];
  const sdArrayHash = ecdsaResult.publicSignals[1];
  const msgHashField = ecdsaResult.publicSignals[2];

  // Step 3: Prove each predicate circuit (fast)
  const predicateProofs: BrowserProofResult[] = [];
  for (let i = 0; i < prepData.predicates.length; i++) {
    const pred = prepData.predicates[i];
    onProgress?.("predicate", `Proving predicate ${i + 1}/${prepData.predicates.length}: ${pred.claim} ${pred.op}...`);

    const predicateInputs: Record<string, string> = {
      claim_value: prepData.claim_value,
      sd_array_hash: sdArrayHash,
      message_hash: msgHashField,
      commitment,
    };

    // Add predicate-specific inputs
    if (pred.circuit === "gte" || pred.circuit === "lte") {
      predicateInputs.threshold = String(pred.value);
    } else if (pred.circuit === "eq" || pred.circuit === "neq") {
      predicateInputs.expected = String(pred.value);
    } else if (pred.circuit === "range") {
      const [low, high] = pred.value as [number, number];
      predicateInputs.low = String(low);
      predicateInputs.high = String(high);
    } else if (pred.circuit === "set_member") {
      // set_member needs special handling — pad to 16 elements
      const set = pred.value as string[];
      for (let j = 0; j < 16; j++) {
        predicateInputs[`set[${j}]`] = j < set.length ? set[j] : "0";
      }
      predicateInputs.set_size = String(set.length);
    }

    const predResult = await proveInBrowser(
      pred.circuit,
      predicateInputs,
      apiBaseUrl,
      (stage, detail) => onProgress?.(`pred-${stage}`, detail),
    );
    predicateProofs.push(predResult);
  }

  const totalTimeMs = performance.now() - totalStart;
  onProgress?.("done", `All proofs generated in ${(totalTimeMs / 1000).toFixed(1)}s`);

  return { ecdsaProof: ecdsaResult, predicateProofs, totalTimeMs };
}

/** Check how much circuit data is cached. */
export async function getCacheStats(): Promise<{ totalBytes: number; entries: number }> {
  try {
    const cache = await caches.open(ARTIFACT_CACHE_NAME);
    const keys = await cache.keys();
    let totalBytes = 0;
    for (const req of keys) {
      const resp = await cache.match(req);
      if (resp) {
        const blob = await resp.blob();
        totalBytes += blob.size;
      }
    }
    return { totalBytes, entries: keys.length };
  } catch {
    return { totalBytes: 0, entries: 0 };
  }
}

/** Clear all cached circuit artifacts. */
export async function clearCache(): Promise<void> {
  await caches.delete(ARTIFACT_CACHE_NAME);
}

export async function verifyInBrowser(
  circuitName: string,
  proof: unknown,
  publicSignals: string[],
  apiBaseUrl: string
): Promise<{ verified: boolean; timeMs: number }> {
  const vkUrl = `${apiBaseUrl}/circuits/${circuitName}/vk.json`;
  const vk = await (await fetch(vkUrl)).json();

  const start = performance.now();
  const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
  return { verified, timeMs: performance.now() - start };
}
