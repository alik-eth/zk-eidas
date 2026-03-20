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

/** SHA-256 hash a string and return first 8 bytes as a decimal string (matches Rust bytes_to_u64). */
async function hashToU64(value: string): Promise<string> {
  const encoded = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", encoded);
  const view = new DataView(hash);
  return view.getBigUint64(0).toString();
}

/** Compute epoch days cutoff for an age threshold (e.g. 18 → epoch days of date 18 years ago). */
function ageCutoffEpochDays(minAge: number): number {
  const now = new Date();
  const cutoffYear = now.getFullYear() - minAge;
  const cutoff = new Date(cutoffYear, now.getMonth(), now.getDate());
  return Math.floor(cutoff.getTime() / 86400000);
}

/** Prove a single circuit in a Web Worker (keeps UI responsive). */
export function proveInBrowser(
  circuitName: string,
  inputs: Record<string, string | string[]>,
  apiBaseUrl: string,
  onProgress?: ProgressCallback,
): Promise<BrowserProofResult> {
  return new Promise((resolve, reject) => {
    const worker = new Worker("/prove-worker.js");

    worker.onmessage = (e) => {
      const msg = e.data;
      if (msg.type === "progress") {
        onProgress?.("worker", msg.detail);
      } else if (msg.type === "result") {
        worker.terminate();
        resolve({
          proof: msg.proof,
          publicSignals: msg.publicSignals,
          provingTimeMs: msg.provingTimeMs,
          verified: msg.verified,
          verificationTimeMs: msg.verificationTimeMs,
        });
      } else if (msg.type === "error") {
        worker.terminate();
        reject(new Error(msg.message));
      }
    };

    worker.onerror = (e) => {
      worker.terminate();
      reject(new Error(e.message || "Worker error"));
    };

    const wasmUrl = `${apiBaseUrl}/circuits/${circuitName}/${circuitName}_js/${circuitName}.wasm`;
    const zkeyUrl = `${apiBaseUrl}/circuits/${circuitName}/${circuitName}.zkey`;
    const vkUrl = `${apiBaseUrl}/circuits/${circuitName}/vk.json`;

    worker.postMessage({ type: "prove", circuitName, inputs, wasmUrl, zkeyUrl, vkUrl });
  });
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
  _format: string,
  predicates: Array<{ claim: string; op: string; value: unknown }>,
  apiBaseUrl: string,
  onProgress?: ProgressCallback,
): Promise<BrowserCompoundResult> {
  const totalStart = performance.now();
  if (!predicates.length) throw new Error("No predicates specified");

  // Step 1: Load WASM for on-device credential parsing
  onProgress?.("preparing", "Loading WASM module...");
  const { default: init, prepare_inputs } = await import("../../pkg/zk-eidas-wasm.js");
  await init();

  // Step 2: Group predicates by claim and generate one ECDSA proof per unique claim
  const uniqueClaims = [...new Set(predicates.map(p => p.claim))];
  const ecdsaCache = new Map<string, { result: BrowserProofResult; claimValue: string }>();

  for (let c = 0; c < uniqueClaims.length; c++) {
    const claim = uniqueClaims[c];
    onProgress?.("ecdsa", `[${c + 1}/${uniqueClaims.length}] Parsing claim "${claim}" on device...`);

    const prepRaw = prepare_inputs(credential, claim);
    const prepData = JSON.parse(prepRaw);

    onProgress?.("ecdsa", `[${c + 1}/${uniqueClaims.length}] ECDSA proof for "${claim}" (1.2 GB download on first run)...`);
    const ecdsaResult = await proveInBrowser(
      "ecdsa_verify",
      prepData.ecdsa_inputs,
      apiBaseUrl,
      (_stage, detail) => onProgress?.("ecdsa", `[${c + 1}/${uniqueClaims.length}] ${detail}`),
    );

    if (!ecdsaResult.verified) {
      throw new Error(`ECDSA proof for "${claim}" failed verification`);
    }

    ecdsaCache.set(claim, { result: ecdsaResult, claimValue: prepData.claim_value });
  }

  // Step 3: Prove each predicate circuit (fast, <1s each)
  const predicateProofs: BrowserProofResult[] = [];
  for (let i = 0; i < predicates.length; i++) {
    const pred = predicates[i];
    const cached = ecdsaCache.get(pred.claim)!;
    const { result: ecdsa, claimValue } = cached;

    // ECDSA public outputs: [0]=commitment, [1]=sd_array_hash, [2]=msg_hash_field
    const commitment = ecdsa.publicSignals[0];
    const sdArrayHash = ecdsa.publicSignals[1];
    const msgHashField = ecdsa.publicSignals[2];

    // Determine circuit and threshold
    // Date claims with small values (< 200) are age thresholds → invert gte↔lte and compute cutoff
    // Date claims with large values (epoch days) are direct comparisons → pass through
    const isDateClaim = typeof pred.value === "number" &&
      (pred.claim.includes("birth") || pred.claim.includes("date"));
    const isAgeThreshold = isDateClaim && (pred.value as number) < 200;
    let circuit = pred.op;
    let threshold = pred.value;

    if (isAgeThreshold) {
      // Age on a date field: gte(age) → lte(birthdate, cutoff), lte(age) → gte(birthdate, cutoff)
      if (pred.op === "gte") {
        circuit = "lte";
        threshold = ageCutoffEpochDays(pred.value as number);
      } else if (pred.op === "lte") {
        circuit = "gte";
        threshold = ageCutoffEpochDays(pred.value as number);
      }
    }
    // Non-age date comparisons (expiry_date >= epochDays) pass through as-is

    onProgress?.("predicate", `Predicate ${i + 1}/${predicates.length}: ${pred.claim} ${pred.op}...`);

    const predicateInputs: Record<string, string | string[]> = {
      claim_value: claimValue,
      sd_array_hash: sdArrayHash,
      message_hash: msgHashField,
      commitment,
    };

    if (circuit === "gte" || circuit === "lte") {
      predicateInputs.threshold = String(threshold);
    } else if (circuit === "eq" || circuit === "neq") {
      const val = threshold;
      if (typeof val === "string" && !/^\d+$/.test(val)) {
        predicateInputs.expected = await hashToU64(val);
      } else {
        predicateInputs.expected = String(val);
      }
    } else if (circuit === "range") {
      const [low, high] = threshold as unknown as [number, number];
      predicateInputs.low = String(low);
      predicateInputs.high = String(high);
    } else if (circuit === "set_member") {
      const set = threshold as unknown as string[];
      const padded: string[] = [];
      for (let j = 0; j < 16; j++) {
        padded.push(j < set.length ? await hashToU64(set[j]) : "0");
      }
      predicateInputs.set = padded;
      predicateInputs.set_len = String(set.length);
    }

    const predResult = await proveInBrowser(
      circuit,
      predicateInputs,
      apiBaseUrl,
      (_stage, detail) => onProgress?.("predicate", detail),
    );
    predicateProofs.push(predResult);
  }

  // Return the first ECDSA result (for backward compat)
  const firstEcdsa = ecdsaCache.values().next().value!;
  const totalTimeMs = performance.now() - totalStart;
  onProgress?.("done", `All proofs generated in ${(totalTimeMs / 1000).toFixed(1)}s`);

  return { ecdsaProof: firstEcdsa.result, predicateProofs, totalTimeMs };
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
  // @ts-expect-error snarkjs doesn't have type declarations
  const snarkjs = await import("snarkjs");
  const vkUrl = `${apiBaseUrl}/circuits/${circuitName}/vk.json`;
  const vk = await (await fetch(vkUrl)).json();

  const start = performance.now();
  const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
  return { verified, timeMs: performance.now() - start };
}
