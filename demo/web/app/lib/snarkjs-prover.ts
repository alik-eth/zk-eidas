// @ts-expect-error snarkjs doesn't have type declarations
import * as snarkjs from "snarkjs";

export interface BrowserProofResult {
  proof: unknown;
  publicSignals: string[];
  provingTimeMs: number;
  verified: boolean;
  verificationTimeMs: number;
}

export async function proveInBrowser(
  circuitName: string,
  inputs: Record<string, string | string[]>,
  apiBaseUrl: string
): Promise<BrowserProofResult> {
  const wasmUrl = `${apiBaseUrl}/circuits/${circuitName}/${circuitName}_js/${circuitName}.wasm`;
  const zkeyUrl = `${apiBaseUrl}/circuits/${circuitName}/${circuitName}.zkey`;
  const vkUrl = `${apiBaseUrl}/circuits/${circuitName}/vk.json`;

  const [wasmResp, zkeyResp, vkResp] = await Promise.all([
    fetch(wasmUrl),
    fetch(zkeyUrl),
    fetch(vkUrl),
  ]);

  if (!wasmResp.ok || !zkeyResp.ok || !vkResp.ok) {
    throw new Error(`Failed to fetch circuit artifacts for ${circuitName}`);
  }

  const wasmBuffer = new Uint8Array(await wasmResp.arrayBuffer());
  const zkeyBuffer = new Uint8Array(await zkeyResp.arrayBuffer());
  const vk = await vkResp.json();

  const proveStart = performance.now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    inputs,
    wasmBuffer,
    zkeyBuffer
  );
  const provingTimeMs = performance.now() - proveStart;

  const verifyStart = performance.now();
  const verified = await snarkjs.groth16.verify(vk, publicSignals, proof);
  const verificationTimeMs = performance.now() - verifyStart;

  return { proof, publicSignals, provingTimeMs, verified, verificationTimeMs };
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
