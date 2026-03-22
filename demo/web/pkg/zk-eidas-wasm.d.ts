/* tslint:disable */
/* eslint-disable */

/**
 * Check if a nullifier has been seen before (client-side dedup).
 * Takes a JSON array of known nullifiers and a new nullifier hex string.
 * Returns true if the nullifier is already in the list.
 */
export function check_nullifier_duplicate(known_nullifiers_json: string, nullifier_hex: string): boolean;

/**
 * Decode a ProofEnvelope from CBOR bytes and return its contents as JSON.
 */
export function decode_envelope(cbor_bytes: Uint8Array): string;

/**
 * Parse a ZK proof from JSON and return proof metadata as JSON.
 *
 * Returns: { "predicateOp": string, "hasNullifier": bool, "nullifier": string|null,
 *            "proofSize": number, "version": number, "hasEcdsaCommitment": bool }
 *
 * Note: Full verification requires snarkjs / native FFI which doesn't compile
 * to wasm32. This function provides proof inspection/parsing in the browser.
 */
export function parse_proof(proof_json: string): string;

/**
 * Prepare ECDSA circuit inputs from an SD-JWT credential — fully client-side.
 *
 * Takes an SD-JWT string and claim name, parses the credential, extracts
 * ECDSA signature data, and returns the circuit input JSON for snarkjs.
 *
 * Returns JSON: { "ecdsa_inputs": {...}, "claim_value": "..." }
 */
export function prepare_inputs(sdjwt: string, claim_name: string): string;

/**
 * Build a compound proof from individual sub-proofs.
 *
 * Takes a JSON string with `{ proofs: [...], op: "And" }` and a composition operator string.
 * Returns JSON string of the compound proof.
 */
export function build_compound_proof(proofs_json: string, op: string): string;

/**
 * Export a compound proof to a CBOR-encoded ProofEnvelope.
 *
 * Takes a compound proof JSON string and a boolean indicating whether to compress.
 * Returns the CBOR bytes as Uint8Array.
 */
export function export_to_envelope(compound_proof_json: string, compress: boolean): Uint8Array;

/**
 * Generate nullifier circuit inputs from an SD-JWT credential.
 *
 * Returns JSON: { "inputs": {...}, "contract_hash_hex": "...", "salt_hex": "..." }
 */
export function generate_nullifier_inputs(sdjwt: string, contract_terms: string, timestamp: string, ecdsa_public_signals: string): string;

/**
 * Generate holder binding circuit inputs from an SD-JWT credential.
 *
 * Returns JSON: { "inputs": {...} }
 */
export function generate_holder_binding_inputs(sdjwt: string, claim_name: string, ecdsa_public_signals: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly check_nullifier_duplicate: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly decode_envelope: (a: number, b: number) => [number, number, number, number];
    readonly parse_proof: (a: number, b: number) => [number, number, number, number];
    readonly prepare_inputs: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
