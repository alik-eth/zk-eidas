/* tslint:disable */
/* eslint-disable */

/**
 * Build a CompoundProof from snarkjs proof results.
 *
 * Takes a JSON object with `proofs` array (each entry has circuitName, proof,
 * publicSignals, vk) and `op` string ("And" or "Or").
 *
 * snarkjs proofs are stored as UTF-8 JSON bytes in proof_bytes.
 * Public signals (decimal strings) are stored as UTF-8 bytes in public_inputs.
 * Verification keys are stored as UTF-8 JSON bytes.
 *
 * ECDSA proofs (circuitName == "ecdsa_verify") go into ecdsa_proofs HashMap.
 * Nullifier proofs (circuitName == "nullifier") are separated for contract_nullifier.
 * All other circuits go into the predicate proofs vec.
 */
export function build_compound_proof(proofs_json: string, op: string): string;

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
 * Export a CompoundProof to a CBOR-encoded ProofEnvelope.
 *
 * Replicates the server's export_compound_proof logic:
 * 1. Parse CompoundProof from JSON
 * 2. Extract only compound.proofs() (predicate sub-proofs)
 *    — ECDSA proofs and contract_nullifier are NOT included
 * 3. Map to EnvelopeProof entries
 * 4. Create ProofEnvelope with logical_op
 * 5. Serialize to CBOR, optionally compress with deflate
 */
export function export_to_envelope(compound_proof_json: string, compress: boolean): Uint8Array;

/**
 * Generate holder binding circuit inputs for one side of a binding.
 *
 * Each credential in a binding pair calls this separately. The circuit proves
 * that claim_value is committed under the ECDSA signature, and outputs
 * binding_hash = Poseidon(claim_value). Both sides must produce the same
 * binding_hash to prove the binding holds.
 */
export function generate_holder_binding_inputs(sdjwt: string, claim_name: string, ecdsa_public_signals: string): string;

/**
 * Generate nullifier circuit inputs from a credential and contract metadata.
 *
 * Parses the SD-JWT to extract credential_id (SHA256 of document_number → u64).
 * Takes ECDSA public signals (commitment, sd_array_hash, message_hash) from a
 * previously generated ECDSA proof.
 * Generates a random salt and computes contract_hash.
 */
export function generate_nullifier_inputs(sdjwt: string, contract_terms: string, timestamp: string, ecdsa_public_signals: string): string;

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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly build_compound_proof: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly check_nullifier_duplicate: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly decode_envelope: (a: number, b: number) => [number, number, number, number];
    readonly export_to_envelope: (a: number, b: number, c: number) => [number, number, number, number];
    readonly generate_holder_binding_inputs: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
    readonly generate_nullifier_inputs: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly parse_proof: (a: number, b: number) => [number, number, number, number];
    readonly prepare_inputs: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
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
