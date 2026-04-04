// @ts-expect-error snarkjs doesn't have type declarations
import * as snarkjs from "snarkjs";
let cachedVks = null;
/**
 * Load trusted verification keys from a URL (typically /trusted-vks.json).
 * Results are cached — subsequent calls return the cached map.
 */
export async function loadTrustedVks(url) {
    if (cachedVks)
        return cachedVks;
    const res = await fetch(url);
    if (!res.ok)
        throw new Error(`Failed to load trusted VKs: ${res.status}`);
    cachedVks = await res.json();
    return cachedVks;
}
let lastInitTiming = null;
let initialized = false;
/** Returns the timing profile from the last initVerifier() call, or null if cached. */
export function getInitTiming() {
    return lastInitTiming;
}
/**
 * Initialize the snarkjs verification backend.
 *
 * snarkjs does not require heavy async initialization,
 * so this is effectively a no-op that records timing.
 */
export async function initVerifier() {
    if (initialized)
        return null;
    const t0 = performance.now();
    // snarkjs is imported statically, so no async init needed.
    // We just verify it's available.
    if (!snarkjs?.groth16?.verify) {
        throw new Error("snarkjs groth16.verify not available");
    }
    initialized = true;
    const tDone = performance.now();
    lastInitTiming = {
        jsImport: tDone - t0,
        wasmCompile: 0,
        srsDownload: 0,
        total: tDone - t0,
    };
    return null;
}
/**
 * Verify a Groth16 proof using snarkjs with a trusted verification key.
 *
 * The VK is looked up from the trusted VK map by predicate operation name,
 * ensuring proofs are verified against VKs derived from trusted circuit
 * setup — not from the proof itself.
 *
 * @param proofBytes - Serialized proof (JSON-encoded Groth16 proof + publicSignals)
 * @param predicateOp - Predicate operation name (e.g., "gte", "GteSigned")
 * @param vks - Trusted verification key map
 */
export async function verifyProof(proofBytes, predicateOp, vks) {
    const result = await verifyProofWithProfile(proofBytes, predicateOp, vks);
    return result.valid;
}
/**
 * Verify a Groth16 proof and return both the result and a per-step timing profile.
 */
export async function verifyProofWithProfile(proofBytes, predicateOp, vks) {
    const t0 = performance.now();
    const vk = vks[predicateOp];
    if (!vk) {
        throw new Error(`No trusted VK for predicate: ${predicateOp}`);
    }
    const tVkDecode = performance.now();
    // Decode proof bytes. Two possible formats:
    // 1. Wrapped: { proof: {...}, publicSignals: [...] }
    // 2. Raw Groth16 from rapidsnark: { pi_a: [...], pi_b: [...], pi_c: [...], ... }
    //    In this case, publicSignals come from ZkProof.public_inputs (passed separately).
    const decoded = JSON.parse(new TextDecoder().decode(proofBytes));
    let proof;
    let publicSignals;
    if (decoded.pi_a) {
        // Raw Groth16 proof — publicSignals not included, must be passed separately
        proof = decoded;
        publicSignals = decoded.publicSignals ?? [];
    }
    else {
        proof = decoded.proof ?? decoded;
        publicSignals = decoded.publicSignals ?? decoded.public_signals ?? [];
    }
    const tProofParse = performance.now();
    // Ensure snarkjs is initialized
    await initVerifier();
    const tInit = performance.now();
    // Verify using snarkjs Groth16
    const valid = await snarkjs.groth16.verify(vk, publicSignals, proof);
    const tVerify = performance.now();
    return {
        valid,
        timing: {
            vkDecode: tVkDecode - t0,
            proofParse: tProofParse - tVkDecode,
            snarkjsInit: tInit - tProofParse,
            snarkjsVerify: tVerify - tInit,
            total: tVerify - t0,
        },
    };
}
/**
 * Verify a compound proof with full chain verification.
 *
 * Checks:
 * 1. Each ECDSA proof is valid (against trusted Ecdsa VK)
 * 2. Each predicate proof is valid (against its predicate VK)
 * 3. Commitment chain: ECDSA public_inputs[0] == predicate public_inputs[0]
 *
 * If ecdsa_proofs is missing/empty, chainValid is null (not false).
 */
export async function verifyCompoundProof(envelope, vks) {
    const t0 = performance.now();
    // Step 1: Verify ECDSA proofs
    const ecdsaResults = {};
    const ecdsaProofs = envelope.ecdsa_proofs ?? {};
    const hasEcdsa = Object.keys(ecdsaProofs).length > 0;
    for (const [claimName, sp] of Object.entries(ecdsaProofs)) {
        const proofJson = new TextDecoder().decode(new Uint8Array(sp.proof_bytes));
        const publicSignals = (sp.public_inputs || []).map((inp) => new TextDecoder().decode(new Uint8Array(inp)));
        const combined = JSON.stringify({ ...JSON.parse(proofJson), publicSignals });
        try {
            const valid = await verifyProof(new TextEncoder().encode(combined), "Ecdsa", vks);
            ecdsaResults[claimName] = {
                valid,
                commitment: publicSignals[0] ?? "",
            };
        }
        catch {
            ecdsaResults[claimName] = { valid: false, commitment: "" };
        }
    }
    const tEcdsa = performance.now();
    // Step 2: Verify predicate proofs
    const predicateResults = [];
    for (const sp of envelope.proofs) {
        const proofJson = new TextDecoder().decode(new Uint8Array(sp.proof_bytes));
        const publicSignals = (sp.public_inputs || []).map((inp) => new TextDecoder().decode(new Uint8Array(inp)));
        const combined = JSON.stringify({ ...JSON.parse(proofJson), publicSignals });
        try {
            const valid = await verifyProof(new TextEncoder().encode(combined), sp.predicate_op, vks);
            predicateResults.push({
                predicate: sp.claim_name ?? "unknown",
                op: sp.predicate_op,
                valid,
                commitment: publicSignals[0] ?? "",
            });
        }
        catch {
            predicateResults.push({
                predicate: sp.claim_name ?? "unknown",
                op: sp.predicate_op,
                valid: false,
                commitment: "",
            });
        }
    }
    const tPredicates = performance.now();
    // Step 3: Check commitment chain
    // When ECDSA proofs are present, every predicate proof MUST have a claim_name
    // and a matching ECDSA commitment. Missing claim_name = chain broken.
    let chainValid = null;
    if (hasEcdsa) {
        chainValid = true;
        for (const pr of predicateResults) {
            if (pr.predicate === "unknown") {
                chainValid = false;
                break;
            }
            const ecdsaResult = ecdsaResults[pr.predicate];
            if (!ecdsaResult) {
                chainValid = false;
                break;
            }
            if (pr.commitment !== ecdsaResult.commitment) {
                chainValid = false;
                break;
            }
        }
    }
    const tChain = performance.now();
    // Step 4: Verify identity escrow proof if present
    let escrowValid = null;
    if (envelope.identity_escrow?.proof) {
        const sp = envelope.identity_escrow.proof;
        const proofJson = new TextDecoder().decode(new Uint8Array(sp.proof_bytes));
        const publicSignals = (sp.public_inputs || []).map((inp) => new TextDecoder().decode(new Uint8Array(inp)));
        const combined = JSON.stringify({ ...JSON.parse(proofJson), publicSignals });
        try {
            escrowValid = await verifyProof(new TextEncoder().encode(combined), sp.predicate_op || "IdentityEscrow", vks);
        }
        catch {
            escrowValid = false;
        }
    }
    const allEcdsaValid = Object.values(ecdsaResults).every((r) => r.valid);
    const allPredicatesValid = predicateResults.every((r) => r.valid);
    const valid = allPredicatesValid && (!hasEcdsa || (allEcdsaValid && chainValid === true));
    return {
        valid,
        ecdsaResults,
        predicateResults,
        chainValid,
        escrowValid,
        timing: {
            ecdsa: tEcdsa - t0,
            predicates: tPredicates - tEcdsa,
            chain: tChain - tPredicates,
            total: performance.now() - t0,
        },
    };
}
