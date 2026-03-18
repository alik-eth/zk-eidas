pragma circom 2.1.5;

include "../node_modules/circom-ecdsa/circuits/ecdsa.circom";
include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/// ECDSA P-256 signature verification + Poseidon commitment output.
///
/// Stage 1 of a two-stage ZK proving architecture:
///   1. This circuit verifies an ECDSA P-256 signature over a message hash
///      and outputs a Poseidon commitment binding claim_value, sd_array_hash,
///      and message_hash together.
///   2. Stage 2 predicate circuits consume the commitment as a public input.
///
/// Limb encoding: P-256 scalars are split into k=6 limbs of n=43 bits each
/// (6 × 43 = 258 bits, enough for 256-bit values).

template EcdsaVerify() {
    // --- Private inputs ---
    signal input signature_r[6];
    signal input signature_s[6];
    signal input message_hash[6];     // 6 × 43-bit limbs
    signal input claim_value;
    signal input disclosure_hash;
    signal input sd_array[16];

    // --- Public inputs ---
    signal input pub_key_x[6];
    signal input pub_key_y[6];

    // --- Public outputs ---
    signal output commitment;
    signal output sd_array_hash_out;
    signal output msg_hash_field_out;

    // -------------------------------------------------------
    // 1. ECDSA P-256 signature verification
    // -------------------------------------------------------
    component ecdsa = ECDSAVerifyNoPubkeyCheck(43, 6);
    for (var i = 0; i < 6; i++) {
        ecdsa.r[i]          <== signature_r[i];
        ecdsa.s[i]          <== signature_s[i];
        ecdsa.msghash[i]    <== message_hash[i];
        ecdsa.pubkey[0][i]  <== pub_key_x[i];
        ecdsa.pubkey[1][i]  <== pub_key_y[i];
    }
    // The signature must be valid (result == 1).
    ecdsa.result === 1;

    // -------------------------------------------------------
    // 2. Compute sd_array_hash = Poseidon(sd_array[0..16])
    // -------------------------------------------------------
    component sd_hasher = Poseidon(16);
    for (var i = 0; i < 16; i++) {
        sd_hasher.inputs[i] <== sd_array[i];
    }

    // -------------------------------------------------------
    // 3. Convert message_hash limbs to a single field element
    //
    //    msg_hash_field = sum_{i=0}^{5} message_hash[i] * 2^{43*i}
    //
    //    This reconstructs the 256-bit hash from its 43-bit limbs
    //    into a BN254 field element (which is ~254 bits, so we take
    //    the value mod p implicitly — acceptable because both prover
    //    and verifier perform the same reduction).
    // -------------------------------------------------------
    signal msg_hash_accum[6];
    // Compute powers of 2^43 as constants
    var base = 1;
    for (var i = 0; i < 6; i++) {
        if (i == 0) {
            msg_hash_accum[i] <== message_hash[i];
        } else {
            msg_hash_accum[i] <== msg_hash_accum[i-1] + message_hash[i] * base;
        }
        base = base * (1 << 43);
    }
    signal msg_hash_field;
    msg_hash_field <== msg_hash_accum[5];

    // -------------------------------------------------------
    // 4. Compute commitment = Poseidon(claim_value, sd_array_hash, msg_hash_field)
    // -------------------------------------------------------
    component comm_hasher = Poseidon(3);
    comm_hasher.inputs[0] <== claim_value;
    comm_hasher.inputs[1] <== sd_hasher.out;
    comm_hasher.inputs[2] <== msg_hash_field;

    commitment <== comm_hasher.out;
    sd_array_hash_out <== sd_hasher.out;
    msg_hash_field_out <== msg_hash_field;
}

component main {public [pub_key_x, pub_key_y]} = EcdsaVerify();
