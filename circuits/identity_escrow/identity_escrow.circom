pragma circom 2.1.5;

include "../lib/commitment.circom";
include "../lib/poseidon.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

/// Identity Escrow — Stage 2 circuit for encrypted credential data.
///
/// Encrypts 8 credential data fields using Poseidon-CTR with a random
/// symmetric key K. The encryption correctness is proven in zero knowledge,
/// bound to the ECDSA-verified credential via the commitment chain.
///
/// Outputs:
///   credential_hash — Poseidon(credential_data[0..7]) for post-decryption integrity
///   ciphertext[8]   — Poseidon-CTR encrypted credential data
///   key_commitment  — Poseidon(K) for binding to external key escrow

template IdentityEscrow() {
    // --- Private inputs ---
    signal input claim_value;
    signal input sd_array_hash;
    signal input message_hash;
    signal input credential_data[8];
    signal input claim_index;
    signal input K;

    // --- Public inputs ---
    signal input commitment;

    // --- Public outputs ---
    signal output credential_hash;
    signal output ciphertext[8];
    signal output key_commitment;

    // -------------------------------------------------------
    // 1. Verify commitment chain
    // -------------------------------------------------------
    component comm = Commitment();
    comm.claim_value <== claim_value;
    comm.sd_array_hash <== sd_array_hash;
    comm.message_hash <== message_hash;
    comm.out === commitment;

    // -------------------------------------------------------
    // 2. Verify credential_data[claim_index] == claim_value
    //
    //    Linear scan with IsEqual selectors. Accumulates the
    //    value at the matching index, then constrains it to
    //    equal claim_value.
    // -------------------------------------------------------
    component is_idx[8];
    signal selected_acc[9];
    selected_acc[0] <== 0;
    for (var i = 0; i < 8; i++) {
        is_idx[i] = IsEqual();
        is_idx[i].in[0] <== claim_index;
        is_idx[i].in[1] <== i;
        selected_acc[i + 1] <== selected_acc[i] + is_idx[i].out * credential_data[i];
    }
    selected_acc[8] === claim_value;

    // -------------------------------------------------------
    // 3. Hash all credential data for integrity verification
    // -------------------------------------------------------
    component cred_hasher = Poseidon(8);
    for (var i = 0; i < 8; i++) {
        cred_hasher.inputs[i] <== credential_data[i];
    }
    credential_hash <== cred_hasher.out;

    // -------------------------------------------------------
    // 4. Poseidon-CTR encryption
    //
    //    keystream[i] = Poseidon(K, i)
    //    ciphertext[i] = credential_data[i] + keystream[i]
    //
    //    Field addition in BN254 scalar field. Decryption is
    //    subtraction: data[i] = ciphertext[i] - Poseidon(K, i)
    // -------------------------------------------------------
    component keystream[8];
    for (var i = 0; i < 8; i++) {
        keystream[i] = Poseidon(2);
        keystream[i].inputs[0] <== K;
        keystream[i].inputs[1] <== i;
        ciphertext[i] <== credential_data[i] + keystream[i].out;
    }

    // -------------------------------------------------------
    // 5. Key commitment for external key escrow binding
    // -------------------------------------------------------
    component key_hasher = Poseidon(1);
    key_hasher.inputs[0] <== K;
    key_commitment <== key_hasher.out;
}

component main {public [commitment]} = IdentityEscrow();
