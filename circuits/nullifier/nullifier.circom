pragma circom 2.1.5;
include "../lib/commitment.circom";
include "../lib/poseidon.circom";

template ContractNullifier() {
    // Private inputs (same as other Stage 2 circuits)
    signal input credential_id;  // wired to Commitment.claim_value
    signal input sd_array_hash;
    signal input message_hash;

    // Public inputs
    signal input commitment;
    signal input contract_hash;
    signal input salt;

    // Public output
    signal output nullifier;

    // 1. Verify commitment chain: credential_id is the issuer-signed document_number
    component comm = Commitment();
    comm.claim_value <== credential_id;
    comm.sd_array_hash <== sd_array_hash;
    comm.message_hash <== message_hash;
    comm.out === commitment;

    // 2. Compute nullifier = Poseidon(credential_id, contract_hash, salt)
    component null_hash = Poseidon(3);
    null_hash.inputs[0] <== credential_id;
    null_hash.inputs[1] <== contract_hash;
    null_hash.inputs[2] <== salt;
    nullifier <== null_hash.out;
}

component main {public [commitment, contract_hash, salt]} = ContractNullifier();
