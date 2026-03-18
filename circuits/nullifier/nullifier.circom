pragma circom 2.1.5;
include "../lib/commitment.circom";
include "../lib/poseidon.circom";

template Nullifier() {
    signal input credential_secret;
    signal input sd_array_hash;
    signal input message_hash;
    signal input claim_value;
    signal input commitment;
    signal input scope;
    signal input nullifier;

    // Verify commitment chain
    component comm = Commitment();
    comm.claim_value <== claim_value;
    comm.sd_array_hash <== sd_array_hash;
    comm.message_hash <== message_hash;
    comm.out === commitment;

    // Verify nullifier = Poseidon(credential_secret, scope)
    component null_hash = Poseidon(2);
    null_hash.inputs[0] <== credential_secret;
    null_hash.inputs[1] <== scope;
    null_hash.out === nullifier;
}
component main {public [commitment, scope, nullifier]} = Nullifier();
