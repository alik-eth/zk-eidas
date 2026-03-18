pragma circom 2.1.5;
include "../lib/commitment.circom";
include "../lib/poseidon.circom";

template HolderBinding() {
    signal input claim_value;
    signal input sd_array_hash;
    signal input message_hash;
    signal input commitment;
    signal input binding_hash;

    // Verify commitment chain
    component comm = Commitment();
    comm.claim_value <== claim_value;
    comm.sd_array_hash <== sd_array_hash;
    comm.message_hash <== message_hash;
    comm.out === commitment;

    // Verify binding_hash = Poseidon(claim_value)
    component bind = Poseidon(1);
    bind.inputs[0] <== claim_value;
    bind.out === binding_hash;
}
component main {public [commitment, binding_hash]} = HolderBinding();
