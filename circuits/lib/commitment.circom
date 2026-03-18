pragma circom 2.1.5;
include "./poseidon.circom";

template Commitment() {
    signal input claim_value;
    signal input sd_array_hash;
    signal input message_hash;
    signal output out;

    component hasher = Poseidon(3);
    hasher.inputs[0] <== claim_value;
    hasher.inputs[1] <== sd_array_hash;
    hasher.inputs[2] <== message_hash;
    out <== hasher.out;
}
