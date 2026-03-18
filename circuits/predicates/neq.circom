pragma circom 2.1.5;
include "../lib/commitment.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Neq() {
    signal input claim_value;
    signal input sd_array_hash;
    signal input message_hash;
    signal input commitment;
    signal input expected;

    component comm = Commitment();
    comm.claim_value <== claim_value;
    comm.sd_array_hash <== sd_array_hash;
    comm.message_hash <== message_hash;
    comm.out === commitment;

    component eq = IsEqual();
    eq.in[0] <== claim_value;
    eq.in[1] <== expected;
    eq.out === 0;
}
component main {public [commitment, expected]} = Neq();
