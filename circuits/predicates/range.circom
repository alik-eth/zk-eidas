pragma circom 2.1.5;
include "../lib/commitment.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Range() {
    signal input claim_value;
    signal input sd_array_hash;
    signal input message_hash;
    signal input commitment;
    signal input low;
    signal input high;

    component comm = Commitment();
    comm.claim_value <== claim_value;
    comm.sd_array_hash <== sd_array_hash;
    comm.message_hash <== message_hash;
    comm.out === commitment;

    component gte = GreaterEqThan(64);
    gte.in[0] <== claim_value;
    gte.in[1] <== low;
    gte.out === 1;

    component lte = LessEqThan(64);
    lte.in[0] <== claim_value;
    lte.in[1] <== high;
    lte.out === 1;
}
component main {public [commitment, low, high]} = Range();
