pragma circom 2.1.5;
include "../lib/commitment.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

template Lte() {
    signal input claim_value;
    signal input sd_array_hash;
    signal input message_hash;
    signal input commitment;
    signal input threshold;

    component comm = Commitment();
    comm.claim_value <== claim_value;
    comm.sd_array_hash <== sd_array_hash;
    comm.message_hash <== message_hash;
    comm.out === commitment;

    component lte = LessEqThan(64);
    lte.in[0] <== claim_value;
    lte.in[1] <== threshold;
    lte.out === 1;
}
component main {public [commitment, threshold]} = Lte();
