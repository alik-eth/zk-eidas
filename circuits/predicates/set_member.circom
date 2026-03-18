pragma circom 2.1.5;
include "../lib/commitment.circom";

template SetMember() {
    signal input claim_value;
    signal input sd_array_hash;
    signal input message_hash;
    signal input commitment;
    signal input set[16];
    signal input set_len;

    component comm = Commitment();
    comm.claim_value <== claim_value;
    comm.sd_array_hash <== sd_array_hash;
    comm.message_hash <== message_hash;
    comm.out === commitment;

    // Compute product of (claim_value - set[i]) for all i.
    // If claim_value is in the set, at least one factor is 0, so product === 0.
    signal diffs[16];
    signal products[16];

    for (var i = 0; i < 16; i++) {
        diffs[i] <== claim_value - set[i];
    }

    products[0] <== diffs[0];
    for (var i = 1; i < 16; i++) {
        products[i] <== products[i-1] * diffs[i];
    }

    products[15] === 0;
}
component main {public [commitment, set, set_len]} = SetMember();
