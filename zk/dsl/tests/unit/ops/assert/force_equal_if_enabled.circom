pragma circom 2.0.0;

include "comparators.circom";

template AssertEqualIf() {
    signal input left;
    signal input right;
    signal input condition;

    condition * (condition - 1) === 0;

    component force = ForceEqualIfEnabled();
    force.enabled <== condition;
    force.in[0] <== left;
    force.in[1] <== right;
}

component main = AssertEqualIf();
