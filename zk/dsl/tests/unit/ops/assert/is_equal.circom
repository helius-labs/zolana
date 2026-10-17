pragma circom 2.0.0;

include "comparators.circom";

template IsEqualClaim() {
    signal input left;
    signal input right;
    signal input claimed;

    component isEqual = IsEqual();
    isEqual.in[0] <== left;
    isEqual.in[1] <== right;
    claimed === isEqual.out;
}

component main = IsEqualClaim();
