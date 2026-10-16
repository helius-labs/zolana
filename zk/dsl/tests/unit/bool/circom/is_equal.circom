pragma circom 2.0.0;

include "comparators.circom";

template IsEqualClaim() {
    signal input a;
    signal input b;
    signal input out;

    a * (a - 1) === 0;
    b * (b - 1) === 0;

    component isEqual = IsEqual();
    isEqual.in[0] <== a;
    isEqual.in[1] <== b;
    out === isEqual.out;
}

component main = IsEqualClaim();
