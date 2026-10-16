pragma circom 2.0.0;

include "comparators.circom";

template IsZeroClaim() {
    signal input x;
    signal input claimed;

    component isZero = IsZero();
    isZero.in <== x;
    claimed === isZero.out;
}

component main = IsZeroClaim();
