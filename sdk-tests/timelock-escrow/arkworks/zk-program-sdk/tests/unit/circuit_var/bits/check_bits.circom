pragma circom 2.0.0;

include "bitify.circom";

template CheckBits(n) {
    signal input x;
    signal output bits[n];

    component num2Bits = Num2Bits(n);
    num2Bits.in <== x;
    bits <== num2Bits.out;
}

component main = CheckBits(4);
