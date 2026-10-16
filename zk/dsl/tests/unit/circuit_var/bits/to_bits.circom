pragma circom 2.0.0;

include "bitify.circom";

template ToBits(n) {
    signal input x;
    signal input bits[n];

    component num2Bits = Num2Bits(n);
    num2Bits.in <== x;
    for (var i = 0; i < n; i++) {
        bits[i] === num2Bits.out[i];
    }
}

component main = ToBits(4);
