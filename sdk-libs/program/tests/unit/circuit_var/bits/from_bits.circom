pragma circom 2.0.0;

include "bitify.circom";

template FromBits(n) {
    signal input bits[n];
    signal input value;

    component bits2Num = Bits2Num(n);
    for (var i = 0; i < n; i++) {
        bits[i] * (bits[i] - 1) === 0;
        bits2Num.in[i] <== bits[i];
    }
    value === bits2Num.out;
}

component main = FromBits(4);
