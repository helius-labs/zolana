pragma circom 2.0.0;

include "gates.circom";

template XorClaim() {
    signal input a;
    signal input b;
    signal input out;

    a * (a - 1) === 0;
    b * (b - 1) === 0;

    component gate = XOR();
    gate.a <== a;
    gate.b <== b;
    out === gate.out;
}

component main = XorClaim();
