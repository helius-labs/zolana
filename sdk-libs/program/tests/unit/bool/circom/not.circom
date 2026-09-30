pragma circom 2.0.0;

include "gates.circom";

template NotClaim() {
    signal input a;
    signal input out;

    a * (a - 1) === 0;

    component gate = NOT();
    gate.in <== a;
    out === gate.out;
}

component main = NotClaim();
