pragma circom 2.0.0;

include "gates.circom";

template AndClaim() {
    signal input a;
    signal input b;
    signal input out;

    a * (a - 1) === 0;
    b * (b - 1) === 0;

    component gate = AND();
    gate.a <== a;
    gate.b <== b;
    out === gate.out;
}

component main = AndClaim();
