pragma circom 2.0.0;

include "gates.circom";

template MultiAndClaim(n) {
    signal input flags[n];
    signal input out;

    for (var i = 0; i < n; i++) {
        flags[i] * (flags[i] - 1) === 0;
    }

    component gate = MultiAND(n);
    for (var i = 0; i < n; i++) {
        gate.in[i] <== flags[i];
    }
    out === gate.out;
}

component main = MultiAndClaim(3);
