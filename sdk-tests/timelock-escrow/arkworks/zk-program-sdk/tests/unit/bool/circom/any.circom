pragma circom 2.0.0;

include "comparators.circom";

template Any(n) {
    signal input in[n];
    signal output out;

    var sum = 0;
    for (var i = 0; i < n; i++) {
        sum += in[i];
    }
    component none = IsZero();
    none.in <== sum;
    out <== 1 - none.out;
}

template AnyClaim(n) {
    signal input flags[n];
    signal input out;

    for (var i = 0; i < n; i++) {
        flags[i] * (flags[i] - 1) === 0;
    }

    component gate = Any(n);
    for (var i = 0; i < n; i++) {
        gate.in[i] <== flags[i];
    }
    out === gate.out;
}

component main = AnyClaim(3);
