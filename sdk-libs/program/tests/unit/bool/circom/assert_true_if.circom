pragma circom 2.0.0;

template AssertTrueIf() {
    signal input a;
    signal input b;

    a * (a - 1) === 0;
    b * (b - 1) === 0;

    (a - 1) * b === 0;
}

component main = AssertTrueIf();
