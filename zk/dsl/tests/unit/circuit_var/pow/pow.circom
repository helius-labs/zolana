pragma circom 2.0.0;

template Pow5() {
    signal input x;
    signal input power;
    signal x2;
    signal x4;
    signal x5;

    x2 <== x * x;
    x4 <== x2 * x2;
    x5 <== x4 * x;
    power === x5;
}

component main = Pow5();
