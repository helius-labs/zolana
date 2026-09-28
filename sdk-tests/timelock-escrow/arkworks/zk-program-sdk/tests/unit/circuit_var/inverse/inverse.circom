pragma circom 2.0.0;

template Inverse() {
    signal input x;
    signal input inverse;
    signal inv;

    inv <-- 1 / x;
    inv * x === 1;
    inverse === inv;
}

component main = Inverse();
