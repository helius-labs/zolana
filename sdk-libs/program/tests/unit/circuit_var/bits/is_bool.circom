pragma circom 2.0.0;

template IsBool() {
    signal input x;

    x * (x - 1) === 0;
}

component main = IsBool();
