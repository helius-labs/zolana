pragma circom 2.0.0;

template Sub() {
    signal input left;
    signal input right;
    signal input difference;

    difference === left - right;
}

component main = Sub();
