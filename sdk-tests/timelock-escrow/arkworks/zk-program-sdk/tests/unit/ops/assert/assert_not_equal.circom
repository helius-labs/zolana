pragma circom 2.0.0;

template AssertNotEqual() {
    signal input left;
    signal input right;

    signal inverse;

    inverse <-- 1 / (left - right);
    (left - right) * inverse === 1;
}

component main = AssertNotEqual();
