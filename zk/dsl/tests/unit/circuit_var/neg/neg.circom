pragma circom 2.0.0;

template Neg() {
    signal input value;
    signal input negation;

    negation === -value;
}

component main = Neg();
