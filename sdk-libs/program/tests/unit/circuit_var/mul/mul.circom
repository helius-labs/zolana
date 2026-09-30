pragma circom 2.0.0;

template Mul() {
    signal input left;
    signal input right;
    signal input product;
    signal computed;

    computed <== left * right;
    product === computed;
}

component main = Mul();
