pragma circom 2.0.0;

template Product() {
    signal input left;
    signal input right;
    signal input product;
    left * right === product;
}

component main = Product();
