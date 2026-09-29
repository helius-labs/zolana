pragma circom 2.2.3;
template AssertIn() {
    signal input value;
    signal input set[3];
    signal product[2];
    product[0] <== (value - set[0]) * (value - set[1]);
    product[1] <== product[0] * (value - set[2]);
    product[1] === 0;
}
component main = AssertIn();
