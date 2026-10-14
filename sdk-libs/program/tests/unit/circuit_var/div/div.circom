pragma circom 2.0.0;

template Div() {
    signal input dividend;
    signal input divisor;
    signal input quotient;
    signal inv;
    signal product;

    inv <-- 1 / divisor;
    inv * divisor === 1;
    product <== dividend * inv;
    quotient === product;
}

component main = Div();
