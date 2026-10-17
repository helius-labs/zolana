pragma circom 2.0.0;

include "bitify.circom";

template AddClaim(n) {
    signal input x;
    signal input y;
    signal input claimed;

    component xBits = Num2Bits(n);
    xBits.in <== x;
    component yBits = Num2Bits(n);
    yBits.in <== y;
    claimed === x + y;
}

template MulClaim(n) {
    signal input x;
    signal input y;
    signal input claimed;

    component xBits = Num2Bits(n);
    xBits.in <== x;
    component yBits = Num2Bits(n);
    yBits.in <== y;
    signal product;
    product <== x * y;
    claimed === product;
}

template CheckedAddClaim(n) {
    signal input x;
    signal input y;
    signal input claimed;

    component xBits = Num2Bits(n);
    xBits.in <== x;
    component yBits = Num2Bits(n);
    yBits.in <== y;
    component fits = Num2Bits(n);
    fits.in <== x + y;
    claimed === x + y;
}

template CheckedMulClaim(n) {
    signal input x;
    signal input y;
    signal input claimed;

    component xBits = Num2Bits(n);
    xBits.in <== x;
    component yBits = Num2Bits(n);
    yBits.in <== y;
    signal product;
    product <== x * y;
    component fits = Num2Bits(n);
    fits.in <== product;
    claimed === product;
}

template CheckedSubClaim(n) {
    signal input x;
    signal input y;
    signal input claimed;

    component xBits = Num2Bits(n);
    xBits.in <== x;
    component yBits = Num2Bits(n);
    yBits.in <== y;
    component fits = Num2Bits(n);
    fits.in <== x - y;
    claimed === x - y;
}
