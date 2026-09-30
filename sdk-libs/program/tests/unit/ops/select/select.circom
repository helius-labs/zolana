pragma circom 2.0.0;

include "mux1.circom";

template Selected() {
    signal input condition;
    signal input if_true;
    signal input if_false;
    signal input selected;

    condition * (condition - 1) === 0;

    component mux = Mux1();
    mux.c[0] <== if_false;
    mux.c[1] <== if_true;
    mux.s <== condition;
    selected === mux.out;
}

component main = Selected();
