pragma circom 2.0.0;

template Add() {
    signal input left;
    signal input right;
    signal input sum;

    sum === left + right;
}

component main = Add();
