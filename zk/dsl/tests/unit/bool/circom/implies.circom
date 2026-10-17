pragma circom 2.0.0;

template Implies() {
    signal input a;
    signal input b;
    signal output out;

    out <== 1 - a + a*b;
}

template ImpliesClaim() {
    signal input a;
    signal input b;
    signal input out;

    a * (a - 1) === 0;
    b * (b - 1) === 0;

    component gate = Implies();
    gate.a <== a;
    gate.b <== b;
    out === gate.out;
}

component main = ImpliesClaim();
