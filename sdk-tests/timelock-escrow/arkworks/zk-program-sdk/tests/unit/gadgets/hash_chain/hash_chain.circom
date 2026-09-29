pragma circom 2.0.0;

include "comparators.circom";
include "poseidon.circom";

template NonzeroHashChain(n) {
    signal input values[n];
    signal input chain;

    signal links[n + 1];
    signal skipped[n];
    component isZero[n];
    component hash[n];

    links[0] <== 0;
    for (var i = 0; i < n; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== values[i];
        hash[i] = Poseidon(2);
        hash[i].inputs[0] <== links[i];
        hash[i].inputs[1] <== values[i];
        skipped[i] <== isZero[i].out * (links[i] - hash[i].out);
        links[i + 1] <== hash[i].out + skipped[i];
    }
    chain === links[n];
}
