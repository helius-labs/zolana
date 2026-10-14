pragma circom 2.0.0;

include "comparators.circom";
include "poseidon.circom";

template NonzeroHashChain(n) {
    signal input values[n];
    signal input chain;

    signal links[n + 1];
    signal nexts[n];
    signal skipped[n];
    component isZero[n];
    component isEmpty[n];
    component hash[n];

    links[0] <== 0;
    for (var i = 0; i < n; i++) {
        isZero[i] = IsZero();
        isZero[i].in <== values[i];
        isEmpty[i] = IsZero();
        isEmpty[i].in <== links[i];
        hash[i] = Poseidon(2);
        hash[i].inputs[0] <== links[i];
        hash[i].inputs[1] <== values[i];
        nexts[i] <== hash[i].out + isEmpty[i].out * (values[i] - hash[i].out);
        skipped[i] <== isZero[i].out * (links[i] - nexts[i]);
        links[i + 1] <== nexts[i] + skipped[i];
    }
    chain === links[n];
}
