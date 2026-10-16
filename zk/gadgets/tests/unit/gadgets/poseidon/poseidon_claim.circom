pragma circom 2.0.0;

include "poseidon.circom";

template PoseidonClaim(n) {
    signal input inputs[n];
    signal input hash;

    component poseidon = Poseidon(n);
    for (var i = 0; i < n; i++) {
        poseidon.inputs[i] <== inputs[i];
    }
    hash === poseidon.out;
}
