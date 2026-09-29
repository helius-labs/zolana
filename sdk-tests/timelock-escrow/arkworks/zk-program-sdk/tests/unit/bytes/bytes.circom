pragma circom 2.0.0;

include "bitify.circom";
include "poseidon.circom";

// Every byte fits in 8 bits.
template CheckedBytes(N) {
    signal input in[N];

    component range[N];
    for (var i = 0; i < N; i++) {
        range[i] = Num2Bits(8);
        range[i].in <== in[i];
    }
}

// The bytes in 31-byte big-endian chunks, the last one shorter.
template PackedChunks(N) {
    var chunks = (N + 30) \ 31;
    signal input in[N];
    signal output out[chunks];

    for (var k = 0; k < chunks; k++) {
        var packed = 0;
        for (var i = 31 * k; i < N && i < 31 * (k + 1); i++) {
            packed = packed * 256 + in[i];
        }
        out[k] <== packed;
    }
}

// The chunks folded from the left with Poseidon(2); N is above 31.
template ChunkedPoseidon(N) {
    var chunks = (N + 30) \ 31;
    signal input in[N];
    signal output out;

    component packed = PackedChunks(N);
    packed.in <== in;
    component hash[chunks - 1];
    signal folded[chunks];
    folded[0] <== packed.out[0];
    for (var k = 1; k < chunks; k++) {
        hash[k - 1] = Poseidon(2);
        hash[k - 1].inputs[0] <== folded[k - 1];
        hash[k - 1].inputs[1] <== packed.out[k];
        folded[k] <== hash[k - 1].out;
    }
    out <== folded[chunks - 1];
}
