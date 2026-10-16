pragma circom 2.0.0;

include "../bytes.circom";

// The packed value is the checked bytes read big-endian.
template Pack(N) {
    signal input bytes[N];
    signal input packed;

    component checked = CheckedBytes(N);
    checked.in <== bytes;
    component chunks = PackedChunks(N);
    chunks.in <== bytes;
    packed === chunks.out[0];
}

component main = Pack(2);
