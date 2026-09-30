pragma circom 2.0.0;

include "../bytes.circom";

// The bytes are the value's big-endian bytes.
template Split(N) {
    signal input value;
    signal input bytes[N];

    component bits = Num2Bits(8 * N);
    bits.in <== value;
    for (var i = 0; i < N; i++) {
        var byte = 0;
        for (var j = 7; j >= 0; j--) {
            byte = byte * 2 + bits.out[8 * (N - 1 - i) + j];
        }
        bytes[i] === byte;
    }
}

component main = Split(2);
