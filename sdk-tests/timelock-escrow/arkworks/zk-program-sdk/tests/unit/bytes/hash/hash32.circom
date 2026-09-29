pragma circom 2.0.0;
include "../bytes.circom";
template Hash(N) {
 signal input bytes[N];
 signal input claimed;
 component checked = CheckedBytes(N);
 checked.in <== bytes;
 component h = ChunkedPoseidon(N);
 h.in <== bytes;
 claimed === h.out;
}
component main = Hash(32);
