pragma circom 2.2.3;
include "multiplexer.circom";
template OneHotClaim() {
    signal input index;
    signal input flags[3];
    component decoder = Decoder(3);
    decoder.inp <== index;
    decoder.success === 1;
    for (var i = 0; i < 3; i++) flags[i] === decoder.out[i];
}
component main = OneHotClaim();
