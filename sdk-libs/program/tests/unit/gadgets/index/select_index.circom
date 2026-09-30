pragma circom 2.2.3;
include "multiplexer.circom";
template SelectIndexClaim() {
    signal input items[3];
    signal input index;
    signal input selected;
    component mux = Multiplexer(1, 3);
    mux.sel <== index;
    for (var i = 0; i < 3; i++) mux.inp[i][0] <== items[i];
    selected === mux.out[0];
}
component main = SelectIndexClaim();
