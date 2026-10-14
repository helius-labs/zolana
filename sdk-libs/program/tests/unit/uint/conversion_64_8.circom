pragma circom 2.0.0;
include "bitify.circom";
template Narrow() {
 signal input x; signal input claimed;
 component wide = Num2Bits(64); wide.in <== x;
 component narrow = Num2Bits(8); narrow.in <== x;
 claimed === x;
}
component main = Narrow();
