pragma circom 2.0.0;
include "bitify.circom";
template Sum() {
 signal input values[3]; signal input claimed;
 component bits[3];
 for (var i=0; i<3; i++) { bits[i] = Num2Bits(4); bits[i].in <== values[i]; }
 claimed === values[0] + values[1] + values[2];
}
component main = Sum();
