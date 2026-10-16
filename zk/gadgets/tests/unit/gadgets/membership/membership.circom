pragma circom 2.2.3;
include "comparators.circom";
template Membership() {
    signal input value;
    signal input set[3];
    signal input member;
    component same[3];
    signal absent[4];
    absent[0] <== 1;
    for (var i = 0; i < 3; i++) {
        same[i] = IsEqual();
        same[i].in[0] <== value;
        same[i].in[1] <== set[i];
        absent[i + 1] <== absent[i] * (1 - same[i].out);
    }
    member === 1 - absent[3];
}
component main = Membership();
