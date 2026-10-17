pragma circom 2.0.0;
include "bitify.circom";
include "comparators.circom";
include "mux1.circom";
template Compare(n, op) {
 signal input x; signal input y; signal input claimed;
 component bx = Num2Bits(n); bx.in <== x;
 component by = Num2Bits(n); by.in <== y;
 if (op == 0 || op == 2) {
  component lt = LessThan(n); lt.in[0] <== x; lt.in[1] <== y;
  if(op == 0) { claimed === lt.out; }
  else { claimed === y + lt.out * (x - y); }
 }
 if (op == 1) {
  component le = LessEqThan(n); le.in[0] <== x; le.in[1] <== y;
  claimed === le.out;
 }
 if(op == 3) {
  component gt = GreaterThan(n); gt.in[0] <== x; gt.in[1] <== y;
  claimed === y + gt.out * (x - y);
 }
 if(op == 4 || op == 5) {
  component eq = IsEqual(); eq.in[0] <== x; eq.in[1] <== y;
  claimed === eq.out;
 }
}
template Division(n, qn, dn) {
 signal input x; signal input divisor; signal input quotient; signal input remainder;
 component bx = Num2Bits(n); bx.in <== x;
 component bd = Num2Bits(dn); bd.in <== divisor;
 component bq = Num2Bits(qn); bq.in <== quotient;
 component br = Num2Bits(dn); br.in <== remainder;
 component lt = LessThan(dn); lt.in[0] <== remainder; lt.in[1] <== divisor;
 lt.out === 1;
 quotient * divisor === x - remainder;
}
template Selection(n) {
 signal input x; signal input y; signal input condition; signal input claimed;
 component bx = Num2Bits(n); bx.in <== x;
 component by = Num2Bits(n); by.in <== y;
 condition * (condition - 1) === 0;
 component mux = Mux1(); mux.c[0] <== y; mux.c[1] <== x; mux.s <== condition;
 claimed === mux.out;
}
template Zero(n) {
 signal input x; signal input claimed;
 component bx = Num2Bits(n); bx.in <== x;
 component z = IsZero(); z.in <== x;
 claimed === z.out;
}
template Pair(n, op) {
 signal input x; signal input y;
 component bx = Num2Bits(n); bx.in <== x;
 component by = Num2Bits(n); by.in <== y;
 if(op == 0) { component lt = LessThan(n); lt.in[0] <== x; lt.in[1] <== y; lt.out === 1; }
 if(op == 1) { component le = LessEqThan(n); le.in[0] <== x; le.in[1] <== y; le.out === 1; }
 if(op == 2 || op == 4) { x === y; }
 if(op == 3 || op == 5) { component eq = IsEqual(); eq.in[0] <== x; eq.in[1] <== y; eq.out === 0; }
}
template Range(n) {
 signal input x; signal input low; signal input high;
 component bx = Num2Bits(n); bx.in <== x;
 component bl = Num2Bits(n); bl.in <== low;
 component bh = Num2Bits(n); bh.in <== high;
 component lower = LessEqThan(n); lower.in[0] <== low; lower.in[1] <== x; lower.out === 1;
 component upper = LessEqThan(n); upper.in[0] <== x; upper.in[1] <== high; upper.out === 1;
}
template Conditional(n) {
 signal input x; signal input y; signal input condition;
 component bx = Num2Bits(n); bx.in <== x;
 component by = Num2Bits(n); by.in <== y;
 condition * (condition - 1) === 0;
 (x - y) * condition === 0;
}
template AssertZero(n, nonzero) {
 signal input x;
 component bx = Num2Bits(n); bx.in <== x;
 component z = IsZero(); z.in <== x;
 z.out === 1-nonzero;
}
