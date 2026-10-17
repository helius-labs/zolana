pragma circom 2.0.0;
include "../bytes.circom";
include "comparators.circom";
include "mux1.circom";
template Pairs(N) {
 signal input left[N]; signal input right[N];
 var chunks=(N+30)\31;
 signal output l[chunks]; signal output r[chunks];
 component a=CheckedBytes(N); component b=CheckedBytes(N);
 a.in <== left; b.in <== right;
 component p=PackedChunks(N); component q=PackedChunks(N);
 p.in <== left; q.in <== right;
 l <== p.out; r <== q.out;
}
template Equal(N) {
 signal input left[N]; signal input right[N];
 component pair=Pairs(N); pair.left <== left; pair.right <== right;
 for(var i=0;i<(N+30)\31;i++) { pair.l[i] === pair.r[i]; }
}
template EqualIf(N) {
 signal input left[N]; signal input right[N]; signal input condition;
 condition*(condition-1) === 0;
 component pair=Pairs(N); pair.left <== left; pair.right <== right;
 for(var i=0;i<(N+30)\31;i++) { condition*(pair.l[i]-pair.r[i]) === 0; }
}
template Equality(N, Negated) {
 signal input left[N]; signal input right[N]; signal input claimed;
 claimed*(claimed-1) === 0;
 component pair=Pairs(N); pair.left <== left; pair.right <== right;
 var chunks=(N+30)\31;
 component eq[chunks]; signal acc[chunks+1]; acc[0] <== 1;
 for(var i=0;i<chunks;i++) {
  eq[i]=IsEqual(); eq[i].in[0] <== pair.l[i]; eq[i].in[1] <== pair.r[i];
  acc[i+1] <== acc[i]*eq[i].out;
 }
 claimed === acc[chunks];
 if(Negated) { claimed === 0; }
}
template Selected(N) {
 signal input condition; signal input left[N]; signal input right[N]; signal input selected[N];
 condition*(condition-1) === 0;
 component pair=Pairs(N); pair.left <== left; pair.right <== right;
 component mux[N];
 for(var i=0;i<N;i++) { mux[i]=Mux1(); mux[i].s <== condition; mux[i].c[0] <== right[i]; mux[i].c[1] <== left[i]; selected[i] === mux[i].out; }
}
