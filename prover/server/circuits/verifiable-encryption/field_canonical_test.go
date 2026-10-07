package verifiableencryption_test

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"

	"zolana/prover/prover-test/hintattack"
)

func TestFieldToBytesRejectsNoncanonicalHint(t *testing.T) {
	cs := compileGadget(t, &fieldToBytesCircuit{})
	w := &fieldToBytesCircuit{Value: 0}
	for i := range w.Bytes {
		w.Bytes[i] = 0
	}
	if err := solveCompiled(t, cs, w); err != nil {
		t.Fatal(err)
	}
	var bitsHint solver.HintID
	for _, hint := range solver.GetRegisteredHints() {
		if strings.HasSuffix(solver.GetHintName(hint), "/math/bits.nBits") {
			bitsHint = solver.GetHintID(hint)
			break
		}
	}
	if bitsHint == 0 {
		t.Fatal("gnark's nBits hint is not registered")
	}
	forge := func(field *big.Int, inputs, outputs []*big.Int) error {
		v := new(big.Int).Add(inputs[0], field)
		for i, out := range outputs {
			out.SetUint64(uint64(v.Bit(i)))
		}
		return nil
	}
	for i, b := range ecc.BN254.ScalarField().FillBytes(make([]byte, 32)) {
		w.Bytes[i] = b
	}
	hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, w, solver.OverrideHint(bitsHint, forge)))
}
