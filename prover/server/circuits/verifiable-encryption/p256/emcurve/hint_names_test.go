package emcurve

import (
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
)

const (
	modulePrefix = "zolana/prover/circuits/verifiable-encryption/p256/emcurve"
)

func TestHintNamesCarryTheModulePrefix(t *testing.T) {
	for _, fn := range []solver.Hint{
		p256RatioHint, p256TangentHint, p256AddHint,
		p256DecomposeScalarHint, p256ScalarMulHint, p256ImplicitChordHint, p256ImplicitSecondSlopeHint, p256HalfTangentHint,
		p256CombRecodeHint, p256CombChainHint, p256XEqualHint, p256UnifiedSlopeHint,
		p256RowLookupHint, p256RowCountHint,
		p256ScalarInverseHint, p256OrderWrapHint, p256LimbBytesHint, p256SplitLowBitsHint,
	} {
		name := solver.GetHintName(fn)
		if !strings.HasPrefix(name, modulePrefix+".") {
			t.Fatalf("hint %s is not under %s", name, modulePrefix)
		}
		if solver.GetRegisteredHint(solver.GetHintID(fn)) == nil {
			t.Fatalf("hint %s is not registered", name)
		}
	}

}
