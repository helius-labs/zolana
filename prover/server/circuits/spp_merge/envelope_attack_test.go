package merge_test

import (
	"testing"
	"time"

	"github.com/consensys/gnark/constraint/solver"

	"zolana/prover/prover-test/hintattack"
)

func TestMergeRejectsHintAttacks(t *testing.T) {
	start := time.Now()
	cs := compiledDefaultMerge(t)
	assignment := buildValidWitness(t)
	t.Logf("compiled and built the witness in %s", time.Since(start).Round(time.Millisecond))
	hintattack.RunHintAttacks(t, func(opts ...solver.Option) error {
		return solveMerge(t, cs, assignment, opts...)
	})
	t.Logf("total %s", time.Since(start).Round(time.Millisecond))
}
