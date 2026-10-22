package base_test

import (
	"errors"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// compiledAudit is one audit circuit compiled as the ring prover compiles it.
type compiledAudit struct {
	cs constraint.ConstraintSystem
	// statementCID is the constraint binding the public input, a refusal must fail elsewhere.
	statementCID int
}

var compiledAudits = map[string]*compiledAudit{}

// compileAudit compiles circuit once per name and locates the public input binding with the honest assignment.
func compileAudit(t *testing.T, name string, circuit, honest frontend.Circuit) *compiledAudit {
	t.Helper()
	if c, ok := compiledAudits[name]; ok {
		return c
	}
	c := &compiledAudit{cs: ringkey.Compile(t, circuit)}
	c.requireSolved(t, honest)
	publicInput := reflect.ValueOf(honest).Elem().FieldByName("PublicInputHash")
	setPublicInput(honest, new(big.Int).Add(spptest.AsBigInt(publicInput.Interface()), big.NewInt(1)))
	c.statementCID = c.unsatisfied(t, honest).CID
	compiledAudits[name] = c
	return c
}

func (c *compiledAudit) requireSolved(t *testing.T, assignment frontend.Circuit) {
	t.Helper()
	if err := c.solve(t, assignment); err != nil {
		t.Fatalf("honest witness refused: %v", err)
	}
}

// refuse requires a constraint other than the public input binding to fail, the host statement matches the mutation.
func (c *compiledAudit) refuse(t *testing.T, assignment frontend.Circuit, options ...solver.Option) {
	t.Helper()
	if unsatisfied := c.unsatisfied(t, assignment, options...); unsatisfied.CID == c.statementCID {
		t.Fatalf("refused by the public input binding only, the host statement drifted: %v", unsatisfied)
	}
}

// refuseStatement requires the public input binding to fail, the statement publishes what the witness does not prove.
func (c *compiledAudit) refuseStatement(t *testing.T, assignment frontend.Circuit) {
	t.Helper()
	if unsatisfied := c.unsatisfied(t, assignment); unsatisfied.CID != c.statementCID {
		t.Fatalf("refused before the public input binding: %v", unsatisfied)
	}
}

// refuseStatementOf requires the public input binding to refuse assignment under the program's statement.
func (c *compiledAudit) refuseStatementOf(t *testing.T, assignment frontend.Circuit, statement []*big.Int) {
	t.Helper()
	setPublicInput(assignment, spptest.MustHashChain4(t, statement))
	c.refuseStatement(t, assignment)
}

func setPublicInput(assignment frontend.Circuit, value *big.Int) {
	reflect.ValueOf(assignment).Elem().FieldByName("PublicInputHash").Set(reflect.ValueOf(value))
}

func (c *compiledAudit) unsatisfied(t *testing.T, assignment frontend.Circuit, options ...solver.Option) *cs_bn254.UnsatisfiedConstraintError {
	t.Helper()
	err := c.solve(t, assignment, options...)
	hintattack.RequireConstraintRejection(t, err)
	var unsatisfied *cs_bn254.UnsatisfiedConstraintError
	errors.As(err, &unsatisfied)
	return unsatisfied
}

func (c *compiledAudit) solve(t *testing.T, assignment frontend.Circuit, options ...solver.Option) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return c.cs.IsSolved(witness, append(options, hintattack.SkipMissingLookupQueries(t))...)
}
