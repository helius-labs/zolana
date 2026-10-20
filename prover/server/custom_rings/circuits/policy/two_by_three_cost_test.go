package policy

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type twoByThreeStage struct {
	TwoByThreeCircuit
	Stage int `gnark:"-"`
}

func (s *twoByThreeStage) Define(api frontend.API) error {
	c := &s.Policy
	c.FixedInputs, c.FixedOutputs, c.FixedMode = 2, 3, 1
	rc := rangecheck.New(api)
	checked := c.checkPolicy(api, rc)
	if s.Stage == 0 {
		return nil
	}
	tx := c.constrainTransaction(api, rc)
	c.constrainNamespace(api, tx)
	if s.Stage == 1 {
		return nil
	}
	subjects := c.resolveSubjects(api, tx, checked)
	if s.Stage == 2 {
		return nil
	}
	c.constrainRules(api, tx, subjects, checked)
	c.constrainLimits(api, checked.limits, tx)
	c.constrainEscrow(api, tx, subjects)
	if s.Stage == 3 {
		return nil
	}
	a := c.Audit
	a.Anonymous = 0
	audit := a.Define(api, rc, c.auditTx(tx))
	if s.Stage == 4 {
		return nil
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, append(audit[:], checked.hash)))
	return nil
}

func TestTwoByThreeCostBreakdown(t *testing.T) {
	previous := 0
	for stage, label := range []string{"policy_table", "plus_transaction", "plus_registry", "plus_rules", "plus_audit", "plus_statement"} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &twoByThreeStage{Stage: stage}, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		count := cs.GetNbConstraints()
		t.Logf("%s cumulative=%d marginal=%d", label, count, count-previous)
		previous = count
	}
}

func TestTwoByThreeCost(t *testing.T) {
	for _, tc := range []struct {
		name      string
		anonymous bool
		delegate  bool
	}{
		{name: "ordinary"},
		{name: "anonymous", anonymous: true},
		{name: "delegate", delegate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			circuit := &TwoByThreeCircuit{Anonymous: tc.anonymous, Delegate: tc.delegate}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("2x3 %s policy and audit: %d constraints", tc.name, cs.GetNbConstraints())
		})
	}
}

func TestPublicTableTwoByThreeCost(t *testing.T) {
	// An anonymous key has no ceiling, its count moves only with a key rotation.
	for _, tc := range []struct {
		anonymous bool
		depth     int
		pinned    int
	}{
		{depth: 3},
		{anonymous: true, pinned: 194119},
		{anonymous: true, depth: 3, pinned: 194119},
	} {
		c := &PublicTableTwoByThreeCircuit{Circuit: TwoByThreeCircuit{Anonymous: tc.anonymous, RegistrySubtreeDepth: tc.depth}}
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("public table anonymous=%v depth=%d constraints=%d public=%d", tc.anonymous, tc.depth, cs.GetNbConstraints(), cs.GetNbPublicVariables())
		if tc.anonymous && cs.GetNbConstraints() != tc.pinned {
			t.Errorf("anonymous depth=%d constraints=%d, pinned %d", tc.depth, cs.GetNbConstraints(), tc.pinned)
		}
	}
}

func TestTwoByThreeChecksShapeAndMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		anonymous bool
		delegate  bool
		depth     int
	}{
		{name: "ordinary"},
		{name: "anonymous", anonymous: true},
		{name: "delegate", delegate: true},
		{name: "ordinary_subtree", depth: 3},
		{name: "anonymous_subtree", anonymous: true, depth: 3},
		{name: "delegate_subtree", delegate: true, depth: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			circuit := &TwoByThreeCircuit{Anonymous: tc.anonymous, Delegate: tc.delegate, RegistrySubtreeDepth: tc.depth}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("2x3 %s: %d constraints", tc.name, cs.GetNbConstraints())
			s := newStatement(t, defaultFixture())
			s.anonymous = tc.anonymous
			s.outputs = append(s.outputs, dummyOpening(t, 0x56))
			s.recipientKeys[2] = s.recipientKeys[0]
			if tc.delegate {
				s.limits = []limitRow{{asset: assetField(t, defaultFixture().transferred), cap: 1, cosign: 1}}
				s.escrowOutputs(t)
			}
			w := &TwoByThreeCircuit{Policy: *s.assignment(t), Anonymous: tc.anonymous, Delegate: tc.delegate, RegistrySubtreeDepth: tc.depth}
			check := func(w *TwoByThreeCircuit, accepted bool) {
				t.Helper()
				witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
				if err != nil {
					t.Fatal(err)
				}
				err = cs.IsSolved(witness)
				if accepted && err != nil {
					t.Fatalf("valid witness rejected: %v", err)
				}
				if !accepted && err == nil {
					t.Fatal("invalid witness accepted")
				}
			}
			check(w, true)
			wrongShape := *w
			wrongShape.Policy.NOut = 2
			check(&wrongShape, false)
			wrongMode := *w
			if tc.anonymous {
				wrongMode.Policy.Anonymous = 0
			} else {
				wrongMode.Policy.Anonymous = 1
			}
			check(&wrongMode, false)
			wrongMember := *w
			wrongMember.Policy.Subjects[NInputs].Path[0] = 123456
			check(&wrongMember, false)
			wrongOutput := *w
			wrongOutput.Policy.Outputs[0].Amount = 123456
			check(&wrongOutput, false)
			wrongAudit := *w
			wrongAudit.Policy.Salt[0] = 123
			check(&wrongAudit, false)
		})
	}
}
