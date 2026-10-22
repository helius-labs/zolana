// Package ringkey compiles a ring key's circuit as the ring prover does and holds it to its pin.
package ringkey

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Pinned is every ring key's constraint count by key file name.
var Pinned = map[string]int{
	"custom_ring_audit_packed_2":            53502,
	"custom_ring_audit_packed_4":            64827,
	"custom_ring_audit_delivered_8":         284405,
	"custom_ring_audit_delivered_16":        524519,
	"custom_ring_audit_anonymous_4_2":       123527,
	"custom_ring_audit_anonymous_8_2":       130338,
	"custom_ring_audit_anonymous_12_2":      137144,
	"custom_ring_audit_anonymous_16_2":      143952,
	"custom_ring_audit_anonymous_24_2":      157569,
	"custom_ring_audit_anonymous_32_2":      171190,
	"custom_ring_audit_anonymous_4_4":       185360,
	"custom_ring_audit_anonymous_8_4":       192172,
	"custom_ring_audit_anonymous_12_4":      198977,
	"custom_ring_audit_anonymous_16_4":      205786,
	"custom_ring_audit_anonymous_24_4":      219403,
	"custom_ring_audit_anonymous_4_8":       310756,
	"custom_ring_audit_anonymous_8_8":       317568,
	"custom_ring_audit_anonymous_12_8":      324373,
	"custom_ring_audit_anonymous_16_8":      331182,
	"custom_ring_audit_anonymous_1_16":      554690,
	"custom_ring_audit_anonymous_entry_8_2": 138067,
	"custom_ring_audit_anonymous_entry_8_4": 199900,
	"custom_ring_audit_anonymous_entry_8_8": 325296,
	"custom_ring_policy_member_2":           48455,
	"custom_ring_policy_member_4":           82348,
	"custom_ring_policy_member_8":           150253,
	"custom_ring_policy_member_16":          286047,
	"custom_ring_policy_delegate_1x2":       48736,
	"custom_ring_policy_delegate_1x4":       82565,
	"custom_ring_policy_delegate_1x8":       150391,
	"custom_ring_policy_delegate_2x2":       50089,
	"custom_ring_policy_delegate_2x4":       83918,
	"custom_ring_policy_delegate_1x16":      285928,
	"custom_ring_policy_delegate_2x8":       151744,
	"custom_ring_policy_delegate_3x2":       51442,
	"custom_ring_policy_delegate_3x4":       85271,
	"custom_ring_policy_delegate_2x16":      287281,
	"custom_ring_policy_delegate_3x8":       153097,
	"custom_ring_policy_delegate_4x2":       52795,
	"custom_ring_policy_delegate_4x4":       86624,
	"custom_ring_policy_delegate_4x8":       154450,
	"custom_ring_policy_delegate_5x2":       54148,
	"custom_ring_policy_delegate_5x4":       87977,
	"custom_ring_policy_delegate_4x16":      289987,
	"custom_ring_policy_delegate_5x8":       155803,
	"custom_ring_policy_delegate_6x2":       55501,
	"custom_ring_policy_delegate_6x4":       89330,
	"custom_ring_policy_delegate_5x16":      291340,
	"custom_ring_policy_delegate_6x8":       157156,
	"custom_ring_policy_delegate_8x2":       58207,
	"custom_ring_policy_delegate_8x4":       92036,
	"custom_ring_policy_delegate_8x8":       159862,
	"custom_ring_policy_delegate_8x16":      295399,
	"custom_ring_policy_delegate_12x2":      63619,
	"custom_ring_policy_delegate_12x4":      97448,
	"custom_ring_policy_delegate_12x8":      165274,
	"custom_ring_policy_delegate_16x2":      69031,
	"custom_ring_policy_delegate_16x4":      102860,
	"custom_ring_policy_delegate_16x8":      170686,
	"custom_ring_policy_delegate_24x2":      79855,
	"custom_ring_policy_delegate_24x4":      113684,
	"custom_ring_policy_delegate_32x2":      90679,
	"custom_ring_policy_delegate_40x2":      101503,
	"custom_ring_apply_records_1":           15492,
	"custom_ring_apply_records_16":          232892,
	"custom_ring_register_key":              36991,
	"custom_ring_deposit":                   148936,
	"custom_ring_merge_anonymous_8":         56192,
	"custom_ring_merge_anonymous_24":        81698,
}

// Name is the key file name of the catalog key a family shape compiles to.
func Name(t testing.TB, family common.RingFamily, inputs, outputs int) string {
	t.Helper()
	for _, key := range common.RingKeys {
		if key.Family == family && key.Inputs == inputs && key.Outputs == outputs {
			return strings.TrimSuffix(common.RingKeyFile(key.Circuit), ".key")
		}
	}
	t.Fatalf("no catalog key of family %d for %d inputs and %d outputs", family, inputs, outputs)
	return ""
}

// Compile uses the compress threshold of prover/custom_ring/ring.go.
func Compile(t testing.TB, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// RequirePinned holds the key to its pin, one public input and the one BSB22 commitment over private wires groth16-solana verifies.
func RequirePinned(t testing.TB, name string, cs constraint.ConstraintSystem) {
	t.Helper()
	pinned, ok := Pinned[name]
	if !ok {
		t.Fatalf("%s has no pin", name)
	}
	if got := cs.GetNbConstraints(); got != pinned {
		t.Errorf("%s: %d constraints, pinned %d", name, got, pinned)
	}
	if public := cs.GetNbPublicVariables() - 1; public != 1 {
		t.Errorf("%s: %d public inputs, the program verifies one", name, public)
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
		t.Errorf("%s: commitments %v, want one over private wires", name, cs.GetCommitments())
	}
}
