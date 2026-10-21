package shared_test

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const (
	ringSlot = 0
	exitSlot = 1
)

// ringRailWitness puts a ring output in ringSlot and, off the authority rail, an exit in exitSlot.
func ringRailWitness(t testing.TB, rail structuralRail) *testAssignment {
	t.Helper()
	a := rail.new(t)
	a.Outputs[ringSlot].Utxo.RingProgramID = a.RingProgramID
	if !rail.authority {
		a.Outputs[exitSlot].Utxo.RingProgramID = 0
	}
	rebuildAfterOwnerChange(t, a)
	return a
}

// A ring output opens only under its own ring secret, and no slot takes the other kind's blinding.
func TestRingOutputBlindingBindsRingSecret(t *testing.T) {
	for _, rail := range structuralRails(t) {
		if rail.name == "default" {
			continue
		}
		t.Run(rail.name, func(t *testing.T) {
			t.Run("honest", func(t *testing.T) {
				rail.check(t, ringRailWitness(t, rail), true)
			})
			t.Run("other ring secret", func(t *testing.T) {
				a := ringRailWitness(t, rail)
				a.Outputs[ringSlot].RingSecret = spptest.Fe(0xBAD)
				rail.check(t, a, false)
			})
			t.Run("ring output in default form", func(t *testing.T) {
				a := ringRailWitness(t, rail)
				blinding, err := protocol.OutputBlinding(spptest.AsBigInt(a.Inputs[0].Nullifier), a.outputBlindingSeed(t), ringSlot)
				a.Outputs[ringSlot].Utxo.Blinding = spptest.MustHash(t, blinding, err)
				refreshOutputCommitments(t, a)
				rail.check(t, a, false)
			})
			t.Run("dummy in ring form", func(t *testing.T) {
				a := ringRailWitness(t, rail)
				structuralCompactOutput(t, a)
				rail.check(t, a, true)
				dummy := &a.Outputs[1]
				dummy.Utxo.RingProgramID = a.RingProgramID
				dummy.Utxo.Blinding = ringaudit.RingBlinding(t, spptest.AsBigInt(a.Inputs[0].Nullifier), spptest.AsBigInt(dummy.RingSecret), 1)
				rail.check(t, a, false)
			})
			if rail.authority {
				return
			}
			t.Run("exit in ring form", func(t *testing.T) {
				a := ringRailWitness(t, rail)
				a.Outputs[exitSlot].Utxo.Blinding = ringaudit.RingBlinding(
					t,
					spptest.AsBigInt(a.Inputs[0].Nullifier),
					spptest.AsBigInt(a.Outputs[exitSlot].RingSecret),
					exitSlot,
				)
				refreshOutputCommitments(t, a)
				rail.check(t, a, false)
			})
		})
	}
}

type ringRailBlindingCircuit struct {
	InDefaultRing  frontend.Variable
	FirstNullifier frontend.Variable
	BlindingSeed   frontend.Variable
	RingSecret     frontend.Variable
	Blinding       frontend.Variable
	OutputIndex    int  `gnark:"-"`
	RingOutput     bool `gnark:"-"`
}

func (c *ringRailBlindingCircuit) Define(api frontend.API) error {
	seed := DeriveOutputBlindingSeed(api, c.FirstNullifier, c.BlindingSeed)
	blinding := DeriveRingRailOutputBlinding(api, c.InDefaultRing, c.FirstNullifier, seed, c.RingSecret, c.OutputIndex)
	api.AssertIsEqual(c.Blinding, blinding)
	if c.RingOutput {
		api.AssertIsEqual(c.Blinding, DeriveRingOutputBlinding(api, c.FirstNullifier, c.RingSecret, c.OutputIndex))
	}
	return nil
}

type ringSecretsVector struct {
	FirstNullifier string `json:"first_nullifier"`
	BlindingSeed   string `json:"blinding_seed"`
	Outputs        []struct {
		OutputIndex            int    `json:"output_index"`
		PackedRingSecret       string `json:"packed_ring_secret"`
		PackedBlinding         string `json:"packed_blinding"`
		ConfidentialRingSecret string `json:"confidential_ring_secret"`
		ConfidentialBlinding   string `json:"confidential_blinding"`
		AnonymousRingSecret    string `json:"anonymous_ring_secret"`
		AnonymousBlinding      string `json:"anonymous_blinding"`
		ExitBlinding           string `json:"exit_blinding"`
	} `json:"outputs"`
}

// Both Go ring blinding derivations reproduce every ring secret form of the
// Rust vector, and a ring rail exit keeps its TXOB blinding whatever ring
// secret the slot carries.
func TestRingRailOutputBlindingMatchesRingSecretsVector(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate ring_output_blinding_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../../test-vectors/ring-secrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector ringSecretsVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.Outputs) == 0 {
		t.Fatal("no ring secret vectors")
	}
	field := func(value string) *big.Int {
		out, ok := new(big.Int).SetString(value, 16)
		if !ok {
			t.Fatalf("%q is not hex", value)
		}
		return out
	}
	for _, output := range vector.Outputs {
		cases := map[string]struct {
			inDefaultRing int
			ringSecret    string
			blinding      string
		}{
			"packed":       {0, output.PackedRingSecret, output.PackedBlinding},
			"confidential": {0, output.ConfidentialRingSecret, output.ConfidentialBlinding},
			"anonymous":    {0, output.AnonymousRingSecret, output.AnonymousBlinding},
			"exit":         {1, output.AnonymousRingSecret, output.ExitBlinding},
		}
		for name, c := range cases {
			shape := ringRailBlindingCircuit{OutputIndex: output.OutputIndex, RingOutput: c.inDefaultRing == 0}
			assignment := shape
			assignment.InDefaultRing = c.inDefaultRing
			assignment.FirstNullifier = field(vector.FirstNullifier)
			assignment.BlindingSeed = field(vector.BlindingSeed)
			assignment.RingSecret = field(c.ringSecret)
			assignment.Blinding = field(c.blinding)
			if err := test.IsSolved(&shape, &assignment, ecc.BN254.ScalarField()); err != nil {
				t.Errorf("slot %d %s: %v", output.OutputIndex, name, err)
			}
		}
	}
}
