package custom_ring

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Every accepted fixture proves under its installed key, and only for its own statement.
func TestGoldenRequestsProveWithTheInstalledKeys(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			payload, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			meta, err := common.ParseProofRequestMeta(payload)
			if err != nil {
				t.Fatal(err)
			}
			ps := loadRingSystem(t, meta.CircuitType)
			assignment := goldenAssignment(t, meta.CircuitType, payload)
			proof, err := Prove(ps, assignment, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyProof(ps, proof, assignment); err != nil {
				t.Fatal(err)
			}
			if verifyProof(ps, proof, withPublicInputHash(assignment, big.NewInt(1))) == nil {
				t.Fatal("proof admitted under a different statement")
			}
		})
	}
}

func TestOrdinaryBaseFallbackAcceptsEverySettledOutputCount(t *testing.T) {
	cs := compileRing(t, common.CustomRingBaseCircuitType)
	for count := 1; count <= 4; count++ {
		params := baseParams(t)
		params.NOut = uint8(count)
		keys := ringaudit.DefaultKeys(t)
		statement := keys.Statement(params.PrivateTxHash.Int)
		statement.Count = count
		params.PublicInputHash = fb(spptest.MustHashChain(t, keys.ChainElementsFor(t, statement)))
		assignment, err := Assign(common.CustomRingBaseCircuitType, params)
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); err != nil {
			t.Fatalf("%d outputs: %v", count, err)
		}
	}
}

// withPublicInputHash replaces the one public input, wherever the circuit nests it.
func withPublicInputHash(assignment frontend.Circuit, value *big.Int) frontend.Circuit {
	copied := reflect.New(reflect.TypeOf(assignment).Elem())
	copied.Elem().Set(reflect.ValueOf(assignment).Elem())
	target := copied.Elem()
	for !target.FieldByName("PublicInputHash").IsValid() {
		target = target.Field(0)
	}
	target.FieldByName("PublicInputHash").Set(reflect.ValueOf(frontend.Variable(value)))
	return copied.Interface().(frontend.Circuit)
}

func TestDelegateProofDoesNotVerifyOnTheMemberRail(t *testing.T) {
	payload, err := os.ReadFile("testdata/custom-ring-delegate-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	ps := loadRingSystem(t, common.CustomRingDelegatePolicyCircuitType)
	member := loadRingSystem(t, common.CustomRingPolicyCircuitType)
	assignment := goldenAssignment(t, common.CustomRingDelegatePolicyCircuitType, payload)
	proof, err := Prove(ps, assignment, nil)
	if err != nil {
		t.Fatal(err)
	}
	if verifyProof(member, proof, assignment) == nil {
		t.Fatal("a delegate proof verified on the member rail")
	}
}

func TestConfidentialAuditKeyCannotReplaceAnonymousAudit(t *testing.T) {
	ordinary, err := os.ReadFile("testdata/custom-ring-base-confidential.json")
	if err != nil {
		t.Fatal(err)
	}
	anonymous, err := os.ReadFile("testdata/custom-ring-base-anonymous.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(common.CustomRingConfidentialCircuitType, anonymous); err == nil {
		t.Fatal("ordinary endpoint accepted anonymous disclosure")
	}
	for _, count := range []byte{'0', '1', '3', '4'} {
		changed := bytes.Replace(ordinary, []byte(`"nOut": 2`), []byte{'"', 'n', 'O', 'u', 't', '"', ':', ' ', count}, 1)
		if bytes.Equal(changed, ordinary) {
			t.Fatal("test fixture has no output count")
		}
		if _, err := Decode(common.CustomRingConfidentialCircuitType, changed); err == nil {
			t.Fatalf("ordinary endpoint accepted %c outputs", count)
		}
	}
	ps := loadRingSystem(t, common.CustomRingConfidentialCircuitType)
	other := loadRingSystem(t, common.CustomRingBaseCircuitType)
	assignment := goldenAssignment(t, common.CustomRingConfidentialCircuitType, ordinary)
	proof, err := Prove(ps, assignment, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProof(ps, proof, assignment); err != nil {
		t.Fatal(err)
	}
	if verifyProof(other, proof, assignment) == nil {
		t.Fatal("ordinary audit proof verified under the anonymous-capable key")
	}
}
