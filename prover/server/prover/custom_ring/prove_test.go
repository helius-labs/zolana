package custom_ring

import (
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark/frontend"

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
			assignment := decodePayload(t, meta.CircuitType, payload)
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

func withPublicInputHash(assignment frontend.Circuit, value *big.Int) frontend.Circuit {
	copied := reflect.New(reflect.TypeOf(assignment).Elem())
	copied.Elem().Set(reflect.ValueOf(assignment).Elem())
	copied.Elem().FieldByName("PublicInputHash").Set(reflect.ValueOf(frontend.Variable(value)))
	return copied.Interface().(frontend.Circuit)
}
