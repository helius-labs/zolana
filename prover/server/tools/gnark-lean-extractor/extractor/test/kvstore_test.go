package extractor_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type keyValueStore interface {
	SetKeyValue(key, value any)
	GetKeyValue(key any) any
}

type storeKey struct{}

type StoreCircuit struct {
	In   frontend.Variable
	seen *[]bool
}

func (c *StoreCircuit) Define(api frontend.API) error {
	kv, ok := api.Compiler().(keyValueStore)
	if !ok {
		panic("extractor does not implement a key-value store")
	}
	_, cached := kv.GetKeyValue(storeKey{}).(frontend.Variable)
	*c.seen = append(*c.seen, cached)
	kv.SetKeyValue(storeKey{}, c.In)
	stored := kv.GetKeyValue(storeKey{}).(frontend.Variable)
	api.AssertIsEqual(stored, 1)
	return nil
}

type OtherStoreCircuit struct {
	A, B frontend.Variable
	seen *[]bool
}

func (c *OtherStoreCircuit) Define(api frontend.API) error {
	kv := api.Compiler().(keyValueStore)
	_, cached := kv.GetKeyValue(storeKey{}).(frontend.Variable)
	*c.seen = append(*c.seen, cached)
	api.AssertIsEqual(c.A, c.B)
	return nil
}

func TestKeyValueStoreResetsPerCircuit(t *testing.T) {
	var seen []bool
	_, err := extractor.ExtractCircuits("Store", ecc.BN254, &StoreCircuit{seen: &seen}, &OtherStoreCircuit{seen: &seen})
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || seen[0] || seen[1] {
		t.Fatalf("store leaked between circuits: %v", seen)
	}
}
