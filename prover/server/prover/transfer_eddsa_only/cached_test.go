package transfereddsaonly

import (
	"encoding/json"
	"math/big"
	"testing"

	defaultring "zolana/prover/circuits/spp_transaction/default"
)

func TestCachedParametersRoundTripAndWitness(t *testing.T) {
	params := sampleTransferParams(CachedVariant)
	params.CacheInputBitmap = big.NewInt(3)
	params.CacheTreeID = big.NewInt(9)
	params.CacheInputHashChain = big.NewInt(123)
	encoded, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	var decoded TransferParameters
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Variant != CachedVariant {
		t.Fatalf("wrong variant: %v", decoded.Variant)
	}
	circuit, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	cached, ok := circuit.(*defaultring.DefaultRingEddsaOnlyCachedCircuit)
	if !ok {
		t.Fatalf("wrong witness: %T", circuit)
	}
	if cached.CachedInputs.InputBitmap.(*big.Int).Cmp(params.CacheInputBitmap) != 0 ||
		cached.CachedInputs.TreeID.(*big.Int).Cmp(params.CacheTreeID) != 0 ||
		cached.CachedInputs.InputHashChain.(*big.Int).Cmp(params.CacheInputHashChain) != 0 {
		t.Fatal("cache transcript changed during marshaling")
	}
}
