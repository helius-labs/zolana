package server

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

func TestKeyWeightIsTheKeySizeOverTheBaseTransfer(t *testing.T) {
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatal(err)
	}
	base := manifest.Keys[meteringBaseKey].Size
	if weight, _ := keyWeight(meteringBaseKey); weight != 1 {
		t.Fatalf("base key weighs %d", weight)
	}
	if weight, _ := keyWeight("transfer_confidential_1_2.key"); weight != 1 {
		t.Fatalf("a key smaller than the base weighs %d, not 1", weight)
	}
	merge := manifest.Keys["merge_54_1.key"].Size
	if weight, _ := keyWeight("merge_54_1.key"); weight != int((merge+base-1)/base) || weight <= 1 {
		t.Fatalf("merge_54_1 weighs %d", weight)
	}
	for _, file := range knownKeyFiles {
		if weight, ok := keyWeight(file); !ok || weight < 1 {
			t.Fatalf("%s weighs %d (%v)", file, weight, ok)
		}
	}
	if _, ok := keyWeight("unknown.key"); ok {
		t.Fatal("an unpinned key has a weight")
	}
}

func TestKeyPathsNameTheirMeteringUnits(t *testing.T) {
	mux := proofMux(t, nil)
	weight, _ := keyWeight("merge_24_1.key")
	weight = tierUnits(weight)
	for _, prefix := range []string{"", gatewayPrefix} {
		for _, path := range []string{"/prove/merge_24_1", "/prove/merge_24_1/indexed"} {
			response := post(mux, prefix+path, transferRequest(t))
			if got := response.Header().Get(MeteringUnitsHeader); got != strconv.Itoa(weight) {
				t.Fatalf("%s%s: %s = %q, want %d", prefix, path, MeteringUnitsHeader, got, weight)
			}
		}
	}
	// Status polls bill at their own price, not the key's weight.
	response := serve(mux, http.MethodGet, "/prove/merge_24_1/status?jobId=x", nil)
	if got := response.Header().Get(MeteringUnitsHeader); got != "" {
		t.Fatalf("status poll reported %q", got)
	}
}

func TestTiersBillFourPrices(t *testing.T) {
	for _, test := range []struct{ weight, units int }{
		{1, 1}, {2, 1}, {3, 4}, {6, 4}, {7, 10}, {14, 10}, {15, 25}, {32, 25}, {33, 25},
	} {
		if units := tierUnits(test.weight); units != test.units {
			t.Errorf("weight %d bills %d units, want %d", test.weight, units, test.units)
		}
	}
	for file, units := range map[string]int{
		"transfer_confidential_2_2.key": 1,
		"transfer_ring_2_2.key":         1,
		"merge_8_1.key":                 4,
		"merge_24_1.key":                10,
		"merge_54_1.key":                25,
	} {
		weight, ok := keyWeight(file)
		if !ok || tierUnits(weight) != units {
			t.Errorf("%s (weight %d) bills %d units, want %d", file, weight, tierUnits(weight), units)
		}
	}
}
