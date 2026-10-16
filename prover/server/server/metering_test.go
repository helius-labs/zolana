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
	merge := manifest.Keys["merge_52_1.key"].Size
	if weight, _ := keyWeight("merge_52_1.key"); weight != int((merge+base-1)/base) || weight <= 1 {
		t.Fatalf("merge_52_1 weighs %d", weight)
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
