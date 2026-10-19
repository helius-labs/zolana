package server

import (
	"net/http"
	"strconv"
	"strings"
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
	for _, prefix := range []string{"", gatewayPrefix} {
		for _, path := range []string{"/prove/merge_24_1", "/prove/merge_24_1/indexed"} {
			response := post(mux, prefix+path, transferRequest(t))
			if got := response.Header().Get(MeteringUnitsHeader); got != strconv.Itoa(unitsM) {
				t.Fatalf("%s%s: %s = %q, want %d", prefix, path, MeteringUnitsHeader, got, unitsM)
			}
		}
	}
	// Status polls bill at their own price, not the proof's.
	response := serve(mux, http.MethodGet, "/prove/merge_24_1/status?jobId=x", nil)
	if got := response.Header().Get(MeteringUnitsHeader); got != "" {
		t.Fatalf("status poll reported %q", got)
	}
}

func TestShapeTiers(t *testing.T) {
	for name, units := range map[string]int{
		"transfer_confidential_1_2":     unitsS,
		"transfer_confidential_4_16":    unitsS,
		"transfer_confidential_5_2":     unitsM,
		"transfer_confidential_12_8":    unitsM,
		"transfer_confidential_16_2":    unitsL,
		"transfer_confidential_32_2":    unitsL,
		"transfer_confidential_40_2":    unitsXL,
		"transfer_ring_2_2":             unitsS,
		"transfer_ring_49_2":            unitsXL,
		"transfer_ring_authority_4_4":   unitsS,
		"transfer_p256_ring_1_2":        unitsM,
		"transfer_p256_ring_6_16":       unitsM,
		"transfer_p256_ring_8_2":        unitsL,
		"transfer_p256_ring_24_4":       unitsL,
		"transfer_p256_ring_32_2":       unitsXL,
		"merge_8_1":                     unitsS,
		"merge_ring_24_1":               unitsM,
		"merge_54_1":                    unitsL,
		"custom_ring_base":              unitsM,
		"custom_ring_deposit":           unitsL,
		"custom_ring_compressed_policy": unitsXL,
	} {
		if got, ok := shapeUnits(name); !ok || got != units {
			t.Errorf("%s bills %d units (%v), want %d", name, got, ok, units)
		}
	}
	for _, name := range []string{"batch_address-append_40_4999", "transfer_unknown_2_2", "merge", "transfer_confidential_x_2"} {
		if _, ok := shapeUnits(name); ok {
			t.Errorf("%s matched a shape rule", name)
		}
	}
}

// Every client key is priced by a shape rule, and the rule never puts a key
// more than one tier away from where its size would: merges sit one tier
// below their size, since a merge keeps later transfers small.
func TestShapeRulesCoverEveryClientKey(t *testing.T) {
	tier := map[int]int{unitsS: 0, unitsM: 1, unitsL: 2, unitsXL: 3}
	for _, file := range knownKeyFiles {
		name := strings.TrimSuffix(file, keyFileSuffix)
		if strings.HasPrefix(name, "batch_") {
			continue
		}
		byShape, ok := shapeUnits(name)
		if !ok {
			t.Errorf("%s has no shape rule", name)
			continue
		}
		weight, _ := keyWeight(file)
		if gap := tier[byShape] - tier[unitsByWeight(weight)]; gap > 1 || gap < -1 {
			t.Errorf("%s: shape tier %d units, size tier %d units", name, byShape, unitsByWeight(weight))
		}
	}
}

func TestAKeyWithoutAShapeRuleBillsByWeight(t *testing.T) {
	file := "batch_address-append_40_10.key"
	weight, ok := keyWeight(file)
	if !ok {
		t.Fatal("batch key not pinned")
	}
	if units, ok := proofUnits(file); !ok || units != unitsByWeight(weight) {
		t.Fatalf("%s bills %d units (%v), want %d", file, units, ok, unitsByWeight(weight))
	}
	if _, ok := proofUnits("unknown.key"); ok {
		t.Fatal("an unknown key bills")
	}
}
