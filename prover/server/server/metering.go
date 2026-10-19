package server

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

// MeteringUnitsHeader tells a gateway how many units a proof bills: its
// proving key's tier. A gateway prices a proof at its per-unit price times
// these units, so a heavier key bills more without a price of its own.
const MeteringUnitsHeader = "X-Helius-Metering-Units"

// meteringTier is the units every key up to maxWeight bills.
type meteringTier struct {
	maxWeight int
	units     int
}

// meteringTiers are S, M, L and XL. A key heavier than the last tier's
// maxWeight bills the last tier's units.
var meteringTiers = []meteringTier{
	{maxWeight: 2, units: 1},
	{maxWeight: 6, units: 4},
	{maxWeight: 14, units: 10},
	{maxWeight: 32, units: 25},
}

// tierUnits is the units a key of `weight` bills.
func tierUnits(weight int) int {
	for _, tier := range meteringTiers {
		if weight <= tier.maxWeight {
			return tier.units
		}
	}
	return meteringTiers[len(meteringTiers)-1].units
}

// meteringBaseKey weighs 1. Proving time grows with a circuit's constraint
// count and so does its Groth16 proving key, so a key weighs its size over
// this one's, rounded up.
const meteringBaseKey = "transfer_confidential_2_2.key"

var keyWeights = sync.OnceValue(func() map[string]int {
	weights := map[string]int{}
	manifest, err := provingkeys.Load()
	if err != nil {
		return weights
	}
	base, ok := manifest.Keys[meteringBaseKey]
	if !ok || base.Size <= 0 {
		return weights
	}
	for file, entry := range manifest.Keys {
		weights[file] = max(1, int((entry.Size+base.Size-1)/base.Size))
	}
	return weights
})

// keyWeight is the weight of key file `file`, false for a key the lockfile
// does not pin.
func keyWeight(file string) (int, bool) {
	weight, ok := keyWeights()[file]
	return weight, ok
}

// setMeteringUnits names the units a proof on `file` bills. A gateway reads
// it only from a successful answer, so an error that follows does not bill.
func setMeteringUnits(w http.ResponseWriter, file string) {
	if weight, ok := keyWeight(file); ok {
		w.Header().Set(MeteringUnitsHeader, strconv.Itoa(tierUnits(weight)))
	}
}
