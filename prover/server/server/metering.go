package server

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

// MeteringUnitsHeader tells a gateway how many units a proof bills: its
// proving key's weight. A gateway prices a proof at its per-unit price times
// these units, so a heavier key bills more without a price of its own.
const MeteringUnitsHeader = "X-Helius-Metering-Units"

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

// keyWeight is the units a proof with key file `file` bills, false for a key
// the lockfile does not pin.
func keyWeight(file string) (int, bool) {
	weight, ok := keyWeights()[file]
	return weight, ok
}

// setMeteringUnits names the units a proof on `file` bills. A gateway reads
// it only from a successful answer, so an error that follows does not bill.
func setMeteringUnits(w http.ResponseWriter, file string) {
	if weight, ok := keyWeight(file); ok {
		w.Header().Set(MeteringUnitsHeader, strconv.Itoa(weight))
	}
}
