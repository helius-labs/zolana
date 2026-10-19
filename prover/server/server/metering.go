package server

import (
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

// MeteringUnitsHeader tells a gateway how many units a proof bills: its
// tier's units. A gateway prices a proof at its per-unit price times these
// units, so a larger proof bills more without a price of its own.
const MeteringUnitsHeader = "X-Helius-Metering-Units"

// The units of the four tiers, S, M, L and XL: each doubles the one before.
const (
	unitsS  = 1
	unitsM  = 2
	unitsL  = 4
	unitsXL = 8
)

// shapeUnits is the units a proof on key `name` (a key file name without
// `.key`) bills by its circuit and input count, false for a key no rule names.
func shapeUnits(name string) (int, bool) {
	switch name {
	case "custom_ring_base", "custom_ring_register_key":
		return unitsM, true
	case "custom_ring_policy", "custom_ring_delegate_policy", "custom_ring_deposit":
		return unitsL, true
	case "custom_ring_compressed_policy":
		return unitsXL, true
	}
	family, inputs, ok := familyAndInputs(name)
	if !ok {
		return 0, false
	}
	switch family {
	case "transfer_ring_authority":
		return unitsS, true
	case "transfer_confidential", "transfer_ring":
		return unitsByInputs(inputs, 4, 12, 32), true
	case "transfer_p256_ring":
		return unitsByInputs(inputs, 0, 6, 24), true
	case "merge", "merge_ring":
		return unitsByInputs(inputs, 8, 24, 54), true
	}
	return 0, false
}

// familyAndInputs splits `<family>_<inputs>_<outputs>`.
func familyAndInputs(name string) (string, int, bool) {
	outputsAt := strings.LastIndexByte(name, '_')
	if outputsAt <= 0 {
		return "", 0, false
	}
	inputsAt := strings.LastIndexByte(name[:outputsAt], '_')
	if inputsAt <= 0 {
		return "", 0, false
	}
	if _, err := strconv.Atoi(name[outputsAt+1:]); err != nil {
		return "", 0, false
	}
	inputs, err := strconv.Atoi(name[inputsAt+1 : outputsAt])
	if err != nil || inputs < 1 {
		return "", 0, false
	}
	return name[:inputsAt], inputs, true
}

// unitsByInputs is S up to maxS inputs, M up to maxM, L up to maxL and XL
// above. A maxS of 0 starts the family at M; a maxL at the family's widest
// shape keeps it out of XL.
func unitsByInputs(inputs, maxS, maxM, maxL int) int {
	switch {
	case inputs <= maxS:
		return unitsS
	case inputs <= maxM:
		return unitsM
	case inputs <= maxL:
		return unitsL
	default:
		return unitsXL
	}
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

// unitsByWeight is the tier of a key no shape rule names, by its weight.
func unitsByWeight(weight int) int {
	switch {
	case weight <= 2:
		return unitsS
	case weight <= 6:
		return unitsM
	case weight <= 14:
		return unitsL
	default:
		return unitsXL
	}
}

// proofUnits is the units a proof on key file `file` bills: its shape's tier,
// or its weight's for a key no shape rule names. False for a key that is
// neither named nor pinned.
func proofUnits(file string) (int, bool) {
	if units, ok := shapeUnits(strings.TrimSuffix(file, keyFileSuffix)); ok {
		return units, true
	}
	weight, ok := keyWeight(file)
	if !ok {
		return 0, false
	}
	return unitsByWeight(weight), true
}

// setMeteringUnits names the units a proof on `file` bills. A gateway reads
// it only from a successful answer, so an error that follows does not bill.
func setMeteringUnits(w http.ResponseWriter, file string) {
	if units, ok := proofUnits(file); ok {
		w.Header().Set(MeteringUnitsHeader, strconv.Itoa(units))
	}
}
