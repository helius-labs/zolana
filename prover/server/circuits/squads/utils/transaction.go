package squadsutils

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/spp_transaction/shared"
)

type Transaction struct {
	Inputs           []Utxo
	Outputs          []Utxo
	ExternalDataHash frontend.Variable
}

func (t Transaction) Hash(api frontend.API) frontend.Variable {
	return t.HashWithDummies(api, nil)
}

// HashWithDummies folds the transaction hash with dummy flags for Inputs[1..]
// (inputsDummy[i] flags Inputs[i+1]). A dummy slot contributes 0 to the
// input-hash fold, matching the SPP transaction circuit's IsDummy convention so
// both proofs bind the same private_tx_hash. Empty/nil inputsDummy reproduces
// Hash exactly.
func (t Transaction) HashWithDummies(api frontend.API, inputsDummy []frontend.Variable) frontend.Variable {
	inputHashes := make([]frontend.Variable, len(t.Inputs))
	for i := range t.Inputs {
		inputHashes[i] = t.Inputs[i].Hash(api)
	}
	for i, dummy := range inputsDummy {
		inputHashes[i+1] = api.Select(dummy, frontend.Variable(0), inputHashes[i+1])
	}
	outputHashes := make([]frontend.Variable, len(t.Outputs))
	for i := range t.Outputs {
		outputHashes[i] = t.Outputs[i].Hash(api)
	}
	addressHashes := make([]frontend.Variable, len(t.Inputs))
	for i := range addressHashes {
		addressHashes[i] = frontend.Variable(0)
	}
	return shared.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
}
