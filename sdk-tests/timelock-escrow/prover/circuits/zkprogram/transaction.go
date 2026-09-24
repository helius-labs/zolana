package zkprogram

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/gnarksdk"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

type Transaction struct {
	ExternalDataHash frontend.Variable
	FirstNullifier   frontend.Variable
	BlindingSeed     frontend.Variable
	OutputTreeID     frontend.Variable
}

type Output struct {
	Owner    frontend.Variable
	Asset    frontend.Variable
	Amount   frontend.Variable
	DataHash frontend.Variable
}

func Payment(owner, asset, amount frontend.Variable) Output {
	return Output{Owner: owner, Asset: asset, Amount: amount, DataHash: 0}
}

type Slots struct {
	transaction        Transaction
	outputBlindingSeed frontend.Variable
	inputs             []frontend.Variable
	outputs            []frontend.Variable
}

func (t Transaction) Slots(nInputs, nOutputs int) *Slots {
	return &Slots{
		transaction: t,
		inputs:      make([]frontend.Variable, nInputs),
		outputs:     make([]frontend.Variable, nOutputs),
	}
}

type InputHash struct {
	value frontend.Variable
}

func (h InputHash) Value() frontend.Variable {
	return h.value
}

func (s *Slots) Input(slot int, input InputHash) {
	reserve(s.inputs, "input", slot)
	if input.value == nil {
		panic(fmt.Sprintf("zkprogram: input slot %d holds no checked input", slot))
	}
	s.inputs[slot] = input.value
}

func (s *Slots) Create(api frontend.API, slot int, output Output) frontend.Variable {
	reserve(s.outputs, "output", slot)
	if s.outputBlindingSeed == nil {
		s.outputBlindingSeed = spp.DeriveOutputBlindingSeed(api, s.transaction.FirstNullifier, s.transaction.BlindingSeed)
	}
	utxo := gnarksdk.Utxo{
		Domain:        spp.UtxoDomain,
		Owner:         output.Owner,
		Asset:         output.Asset,
		Amount:        output.Amount,
		Blinding:      spp.DeriveOutputBlinding(api, s.transaction.FirstNullifier, s.outputBlindingSeed, slot),
		DataHash:      output.DataHash,
		RingDataHash:  0,
		RingProgramID: 0,
		TreeID:        s.transaction.OutputTreeID,
	}
	utxoHash := utxo.Hash(api)
	s.outputs[slot] = utxoHash
	return utxoHash
}

func (s *Slots) PrivateTxHash(api frontend.API) frontend.Variable {
	inputs := make([]frontend.Variable, len(s.inputs))
	for slot, utxoHash := range s.inputs {
		if utxoHash == nil {
			inputs[slot] = 0
		} else {
			inputs[slot] = utxoHash
		}
	}
	for slot, utxoHash := range s.outputs {
		if utxoHash == nil {
			panic(fmt.Sprintf("zkprogram: output slot %d is not created", slot))
		}
	}
	privateTxBlinding := spp.DerivePrivateTxBlinding(api, s.transaction.FirstNullifier, s.transaction.BlindingSeed)
	return gnarksdk.PrivateTxHash(api, inputs, s.outputs, s.transaction.ExternalDataHash, privateTxBlinding)
}

func reserve(slots []frontend.Variable, kind string, slot int) {
	if slot < 0 || slot >= len(slots) {
		panic(fmt.Sprintf("zkprogram: %s slot %d is outside a transaction of %d %ss", kind, slot, len(slots), kind))
	}
	if slots[slot] != nil {
		panic(fmt.Sprintf("zkprogram: %s slot %d is set twice", kind, slot))
	}
}
