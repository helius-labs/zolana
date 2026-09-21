package base

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

const (
	AuditOutputSlots       = 4
	AuditOutputFieldCount  = 9
	outputDisclosureDomain = 0x4352_5f4f44 // "CR_OD" separates disclosure streams.
)

type AuditOutputWires struct {
	Domain        frontend.Variable
	TreeID        frontend.Variable
	OwnerHash     frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

func (w AuditOutputWires) fields() [AuditOutputFieldCount]frontend.Variable {
	return [AuditOutputFieldCount]frontend.Variable{
		w.Domain, w.TreeID, w.OwnerHash, w.Asset, w.Amount, w.Blinding,
		w.DataHash, w.RingDataHash, w.RingProgramID,
	}
}

func (w AuditOutputWires) hash(api frontend.API) frontend.Variable {
	return shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain: w.Domain, Owner: w.OwnerHash, Asset: w.Asset, Amount: w.Amount,
		Blinding: w.Blinding, DataHash: w.DataHash, RingDataHash: w.RingDataHash,
		RingProgramID: w.RingProgramID,
	}, w.TreeID)
}

func disclosureElements(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	txViewingSk [32]frontend.Variable,
	salt [16]frontend.Variable,
	outputs [AuditOutputSlots]AuditOutputWires,
	countSelected [AuditOutputSlots]frontend.Variable,
) (frontend.Variable, frontend.Variable) {
	assertOneHot(api, countSelected[:])
	active := suffixSums(api, countSelected[:])
	outputHashes := make([]frontend.Variable, AuditOutputSlots)
	plaintext := make([]frontend.Variable, 0, AuditOutputSlots*AuditOutputFieldCount)
	for i, output := range outputs {
		outputHashes[i] = output.hash(api)
		for _, field := range output.fields() {
			plaintext = append(plaintext, api.Mul(active[i], field))
		}
	}

	for _, b := range salt {
		rangeChecker.Check(b, 8)
	}
	saltField := gadget.PackBytesBE(api, salt[:])[0]
	keyLo, keyHi := Pack32To2FECircuit(api, txViewingSk)
	ciphertext := make([]frontend.Variable, len(plaintext))
	for i, value := range plaintext {
		stream := gadget.PoseidonHash(api, []frontend.Variable{
			frontend.Variable(new(big.Int).SetUint64(outputDisclosureDomain)),
			keyLo, keyHi, saltField, frontend.Variable(i),
		})
		ciphertext[i] = api.Add(value, stream)
	}
	return hashPrefix4(api, outputHashes, countSelected[:]), gadget.HashChain(api, ciphertext)
}

func hashPrefix4(api frontend.API, values, oneHot []frontend.Variable) frontend.Variable {
	head := values[0]
	selected := api.Mul(oneHot[0], head)
	for start := 1; start < len(values); start += 3 {
		end := min(start+3, len(values))
		for stop := start + 1; stop <= end; stop++ {
			group := []frontend.Variable{head, 0, 0, 0}
			copy(group[1:], values[start:stop])
			hash := gadget.PoseidonHash(api, group)
			selected = api.Add(selected, api.Mul(oneHot[stop-1], hash))
			if stop == end {
				head = hash
			}
		}
	}
	return selected
}

func assertOneHot(api frontend.API, oneHot []frontend.Variable) {
	sum := frontend.Variable(0)
	for _, bit := range oneHot {
		api.AssertIsBoolean(bit)
		sum = api.Add(sum, bit)
	}
	api.AssertIsEqual(sum, 1)
}

func suffixSums(api frontend.API, oneHot []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(oneHot))
	sum := frontend.Variable(0)
	for i := len(oneHot) - 1; i >= 0; i-- {
		sum = api.Add(sum, oneHot[i])
		out[i] = sum
	}
	return out
}
