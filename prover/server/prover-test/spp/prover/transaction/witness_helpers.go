package transaction

import (
	"math/big"

	txcircuit "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/parse"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark/frontend"
)

func toProofCircuitFields(utxo protocol.Utxo) txcircuit.UtxoCircuitFields {
	return txcircuit.UtxoCircuitFields{
		Domain:        utxo.Domain,
		Owner:         utxo.Owner,
		Asset:         utxo.Asset,
		Amount:        utxo.Amount,
		Blinding:      utxo.Blinding,
		DataHash:      utxo.DataHash,
		ZoneDataHash:  utxo.ZoneDataHash,
		ZoneProgramID: utxo.ZoneProgramID,
	}
}

// dummyUtxoFields is the all-zero UTXO used to fill unused input/output slots.
// Its amount is zero (the circuit requires this of dummies) and its hash is
// never bound, so the concrete field values are irrelevant.
func dummyUtxoFields() txcircuit.UtxoCircuitFields {
	return toProofCircuitFields(protocol.Utxo{
		Domain:        big.NewInt(0),
		Owner:         big.NewInt(0),
		Asset:         big.NewInt(0),
		Amount:        big.NewInt(0),
		Blinding:      big.NewInt(0),
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	})
}

func zeroVariables(n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

func fillPathElements(pathElements []frontend.Variable, proofElements []*big.Int) {
	for i := range proofElements {
		pathElements[i] = proofElements[i]
	}
}

func pathIndexVariable(index uint64) frontend.Variable {
	return new(big.Int).SetUint64(index)
}

func proofBigIntHexes(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = parse.FieldHex(value)
	}
	return out
}

func proofFieldInput(value *big.Int) string {
	return "0x" + parse.FieldHex(value)
}
