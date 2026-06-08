package transaction

import (
	"math/big"

	txcircuit "light/light-prover/prover/spp/circuit/transaction"
	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark/frontend"
)

func toProofCircuitFields(utxo protocol.Utxo) txcircuit.UtxoCircuitFields {
	return txcircuit.FieldsFromUtxo(utxo)
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
