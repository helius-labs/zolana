package transaction

import (
	"math/big"

	txcircuit "light/light-prover/prover/spp/circuit/transaction"
	"light/light-prover/prover/spp/model"
	"light/light-prover/prover/spp/parse"

	"github.com/consensys/gnark/frontend"
)

func toProofCircuitFields(utxo model.Utxo) txcircuit.UtxoCircuitFields {
	return txcircuit.UtxoCircuitFields{
		Domain:        utxo.Domain,
		Owner:         utxo.Owner,
		AssetID:       utxo.AssetID,
		AssetAmount:   utxo.AssetAmount,
		Blinding:      utxo.Blinding,
		DataHash:      utxo.DataHash,
		ZoneDataHash:  utxo.ZoneDataHash,
		ZoneProgramID: utxo.ZoneProgramID,
	}
}

func zeroVariables(n int) []frontend.Variable {
	out := make([]frontend.Variable, n)
	for i := range out {
		out[i] = big.NewInt(0)
	}
	return out
}

func fillProofPath(path []frontend.Variable, dirs []frontend.Variable, siblings []*big.Int, directions []int) {
	for i := range siblings {
		path[i] = siblings[i]
		dirs[i] = big.NewInt(int64(directions[i]))
	}
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
