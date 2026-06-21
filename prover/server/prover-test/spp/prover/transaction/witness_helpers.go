package transaction

import (
	"crypto/rand"
	"fmt"
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

// dummyUtxo returns a dummy UTXO with random blinding. All fields are zero
// except the blinding, so its UTXO hash and derived nullifier are
// indistinguishable from a real UTXO's on the public transcript.
func dummyUtxo(blinding *big.Int) protocol.Utxo {
	return protocol.Utxo{
		Domain:        big.NewInt(0),
		Owner:         big.NewInt(0),
		Asset:         big.NewInt(0),
		Amount:        big.NewInt(0),
		Blinding:      blinding,
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	}
}

func dummyUtxoFields(blinding *big.Int) txcircuit.UtxoCircuitFields {
	return toProofCircuitFields(dummyUtxo(blinding))
}

// randomBlinding generates a random 31-byte blinding factor as a field element.
func randomBlinding() (*big.Int, error) {
	b := make([]byte, 31)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("random blinding: %w", err)
	}
	padded := make([]byte, 32)
	copy(padded[1:], b)
	return new(big.Int).SetBytes(padded), nil
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
