package ringutils

import (
	"github.com/consensys/gnark/frontend"

	sppringutils "github.com/helius-labs/zolana/prover/server/circuits/ring-utils"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type Utxo = sppringutils.Utxo

// Transaction is the witnessed SPP transaction a ring proof binds to through
// private_tx_hash. Its slots follow the SPP slot order and domains.
type Transaction struct {
	Inputs           []Utxo
	Outputs          []Utxo
	ExternalDataHash frontend.Variable
}

// PrivateTxHash recomputes SPP's private_tx_hash. Only UtxoDomain slots enter
// the chains; a ring proof that admits no address slots passes zero address
// nullifiers.
func (t Transaction) PrivateTxHash(api frontend.API, privateTxBlinding frontend.Variable) frontend.Variable {
	inputHashes := make([]frontend.Variable, len(t.Inputs))
	addressNullifiers := make([]frontend.Variable, len(t.Inputs))
	for i := range t.Inputs {
		inputHashes[i] = chainElement(api, t.Inputs[i])
		addressNullifiers[i] = frontend.Variable(0)
	}
	outputHashes := make([]frontend.Variable, len(t.Outputs))
	for i := range t.Outputs {
		outputHashes[i] = chainElement(api, t.Outputs[i])
	}
	return transaction.PrivateTxHashCircuit(
		api,
		inputHashes,
		outputHashes,
		addressNullifiers,
		privateTxBlinding,
	)
}

// IsUtxo reports whether the slot is a real UTXO.
func IsUtxo(api frontend.API, u Utxo) frontend.Variable {
	return api.IsZero(api.Sub(u.Domain, transaction.UtxoDomain))
}

// chainElement is the slot's contribution to its private_tx_hash chain: the
// UTXO hash for a real UTXO, 0 for a dummy or address slot, as in SPP.
func chainElement(api frontend.API, u Utxo) frontend.Variable {
	return api.Select(IsUtxo(api, u), u.Hash(api), frontend.Variable(0))
}
