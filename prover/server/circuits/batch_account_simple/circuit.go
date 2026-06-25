package batchaccountsimple

import (
	"fmt"

	gadget "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// AmountBits bounds every per-UTXO amount and the min/max band to 64 bits.
const AmountBits = 64

// SimpleUtxo is the simplified commitment: a single Poseidon over blinding,
// amount, and the two program data hashes. Unlike the canonical UTXO it carries
// no owner, asset, or domain.
type SimpleUtxo struct {
	Blinding     frontend.Variable
	Amount       frontend.Variable
	DataHash     frontend.Variable
	ZoneDataHash frontend.Variable
}

func (u SimpleUtxo) DefineGadget(api frontend.API) interface{} {
	return gadget.PoseidonHash(api, []frontend.Variable{
		u.Blinding,
		u.Amount,
		u.DataHash,
		u.ZoneDataHash,
	})
}

// Circuit proves that N simplified UTXO commitments fold into a single public
// hash chain, that every real amount lies in the public [MinAmount, MaxAmount]
// band, and that the real amounts sum to AggregateAmount. Dummy UTXOs still
// hash into the length-N chain but are exempt from the band check and excluded
// from the aggregate, so a caller can pad to N without owning N real UTXOs.
//
// This is the simplified counterpart to the batch_account circuit: it omits the
// owner and asset binding to isolate the cost of the cheaper leaf hash.
type Circuit struct {
	N int `gnark:"-"`

	Utxos   []SimpleUtxo
	IsDummy []frontend.Variable

	HashChain       frontend.Variable `gnark:",public"`
	AggregateAmount frontend.Variable `gnark:",public"`
	MinAmount       frontend.Variable `gnark:",public"`
	MaxAmount       frontend.Variable `gnark:",public"`
}

// NewCircuit returns a circuit sized for n UTXOs with its witness slices
// allocated so gnark can introspect the fixed shape.
func NewCircuit(n int) *Circuit {
	return &Circuit{
		N:       n,
		Utxos:   make([]SimpleUtxo, n),
		IsDummy: make([]frontend.Variable, n),
	}
}

func (c *Circuit) Define(api frontend.API) error {
	if len(c.Utxos) != c.N || len(c.IsDummy) != c.N {
		return fmt.Errorf(
			"batch account simple: expected %d utxos, got %d utxos / %d dummy flags",
			c.N, len(c.Utxos), len(c.IsDummy),
		)
	}

	leaves := make([]frontend.Variable, c.N)
	sum := frontend.Variable(0)
	for i := 0; i < c.N; i++ {
		utxo := c.Utxos[i]
		isDummy := c.IsDummy[i]
		api.AssertIsBoolean(isDummy)
		notDummy := api.Sub(1, isDummy)

		// Simplified commitment; every leaf folds into the chain even when it is
		// a dummy.
		leaves[i] = abstractor.Call(api, utxo)

		// MinAmount <= amount <= MaxAmount for real UTXOs. A dummy substitutes
		// MinAmount so both differences stay non-negative and the 64-bit
		// decomposition cannot underflow on padding.
		checked := api.Select(notDummy, utxo.Amount, c.MinAmount)
		api.ToBinary(api.Sub(checked, c.MinAmount), AmountBits)
		api.ToBinary(api.Sub(c.MaxAmount, checked), AmountBits)

		sum = api.Add(sum, api.Mul(notDummy, utxo.Amount))
	}

	api.AssertIsEqual(gadget.HashChain(api, leaves), c.HashChain)
	api.AssertIsEqual(sum, c.AggregateAmount)
	return nil
}
