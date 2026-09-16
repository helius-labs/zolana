package directspend

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

type Value struct {
	ID         frontend.Variable
	Commitment frontend.Variable
	Amount     frontend.Variable
	Randomness frontend.Variable
}

type Output struct {
	OwnerKey    frontend.Variable
	NullifierPK frontend.Variable
	Amount      frontend.Variable
	Blinding    frontend.Variable
	Hash        frontend.Variable
}

type Balance struct {
	Intent       frontend.Variable
	OutputTreeID frontend.Variable
	Asset        frontend.Variable
	Values       []Value
	Outputs      []Output
}

type BalanceCircuit struct {
	Balance
	PublicInputHash frontend.Variable `gnark:",public"`
}

func NewBalance(certificates, outputs int) *BalanceCircuit {
	return &BalanceCircuit{Balance: Balance{
		Values: make([]Value, certificates), Outputs: make([]Output, outputs),
	}}
}

func (c *BalanceCircuit) Define(api frontend.API) error {
	if err := c.Balance.constrain(api); err != nil {
		return err
	}
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.fields(api)))
	return nil
}

func (b *Balance) constrain(api frontend.API) error {
	if len(b.Values) == 0 || len(b.Values) > MaxCertificates || len(b.Outputs) == 0 || len(b.Outputs) > 2 {
		return fmt.Errorf("direct spend: invalid balance shape")
	}
	api.ToBinary(b.OutputTreeID, 16)
	api.AssertIsDifferent(b.Asset, 0)
	inputs, outputs, previous := frontend.Variable(0), frontend.Variable(0), frontend.Variable(1)
	for _, value := range b.Values {
		api.ToBinary(value.Amount, 73)
		active := api.Sub(1, api.IsZero(value.Commitment))
		api.AssertIsEqual(api.Mul(active, api.Sub(1, previous)), 0)
		previous = active
		api.AssertIsEqual(value.Commitment, api.Mul(active, valueCommitment(api, value.ID, b.Asset, value.Amount, value.Randomness)))
		for _, padding := range []frontend.Variable{value.ID, value.Amount, value.Randomness} {
			api.AssertIsEqual(api.Mul(api.Sub(1, active), padding), 0)
		}
		inputs = api.Add(inputs, value.Amount)
	}
	for _, output := range b.Outputs {
		api.ToBinary(output.Amount, 64)
		owner := gadget.PoseidonHash(api, []frontend.Variable{output.OwnerKey, output.NullifierPK})
		hash := transaction.UtxoHashCircuit(api, plainNote(owner, b.Asset, output.Amount, output.Blinding), b.OutputTreeID)
		api.AssertIsEqual(output.Hash, hash)
		outputs = api.Add(outputs, output.Amount)
	}
	api.AssertIsDifferent(b.Values[0].Commitment, 0)
	api.AssertIsEqual(inputs, outputs)
	return nil
}

func (b *Balance) fields(api frontend.API) []frontend.Variable {
	values := make([]frontend.Variable, 0, 2*len(b.Values))
	for _, value := range b.Values {
		values = append(values, value.ID, value.Commitment)
	}
	outputs := make([]frontend.Variable, 0, 2*len(b.Outputs))
	for _, output := range b.Outputs {
		outputs = append(outputs, output.Hash, output.OwnerKey)
	}
	return []frontend.Variable{
		BalanceDomain, b.Intent, b.OutputTreeID,
		gadget.HashChain4(api, values), gadget.HashChain4(api, outputs),
	}
}
