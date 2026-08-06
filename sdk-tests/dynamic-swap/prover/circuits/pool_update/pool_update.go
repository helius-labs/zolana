package pool_update

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction/shared"
)

// Circuit moves value between the pool UTXO and an authority-owned note of the
// same asset, entirely inside the shielded set: it spends the current pool UTXO
// plus an authority note and recreates both, with value conserved across the
// pair. deposit_liquidity and withdraw_liquidity share this circuit; direction
// is decided purely by the witness (deposit: PoolOut > PoolIn, AuthOut is the
// change; withdraw: PoolOut < PoolIn, AuthOut receives the withdrawn amount).
//
// No amount is ever public: the transaction balances via shielded conservation
// (PoolIn + AuthIn == PoolOut + AuthOut), so the SPP transact needs no public
// settlement leg. There is deliberately no Delta witness -- an earlier revision
// carried one and balanced the pool credit/debit through SPP's PUBLIC SOL
// settlement, which revealed the amount on-chain.
type Circuit struct {
	Public PublicInputs

	PoolIn spp.UtxoCircuitFields
	AuthIn spp.UtxoCircuitFields

	PoolOut spp.UtxoCircuitFields
	AuthOut spp.UtxoCircuitFields

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	poolInHash := c.checkPoolInputUtxo(api)
	authInHash := c.checkAuthInputUtxo(api)

	poolOutHash := c.checkPoolOutputUtxo(api)
	authOutHash := c.checkAuthOutputUtxo(api)

	// Value conservation across the pair. Every amount except PoolIn.Amount is
	// range-checked to 64 bits in the check* helpers above, and PoolIn.Amount
	// is pinned by the public PoolInHash to a real (already 64-bit) pool UTXO,
	// so both sides stay well below the BN254 modulus and this field equality
	// is true value conservation, not a modular coincidence.
	api.AssertIsEqual(
		api.Add(c.PoolIn.Amount, c.AuthIn.Amount),
		api.Add(c.PoolOut.Amount, c.AuthOut.Amount),
	)

	api.AssertIsBoolean(c.Public.RefreshCapacity)
	required := api.Add(
		c.Public.ReservedLiability,
		api.Mul(c.Public.AvailableSlots, c.Public.SlotValue),
	)
	api.AssertIsEqual(cmp.IsLessOrEqual(api, required, c.PoolOut.Amount), 1)
	// A refresh publishes the exact quotient after reserved liability.
	nextRequired := api.Add(required, c.Public.SlotValue)
	nextFits := cmp.IsLessOrEqual(api, nextRequired, c.PoolOut.Amount)
	api.AssertIsEqual(api.Mul(c.Public.RefreshCapacity, nextFits), 0)

	privateTxHashInputs{
		PoolInputUtxoHash:  poolInHash,
		AuthInputUtxoHash:  authInHash,
		PoolOutputUtxoHash: poolOutHash,
		AuthOutputUtxoHash: authOutHash,
		ExternalDataHash:   c.ExternalDataHash,
		PrivateTxHash:      c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api, poolInHash)
	return nil
}

// PublicInputs folds PrivateTxHash and PoolInHash into a single public hash.
// PoolInHash is the *witnessed* pool-input UTXO's own reconstructed hash
// (asserted equal in Check below), not a free value -- the native program
// recomputes this same hash using its own on-chain `Liquidity.available_hash`,
// so the proof only verifies if the prover's witnessed PoolIn preimage really
// is the account's current live pool UTXO. Without this binding, any unspent
// UTXO owned by the same pool_authority PDA (e.g. stale dust from a different
// pair) could stand in as PoolIn. No amount appears here -- the authority note
// (AuthIn/AuthOut) balances the pool credit/debit inside the shielded set.
type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash     frontend.Variable
	PoolInHash        frontend.Variable
	DestinationAsset  frontend.Variable
	ReservedLiability frontend.Variable
	SlotValue         frontend.Variable
	AvailableSlots    frontend.Variable
	RefreshCapacity   frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, poolInHash frontend.Variable) {
	api.AssertIsEqual(p.PoolInHash, poolInHash)
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{
		p.PrivateTxHash,
		p.PoolInHash,
		p.DestinationAsset,
		p.ReservedLiability,
		p.SlotValue,
		p.AvailableSlots,
		p.RefreshCapacity,
	})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	PoolInputUtxoHash  frontend.Variable
	AuthInputUtxoHash  frontend.Variable
	PoolOutputUtxoHash frontend.Variable
	AuthOutputUtxoHash frontend.Variable
	ExternalDataHash   frontend.Variable
	PrivateTxHash      frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	// The real shape is 2-in/2-out, exactly the supported IN2_OUT2 shape -- no
	// padding needed on either side.
	inputHashes := []frontend.Variable{t.PoolInputUtxoHash, t.AuthInputUtxoHash}
	outputHashes := []frontend.Variable{t.PoolOutputUtxoHash, t.AuthOutputUtxoHash}
	addressHashes := []frontend.Variable{frontend.Variable(0), frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkPoolInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.PoolIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.PoolIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.PoolIn.ZoneProgramID, 0)
	api.AssertIsEqual(c.PoolIn.DataHash, 0)
	api.AssertIsEqual(c.PoolIn.Asset, c.Public.DestinationAsset)
	return spp.UtxoHashCircuit(api, c.PoolIn)
}

// checkAuthInputUtxo constrains the authority's spent note. Its owner is a free
// witness -- it is the authority's own money and the authority signs the
// transaction -- but its asset must equal the pool asset so conservation is a
// single-asset relation and cannot be balanced with an unrelated token.
func (c *Circuit) checkAuthInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.AuthIn.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.AuthIn.ZoneDataHash, 0)
	api.AssertIsEqual(c.AuthIn.ZoneProgramID, 0)
	api.AssertIsEqual(c.AuthIn.DataHash, 0)
	api.AssertIsEqual(c.AuthIn.Asset, c.PoolIn.Asset)
	api.ToBinary(c.AuthIn.Amount, 64)
	return spp.UtxoHashCircuit(api, c.AuthIn)
}

func (c *Circuit) checkPoolOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.PoolOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.PoolOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.PoolOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.PoolOut.DataHash, 0)
	api.AssertIsEqual(c.PoolOut.Asset, c.PoolIn.Asset)
	api.AssertIsEqual(c.PoolOut.Owner, c.PoolIn.Owner)
	api.ToBinary(c.PoolOut.Amount, 64)
	return spp.UtxoHashCircuit(api, c.PoolOut)
}

// checkAuthOutputUtxo constrains the authority's recreated note (deposit
// change, or the funds received on withdrawal). Owner is a free witness (the
// authority chooses where its own funds land); asset must equal the pool asset.
func (c *Circuit) checkAuthOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.AuthOut.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.AuthOut.ZoneDataHash, 0)
	api.AssertIsEqual(c.AuthOut.ZoneProgramID, 0)
	api.AssertIsEqual(c.AuthOut.DataHash, 0)
	api.AssertIsEqual(c.AuthOut.Asset, c.PoolIn.Asset)
	api.ToBinary(c.AuthOut.Amount, 64)
	return spp.UtxoHashCircuit(api, c.AuthOut)
}
