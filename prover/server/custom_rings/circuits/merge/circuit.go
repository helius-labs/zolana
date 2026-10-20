// Package merge binds an anonymous ring's SPP merge to a disclosure only its auditor opens.
package merge

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	ve "github.com/helius-labs/zolana/prover/server/circuits/encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
)

const (
	// Domain is "CRMG", the first element of the statement chain.
	Domain         = 0x43524d47
	EncryptionInfo = "CRING/mrg1"
	// HeaderBytes is owner key, nullifier pk, mint, amount and output blinding, the output opening.
	HeaderBytes = 32 + 32 + 32 + 8 + 32
)

// DisclosureBytes is the plaintext length of the n-input circuit.
func DisclosureBytes(n int) int {
	return HeaderBytes + 32*n
}

// Input is one merge slot, the owner, asset and ring program come from the circuit.
type Input struct {
	Domain       frontend.Variable
	TreeID       frontend.Variable
	Amount       frontend.Variable
	Blinding     frontend.Variable
	RingDataHash frontend.Variable
}

type Circuit struct {
	NumInputs int `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash      frontend.Variable
	OutputUtxoHash     frontend.Variable
	FirstNullifier     frontend.Variable
	RingProgramID      frontend.Variable
	MemberRegistryRoot frontend.Variable
	AuditorPk          [32]frontend.Variable
	// Salt is the SPP output ciphertext salt packed as one field.
	Salt frontend.Variable

	EphSk              [32]frontend.Variable
	DisclosureKey      [32]frontend.Variable
	OwnerKey           [32]frontend.Variable
	NullifierSecret    frontend.Variable
	MintChunks         [2]frontend.Variable
	Inputs             []Input
	OutputTreeID       frontend.Variable
	OutputRingDataHash frontend.Variable
	MemberRecord       registry.RecordOpening
}

// New allocates the circuit of one supported merge width.
func New(n int) *Circuit {
	return &Circuit{NumInputs: n, Inputs: make([]Input, n)}
}

// Define recomputes private_tx_hash, the output hash and the first nullifier from the openings
// under one owner, one asset and the owner's nullifier secret, so the statement names one SPP merge.
func (c *Circuit) Define(api frontend.API) error {
	if !mergeshared.IsSupportedInputCount(c.NumInputs) || len(c.Inputs) != c.NumInputs {
		return fmt.Errorf("merge: %d inputs, want %v", len(c.Inputs), mergeshared.SupportedInputCounts)
	}
	rc := rangecheck.New(api)
	api.AssertIsDifferent(c.RingProgramID, 0)
	ownerPkHash := gadget.SolanaOwnerIdentity(api, c.OwnerKey)
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{c.NullifierSecret})
	ownerHash := gadget.PoseidonHash(api, []frontend.Variable{ownerPkHash, nullifierPk})
	asset := gadget.HashChain(api, c.MintChunks[:])
	mint := slices.Concat(ve.FieldToBytesBE(api, c.MintChunks[0], 31), ve.FieldToBytesBE(api, c.MintChunks[1], 1))

	inputHashes := make([]frontend.Variable, c.NumInputs)
	zero := make([]frontend.Variable, c.NumInputs)
	sum := frontend.Variable(0)
	var firstNullifier frontend.Variable
	for i, in := range c.Inputs {
		zero[i] = 0
		isDummy := api.IsZero(api.Sub(in.Domain, mergeshared.DummyDomain))
		api.AssertIsEqual(api.Add(api.IsZero(api.Sub(in.Domain, mergeshared.UtxoDomain)), isDummy), 1)
		abstractor.CallVoid(api, transaction.RangeCheck64{Value: in.Amount})
		utxo := transaction.UtxoCircuitFields{
			Domain: in.Domain, Owner: api.Select(isDummy, 0, ownerHash), Asset: api.Select(isDummy, 0, asset),
			Amount: in.Amount, Blinding: in.Blinding, DataHash: 0, RingDataHash: in.RingDataHash,
			RingProgramID: api.Select(isDummy, 0, c.RingProgramID),
		}
		transaction.AssertWhen(api, isDummy, utxo.CheckDummy(api))
		hash := transaction.UtxoHashCircuit(api, utxo, in.TreeID)
		inputHashes[i] = api.Select(isDummy, 0, hash)
		sum = api.Add(sum, in.Amount)
		if i == 0 {
			// SPP seeds every derived merge value from the real slot zero.
			api.AssertIsEqual(in.Domain, mergeshared.UtxoDomain)
			firstNullifier = abstractor.Call(api, transaction.NullifierGadget{
				UtxoHash: hash, Blinding: in.Blinding, NullifierSecret: c.NullifierSecret,
			})
			api.AssertIsEqual(c.FirstNullifier, firstNullifier)
		}
	}
	amount := gadget.BitsToBytesBE(api, api.ToBinary(sum, 64))
	outputBlinding := mergeshared.MergeOutputBlinding(api, c.NullifierSecret, firstNullifier)
	outputHash := transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain: mergeshared.UtxoDomain, Owner: ownerHash, Asset: asset, Amount: sum,
		Blinding: outputBlinding, DataHash: 0,
		RingDataHash: c.OutputRingDataHash, RingProgramID: c.RingProgramID,
	}, c.OutputTreeID)
	api.AssertIsEqual(c.OutputUtxoHash, outputHash)
	api.AssertIsEqual(c.PrivateTxHash, transaction.PrivateTxHashCircuit(api, inputHashes,
		[]frontend.Variable{outputHash}, zero, transaction.DerivePrivateTxBlinding(api, firstNullifier, c.NullifierSecret)))
	// Presence alone admits the owner, a frozen member still consolidates its own notes.
	c.MemberRecord.AssertPresent(api, 1, c.MemberRegistryRoot, ownerPkHash)

	base.CheckBytes(rc, c.DisclosureKey[:])
	sealed := base.Envelope{Plaintext: c.DisclosureKey[:], EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: EncryptionInfo}.Seal(api)
	plaintext := slices.Concat(c.OwnerKey[:], base.FieldBytes(api, nullifierPk), mint, amount, base.FieldBytes(api, outputBlinding))
	for _, hash := range inputHashes {
		plaintext = append(plaintext, base.FieldBytes(api, hash)...)
	}
	fields := base.PackDisclosure(api, plaintext)
	pad := base.DisclosurePad(api, base.MergeDisclosureDomain, gadget.PackBytesBE(api, c.DisclosureKey[:]), c.Salt, len(fields))
	for i := range fields {
		fields[i] = api.Add(fields[i], pad[i])
	}

	chain := []frontend.Variable{Domain, c.PrivateTxHash, c.OutputUtxoHash, c.FirstNullifier, c.RingProgramID, c.MemberRegistryRoot}
	chain = slices.Concat(chain, sealed.Auditor, sealed.Eph,
		[]frontend.Variable{gadget.HashBytes(api, sealed.Ciphertext), c.Salt, gadget.HashChain4(api, fields)})
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}
