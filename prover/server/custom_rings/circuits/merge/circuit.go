// Package merge binds an anonymous ring's SPP merge to a disclosure only its auditor opens.
package merge

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// Properties:
// 1. PrivateTxHash, OutputUtxoHash and FirstNullifier are the SPP merge's, recomputed under one owner, one asset and the owner's nullifier secret.
// 2. Membership is not proven, a merge consolidates one owner's notes and moves no value between parties.
// 3. Only the auditor opens the disclosure of the owner key, nullifier key, mint, amount, output blinding and every input commitment.

const (
	// Domain is "CRMG", the first element of the statement chain.
	Domain         = 0x43524d47
	EncryptionInfo = "CRING/mrg1"
	// HeaderBytes is owner key, nullifier pk, mint, amount and output blinding, the output opening.
	HeaderBytes = 32 + 32 + 32 + 8 + 32
)

// Input is one merge slot, the owner, asset and ring program come from the circuit.
type Input struct {
	Domain       frontend.Variable
	TreeID       frontend.Variable
	Amount       frontend.Variable
	Blinding     frontend.Variable
	RingDataHash frontend.Variable
}

type AnonymousMergeCircuit struct {
	NumInputs int `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash  frontend.Variable
	OutputUtxoHash frontend.Variable
	FirstNullifier frontend.Variable
	RingProgramID  frontend.Variable
	AuditorPk      [32]frontend.Variable
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
}

// NewAnonymousMergeCircuit allocates the circuit of one supported merge width.
func NewAnonymousMergeCircuit(n int) *AnonymousMergeCircuit {
	return &AnonymousMergeCircuit{NumInputs: n, Inputs: make([]Input, n)}
}

// DisclosureBytes is the plaintext length of the n-input circuit.
func DisclosureBytes(n int) int {
	return HeaderBytes + 32*n
}

func (c *AnonymousMergeCircuit) Define(api frontend.API) error {
	if !mergeshared.IsSupportedInputCount(c.NumInputs) {
		return fmt.Errorf("merge: unsupported input count %d, want one of %v", c.NumInputs, mergeshared.SupportedInputCounts)
	}
	if len(c.Inputs) != c.NumInputs {
		return fmt.Errorf("merge: input count mismatch: got %d want %d", len(c.Inputs), c.NumInputs)
	}
	// 1. One owner, the Solana identity of the disclosed key under the secret's nullifier key, and one asset,
	// the mint whose chunks bound to 31 and 1 bytes give it one 32-byte opening.
	ownerPkHash := gadget.SolanaOwnerIdentity(api, c.OwnerKey)
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{c.NullifierSecret})
	ownerHash := gadget.PoseidonHash(api, []frontend.Variable{ownerPkHash, nullifierPk})
	asset := gadget.HashChain(api, c.MintChunks[:])
	mint := slices.Concat(gadget.BitsToBytesBE(api, api.ToBinary(c.MintChunks[0], 31*8)), gadget.BitsToBytesBE(api, api.ToBinary(c.MintChunks[1], 8)))

	// 2. Every slot is a UTXO of that owner, asset and ring with no data, or a dummy, and slot zero yields
	// the public first nullifier.
	inputHashes := make([]frontend.Variable, c.NumInputs)
	addressNullifiers := make([]frontend.Variable, c.NumInputs)
	sum := frontend.Variable(0)
	var firstNullifier frontend.Variable
	for i, in := range c.Inputs {
		addressNullifiers[i] = 0
		isDummy := api.IsZero(api.Sub(in.Domain, mergeshared.DummyDomain))
		// A merge spends no address slot.
		api.AssertIsEqual(api.Add(api.IsZero(api.Sub(in.Domain, mergeshared.UtxoDomain)), isDummy), 1)
		utxo := transaction.UtxoCircuitFields{
			Domain: in.Domain, Owner: api.Select(isDummy, 0, ownerHash), Asset: api.Select(isDummy, 0, asset),
			Amount: in.Amount, Blinding: in.Blinding, DataHash: 0, RingDataHash: in.RingDataHash,
			RingProgramID: api.Select(isDummy, 0, c.RingProgramID),
		}
		// A dummy carries nothing but its blinding, so it hides no amount.
		transaction.AssertWhen(api, isDummy, utxo.CheckDummy(api))
		hash := transaction.UtxoHashCircuit(api, utxo, in.TreeID)
		inputHashes[i] = api.Select(isDummy, 0, hash)
		// SPP's merge range-checks every amount private_tx_hash binds here, a dummy's is zero.
		sum = api.Add(sum, in.Amount)
		if i == 0 {
			// SPP seeds every derived merge value from the real slot zero.
			api.AssertIsEqual(in.Domain, mergeshared.UtxoDomain)
			firstNullifier = abstractor.Call(api, transaction.NullifierGadget{
				UtxoHash: hash, Blinding: in.Blinding, NullifierSecret: c.NullifierSecret,
			})
			// The nullifier SPP inserted names the merge the disclosure opens.
			api.AssertIsEqual(c.FirstNullifier, firstNullifier)
		}
	}
	// 3. The output is the SPP merge output, the 64-bit sum under the owner with the TMOB blinding.
	amount := gadget.BitsToBytesBE(api, api.ToBinary(sum, 64))
	outputBlinding := mergeshared.MergeOutputBlinding(api, c.NullifierSecret, firstNullifier)
	outputHash := transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain: mergeshared.UtxoDomain, Owner: ownerHash, Asset: asset, Amount: sum,
		Blinding: outputBlinding, DataHash: 0,
		RingDataHash: c.OutputRingDataHash, RingProgramID: c.RingProgramID,
	}, c.OutputTreeID)
	api.AssertIsEqual(c.OutputUtxoHash, outputHash)
	// 4. The private tx hash is SPP's, so the disclosed commitments are the ones SPP spent.
	api.AssertIsEqual(c.PrivateTxHash, transaction.PrivateTxHashCircuit(api, inputHashes,
		[]frontend.Variable{outputHash}, addressNullifiers, transaction.DerivePrivateTxBlinding(api, firstNullifier, c.NullifierSecret)))

	// 5. The envelope seals the disclosure key to the auditor, its cipher bounds every key and ciphertext byte.
	sealed := base.Envelope{Plaintext: c.DisclosureKey[:], EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: EncryptionInfo}.Seal(api)
	// 6. The disclosure is the canonical opening of the output and every input commitment under the key's pad.
	rc := rangecheck.New(api)
	nullifierPkBytes, outputBlindingBytes := gadget.FieldToBytesBEWith(api, rc, nullifierPk), gadget.FieldToBytesBEWith(api, rc, outputBlinding)
	plaintext := slices.Concat(c.OwnerKey[:], nullifierPkBytes[:], mint, amount, outputBlindingBytes[:])
	for _, hash := range inputHashes {
		hashBytes := gadget.FieldToBytesBEWith(api, rc, hash)
		plaintext = append(plaintext, hashBytes[:]...)
	}
	fields := base.PackDisclosure(api, plaintext)
	pad := gadget.DisclosurePad(api, base.MergeDisclosureDomain, [2]frontend.Variable(gadget.PackBytesBEWith(api, gadget.BoundedBytes{}, c.DisclosureKey[:])), c.Salt, len(fields))
	for i := range fields {
		fields[i] = api.Add(fields[i], pad[i])
	}
	// 7. The statement binds the SPP merge, the ring, the envelope and the masked disclosure.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, c.statement(api, sealed, fields)))
	return nil
}

// statement is the anonymous merge preimage, mirrored by MergeAnonymousPublicInput::elements in custom-rings/interface/src/merge.rs.
//
//	CRMG, private_tx_hash, output_utxo_hash, first_nullifier, ring_id, aud0, aud1, eph0, eph1, ct_hash, salt, HashChain4(fields)
func (c *AnonymousMergeCircuit) statement(api frontend.API, sealed base.Sealed, fields []frontend.Variable) []frontend.Variable {
	return slices.Concat(
		[]frontend.Variable{Domain, c.PrivateTxHash, c.OutputUtxoHash, c.FirstNullifier, c.RingProgramID},
		sealed.Auditor,
		sealed.Eph,
		[]frontend.Variable{gadget.HashBoundedBytes(api, sealed.Ciphertext), c.Salt, gadget.HashChain4(api, fields)},
	)
}
