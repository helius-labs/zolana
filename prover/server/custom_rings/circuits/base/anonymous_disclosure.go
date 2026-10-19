package base

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// The disclosure is a list of slots. Each slot is a byte string, zero padded
// to a multiple of 31 bytes and split into 31-byte big-endian chunks. Integers
// are big-endian, fields are canonical 32-byte big-endian, and an identity is
// its owner tag byte followed by its 32 key bytes.
//
//	header (anonymous only)          33 B, 2 chunks
//	  0    sender identity           33
//	input slot (anonymous only)      74 B, 3 chunks
//	  0    tree id u16               2
//	  2    amount u64                8
//	  10   asset                     32
//	  42   blinding                  32
//	output slot                      235 B, 8 chunks
//	  0    recipient identity        33
//	  33   recipient viewing pk      33
//	  66   nullifier pk              32
//	  98   amount u64                8
//	  106  asset                     32
//	  138  blinding                  32
//	  170  data hash                 32
//	  202  ring data hash            32
//	  234  ring note flag            1
//
// The published slots are the header, the first n_in input slots and the first
// n_out output slots, in that order. A dummy slot is all zero. Published chunk j
// is chunk + Poseidon(CR_OD, sk_lo, sk_hi, salt, j), where Pack32To2FECircuit
// splits the viewing secret into sk_lo and sk_hi. The disclosure hash is
// HashChain over the published chunks.
const (
	AuditInputSlots   = 4
	auditHeaderChunks = 2
	auditInputChunks  = 3
	auditOutputChunks = 8
)

// AuditIdentityWires opens an owner pk hash as HashBytes(Tag || Key).
type AuditIdentityWires struct {
	Tag       frontend.Variable
	Key       [32]frontend.Variable
	ViewingPk [33]frontend.Variable
}

// ZeroAuditIdentity fills an unused identity slot with a valid zero witness.
func ZeroAuditIdentity() AuditIdentityWires {
	w := AuditIdentityWires{Tag: 0}
	for i := range w.Key {
		w.Key[i] = 0
	}
	for i := range w.ViewingPk {
		w.ViewingPk[i] = 0
	}
	return w
}

// AuditUtxoWires opens one transaction slot.
type AuditUtxoWires struct {
	Domain        frontend.Variable
	TreeID        frontend.Variable
	OwnerPkHash   frontend.Variable
	NullifierPk   frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

// ZeroAuditUtxo fills an unused transaction slot with a valid zero witness.
func ZeroAuditUtxo() AuditUtxoWires {
	return AuditUtxoWires{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
}

// hash zeroes the owner of every slot but a UTXO, as SPP hashes a dummy.
func (w AuditUtxoWires) hash(api frontend.API, isUtxo frontend.Variable) frontend.Variable {
	owner := gadget.PoseidonHash(api, []frontend.Variable{w.OwnerPkHash, w.NullifierPk})
	return shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain:        w.Domain,
		Owner:         api.Mul(isUtxo, owner),
		Asset:         w.Asset,
		Amount:        w.Amount,
		Blinding:      w.Blinding,
		DataHash:      w.DataHash,
		RingDataHash:  w.RingDataHash,
		RingProgramID: w.RingProgramID,
	}, w.TreeID)
}

// isDomain returns a constrained indicator for a single domain match.
// The caller still restricts the full set of accepted domains.
func (w AuditUtxoWires) isDomain(api frontend.API, domain int) frontend.Variable {
	return api.IsZero(api.Sub(w.Domain, domain))
}

// inputBytes bounds the tree and amount and canonically encodes both field values.
func (w AuditUtxoWires) inputBytes(api frontend.API) []frontend.Variable {
	out := uintBytes(api, w.TreeID, 2)
	out = append(out, uintBytes(api, w.Amount, 8)...)
	out = append(out, fieldBytes(api, w.Asset)...)
	return append(out, fieldBytes(api, w.Blinding)...)
}

// outputBytes canonically encodes the output opening and ring-presence flag.
// The caller binds and bounds the supplied recipient and viewing-key bytes.
func (w AuditUtxoWires) outputBytes(api frontend.API, recipient []frontend.Variable, viewingPk [33]frontend.Variable) []frontend.Variable {
	out := append([]frontend.Variable{}, recipient...)
	out = append(out, viewingPk[:]...)
	out = append(out, fieldBytes(api, w.NullifierPk)...)
	out = append(out, uintBytes(api, w.Amount, 8)...)
	out = append(out, fieldBytes(api, w.Asset)...)
	out = append(out, fieldBytes(api, w.Blinding)...)
	out = append(out, fieldBytes(api, w.DataHash)...)
	out = append(out, fieldBytes(api, w.RingDataHash)...)
	return append(out, api.Sub(1, api.IsZero(w.RingProgramID)))
}

// anonymousDisclosureElements binds the disclosed owner and note openings to
// the transaction commitment, then encrypts the exact published slot prefix.
func anonymousDisclosureElements(api frontend.API, w AuditBlockWires) (frontend.Variable, frontend.Variable) {
	// 1. Input slots exist only in anonymous mode, which also forces a nonzero count.
	anonymous := w.Anonymous
	assertOneHot(api, w.InputCountSelected[:])
	api.AssertIsEqual(w.InputCountSelected[0], api.Sub(1, anonymous))
	activeIn := suffixSums(api, w.InputCountSelected[1:])
	assertOneHot(api, w.OutputCountSelected[:])
	activeOut := suffixSums(api, w.OutputCountSelected[:])

	// 2. The header names the owner of every real input and is zero otherwise.
	sender := identityBytes(w.Sender)
	senderPkHash := gadget.HashBytes(api, sender)
	// The auditor parser accepts the Ed25519 sender tag only. A different tag
	// would yield an on-chain-valid proof with an unreadable trace.
	api.AssertIsEqual(api.Mul(anonymous, api.Sub(w.Sender.Tag, 0x53)), 0)
	for _, b := range sender {
		api.AssertIsEqual(api.Mul(api.Sub(1, anonymous), b), 0)
	}
	for _, b := range w.Sender.ViewingPk {
		api.AssertIsEqual(b, 0)
	}
	slots := [][]frontend.Variable{chunks(api, sender, auditHeaderChunks, 1)}

	// 3. Address slots would publish a nullifier derivable from the sender (S2).
	inputHashes := make([]frontend.Variable, AuditInputSlots)
	realInputs := frontend.Variable(0)
	for i, input := range w.Inputs {
		isUtxo := input.isDomain(api, shared.UtxoDomain)
		shared.AssertWhen(api, activeIn[i], api.Add(isUtxo, input.isDomain(api, shared.DummyDomain)))
		disclosed := api.Mul(activeIn[i], isUtxo)
		api.AssertIsEqual(api.Mul(disclosed, api.Sub(input.OwnerPkHash, senderPkHash)), 0)
		inputHashes[i] = api.Mul(disclosed, input.hash(api, isUtxo))
		realInputs = api.Add(realInputs, disclosed)
		slots = append(slots, chunks(api, input.inputBytes(api), auditInputChunks, disclosed))
	}
	api.AssertIsDifferent(api.Add(api.Sub(1, anonymous), realInputs), 0)

	// 4. Every real output discloses the preimage of its owner pk hash.
	outputHashes := make([]frontend.Variable, AuditOutputSlots)
	realOutputHashes := make([]frontend.Variable, AuditOutputSlots)
	byteRange := rangecheck.New(api)
	for i, output := range w.AnonymousOutputs {
		isUtxo := output.isDomain(api, shared.UtxoDomain)
		disclosed := api.Mul(anonymous, activeOut[i], isUtxo)
		recipient := identityBytes(w.Recipients[i])
		for _, b := range w.Recipients[i].ViewingPk {
			byteRange.Check(b, 8)
		}
		// Every ring-bound real note must be spendable by the EdDSA rail.
		ringOutput := api.Mul(disclosed, api.Sub(1, api.IsZero(output.RingProgramID)))
		api.AssertIsEqual(api.Mul(ringOutput, api.Sub(w.Recipients[i].Tag, 0x53)), 0)
		// Disclosed viewing keys use the same unique X25519 encoding as the host.
		api.AssertIsEqual(api.Mul(disclosed, api.Sub(w.Recipients[i].ViewingPk[0], 4)), 0)
		var viewingKey [32]frontend.Variable
		for j := range viewingKey {
			viewingKey[j] = api.Mul(disclosed, w.Recipients[i].ViewingPk[j+1])
		}
		x25519.AssertCanonical(api, viewingKey)
		api.AssertIsEqual(api.Mul(disclosed, api.Sub(output.OwnerPkHash, gadget.HashBytes(api, recipient))), 0)
		outputHashes[i] = output.hash(api, isUtxo)
		realOutputHashes[i] = api.Mul(disclosed, outputHashes[i])
		slots = append(slots, chunks(api, output.outputBytes(api, recipient, w.Recipients[i].ViewingPk), auditOutputChunks, disclosed))
	}

	// 5. Anonymous mode opens private_tx_hash with an empty address chain.
	opened := shared.PrivateTxHashCircuit(api, inputHashes, realOutputHashes, nil, w.PrivateTxBlinding)
	api.AssertIsEqual(api.Mul(anonymous, api.Sub(w.PrivateTxHash, opened)), 0)

	return hashPrefix4(api, outputHashes, w.OutputCountSelected[:]),
		disclosureHash(api, w, slots, activeIn, activeOut)
}

// disclosureHash encrypts every chunk at its published position and chains the
// published ones.
func disclosureHash(
	api frontend.API,
	w AuditBlockWires,
	slots [][]frontend.Variable,
	activeIn, activeOut []frontend.Variable,
) frontend.Variable {
	saltField := gadget.PackBytesBE(api, w.Salt[:])[0]
	keyLo, keyHi := Pack32To2FECircuit(api, w.TxViewingSk)
	pad := func(index frontend.Variable) frontend.Variable {
		return gadget.PoseidonHash(api, []frontend.Variable{
			frontend.Variable(new(big.Int).SetUint64(outputDisclosureDomain)),
			keyLo, keyHi, saltField, index,
		})
	}
	chain := func(acc, active, chunk frontend.Variable) frontend.Variable {
		return api.Select(active, gadget.PoseidonHash(api, []frontend.Variable{acc, chunk}), acc)
	}

	// 1. Encrypt the fixed header and selected inputs at their public positions.
	anonymous := w.Anonymous
	header, inputs, outputs := slots[0], slots[1:1+AuditInputSlots], slots[1+AuditInputSlots:]
	acc := api.Add(header[0], pad(0))
	acc = chain(acc, anonymous, api.Add(header[1], pad(1)))
	for i, slot := range inputs {
		for k, chunk := range slot {
			acc = chain(acc, activeIn[i], api.Add(chunk, pad(auditHeaderChunks+auditInputChunks*i+k)))
		}
	}
	// 2. Place outputs immediately after the selected input prefix.
	inputCount := frontend.Variable(0)
	for _, active := range activeIn {
		inputCount = api.Add(inputCount, active)
	}
	outputBase := api.Mul(anonymous, api.Add(auditHeaderChunks, api.Mul(inputCount, auditInputChunks)))
	// 3. Chain only published ciphertext chunks in their serialized order.
	for i, slot := range outputs {
		for k, chunk := range slot {
			ciphertext := api.Add(chunk, pad(api.Add(outputBase, auditOutputChunks*i+k)))
			if i == 0 && k == 0 {
				// The first output chunk opens the chain when no header precedes it.
				acc = api.Select(anonymous, gadget.PoseidonHash(api, []frontend.Variable{acc, ciphertext}), ciphertext)
				continue
			}
			acc = chain(acc, activeOut[i], ciphertext)
		}
	}
	return acc
}

// identityBytes preserves the owner domain tag. HashBytes supplies byte bounds.
func identityBytes(w AuditIdentityWires) []frontend.Variable {
	return append([]frontend.Variable{w.Tag}, w.Key[:]...)
}

// chunks pads bytes to n 31-byte chunks and zeroes them unless disclosed is set.
func chunks(api frontend.API, bytes []frontend.Variable, n int, disclosed frontend.Variable) []frontend.Variable {
	padded := make([]frontend.Variable, n*gadget.HashBytesChunkSize)
	for i := range padded {
		padded[i] = 0
	}
	if len(bytes) > len(padded) {
		panic("disclosure slot exceeds its chunks")
	}
	copy(padded, bytes)
	out := gadget.PackBytesBE(api, padded)
	for i := range out {
		out[i] = api.Mul(disclosed, out[i])
	}
	return out
}

// fieldBytes returns the unique native-field encoding so aliases cannot change a trace.
func fieldBytes(api frontend.API, value frontend.Variable) []frontend.Variable {
	bytes := gadget.FieldToBytesBE(api, value)
	return bytes[:]
}

// uintBytes constrains an unsigned integer to n bytes before big-endian serialization.
func uintBytes(api frontend.API, value frontend.Variable, n int) []frontend.Variable {
	return gadget.BitsToBytesBE(api, api.ToBinary(value, 8*n))
}
