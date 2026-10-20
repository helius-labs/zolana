package base

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Published field j is chunk j of the header, the first NIn input slots and the first NOut output slots, each
// slot zero padded to whole 31-byte chunks, test-vectors/audit-disclosure-anonymous.json spells the bytes.
const (
	auditHeaderChunks = 2
	auditInputChunks  = 3
	// An output discloses its recipient address only, the auditor opens the note from the proven body.
	auditOutputChunks = 4
	solanaOwnerTag    = 0x53
)

// AuditUtxoWires opens one transaction slot, the owner is Poseidon(OwnerPkHash, NullifierPk).
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

// Hash commits the slot as SPP does, the owner of every slot but a UTXO is zero.
func (w AuditUtxoWires) Hash(api frontend.API) (hash, utxo frontend.Variable) {
	opening, utxo := w.Opening(api)
	return opening.Hash(api), utxo
}

// Opening binds the owner before the caller chooses the disclosure mode.
func (w AuditUtxoWires) Opening(api frontend.API) (AuditOutputWires, frontend.Variable) {
	utxo := isDomain(api, w.Domain, shared.UtxoDomain)
	owner := gadget.PoseidonHash(api, []frontend.Variable{w.OwnerPkHash, w.NullifierPk})
	return AuditOutputWires{
		Domain: w.Domain, TreeID: w.TreeID, OwnerHash: api.Mul(utxo, owner), Asset: w.Asset, Amount: w.Amount,
		Blinding: w.Blinding, DataHash: w.DataHash, RingDataHash: w.RingDataHash, RingProgramID: w.RingProgramID,
	}, utxo
}

type anonymousShape struct {
	// selected is set in an anonymous ring for this input and output count.
	selected frontend.Variable
	length   int
}

// layout is the dense anonymous plaintext, zero outside an anonymous ring.
type layout struct {
	chunks []frontend.Variable
	shapes []anonymousShape
}

// anonymousLayout binds every disclosed identity to its slot and places the chunks at their published positions.
func (a Audit) anonymousLayout(api frontend.API, rc frontend.Rangechecker, tx AuditTx) layout {
	anonymous := a.Anonymous
	// The auditor parser reads the Ed25519 sender tag only, another tag would leave an unreadable trace.
	senderPkHash := gadget.HashBytes(api, a.Sender[:])
	api.AssertIsEqual(api.Mul(anonymous, api.Sub(a.Sender[0], solanaOwnerTag)), 0)
	for _, b := range a.Sender {
		api.AssertIsEqual(api.Mul(api.Sub(1, anonymous), b), 0)
	}
	header := chunks(api, a.Sender[:], auditHeaderChunks, 1)

	inputs := make([][]frontend.Variable, len(tx.Inputs))
	disclosedInputs := frontend.Variable(0)
	for i, w := range tx.Inputs {
		active := api.Mul(anonymous, tx.NIn.Active[i])
		if tx.Compact && constantZero(api, active) {
			inputs[i] = make([]frontend.Variable, auditInputChunks)
			for j := range inputs[i] {
				inputs[i][j] = 0
			}
			continue
		}
		utxo := isDomain(api, w.Domain, shared.UtxoDomain)
		// An address slot would publish a nullifier the sender's key derives.
		shared.AssertWhen(api, active, api.Add(utxo, isDomain(api, w.Domain, shared.DummyDomain)))
		disclosed := api.Mul(active, utxo)
		api.AssertIsEqual(api.Mul(disclosed, api.Sub(w.OwnerPkHash, senderPkHash)), 0)
		disclosedInputs = api.Add(disclosedInputs, disclosed)
		inputs[i] = chunks(api, slices.Concat(
			uintBytes(api, api.Mul(disclosed, w.TreeID), 2), uintBytes(api, api.Mul(disclosed, w.Amount), 8),
			FieldBytes(api, w.Asset), FieldBytes(api, w.Blinding),
		), auditInputChunks, disclosed)
	}
	api.AssertIsDifferent(api.Add(api.Sub(1, anonymous), disclosedInputs), 0)

	var outputs [AuditOutputSlots][]frontend.Variable
	for i, w := range tx.Notes {
		if tx.Compact && constantZero(api, tx.NOut.Active[i]) {
			outputs[i] = make([]frontend.Variable, auditOutputChunks)
			for j := range outputs[i] {
				outputs[i][j] = 0
			}
			continue
		}
		disclosed := api.Mul(anonymous, tx.NOut.Active[i], isDomain(api, w.Domain, shared.UtxoDomain))
		recipient, viewing := a.Recipients[i][:], a.RecipientViewingKeys[i]
		CheckBytes(rc, viewing[:])
		// A ring note must stay spendable by the Ed25519 rail.
		ringNote := NonZero(api, w.RingProgramID)
		api.AssertIsEqual(api.Mul(disclosed, ringNote, api.Sub(recipient[0], solanaOwnerTag)), 0)
		// A disclosed viewing key takes the unique tagged X25519 encoding the host derives.
		api.AssertIsEqual(api.Mul(disclosed, api.Sub(viewing[0], 4)), 0)
		var u [32]frontend.Variable
		for j := range u {
			u[j] = api.Mul(disclosed, viewing[j+1])
		}
		if tx.Compact {
			assertCanonicalX25519Compact(api, u)
		} else {
			x25519.AssertCanonical(api, u)
		}
		api.AssertIsEqual(api.Mul(disclosed, api.Sub(w.OwnerPkHash, gadget.HashBytes(api, recipient))), 0)
		outputs[i] = chunks(api, slices.Concat(recipient, FieldBytes(api, w.NullifierPk), viewing[:]), auditOutputChunks, disclosed)
	}

	// The output region starts after the selected input prefix, so the layout is a sum over input counts.
	out := layout{chunks: make([]frontend.Variable, auditHeaderChunks+len(tx.Inputs)*auditInputChunks+AuditOutputSlots*auditOutputChunks)}
	copy(out.chunks, header)
	selectedSum := frontend.Variable(0)
	for n := range tx.Inputs {
		count := n + 1
		selected := api.Mul(anonymous, tx.NIn.OneHot[n])
		selectedSum = api.Add(selectedSum, selected)
		published := slices.Concat(inputs[:count]...)
		published = append(published, slices.Concat(outputs[:]...)...)
		for k, chunk := range published {
			j := auditHeaderChunks + k
			if out.chunks[j] == nil {
				out.chunks[j] = 0
			}
			out.chunks[j] = api.Add(out.chunks[j], api.Mul(selected, chunk))
		}
		for m := range AuditOutputSlots {
			out.shapes = append(out.shapes, anonymousShape{
				selected: api.Mul(selected, tx.NOut.OneHot[m]),
				length:   auditHeaderChunks + count*auditInputChunks + (m+1)*auditOutputChunks,
			})
		}
	}
	api.AssertIsEqual(selectedSum, anonymous)
	for j := range out.chunks {
		if out.chunks[j] == nil {
			out.chunks[j] = 0
		}
	}
	return out
}

func isDomain(api frontend.API, domain frontend.Variable, want int) frontend.Variable {
	return api.IsZero(api.Sub(domain, want))
}

// chunks pads bytes to n 31-byte chunks, each zero unless disclosed is set.
func chunks(api frontend.API, bytes []frontend.Variable, n int, disclosed frontend.Variable) []frontend.Variable {
	if len(bytes) > n*gadget.HashBytesChunkSize {
		panic("disclosure slot exceeds its chunks")
	}
	padded := make([]frontend.Variable, n*gadget.HashBytesChunkSize)
	for i := range padded {
		padded[i] = 0
	}
	copy(padded, bytes)
	out := gadget.PackBytesBEWith(api, boundedBytes{}, padded)
	for i := range out {
		out[i] = api.Mul(disclosed, out[i])
	}
	return out
}

// boundedBytes skips the byte check, every chunk byte is bounded where it is produced.
type boundedBytes struct{}

func (boundedBytes) Check(frontend.Variable, int) {}

// FieldBytes is the unique native field encoding, so no alias changes a trace.
func FieldBytes(api frontend.API, value frontend.Variable) []frontend.Variable {
	return canonicalBytes(api, value)
}

// PackDisclosure zero pads bytes to whole 31-byte chunks, every byte is bounded where it is produced.
func PackDisclosure(api frontend.API, bytes []frontend.Variable) []frontend.Variable {
	n := (len(bytes) + gadget.HashBytesChunkSize - 1) / gadget.HashBytesChunkSize
	return chunks(api, bytes, n, 1)
}

// uintBytes bounds an unsigned integer to n bytes.
func uintBytes(api frontend.API, value frontend.Variable, n int) []frontend.Variable {
	return gadget.BitsToBytesBE(api, api.ToBinary(value, 8*n))
}
