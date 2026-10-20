package base

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

const (
	// RecipientKeyDomain is "CR_R", the recipient stream secret domain mirrored by Rust and TS.
	RecipientKeyDomain = 0x4352_5f52
	// AnonymousOutputScheme leads every published anonymous output body.
	AnonymousOutputScheme = 0x09
	// AnonymousOutputPlaintextLen is asset_address(32) || amount(8) || blinding(32) || pair_u(32).
	AnonymousOutputPlaintextLen = 104
	AnonymousOutputBodyLen      = AnonymousOutputPlaintextLen + 1
)

// DeliveryWires is the published body of one output slot with the plaintext parts its note does not commit.
type DeliveryWires struct {
	AssetAddress [32]frontend.Variable
	PairU        [32]frontend.Variable
	Ciphertext   [AnonymousOutputPlaintextLen]frontend.Variable
}

// Delivery proves every real ring output body is the recipient's AES-CTR encryption of the committed note.
type Delivery struct {
	RingProgramID [32]frontend.Variable
	Outputs       [AuditOutputSlots]DeliveryWires
}

// auditKeys are the transaction values every recipient stream reuses.
type auditKeys struct {
	txSk [32]frontend.Variable
	txPk []frontend.Variable
	salt frontend.Variable
}

// deliverySlot is the committed note of one output slot and the address its disclosure names.
type deliverySlot struct {
	index     int
	note      AuditUtxoWires
	viewing   [33]frontend.Variable
	anonymous frontend.Variable
	// active is set below the output count.
	active   frontend.Variable
	ringHash frontend.Variable
}

// Define returns the body hash chain the ring program recomputes, zero under a pinned ordinary mode.
func (d Delivery) Define(api frontend.API, rc frontend.Rangechecker, keys auditKeys, a Audit, tx AuditTx) frontend.Variable {
	bodyHashes := make([]frontend.Variable, AuditOutputSlots)
	for i := range bodyHashes {
		bodyHashes[i] = 0
	}
	if !constantZero(api, a.Anonymous) {
		ringHash := gadget.HashBytesWith(api, rc, d.RingProgramID[:])
		for i, w := range d.Outputs {
			if constantZero(api, tx.NOut.Active[i]) {
				continue
			}
			bodyHashes[i] = w.define(api, rc, keys, deliverySlot{
				index: i, note: tx.Notes[i], viewing: a.RecipientViewingKeys[i],
				anonymous: a.Anonymous, active: tx.NOut.Active[i], ringHash: ringHash,
			})
		}
	}
	return prefixChain(api, tx, bodyHashes)
}

// define returns HashBytes of the slot's scheme-9 body, zero where the slot publishes none.
func (w DeliveryWires) define(api frontend.API, rc frontend.Rangechecker, keys auditKeys, s deliverySlot) frontend.Variable {
	utxo := isDomain(api, s.note.Domain, shared.UtxoDomain)
	ringNote := NonZero(api, s.note.RingProgramID)
	real := api.Mul(s.anonymous, s.active, utxo, ringNote)

	// 1. The recipient recomputes the commitment from the body, the public ring and its own keys.
	assertWhen(api, real, api.Sub(s.note.RingProgramID, s.ringHash))
	assertWhen(api, real, s.note.DataHash)
	assertWhen(api, real, s.note.RingDataHash)
	assertWhen(api, real, api.Sub(s.note.Asset, gadget.HashBytesWith(api, rc, w.AssetAddress[:])))

	// 2. A slot without a recipient keys the base point, a gated assertion would not keep an
	// invalid key from making the agreement unsatisfiable.
	var u [32]frontend.Variable
	for j := range u {
		u[j] = api.Select(real, s.viewing[j+1], basepointByte(j))
	}
	dh := x25519.ECDH(api, keys.txSk, u)
	recipient := gadget.PackBytesBEWith(api, boundedBytes{}, append([]frontend.Variable{4}, u[:]...))
	secret := gadget.PoseidonHash(api, slices.Concat(
		[]frontend.Variable{RecipientKeyDomain}, gadget.PackBytesBEWith(api, boundedBytes{}, dh[:]),
		keys.txPk, recipient, []frontend.Variable{keys.salt, s.index},
	))
	key, nonce := auditStreamKeySchedule(api, secret)

	// 3. The plaintext is derived from the opened note, a padding slot encrypts zeros.
	CheckBytes(rc, w.PairU[:])
	plaintext := slices.Concat(
		masked(api, real, w.AssetAddress[:]), uintBytes(api, api.Mul(real, s.note.Amount), 8),
		fieldBytes(api, api.Mul(real, s.note.Blinding)), masked(api, real, w.PairU[:]),
	)
	for j, b := range aes.NewCipher(api, key).CTREncrypt(nonce, plaintext) {
		assertWhen(api, real, api.Sub(b, w.Ciphertext[j]))
	}

	// 4. A scheme-3 exit and every slot of an ordinary ring publish no body, the program chains zero.
	body := gadget.HashBytesWith(api, rc, append([]frontend.Variable{AnonymousOutputScheme}, w.Ciphertext[:]...))
	exit := api.Mul(utxo, api.Sub(1, ringNote))
	return api.Mul(s.anonymous, api.Sub(1, exit), body)
}

func assertWhen(api frontend.API, when, zero frontend.Variable) {
	api.AssertIsEqual(api.Mul(when, zero), 0)
}

func masked(api frontend.API, flag frontend.Variable, bytes []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = api.Mul(flag, b)
	}
	return out
}

// basepointByte is byte j of the X25519 base point u = 9.
func basepointByte(j int) frontend.Variable {
	if j == 0 {
		return 9
	}
	return 0
}
