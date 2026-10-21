// Package deposit binds every deposited owner commitment to an opening encrypted for the auditor.
package deposit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/records"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// Properties:
// 1. The first Count of 1..8 owner commitments open to (owner hash, blinding, owner key)
// AES-CTR encrypted to AuditorPk, the padding slots carry nothing.
// 2. Every blinding is Poseidon(CRDB, BlindingSecret), so no deposit opens as the first
// contact of an anonymous pair stream.
// 3. An anonymous ring's deposit names the Ed25519 key behind each owner, any other deposit
// names none.
// 4. Under key escrow every owner's record lies under MemberRegistryRoot and escrows the key
// the owner's nullifier key and ciphertext hash name.

const (
	MaxDeposits = 8
	// OpeningBytes is owner hash || blinding || owner key.
	OpeningBytes = 96
	// Domain = "CRDP", the first statement element.
	Domain         = 0x43524450
	EncryptionInfo = "CRING/dep1"
)

type CustomRingDepositCircuit struct {
	PublicInputHash    frontend.Variable `gnark:",public"`
	ContextHash        frontend.Variable
	Count              frontend.Variable
	Anonymous          frontend.Variable
	OwnerPkHashes      [MaxDeposits]frontend.Variable
	OwnerKeys          [MaxDeposits][32]frontend.Variable
	NullifierPks       [MaxDeposits]frontend.Variable
	BlindingSecrets    [MaxDeposits]frontend.Variable
	EphSk              [32]frontend.Variable
	AuditorPk          [32]frontend.Variable
	KeyEscrow          frontend.Variable
	MemberRegistryRoot frontend.Variable
	CtHashes           [MaxDeposits]frontend.Variable
	Members            [MaxDeposits]records.QuadRecordOpening
}

func (c *CustomRingDepositCircuit) Define(api frontend.API) error {
	// 1. Count selects 1..8 occupied slots, DepositPublicInput::hash builds both flags as 0 or 1 and a zero root without escrow.
	count := base.SelectCount(api, c.Count, 1, MaxDeposits)
	rc := rangecheck.New(api)
	commitments := make([]frontend.Variable, MaxDeposits)
	var plaintext []frontend.Variable
	for i := range commitments {
		active := count.Active[i]
		// 2. A padding slot carries no owner, key or blinding secret, the plaintext past Count stays fixed.
		for _, value := range []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i], c.BlindingSecrets[i]} {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: value})
		}
		// 3. Under escrow the owner's record exists and escrows Poseidon(nullifier_pk, ct_hash).
		escrowed := api.Mul(active, c.KeyEscrow)
		c.Members[i].AssertPresent(api, escrowed, c.MemberRegistryRoot, c.OwnerPkHashes[i])
		key := records.EscrowKey(api, c.NullifierPks[i], c.CtHashes[i])
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: c.Members[i].EscrowKey, B: key})
		// 4. An anonymous slot's owner hash is the owner identity of its key, the envelope's cipher
		// bounds the key bytes, any other slot discloses no key.
		anonymous := api.Mul(c.Anonymous, active)
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: anonymous, A: c.OwnerPkHashes[i], B: gadget.SolanaOwnerIdentityBounded(api, c.OwnerKeys[i])})
		for _, b := range c.OwnerKeys[i] {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, anonymous), V: b})
		}
		// 5. The blinding is derived in the CRDB domain, the commitment is the deposited UTXO's owner part.
		owner := gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		blinding := base.DepositBlinding(api, c.BlindingSecrets[i])
		commitments[i] = gadget.PoseidonHash(api, []frontend.Variable{owner, blinding})
		// 6. The canonical field encodings keep one plaintext per opening.
		ownerBytes, blindingBytes := gadget.FieldToBytesBEWith(api, rc, owner), gadget.FieldToBytesBEWith(api, rc, blinding)
		plaintext = slices.Concat(plaintext, ownerBytes[:], blindingBytes[:], c.OwnerKeys[i][:])
	}
	// 7. The statement binds every commitment SPP receives to the ciphertext the auditor opens,
	// the cipher bounds every ciphertext byte.
	sealed := base.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: EncryptionInfo}.Seal(api)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, c.statement(api, count, commitments, sealed)))
	return nil
}

// statement is [CRDP, context, count, anonymous, (commitment, ct_hash) per slot, aud0,
// aud1, eph0, eph1, key_escrow, registry_root], a zero pair per padding slot, mirrored by
// DepositPublicInput::hash in custom-rings/interface/src/deposit.rs.
func (c *CustomRingDepositCircuit) statement(api frontend.API, count base.Count, commitments []frontend.Variable, sealed base.Sealed) []frontend.Variable {
	chain := []frontend.Variable{Domain, c.ContextHash, c.Count, c.Anonymous}
	for i, commitment := range commitments {
		ciphertext := gadget.HashBoundedBytes(api, sealed.Ciphertext[i*OpeningBytes:(i+1)*OpeningBytes])
		chain = append(chain, api.Mul(count.Active[i], commitment), api.Mul(count.Active[i], ciphertext))
	}
	return slices.Concat(chain, sealed.Auditor, sealed.Eph, []frontend.Variable{c.KeyEscrow, c.MemberRegistryRoot})
}
