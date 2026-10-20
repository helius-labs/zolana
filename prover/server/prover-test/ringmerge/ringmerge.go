// Package ringmerge builds the host side of an anonymous ring merge statement for the Go tests.
package ringmerge

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/merge"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const (
	// RealInputs lead the slots, the rest is dummy padding.
	RealInputs   = 2
	InputTreeID  = 7
	OutputTreeID = 9
)

// Statement is the host side of one anonymous merge, every public value recomputed off circuit.
type Statement struct {
	Keys        ringaudit.Keys
	Circuit     *merge.Circuit
	Registry    *spptest.MemberRegistry
	OwnerKey    [32]byte
	OwnerPkHash *big.Int
	NullifierPk *big.Int
	Secret      *big.Int
	Mint        [32]byte
	Amounts     []*big.Int
	InputHashes []*big.Int
	FirstNf     *big.Int
	OutputHash  *big.Int
	// OutputBlinding opens OutputHash with the disclosed owner, mint and amount.
	OutputBlinding *big.Int
	PrivateTxHash  *big.Int
	DisclosureKey  [32]byte
	// Salt is the SPP output ciphertext salt the disclosure pad reuses.
	Salt      [16]byte
	Plaintext []byte
	// Fields are the masked disclosure chunks the ring instruction carries.
	Fields []*big.Int
}

// Build is a two-input merge padded to n slots under the default audit keys.
func Build(t testing.TB, n int) *Statement {
	t.Helper()
	must := MustOf(t)
	s := &Statement{Keys: ringaudit.DefaultKeys(t), Secret: big.NewInt(19)}
	for i := range s.Salt {
		s.Salt[i] = byte(0x50 + i)
	}
	for i := range s.Mint {
		s.Mint[i] = byte(0xc0 + i)
	}
	for i := range s.DisclosureKey {
		s.DisclosureKey[i] = byte(0x40 ^ i)
	}
	for i := range s.OwnerKey {
		s.OwnerKey[i] = byte(0xa0 + i)
	}
	c := merge.New(n)
	s.Circuit = c
	s.OwnerPkHash = must(protocol.SolanaPkField(s.OwnerKey))
	s.NullifierPk = must(protocol.NullifierPk(s.Secret))
	ownerHash := must(protocol.OwnerHash(s.OwnerPkHash, s.NullifierPk))
	asset := must(protocol.AssetField(s.Mint))
	ringProgramID := big.NewInt(0x5a0e)
	ringData := big.NewInt(0xd0)

	s.Amounts = []*big.Int{big.NewInt(5), big.NewInt(7)}
	s.InputHashes = make([]*big.Int, n)
	for i := range n {
		s.InputHashes[i] = big.NewInt(0)
		c.Inputs[i] = merge.Input{Domain: protocol.DummyDomain, TreeID: 0, Amount: 0, Blinding: 0, RingDataHash: 0}
		if i >= RealInputs {
			continue
		}
		blinding := big.NewInt(int64(0x1111 * (i + 1)))
		utxo := protocol.Utxo{
			Domain: big.NewInt(protocol.UtxoDomain), Owner: ownerHash, Asset: asset, Amount: s.Amounts[i],
			Blinding: blinding, DataHash: big.NewInt(0), RingDataHash: ringData, RingProgramID: ringProgramID,
		}
		s.InputHashes[i] = spptest.MustUtxoHash(t, utxo, big.NewInt(InputTreeID))
		c.Inputs[i] = merge.Input{Domain: protocol.UtxoDomain, TreeID: InputTreeID, Amount: s.Amounts[i], Blinding: blinding, RingDataHash: ringData}
		if i == 0 {
			s.FirstNf = must(protocol.Nullifier(s.InputHashes[0], blinding, s.Secret))
		}
	}
	sum := new(big.Int).Add(s.Amounts[0], s.Amounts[1])
	s.OutputBlinding = spptest.MustPoseidon(t, 4, []*big.Int{big.NewInt(mergeshared.MergeOutputBlindingDomainV1), s.Secret, s.FirstNf})
	s.OutputHash = spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: ownerHash, Asset: asset, Amount: sum, Blinding: s.OutputBlinding,
		DataHash: big.NewInt(0), RingDataHash: ringData, RingProgramID: ringProgramID,
	}, big.NewInt(OutputTreeID))
	s.PrivateTxHash = s.PrivateTx(t, s.InputHashes)

	s.Registry = spptest.NewMemberRegistry(t, registry.Height)
	s.Registry.Update(t, big.NewInt(3), big.NewInt(0), big.NewInt(0))
	// A frozen member keeps its merge, only the presence of the record is read.
	s.Registry.Update(t, s.OwnerPkHash, big.NewInt(1), big.NewInt(0))
	s.Registry.Update(t, big.NewInt(0x77), big.NewInt(0), big.NewInt(0))

	c.OwnerKey = bytesOf(s.OwnerKey[:])
	c.NullifierSecret = s.Secret
	chunks := protocol.MintChunks(s.Mint)
	c.MintChunks = [2]frontend.Variable{chunks[0], chunks[1]}
	c.OutputTreeID = OutputTreeID
	c.OutputRingDataHash = ringData
	c.RingProgramID = ringProgramID
	c.EphSk = bytesOf(ephSk(s.Keys))
	c.AuditorPk = bytesOf(auditorPk(s.Keys))
	c.DisclosureKey = bytesOf(s.DisclosureKey[:])
	c.Salt = s.SaltField()
	c.PrivateTxHash = s.PrivateTxHash
	c.OutputUtxoHash = s.OutputHash
	c.FirstNullifier = s.FirstNf
	s.Bind(t)
	return s
}

// PrivateTx is the SPP private transaction hash over inputHashes and the merged output.
func (s *Statement) PrivateTx(t testing.TB, inputHashes []*big.Int) *big.Int {
	t.Helper()
	must := MustOf(t)
	addresses := make([]*big.Int, len(inputHashes))
	for i := range addresses {
		addresses[i] = big.NewInt(0)
	}
	blinding := must(protocol.PrivateTxBlinding(s.FirstNf, s.Secret))
	return must(protocol.PrivateTxHash(inputHashes, []*big.Int{s.OutputHash}, addresses, blinding))
}

// Bind recomputes the member opening, the disclosure and the public input hash from the host values.
func (s *Statement) Bind(t testing.TB) {
	t.Helper()
	amount := new(big.Int).Add(s.Amounts[0], s.Amounts[1])
	c := s.Circuit
	opened := s.Registry.Opening(s.OwnerPkHash)
	c.MemberRecord = registry.RecordOpening{Next: opened.Record.Next, Lists: opened.Record.Lists, EscrowKey: opened.Record.EscrowKey, Index: opened.Index}
	for i := range opened.Path {
		c.MemberRecord.Path[i] = new(big.Int).Set(&opened.Path[i])
	}
	c.MemberRegistryRoot = s.Registry.Root()

	plaintext := append([]byte{}, s.OwnerKey[:]...)
	plaintext = append(plaintext, fieldBytes(t, s.NullifierPk)...)
	plaintext = append(plaintext, s.Mint[:]...)
	var amountBytes [8]byte
	amount.FillBytes(amountBytes[:])
	plaintext = append(plaintext, amountBytes[:]...)
	plaintext = append(plaintext, fieldBytes(t, s.OutputBlinding)...)
	for _, hash := range s.InputHashes {
		plaintext = append(plaintext, fieldBytes(t, hash)...)
	}
	if len(plaintext) != merge.DisclosureBytes(len(c.Inputs)) {
		t.Fatalf("plaintext %d bytes, want %d", len(plaintext), merge.DisclosureBytes(len(c.Inputs)))
	}
	s.Plaintext = plaintext
	s.Fields = Disclose(t, s.DisclosureKey, s.Salt, plaintext)
	s.Rebind(t)
}

// SaltField is the salt right aligned in one field, as SPP binds it.
func (s *Statement) SaltField() *big.Int {
	return new(big.Int).SetBytes(s.Salt[:])
}

// Elements is the public statement chain from the current host values.
func (s *Statement) Elements(t testing.TB) []*big.Int {
	t.Helper()
	c := s.Circuit
	sealed := s.Sealed(t)
	return []*big.Int{big.NewInt(merge.Domain), s.PrivateTxHash, s.OutputHash, s.FirstNf,
		spptest.AsBigInt(c.RingProgramID), spptest.AsBigInt(c.MemberRegistryRoot),
		sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
		s.SaltField(), spptest.MustHashChain4(t, s.Fields)}
}

// Sealed is the disclosure key enveloped to the auditor.
func (s *Statement) Sealed(t testing.TB) ringaudit.Sealed {
	t.Helper()
	return s.Keys.Seal(t, s.DisclosureKey[:], merge.EncryptionInfo)
}

// Rebind hashes the public statement from the current host values.
func (s *Statement) Rebind(t testing.TB) {
	t.Helper()
	s.Circuit.PublicInputHash = spptest.MustHashChain(t, s.Elements(t))
}

// Disclose packs the plaintext into whole 31-byte chunks and masks each with the merge pad.
func Disclose(t testing.TB, key [32]byte, salt [16]byte, plaintext []byte) []*big.Int {
	t.Helper()
	const chunk = 31
	padded := append([]byte{}, plaintext...)
	for len(padded)%chunk != 0 {
		padded = append(padded, 0)
	}
	fields := make([]*big.Int, len(padded)/chunk)
	pad := ringaudit.DomainPad(t, base.MergeDisclosureDomain, key, salt, len(fields))
	for i := range fields {
		fields[i] = new(big.Int).SetBytes(padded[i*chunk : (i+1)*chunk])
		fields[i].Add(fields[i], pad[i]).Mod(fields[i], ecc.BN254.ScalarField())
	}
	return fields
}

// MustOf lifts a protocol derivation into a single value.
func MustOf(t testing.TB) func(*big.Int, error) *big.Int {
	return func(value *big.Int, err error) *big.Int {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
}

func fieldBytes(t testing.TB, value *big.Int) []byte {
	t.Helper()
	bytes := spptest.MustFieldBytes(t, value)
	return bytes[:]
}

func bytesOf(bytes []byte) [32]frontend.Variable {
	var out [32]frontend.Variable
	for i, b := range bytes {
		out[i] = uint64(b)
	}
	return out
}

func ephSk(keys ringaudit.Keys) []byte {
	sk := keys.EphSk()
	return sk[:]
}

func auditorPk(keys ringaudit.Keys) []byte {
	pk := keys.AuditorPk()
	return pk[:]
}
