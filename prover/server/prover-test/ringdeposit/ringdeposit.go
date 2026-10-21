// Package ringdeposit builds the host side of a custom ring deposit for the Go tests.
package ringdeposit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/deposit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// RingMode mirrors RingMode in custom-rings/interface/src/state.rs, the flags DepositPublicInput binds follow it.
type RingMode int

const (
	ModeOff RingMode = iota
	ModeRegistry
	ModeAnonymous
)

// Deposit is the host side of one deposit, every public value recomputed off circuit.
type Deposit struct {
	Keys     ringaudit.Keys
	Registry *ringrecords.Registry
	Circuit  *deposit.CustomRingDepositCircuit
	// Commitments are the owner commitments of the first Count slots.
	Commitments []*big.Int
	// Ciphertext seals every slot's opening, slot i at i*deposit.OpeningBytes.
	Ciphertext []byte
	Chain      []*big.Int
}

// Build deposits count owners under the CRDB blinding, escrowed on ModeRegistry and disclosing their keys on ModeAnonymous.
func Build(t testing.TB, count int, mode RingMode) *Deposit {
	t.Helper()
	return BuildBlinded(t, count, mode, ringaudit.DepositBlinding)
}

// BuildBlinded is Build with blindingOf deriving the blinding every commitment and opening carries.
func BuildBlinded(t testing.TB, count int, mode RingMode, blindingOf func(testing.TB, *big.Int) *big.Int) *Deposit {
	t.Helper()
	anonymous, escrow := mode == ModeAnonymous, mode == ModeRegistry
	d := &Deposit{Keys: ringaudit.DefaultKeys(t), Registry: ringrecords.New(t)}
	c := &deposit.CustomRingDepositCircuit{ContextHash: big.NewInt(0xabcdef), Count: count, Anonymous: 0, KeyEscrow: 0, MemberRegistryRoot: 0}
	if anonymous {
		c.Anonymous = 1
	}
	if escrow {
		c.KeyEscrow = 1
	}
	eph, auditor := d.Keys.EphSk(), d.Keys.AuditorPk()
	for i := range eph {
		c.EphSk[i], c.AuditorPk[i] = int(eph[i]), int(auditor[i])
	}
	plaintext := make([]byte, deposit.MaxDeposits*deposit.OpeningBytes)
	commitments := make([]*big.Int, deposit.MaxDeposits)
	for i := range deposit.MaxDeposits {
		var key [32]byte
		ownerPkHash, nullifierPk, secret, ctHash := big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)
		if i < count {
			ownerPkHash = big.NewInt(int64(11 + i))
			if anonymous {
				for j := range key {
					key[j] = byte(i + j + 1)
				}
				identity, err := protocol.SolanaPkField(key)
				ownerPkHash = spptest.MustHash(t, identity, err)
			}
			nullifierPk = spptest.MustNullifierPk(t, big.NewInt(int64(51+i)))
			secret = big.NewInt(int64(91 + i))
			if escrow {
				ctHash = big.NewInt(int64(0xc0 + i))
				d.Registry.Apply(t, ringrecords.Entry{Member: ownerPkHash, Mask: big.NewInt(ringrecords.EscrowBit), Value: big.NewInt(ringrecords.EscrowBit),
					EscrowKey: spptest.MustPoseidon(t, 3, []*big.Int{nullifierPk, ctHash})})
			}
		}
		c.OwnerPkHashes[i], c.NullifierPks[i], c.BlindingSecrets[i], c.CtHashes[i] = ownerPkHash, nullifierPk, secret, ctHash
		for j, b := range key {
			c.OwnerKeys[i][j] = int(b)
		}
		owner := spptest.MustOwnerHash(t, ownerPkHash, nullifierPk)
		blinding := blindingOf(t, secret)
		commitments[i] = spptest.MustPoseidon(t, 3, []*big.Int{owner, blinding})
		opening := plaintext[i*deposit.OpeningBytes : (i+1)*deposit.OpeningBytes]
		owner.FillBytes(opening[:32])
		blinding.FillBytes(opening[32:64])
		copy(opening[64:], key[:])
	}
	for i := range deposit.MaxDeposits {
		c.Members[i] = ringrecords.UnreadRecordWires()
		if escrow {
			c.Members[i] = d.Registry.Opening(spptest.AsBigInt(c.OwnerPkHashes[i])).RecordWires()
		}
	}
	if escrow {
		c.MemberRegistryRoot = d.Registry.Root()
	}
	d.Circuit, d.Commitments = c, commitments[:count]
	d.Ciphertext = d.Keys.EnvelopeCiphertext(t, plaintext, deposit.EncryptionInfo)
	sealed := d.Keys.Seal(t, plaintext, deposit.EncryptionInfo)
	d.Chain = []*big.Int{big.NewInt(deposit.Domain), spptest.AsBigInt(c.ContextHash), big.NewInt(int64(count)), spptest.AsBigInt(c.Anonymous)}
	for i := range deposit.MaxDeposits {
		if i >= count {
			d.Chain = append(d.Chain, big.NewInt(0), big.NewInt(0))
			continue
		}
		d.Chain = append(d.Chain, commitments[i], ringaudit.HashBytes(t, d.Ciphertext[i*deposit.OpeningBytes:(i+1)*deposit.OpeningBytes]))
	}
	d.Chain = append(d.Chain, sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, spptest.AsBigInt(c.KeyEscrow), spptest.AsBigInt(c.MemberRegistryRoot))
	d.Bind(t)
	return d
}

// Bind hashes the statement elements, as DepositPublicInput::hash does.
func (d *Deposit) Bind(t testing.TB) {
	t.Helper()
	d.Circuit.PublicInputHash = spptest.MustHashChain(t, d.Chain)
}
