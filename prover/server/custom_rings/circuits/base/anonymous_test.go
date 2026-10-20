package base_test

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	base "github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base/audittest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// The host independently hashes the hidden owner, note commitments and
// disclosed bytes. Mutations must break the same proof used by the program.
func TestAnonymousDisclosure(t *testing.T) {
	keys := audittest.DefaultKeys(t)
	w := keys.AuditBlockWires(big.NewInt(0))
	w.Anonymous = 1
	w.InputCountSelected[0], w.InputCountSelected[1] = 0, 1
	w.PrivateTxBlinding = big.NewInt(0x5b1d)
	w.Sender, w.Inputs[0].OwnerPkHash = anonymousIdentity(t, 0xa1)
	w.Recipients[0], w.AnonymousOutputs[0].OwnerPkHash = anonymousIdentity(t, 0xb2)
	w.Recipients[0].ViewingPk[0] = 4
	for i := 1; i < len(w.Recipients[0].ViewingPk); i++ {
		w.Recipients[0].ViewingPk[i] = int(byte(i))
	}
	w.Inputs[0] = base.AuditUtxoWires{
		Domain: big.NewInt(protocol.UtxoDomain), TreeID: big.NewInt(3),
		OwnerPkHash: w.Inputs[0].OwnerPkHash, NullifierPk: spptest.MustNullifierPk(t, big.NewInt(7)),
		Asset: big.NewInt(10), Amount: big.NewInt(100), Blinding: big.NewInt(51),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(77), RingProgramID: big.NewInt(90),
	}
	w.AnonymousOutputs[0] = base.AuditUtxoWires{
		Domain: big.NewInt(protocol.UtxoDomain), TreeID: big.NewInt(9),
		OwnerPkHash: w.AnonymousOutputs[0].OwnerPkHash, NullifierPk: spptest.MustNullifierPk(t, big.NewInt(20)),
		Asset: big.NewInt(10), Amount: big.NewInt(100), Blinding: big.NewInt(61),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(78), RingProgramID: big.NewInt(90),
	}
	inputHash := anonymousUtxoHash(t, w.Inputs[0])
	outputHash := anonymousUtxoHash(t, w.AnonymousOutputs[0])
	w.PrivateTxHash = spptest.MustPrivateTxHash(t, []*big.Int{inputHash}, []*big.Int{outputHash}, nil, big.NewInt(0x5b1d))
	chain := keys.ChainElementsFor(t, w, 1)
	chain[8] = spptest.MustHashChain4(t, []*big.Int{outputHash})
	chain[10] = anonymousDisclosureHash(t, w)
	chain[11] = big.NewInt(1)
	assignment := anonymousAssignment(w, spptest.MustHashChain(t, chain))
	cs := testConstraintSystem(t)
	solve(t, cs, assignment)

	for _, encoding := range []string{"wrong tag", "coordinate alias"} {
		t.Run(encoding, func(t *testing.T) {
			bad := w
			if encoding == "wrong tag" {
				bad.Recipients[0].ViewingPk[0] = 3
			} else {
				for i := 1; i < 33; i++ {
					bad.Recipients[0].ViewingPk[i] = 255
				}
				bad.Recipients[0].ViewingPk[1], bad.Recipients[0].ViewingPk[32] = 237, 127
			}
			badChain := append([]*big.Int{}, chain...)
			badChain[10] = anonymousDisclosureHash(t, bad)
			witness, err := frontend.NewWitness(anonymousAssignment(bad, spptest.MustHashChain(t, badChain)), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if cs.IsSolved(witness) == nil {
				t.Fatal("invalid viewing key encoding solved")
			}
		})
	}

	for _, tc := range []struct {
		name string
		edit func(*base.CustomRingBaseCircuit)
	}{
		{"sender changed", func(c *base.CustomRingBaseCircuit) { c.Sender.Key[0] = 3 }},
		{"sender tag changed", func(c *base.CustomRingBaseCircuit) { c.Sender.Tag = 0x50 }},
		{"input amount changed", func(c *base.CustomRingBaseCircuit) { c.Inputs[0].Amount = 101 }},
		{"recipient changed", func(c *base.CustomRingBaseCircuit) { c.Recipients[0].Key[0] = 3 }},
		{"recipient tag changed", func(c *base.CustomRingBaseCircuit) { c.Recipients[0].Tag = 0x50 }},
		{"recipient viewing key changed", func(c *base.CustomRingBaseCircuit) { c.Recipients[0].ViewingPk[1] = 9 }},
		{"address input", func(c *base.CustomRingBaseCircuit) { c.Inputs[0].Domain = protocol.AddressDomain }},
		{"output count changed", func(c *base.CustomRingBaseCircuit) { c.OutputCountSelected[0], c.OutputCountSelected[1] = 0, 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := *assignment
			tc.edit(&bad)
			witness, err := frontend.NewWitness(&bad, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := cs.IsSolved(witness); err == nil {
				t.Fatal("tampered anonymous witness solved")
			}
		})
	}
}

func anonymousIdentity(t *testing.T, seed byte) (base.AuditIdentityWires, *big.Int) {
	t.Helper()
	w := base.ZeroAuditIdentity()
	w.Tag = int(protocol.SolanaOwnerTag)
	bytes := make([]byte, 33)
	bytes[0] = protocol.SolanaOwnerTag
	for i := range w.Key {
		w.Key[i], bytes[i+1] = int(seed), seed
	}
	hash, err := protocol.HashBytes(bytes)
	return w, spptest.MustHash(t, hash, err)
}

func anonymousUtxoHash(t *testing.T, w base.AuditUtxoWires) *big.Int {
	t.Helper()
	v := spptest.AsBigInt
	owner := spptest.MustOwnerHash(t, v(w.OwnerPkHash), v(w.NullifierPk))
	return spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: v(w.Domain), Owner: owner, Asset: v(w.Asset), Amount: v(w.Amount),
		Blinding: v(w.Blinding), DataHash: v(w.DataHash), RingDataHash: v(w.RingDataHash),
		RingProgramID: v(w.RingProgramID),
	}, v(w.TreeID))
}

func anonymousDisclosureHash(t *testing.T, w base.AuditBlockWires) *big.Int {
	t.Helper()
	v := spptest.AsBigInt
	plaintext := make([]byte, 62+93+248)
	plaintext[0] = byte(v(w.Sender.Tag).Uint64())
	for i, b := range w.Sender.Key {
		plaintext[1+i] = byte(v(b).Uint64())
	}
	input := plaintext[62:155]
	binary.BigEndian.PutUint16(input, uint16(v(w.Inputs[0].TreeID).Uint64()))
	binary.BigEndian.PutUint64(input[2:], v(w.Inputs[0].Amount).Uint64())
	v(w.Inputs[0].Asset).FillBytes(input[10:42])
	v(w.Inputs[0].Blinding).FillBytes(input[42:74])
	output := plaintext[155:]
	output[0] = byte(v(w.Recipients[0].Tag).Uint64())
	for i, b := range w.Recipients[0].Key {
		output[1+i] = byte(v(b).Uint64())
	}
	for i, b := range w.Recipients[0].ViewingPk {
		output[33+i] = byte(v(b).Uint64())
	}
	v(w.AnonymousOutputs[0].NullifierPk).FillBytes(output[66:98])
	binary.BigEndian.PutUint64(output[98:], v(w.AnonymousOutputs[0].Amount).Uint64())
	v(w.AnonymousOutputs[0].Asset).FillBytes(output[106:138])
	v(w.AnonymousOutputs[0].Blinding).FillBytes(output[138:170])
	v(w.AnonymousOutputs[0].DataHash).FillBytes(output[170:202])
	v(w.AnonymousOutputs[0].RingDataHash).FillBytes(output[202:234])
	output[234] = 1

	viewing := make([]byte, 32)
	for i, b := range w.TxViewingSk {
		viewing[i] = byte(v(b).Uint64())
	}
	lo, hi := new(big.Int).SetBytes(viewing[:31]), new(big.Int).SetUint64(uint64(viewing[31]))
	salt := make([]byte, 16)
	for i, b := range w.Salt {
		salt[i] = byte(v(b).Uint64())
	}
	fields := make([]*big.Int, len(plaintext)/31)
	for i := range fields {
		pad := spptest.MustPoseidon(t, 6, []*big.Int{
			big.NewInt(0x4352_5f4f44), lo, hi, new(big.Int).SetBytes(salt), big.NewInt(int64(i)),
		})
		fields[i] = new(big.Int).SetBytes(plaintext[31*i : 31*(i+1)])
		fields[i].Add(fields[i], pad).Mod(fields[i], ecc.BN254.ScalarField())
	}
	return spptest.MustHashChain(t, fields)
}

func anonymousAssignment(w base.AuditBlockWires, hash *big.Int) *base.CustomRingBaseCircuit {
	return &base.CustomRingBaseCircuit{
		PublicInputHash: hash, PrivateTxHash: w.PrivateTxHash, Anonymous: w.Anonymous,
		TxViewingSk: w.TxViewingSk, EphSk: w.EphSk, AuditorPk: w.AuditorPk, Salt: w.Salt,
		Outputs: w.Outputs, OutputCountSelected: w.OutputCountSelected, Sender: w.Sender,
		Inputs: w.Inputs, InputCountSelected: w.InputCountSelected,
		AnonymousOutputs: w.AnonymousOutputs, Recipients: w.Recipients,
		PrivateTxBlinding: w.PrivateTxBlinding,
	}
}
