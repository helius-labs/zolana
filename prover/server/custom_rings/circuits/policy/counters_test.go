package policy

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"zolana/prover/prover-test/spp/spptest"
)

type counterCircuit struct {
	Hash            frontend.Variable `gnark:",public"`
	Secret          [32]frontend.Variable
	TransactionSalt [16]frontend.Variable
	Salt            frontend.Variable
	Assets          [NVelocityAssets]frontend.Variable
	Spent           [NVelocityAssets]frontend.Variable
}

func (c *counterCircuit) Define(api frontend.API) error {
	hash, err := (successorCounters{salt: c.Salt, assets: c.Assets, spent: c.Spent}).seal(api, c.Secret, c.TransactionSalt)
	if err != nil {
		return err
	}
	api.AssertIsEqual(c.Hash, hash)
	return nil
}

func counterVector() spptest.CounterDisclosure {
	var secret [32]byte
	secret[31] = 17
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	return spptest.CounterDisclosure{Secret: secret, TransactionSalt: salt,
		CounterSalt: new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1)),
		Assets:      []*big.Int{big.NewInt(1), big.NewInt(2)}, Spent: []uint64{42, ^uint64(0)}}
}

func TestCounterCiphertextMatchesSDKFormat(t *testing.T) {
	native := counterVector()
	var vector struct{ Body, Hash string }
	bytes, err := os.ReadFile("../../../../../test-vectors/spend-counters.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(bytes, &vector); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(native.Body(t)); got != vector.Body {
		t.Fatal("counter wire format differs")
	}
	if got := native.Hash(t).Text(16); got != vector.Hash {
		t.Fatal("counter disclosure hash differs")
	}
	assignment := counterCircuit{Hash: native.Hash(t), Salt: native.CounterSalt}
	for i, b := range native.Secret {
		assignment.Secret[i] = b
	}
	for i, b := range native.TransactionSalt {
		assignment.TransactionSalt[i] = b
	}
	for i := range assignment.Assets {
		assignment.Assets[i], assignment.Spent[i] = 0, 0
	}
	for i, asset := range native.Assets {
		assignment.Assets[i] = asset
	}
	for i, spent := range native.Spent {
		assignment.Spent[i] = spent
	}
	if err := test.IsSolved(&counterCircuit{}, &assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*counterCircuit){
		func(c *counterCircuit) { c.TransactionSalt[0] = 2 },
		func(c *counterCircuit) { c.Spent[0] = 43 },
		func(c *counterCircuit) { c.Spent[7] = 1 },
		func(c *counterCircuit) { c.Assets[0] = 3 },
		func(c *counterCircuit) { c.Salt = 5 },
		func(c *counterCircuit) { c.Secret[31] = 18 },
	} {
		changed := assignment
		mutate(&changed)
		if err := test.IsSolved(&counterCircuit{}, &changed, ecc.BN254.ScalarField()); err == nil {
			t.Fatal("changed disclosure accepted")
		}
	}
}
