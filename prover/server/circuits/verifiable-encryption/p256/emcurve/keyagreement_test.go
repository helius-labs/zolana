package emcurve

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type agreeKeyCircuit struct {
	NoLookups bool `gnark:"-"`
	Scalar    [32]frontend.Variable
	PublicKey [65]frontend.Variable
	Expected  [6]frontend.Variable `gnark:",public"`
}

func (c *agreeKeyCircuit) Define(api frontend.API) error {
	got := AgreeKeyFor(api, c.Scalar, c.PublicKey, !c.NoLookups)
	for i, v := range []frontend.Variable{got.RecipientLo, got.RecipientHi, got.EphemeralLo, got.EphemeralHi, got.SharedLo, got.SharedHi} {
		api.AssertIsEqual(v, c.Expected[i])
	}
	return nil
}

func packBytes(bytes []byte) (lo, hi *big.Int) {
	lo = new(big.Int).SetBytes(bytes[:31])
	hi = new(big.Int).SetBytes(bytes[31:])
	return lo, hi
}

func compressed(uncompressed []byte) []byte {
	x, y := elliptic.Unmarshal(elliptic.P256(), uncompressed)
	return elliptic.MarshalCompressed(elliptic.P256(), x, y)
}

func agreeKeyWitness(t *testing.T, scalar *big.Int, peer *ecdh.PublicKey) *agreeKeyCircuit {
	t.Helper()
	var w agreeKeyCircuit
	setBytes(w.Scalar[:], scalar.FillBytes(make([]byte, 32)))
	setBytes(w.PublicKey[:], peer.Bytes())
	reduced := new(big.Int).Mod(scalar, GroupOrder())
	key, err := ecdh.P256().NewPrivateKey(reduced.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	var values []*big.Int
	for _, bytes := range [][]byte{compressed(peer.Bytes()), compressed(key.PublicKey().Bytes()), shared} {
		lo, hi := packBytes(bytes)
		values = append(values, lo, hi)
	}
	for i, v := range values {
		w.Expected[i] = v
	}
	return &w
}

func TestAgreeKeyMatchesHostECDH(t *testing.T) {
	assert := test.NewAssert(t)
	peer := peerKey(t).PublicKey()
	n := GroupOrder()
	scalars := []*big.Int{
		new(big.Int).SetBytes([]byte("ephemeral scalar for the merge!!")),
		big.NewInt(2),
		new(big.Int).Sub(n, big.NewInt(2)),
		new(big.Int).Add(big.NewInt(0x1234_5678), n),
	}
	for _, s := range scalars {
		assert.NoError(test.IsSolved(&agreeKeyCircuit{}, agreeKeyWitness(t, s, peer), ecc.BN254.ScalarField()))
	}
}
