package p256

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestComputeKeyAgreementAcceptsZeroXRecipient(t *testing.T) {
	params := elliptic.P256().Params()
	y := new(big.Int).ModSqrt(params.B, params.P)
	if y == nil {
		t.Fatal("P-256 has no point at x=0")
	}
	cs := compile(t, &keyAgreementCircuit{})
	for _, y := range []*big.Int{y, new(big.Int).Sub(params.P, y)} {
		peer, err := ecdh.P256().NewPublicKey(uncompressedBytes(big.NewInt(0), y))
		if err != nil {
			t.Fatal(err)
		}
		for _, scalar := range []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(0xc0ffee), new(big.Int).Sub(params.N, big.NewInt(1))} {
			if err := solveAgreement(t, cs, keyAgreementWitness(t, scalar, peer)); err != nil {
				t.Fatalf("scalar %x, y parity %d: %v", scalar, y.Bit(0), err)
			}
		}
	}
}
