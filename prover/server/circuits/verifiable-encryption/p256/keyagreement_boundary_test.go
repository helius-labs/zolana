package p256_test

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
)

var boundaryScalar = new(big.Int).SetBytes([]byte("ephemeral scalar for the merge!!"))

func boundaryPeer() *ecdh.PublicKey {
	return hosttest.DefaultKeys().RecipientSecret.PublicKey()
}

func scalarBytes(scalar *big.Int) []byte {
	return scalar.FillBytes(make([]byte, 32))
}

func assignBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}

func presentedAgreement(ephemeral *ecdh.PrivateKey, presented [65]byte, sharedX []byte) *p256.KeyAgreementCircuit {
	var w p256.KeyAgreementCircuit
	assignBytes(w.Scalar[:], ephemeral.Bytes())
	assignBytes(w.PublicKey[:], presented[:])
	recipientLo, recipientHi := hosttest.PackCompressed(hosttest.CompressP256(presented[:]))
	ephemeralLo, ephemeralHi := hosttest.PackCompressed(hosttest.CompressP256(ephemeral.PublicKey().Bytes()))
	sharedLo, sharedHi := hosttest.PackShared([32]byte(sharedX))
	for i, v := range []*big.Int{recipientLo, recipientHi, ephemeralLo, ephemeralHi, sharedLo, sharedHi} {
		w.Expected[i] = v
	}
	return &w
}

func selfAgreementWitness(t *testing.T, scalar []byte, reduced *big.Int) *p256.SelfAgreementCircuit {
	t.Helper()
	var w p256.SelfAgreementCircuit
	assignBytes(w.Scalar[:], scalar)
	shared := make([]byte, 32)
	public := [33]byte{0x02}
	if reduced != nil {
		key, err := ecdh.P256().NewPrivateKey(scalarBytes(reduced))
		if err != nil {
			t.Fatalf("private key: %v", err)
		}
		if shared, err = key.ECDH(key.PublicKey()); err != nil {
			t.Fatalf("ecdh: %v", err)
		}
		public = hosttest.CompressP256(key.PublicKey().Bytes())
	}
	assignBytes(w.SharedX[:], shared)
	assignBytes(w.PublicKey[:], public[:])
	return &w
}

type carriedByte struct {
	name string
	k    int
}

func requireRangeChecks(t *testing.T, cs constraint.ConstraintSystem, honest func() frontend.Circuit, bytes func(frontend.Circuit) []frontend.Variable, carries []carriedByte) {
	t.Helper()
	for _, prover := range hosttest.RangeCheckProvers(t) {
		t.Run(prover.Name, func(t *testing.T) {
			if err := p256.SolveAgreement(t, cs, honest(), prover.Options...); err != nil {
				t.Fatalf("honest witness rejected: %v", err)
			}
			for _, carry := range carries {
				t.Run(carry.name, func(t *testing.T) {
					w := honest()
					hosttest.CarryIntoByte(t, bytes(w), carry.k)
					hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, w, prover.Options...))
				})
			}
		})
	}
}

func TestComputeKeyAgreementBoundaryRecipientByteRangeCheck(t *testing.T) {
	requireRangeChecks(t, p256.Compile(t, &p256.KeyAgreementCircuit{}),
		func() frontend.Circuit { return p256.KeyAgreementWitness(t, boundaryScalar, boundaryPeer()) },
		func(w frontend.Circuit) []frontend.Variable { return w.(*p256.KeyAgreementCircuit).PublicKey[:] },
		[]carriedByte{{"x byte 5", 5}, {"y byte 40", 40}},
	)
}

func TestComputeKeyAgreementBoundaryEphemeralByteRangeCheck(t *testing.T) {
	requireRangeChecks(t, p256.Compile(t, &p256.KeyAgreementCircuit{}),
		func() frontend.Circuit { return p256.KeyAgreementWitness(t, boundaryScalar, boundaryPeer()) },
		func(w frontend.Circuit) []frontend.Variable { return w.(*p256.KeyAgreementCircuit).Scalar[:] },
		[]carriedByte{{"scalar byte 5", 5}, {"scalar byte 29", 29}},
	)
}

func TestSelfAgreeKeyBoundaryScalarByteRangeCheck(t *testing.T) {
	requireRangeChecks(t, p256.Compile(t, &p256.SelfAgreementCircuit{}),
		func() frontend.Circuit { return selfAgreementWitness(t, scalarBytes(boundaryScalar), boundaryScalar) },
		func(w frontend.Circuit) []frontend.Variable { return w.(*p256.SelfAgreementCircuit).Scalar[:] },
		[]carriedByte{{"scalar byte 5", 5}, {"scalar byte 29", 29}},
	)
}

func TestComputeKeyAgreementBoundaryNonCanonicalRecipient(t *testing.T) {
	cs := p256.Compile(t, &p256.KeyAgreementCircuit{})
	ephemeral := hosttest.DefaultKeys().EphemeralSecret
	for _, row := range hosttest.NonCanonicalRecipients(t) {
		t.Run(row.Name, func(t *testing.T) {
			shared := hosttest.SharedX(t, ephemeral, row.Canonical)
			if err := p256.SolveAgreement(t, cs, presentedAgreement(ephemeral, row.Canonical, shared)); err != nil {
				t.Fatalf("canonical recipient rejected: %v", err)
			}
			hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, presentedAgreement(ephemeral, row.Presented, shared)))
		})
	}
}

type orderBoundaryScalar struct {
	name    string
	raw     *big.Int
	reduced *big.Int
}

func orderBoundaryScalars() []orderBoundaryScalar {
	n := elliptic.P256().Params().N
	allOnes := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	return []orderBoundaryScalar{
		{"group order plus one as scalar one", new(big.Int).Add(n, big.NewInt(1)), big.NewInt(1)},
		{"2^256 minus one as its residue", allOnes, new(big.Int).Mod(allOnes, n)},
	}
}

func TestComputeKeyAgreementBoundaryScalarAtGroupOrder(t *testing.T) {
	cs := p256.Compile(t, &p256.KeyAgreementCircuit{})
	peer := boundaryPeer()
	t.Run("group order", func(t *testing.T) {
		w := p256.KeyAgreementWitness(t, big.NewInt(1), peer)
		assignBytes(w.Scalar[:], scalarBytes(elliptic.P256().Params().N))
		infinityLo, infinityHi := hosttest.PackCompressed([33]byte{0x02})
		sharedLo, sharedHi := hosttest.PackShared([32]byte{})
		w.Expected[2], w.Expected[3], w.Expected[4], w.Expected[5] = infinityLo, infinityHi, sharedLo, sharedHi
		hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, w))
	})
	for _, row := range orderBoundaryScalars() {
		t.Run(row.name, func(t *testing.T) {
			w := p256.KeyAgreementWitness(t, row.reduced, peer)
			assignBytes(w.Scalar[:], scalarBytes(row.raw))
			if err := p256.SolveAgreement(t, cs, w); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestSelfAgreeKeyBoundaryScalarAtGroupOrder(t *testing.T) {
	cs := p256.Compile(t, &p256.SelfAgreementCircuit{})
	t.Run("group order", func(t *testing.T) {
		w := selfAgreementWitness(t, scalarBytes(elliptic.P256().Params().N), nil)
		hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, w))
	})
	for _, row := range orderBoundaryScalars() {
		t.Run(row.name, func(t *testing.T) {
			if err := p256.SolveAgreement(t, cs, selfAgreementWitness(t, scalarBytes(row.raw), row.reduced)); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}
