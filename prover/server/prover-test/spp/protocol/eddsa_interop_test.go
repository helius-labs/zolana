package protocol_test

import (
	"math/big"
	"testing"

	"zolana/prover/circuits/gadget"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	gnarkeddsa "github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test"
)

// spendVerifyCircuit is the in-circuit half of the host signer: it is exactly
// what the transaction circuit will run per input slot.
type spendVerifyCircuit struct {
	PubKey gnarkeddsa.PublicKey
	Sig    gnarkeddsa.Signature
	Msg    frontend.Variable
}

func (c *spendVerifyCircuit) Define(api frontend.API) error {
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	return gnarkeddsa.Verify(curve, c.Sig, c.Msg, c.PubKey, gadget.NewPoseidonFieldHasher(api))
}

func spendAssignment(public protocol.SpendPoint, signature protocol.SpendSignature, msg *big.Int) *spendVerifyCircuit {
	assignment := &spendVerifyCircuit{Msg: msg}
	assignment.PubKey.A.X = public.X
	assignment.PubKey.A.Y = public.Y
	assignment.Sig.R.X = signature.R.X
	assignment.Sig.R.Y = signature.R.Y
	assignment.Sig.S = signature.S
	return assignment
}

func testSpendKey(t *testing.T, secret int64) protocol.SpendKey {
	t.Helper()
	key, err := protocol.NewSpendKey(big.NewInt(secret))
	if err != nil {
		t.Fatalf("spend key: %v", err)
	}
	return key
}

// The gate for the whole scheme: a signature this repo produces on the host must
// satisfy gnark's in-circuit verification with the Poseidon hasher.
func TestHostSpendSignatureVerifiesInCircuit(t *testing.T) {
	key := testSpendKey(t, 987654321)
	msg := big.NewInt(0xfeed)
	signature, err := protocol.SignSpend(key, msg, 0)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if err := test.IsSolved(
		&spendVerifyCircuit{},
		spendAssignment(key.Public, signature, msg),
		ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatalf("host signature rejected in circuit: %v", err)
	}
}

func TestInCircuitVerifyRejectsTamperedSignature(t *testing.T) {
	key := testSpendKey(t, 987654321)
	msg := big.NewInt(0xfeed)
	signature, err := protocol.SignSpend(key, msg, 0)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	other, err := protocol.SignSpend(key, big.NewInt(0xbeef), 0)
	if err != nil {
		t.Fatalf("sign other: %v", err)
	}

	tampered := map[string]*spendVerifyCircuit{
		"S": spendAssignment(key.Public, protocol.SpendSignature{
			R: signature.R,
			S: new(big.Int).Add(signature.S, big.NewInt(1)),
		}, msg),
		"R": spendAssignment(key.Public, protocol.SpendSignature{
			R: other.R,
			S: signature.S,
		}, msg),
		"message": spendAssignment(key.Public, signature, big.NewInt(0xbeef)),
		"public key": spendAssignment(
			testSpendKey(t, 123456789).Public,
			signature,
			msg,
		),
	}
	for name, assignment := range tampered {
		t.Run(name, func(t *testing.T) {
			if err := test.IsSolved(&spendVerifyCircuit{}, assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatalf("circuit accepted a signature with a tampered %s", name)
			}
		})
	}
}

// The non-signing convention every dummy and address slot carries must satisfy
// the verification equation, otherwise the signature check cannot run ungated
// and each slot needs a conditional bit instead.
func TestIdentityConventionSatisfiesInCircuitVerify(t *testing.T) {
	if err := test.IsSolved(
		&spendVerifyCircuit{},
		spendAssignment(
			protocol.IdentitySpendPoint(),
			protocol.IdentitySpendSignature(),
			big.NewInt(0),
		),
		ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatalf("identity convention does not verify, the ungated design does not hold: %v", err)
	}
}

// The identity key verifies against a signature anyone can forge, which is why
// the circuit must reject it for real UTXOs. Pin the forgery here so the reason
// for that gate is documented where the convention is defined.
func TestIdentityKeyAcceptsForgedSignature(t *testing.T) {
	forgedNonce := big.NewInt(4242)
	forged, err := protocol.NewSpendKey(forgedNonce)
	if err != nil {
		t.Fatalf("forged nonce key: %v", err)
	}
	if err := test.IsSolved(
		&spendVerifyCircuit{},
		spendAssignment(
			protocol.IdentitySpendPoint(),
			protocol.SpendSignature{R: forged.Public, S: forgedNonce},
			big.NewInt(0xfeed),
		),
		ecc.BN254.ScalarField(),
	); err != nil {
		t.Fatalf("expected the identity key to accept a forged signature, got: %v", err)
	}
}

// The secret must stay below 2^250 so that secret and secret+order cannot both
// be presented for one public key.
func TestNewSpendKeyRejectsOversizedSecret(t *testing.T) {
	order := protocol.SpendKeyOrder()
	if _, err := protocol.NewSpendKey(order); err == nil {
		t.Fatal("expected the subgroup order to be rejected as a secret")
	}
	aliased := new(big.Int).Add(big.NewInt(987654321), order)
	if _, err := protocol.NewSpendKey(aliased); err == nil {
		t.Fatal("expected an aliased secret to be rejected")
	}
}

// Host verification must agree with the circuit on both answers.
func TestHostVerifySpendAgrees(t *testing.T) {
	key := testSpendKey(t, 987654321)
	msg := big.NewInt(0xfeed)
	signature, err := protocol.SignSpend(key, msg, 0)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := protocol.VerifySpend(key.Public, msg, signature); err != nil {
		t.Fatalf("host rejected its own signature: %v", err)
	}
	if err := protocol.VerifySpend(key.Public, big.NewInt(1), signature); err == nil {
		t.Fatal("host accepted a signature over the wrong message")
	}
}

// Two slots of one key must not share a nonce.
func TestSignSpendUsesDistinctNoncePerSlot(t *testing.T) {
	key := testSpendKey(t, 987654321)
	msg := big.NewInt(0xfeed)
	first, err := protocol.SignSpend(key, msg, 0)
	if err != nil {
		t.Fatalf("sign slot 0: %v", err)
	}
	second, err := protocol.SignSpend(key, msg, 1)
	if err != nil {
		t.Fatalf("sign slot 1: %v", err)
	}
	if first.R.X.Cmp(second.R.X) == 0 && first.R.Y.Cmp(second.R.Y) == 0 {
		t.Fatal("two slots produced the same nonce point")
	}
}
