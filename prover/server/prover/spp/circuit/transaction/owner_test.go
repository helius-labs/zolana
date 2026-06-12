package transaction

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestCircuitRejectsProgramOwnedInput(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	asset := spptest.Fe(7)
	input := sampleUtxoWithAssetAndAmount(10, asset, spptest.Fe(100))
	// A zone-owned input must be spent via zone_transact (zone PDA authorization),
	// not the default transact. The circuit pins zone fields to zero.
	input.ZoneProgramID = spptest.Fe(1)
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{input},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, asset, spptest.Fe(60)),
			sampleUtxoWithAssetAndAmount(110, asset, spptest.Fe(40)),
		},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsSolanaOwnerKeyMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].SolanaOwnerPkHash = spptest.Fe(12345)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitAcceptsP256Owner(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// The Solana-only circuit variant (no P256 gadget) proves a Solana-owned
// transaction. P256MessageHash must be 0 on this rail (no signature).
func TestSolanaCircuitSolvesSolanaInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewSolanaCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.P256MessageHash = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Soundness guard: the Solana-only variant must reject a P256-owned input
// (solana_owner_pk_hashes[i] == 0 on a real slot), since it skips the
// signature gadget. Otherwise a UTXO owned by OwnerHash(0, nullifier_pk)
// could be spent with no signature.
func TestSolanaCircuitRejectsP256Input(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewSolanaCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.P256MessageHash = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Spec UTXO Ownership: each input's solana_owner_pk_hashes entry selects its own path
func TestCircuitAcceptsMixedP256AndSolanaInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, priv, priv)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Spec UTXO Ownership: Ed25519 owners may differ per input — each entry binds
// its own input, each with its own nullifier secret.
func TestCircuitAcceptsDistinctSolanaOwners(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	rewriteInputAsSolanaOwner(t, assignment, 1, 0x43, spptest.Fe(777))

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// An input's entry must match the key committed in that input's owner hash:
// swapping in a sibling's (or any foreign) key fails the owner binding even
// though every entry is individually a valid pk_field.
func TestCircuitRejectsForeignSolanaOwnerEntry(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	rewriteInputAsSolanaOwner(t, assignment, 1, 0x43, spptest.Fe(777))
	assignment.Inputs[1].SolanaOwnerPkHash = testSolanaPkField(t)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// A non-zero entry binds the input's owner to the entry, never to the P256
// witness key: a P256-owned input carrying a stray non-zero entry cannot bind
// its owner.
func TestCircuitRejectsP256OwnerWithNonZeroOwnerKey(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.Inputs[0].SolanaOwnerPkHash = testSolanaPkField(t)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadP256Signature(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	wrongSigner := spptest.FixedP256Key(t, 12)
	rewriteSingleInputAsP256(t, assignment, priv, wrongSigner)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadP256MessageHash(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.P256MessageHash = new(big.Int).Add(spptest.AsBigInt(assignment.P256MessageHash), big.NewInt(1))
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsP256PubkeyOwnerMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	ownerPriv := spptest.FixedP256Key(t, 11)
	signingPriv := spptest.FixedP256Key(t, 12)
	rewriteSingleInputAsP256(t, assignment, ownerPriv, signingPriv)
	assignment.P256Pub = spptest.P256PubkeyAssignment(signingPriv)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// p256PkFieldUnitCircuit wraps P256PkFieldFromPubkeyCircuit alone. The gnark
// ECDSA gadget assumes a valid public key and never checks it lies on the
// curve, so the AssertIsOnCurve here is the sole constraint rejecting an
// off-curve point. It cannot be exercised through the full circuit: the
// signature gadget's prover-side scalar-mul hint calls crypto/elliptic, which
// panics on an invalid point before solving reaches any constraint.
type p256PkFieldUnitCircuit struct {
	Pub     P256PublicKey
	PkField frontend.Variable `gnark:",public"`
}

func (c *p256PkFieldUnitCircuit) Define(api frontend.API) error {
	pkField, err := P256PkFieldFromPubkeyCircuit(api, c.Pub)
	if err != nil {
		return err
	}
	api.AssertIsEqual(pkField, c.PkField)
	return nil
}

// Positive control for the rejection test below: a valid key solves and the
// circuit pk_field matches the native protocol.P256PkField.
func TestP256PkFieldCircuitMatchesNative(t *testing.T) {
	assert := test.NewAssert(t)
	priv := spptest.FixedP256Key(t, 11)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	pkField, err := protocol.P256PkField(compressed)
	if err != nil {
		t.Fatalf("native P256 pk field: %v", err)
	}
	assignment := &p256PkFieldUnitCircuit{
		Pub:     spptest.P256PubkeyAssignment(priv),
		PkField: pkField,
	}

	assert.SolvingSucceeded(&p256PkFieldUnitCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

func TestP256PkFieldCircuitRejectsOffCurvePubkey(t *testing.T) {
	assert := test.NewAssert(t)
	// (1,1) is not on P256 (1 != 1 - 3 + b) and is not the (0,0) infinity
	// encoding AssertIsOnCurve admits. PkField carries the hash these
	// coordinates would produce (yIsOdd=1, xLow=1, xHigh=0), so the on-curve
	// check is the only constraint left to reject.
	xHash := spptest.MustPoseidon(t, 3, []*big.Int{spptest.Fe(1), spptest.Fe(0)})
	pkField := spptest.MustPoseidon(t, 3, []*big.Int{spptest.Fe(1), xHash})
	assignment := &p256PkFieldUnitCircuit{
		Pub: P256PublicKey{
			X: emulated.ValueOf[emulated.P256Fp](1),
			Y: emulated.ValueOf[emulated.P256Fp](1),
		},
		PkField: pkField,
	}

	assert.SolvingFailed(&p256PkFieldUnitCircuit{}, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsOwnerHashPreimageMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].Utxo.Owner = spptest.Fe(12345)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
