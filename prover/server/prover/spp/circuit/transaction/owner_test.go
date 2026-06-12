package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
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
	assignment.SolanaOwnerPkHash = spptest.Fe(12345)
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

// Soundness guard: the Solana-only variant must reject a P256-owned
// transaction (SolanaOwnerPkHash == 0), since it skips the signature gadget.
// Otherwise a UTXO owned by OwnerHash(0, nullifier_pk) could be spent with no
// signature.
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

// Spec single-owner rule: all non-dummy inputs must share one owner. Mixing a
// P256-owned input with a Solana-owned input in one transaction is rejected.
func TestCircuitRejectsMixedP256AndSolanaInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteInputAsP256(t, assignment, 0, priv, priv)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// The owner key selects the ownership path for the whole proof: non-zero
// forces the Solana path, so a P256-owned transaction carrying a stray
// non-zero SolanaOwnerPkHash cannot bind its inputs' owners.
func TestCircuitRejectsP256OwnerWithNonZeroOwnerKey(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	priv := spptest.FixedP256Key(t, 11)
	rewriteSingleInputAsP256(t, assignment, priv, priv)
	assignment.SolanaOwnerPkHash = testSolanaPkField(t)
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

func TestCircuitRejectsOwnerHashPreimageMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].Utxo.Owner = spptest.Fe(12345)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}
