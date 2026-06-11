package transaction

import (
	"math/big"
	"testing"

	"light/light-prover/prover/poseidon"
	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
)

func TestCircuitRejectsBadNullifierRange(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.Inputs[0].NullifierLowValue = assignment.Inputs[0].Nullifier

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsBadNullifierSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assignment := buildCircuitAssignment(t, shape)
	assignment.NullifierSecret = spptest.Fe(998)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

func TestCircuitRejectsDuplicateInputWithinTransaction(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(shape)
	assetID := spptest.Fe(7)
	input := sampleUtxoWithAssetAndAmount(10, assetID, spptest.Fe(100))
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{input, input},
		[]protocol.Utxo{
			sampleUtxoWithAssetAndAmount(100, assetID, spptest.Fe(125)),
			sampleUtxoWithAssetAndAmount(110, assetID, spptest.Fe(75)),
		},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)

	// Spending the same UTXO twice yields equal nullifiers; assertDistinctNullifiers
	// rejects it in-circuit so its amount can't be counted twice in the balance.
	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// Output binding: the public Nullifier must equal the in-circuit
// canonicalTruncate248 of the Poseidon image. Two substituted witnesses must
// fail — the untruncated full image, and the low 248 bits of the alias full+p.
//
// NOTE: this only pins the OUTPUT (Nullifier == computed), and both cases fail
// on that equality. It does NOT exercise the canonical (< p) decomposition that
// blocks the double-spend alias, because the in-circuit bits come from gnark's
// honest nBits hint (always canonical) regardless of the substituted witness.
// The < p soundness is pinned by TestCanonicalTruncate248RejectsAliasBits, which
// overrides the hint to force the non-canonical x+p bits.
func TestCircuitRejectsNonCanonicalNullifierWitness(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(shape)

	inputUtxos, _ := defaultBalancedUtxos(t, shape)
	inputHash := spptest.MustUtxoHash(t, inputUtxos[0])
	full, err := poseidon.HashWithT(4, []*big.Int{inputHash, inputUtxos[0].Blinding, spptest.Fe(99)})
	if err != nil {
		t.Fatal(err)
	}
	if full.BitLen() <= 248 {
		// The fixture's full image happens to fit 248 bits, which would make
		// the untruncated case vacuous. Deterministic fixtures make this a
		// stable property — fail loudly so the fixture gets adjusted.
		t.Fatal("fixture nullifier image fits 248 bits; pick a different fixture")
	}

	untruncated := buildCircuitAssignment(t, shape)
	untruncated.Inputs[0].Nullifier = new(big.Int).Set(full)
	assert.SolvingFailed(circuit, untruncated, test.WithCurves(ecc.BN254))

	alias := buildCircuitAssignment(t, shape)
	aliasFull := new(big.Int).Add(full, poseidon.Modulus)
	alias.Inputs[0].Nullifier = protocol.Truncate248(aliasFull)
	assert.SolvingFailed(circuit, alias, test.WithCurves(ecc.BN254))
}

// truncate248Circuit exercises ONLY canonicalTruncate248, so a bit-decomposition
// hint override targets exactly its full-width ToBinary (the < p modulus check).
// The full transact circuit has many ToBinary calls; a global hint override
// would corrupt unrelated ones.
type truncate248Circuit struct {
	X         frontend.Variable
	Truncated frontend.Variable `gnark:",public"`
}

func (c *truncate248Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(canonicalTruncate248(api, c.X), c.Truncated)
	return nil
}

// TestCanonicalTruncate248RejectsAliasBits is the genuine pin for the spec's
// double-spend negative vector (spec.md:506): canonicalTruncate248 must reject
// the non-canonical bit decomposition of x+p.
//
// It overrides gnark's nBits hint to emit the bits of x+p (≡ x mod p but ≥ p) —
// the only way to feed non-canonical bits, since the honest hint always returns
// canonical bits regardless of the witness. The witness Truncated is set to the
// alias truncation Truncate248(x+p), so the recomposition (x+p ≡ x mod p) and
// the output equality both hold; the SOLE remaining constraint that can reject
// is the full-width ToBinary's < p modulus check. So:
//   - with the check (current canonicalTruncate248): x+p ≥ p fails it -> SolvingFailed.
//   - without it (e.g. bits.OmitModulusCheck): the alias bits are accepted and
//     the circuit solves -> this assertion fails, catching the regression.
func TestCanonicalTruncate248RejectsAliasBits(t *testing.T) {
	assert := test.NewAssert(t)

	// A 248-bit value: x+p stays below 2^254 so the alias is representable in the
	// 254-bit decomposition (for x near the modulus, x+p would overflow 254 bits
	// and the alias attack could not be encoded at all).
	x := new(big.Int).Lsh(big.NewInt(0x9abcdef), 220)
	if x.BitLen() > 252 {
		t.Fatalf("x must stay below ~2^252 so x+p fits 254 bits, got %d bits", x.BitLen())
	}
	aliasTruncated := protocol.Truncate248(new(big.Int).Add(x, poseidon.Modulus))
	if aliasTruncated.Cmp(protocol.Truncate248(x)) == 0 {
		t.Fatal("alias truncation must differ from the canonical truncation")
	}

	// nBits is GetHints()[1] (order: ithBit, nBits, nTrits). Force its bits to be
	// those of value+p instead of value.
	nBitsID := solver.GetHintID(gnarkbits.GetHints()[1])
	aliasBitsHint := func(field *big.Int, inputs []*big.Int, outputs []*big.Int) error {
		vp := new(big.Int).Add(inputs[0], field)
		for i := range outputs {
			outputs[i].SetUint64(uint64(vp.Bit(i)))
		}
		return nil
	}

	assignment := &truncate248Circuit{X: x, Truncated: aliasTruncated}
	assert.SolvingFailed(
		&truncate248Circuit{},
		assignment,
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.OverrideHint(nBitsID, aliasBitsHint)),
	)
}
