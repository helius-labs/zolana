package transaction_test

import (
	"math/big"
	"testing"
	. "zolana/prover/circuits/spp_transaction"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

// A program-owned value UTXO is a real input/output whose owner equals the public
// program_id (the authenticated CPI caller). It is authorized by the cpi_signer
// out of circuit: no user signature, no owner-hash binding, nullifier_secret 0. It
// may carry program data. User-owned slots may carry none.

// programOwnerID is a stand-in for solana_pk_hash(invoking_program); any non-zero
// field element distinct from the sample owner hashes.
func programOwnerID(t testing.TB) *big.Int {
	return testSolanaPkFieldSeed(t, 0x66)
}

// makeProgramOwnedInput rewrites input idx into a program-owned spend owned by
// programID, optionally carrying programData, then rebuilds the assignment so the
// state/nullifier proofs, private-tx hash, and public-input hash stay consistent.
func makeProgramOwnedInput(t testing.TB, assignment *Circuit, idx int, programID, programData *big.Int) {
	t.Helper()
	in := &assignment.Inputs[idx]
	in.Utxo.Owner = programID
	in.OwnerPkHash = programID
	in.NullifierSecret = spptest.Fe(0)
	in.Utxo.Address = spptest.Fe(0)
	in.Utxo.DataHash = programData
	assignment.ProgramID = programID
	rebuildAfterOwnerChange(t, assignment)
}

// TestProgramOwnedInputSolves: a single program-owned input spends and verifies.
func TestProgramOwnedInputSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestProgramOwnedInputCarriesData: a program-owned input may carry program data.
func TestProgramOwnedInputCarriesData(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0xDA7A))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestProgramOwnedMixedInputs: one user input and one program-owned input in the
// same transaction.
func TestProgramOwnedMixedInputs(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	// input 0 stays user-owned; input 1 becomes program-owned.
	makeProgramOwnedInput(t, assignment, 1, programOwnerID(t), spptest.Fe(0))
	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestProgramOwnedOutputSolves: an output owned by the program carries value and
// program data.
func TestProgramOwnedOutputSolves(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 1}
	solAsset := protocol.SolAsset()
	circuit := MustNewCircuit(Shape(shape))
	programID := programOwnerID(t)

	output := protocol.Utxo{
		Domain:        spptest.Fe(protocol.UtxoDomain),
		Owner:         programID,
		Asset:         solAsset,
		Amount:        spptest.Fe(100),
		Blinding:      spptest.Fe(5),
		DataHash:      spptest.Fe(0xDA7A),
		ProgramID:     spptest.Fe(0),
		ZoneDataHash:  spptest.Fe(0),
		ZoneProgramID: spptest.Fe(0),
	}
	assignment := buildCircuitAssignmentFromUtxos(
		t,
		shape,
		[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
		[]protocol.Utxo{output},
		big.NewInt(0),
		big.NewInt(0),
		spptest.Fe(0),
	)
	assignment.ProgramID = programID
	refreshPublicInputHash(t, assignment)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestProgramOwnedRejectsNonZeroSecret pins nullifier_secret == 0 for a
// program-owned spend (the nullifier is recomputed to match, isolating the pin).
func TestProgramOwnedRejectsNonZeroSecret(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0))

	assignment.Inputs[0].NullifierSecret = spptest.Fe(5)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestProgramOwnedRejectsZeroProgramID: with program_id unset the slot is not
// program-owned, so it falls to the user path and the owner-hash binding fails --
// a program-owned UTXO cannot be spent without an authenticated program.
func TestProgramOwnedRejectsZeroProgramID(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0))

	assignment.ProgramID = spptest.Fe(0)
	refreshPublicInputHash(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestConfidentialProgramOwnedOutputBindsAddress: in the confidential variant a
// program-owned output places its Address in the public OwnerPkHash owner tag and
// the circuit binds OwnerPkHash == Address. A mismatch is rejected.
func TestConfidentialProgramOwnedOutputBindsAddress(t *testing.T) {
	shape := protocol.Shape{NInputs: 1, NOutputs: 1}
	solAsset := protocol.SolAsset()
	programID := programOwnerID(t)
	address := spptest.Fe(0xADD2E55)

	build := func(t testing.TB, ownerTag *big.Int) *Circuit {
		output := protocol.Utxo{
			Domain:        spptest.Fe(protocol.UtxoDomain),
			Owner:         programID,
			Asset:         solAsset,
			Amount:        spptest.Fe(100),
			Blinding:      spptest.Fe(5),
			DataHash:      spptest.Fe(0xDA7A),
			ProgramID:     address, // mirrors UtxoCircuitFields.Address
			ZoneDataHash:  spptest.Fe(0),
			ZoneProgramID: spptest.Fe(0),
		}
		assignment := buildCircuitAssignmentFromUtxos(
			t, shape,
			[]protocol.Utxo{sampleUtxoWithAssetAndAmount(10, solAsset, spptest.Fe(100))},
			[]protocol.Utxo{output},
			big.NewInt(0), big.NewInt(0), spptest.Fe(0),
		)
		assignment.ProgramID = programID
		assignment.Confidential = true
		assignment.P256SigningPkField = spptest.Fe(0)
		assignment.P256MessageHashLow = spptest.Fe(0)
		assignment.P256MessageHashHigh = spptest.Fe(0)
		assignment.Outputs[0].OwnerPkHash = ownerTag
		assignment.Outputs[0].NullifierPk = spptest.Fe(0)
		refreshPublicInputHashVariant(t, assignment, true, false)
		return assignment
	}

	t.Run("binds", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewSolanaConfidentialCircuit(Shape(shape))
		assert.SolvingSucceeded(circuit, build(t, address), test.WithCurves(ecc.BN254))
	})
	t.Run("rejects_wrong_tag", func(t *testing.T) {
		assert := test.NewAssert(t)
		circuit := MustNewSolanaConfidentialCircuit(Shape(shape))
		assert.SolvingFailed(circuit, build(t, spptest.Fe(0xBAD)), test.WithCurves(ecc.BN254))
	})
}

// TestProgramOwnedReusesAddress: a program-owned reuse spend carries a non-zero
// Address (the program-owned address committed in program_hash). It is a free
// witness recomputed into utxo_hash and proven by state-tree inclusion -- the
// circuit does not re-derive it, so it survives program_data updates.
func TestProgramOwnedReusesAddress(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)
	makeProgramOwnedInput(t, assignment, 0, programOwnerID(t), spptest.Fe(0xDA7A))

	assignment.Inputs[0].Utxo.Address = spptest.Fe(0xADD2E55)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestUserInputRejectsProgramData: a user-owned spend may not carry program data.
func TestUserInputRejectsProgramData(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	assignment.Inputs[0].Utxo.DataHash = spptest.Fe(0xDA7A)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestUserInputRejectsAddress: a user-owned spend may not carry a non-zero
// Address; that field is reserved for program-owned UTXOs.
func TestUserInputRejectsAddress(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 1, NOutputs: 2}
	circuit := MustNewCircuit(Shape(shape))
	assignment := buildCircuitAssignment(t, shape)

	assignment.Inputs[0].Utxo.Address = spptest.Fe(0xADD2E55)
	rebuildAfterOwnerChange(t, assignment)

	assert.SolvingFailed(circuit, assignment, test.WithCurves(ecc.BN254))
}

// TestAddressCreateThenReuse: one transaction both creates an address (input 0 is
// an address slot for the derived address) and reuses it (input 1 is a
// program-owned real spend whose Address is that same derived address, carrying
// program data and proven by state-tree inclusion). The two slots stay distinct:
// the create's nullifier is the address; the reuse's is a normal spend nullifier.
func TestAddressCreateThenReuse(t *testing.T) {
	assert := test.NewAssert(t)
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	// Solana-only zone rail: every input is program-owned or an address slot, so no
	// user signature is needed and the P256 gadget is omitted.
	circuit := MustNewSolanaCircuit(Shape(shape))

	programID := programOwnerID(t)
	seed := spptest.Fe(0xABCDEF)
	treePubkey := defaultAddressTreePubkey()
	address := deriveAddress(t, programID, treePubkey, seed)

	assignment := buildAddressCreateThenReuseAssignment(t, shape, programID, seed, address, treePubkey)

	assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}

// buildAddressCreateThenReuseAssignment hand-builds a 2-input zone transaction:
// input 0 is an address slot (dummy, create) and input 1 is a program-owned reuse
// spend whose Address equals the created address. State inclusion covers only the
// real spend; both nullifiers are proven absent from the nullifier tree.
func buildAddressCreateThenReuseAssignment(t testing.TB, shape protocol.Shape, programID, seed, address, treePubkey *big.Int) *Circuit {
	t.Helper()
	solAsset := protocol.SolAsset()

	// The reuse UTXO: program-owned, carries program data and the address.
	reuse := protocol.Utxo{
		Domain:        spptest.Fe(protocol.UtxoDomain),
		Owner:         programID,
		Asset:         solAsset,
		Amount:        spptest.Fe(0),
		Blinding:      spptest.Fe(5),
		DataHash:      spptest.Fe(0xDA7A),
		ProgramID:     address, // protocol.Utxo.ProgramID mirrors UtxoCircuitFields.Address
		ZoneDataHash:  spptest.Fe(0),
		ZoneProgramID: spptest.Fe(0),
	}
	reuseHash := spptest.MustUtxoHash(t, reuse)
	reuseNullifier := spptest.MustNullifier(t, reuseHash, reuse.Blinding, big.NewInt(0))

	// Address slot utxo hash, for the address chain contribution.
	addressUtxo := protocol.Utxo{
		Domain:        spptest.Fe(protocol.UtxoDomain),
		Owner:         programID,
		Asset:         spptest.Fe(0),
		Amount:        spptest.Fe(0),
		Blinding:      spptest.Fe(0),
		DataHash:      seed,
		ProgramID:     address,
		ZoneDataHash:  spptest.Fe(0),
		ZoneProgramID: spptest.Fe(0),
	}
	addressUtxoHash := spptest.MustUtxoHash(t, addressUtxo)

	// State tree contains only the real reuse spend.
	stateRoot, stateProofs := spptest.MustBuildSparseStateTree(t, map[uint64]*big.Int{17: reuseHash})
	reuseProof := stateProofs[17]

	nullifierTree := spptest.MustNewNullifierTree(t)
	addrWitness := spptest.MustNonInclusion(t, nullifierTree, address)
	reuseWitness := spptest.MustNonInclusion(t, nullifierTree, reuseNullifier)
	nfRoot := nullifierTree.Root()

	mkPath := func(n int, elems []*big.Int) []frontend.Variable {
		out := spptest.ZeroVariables(n)
		for i := range elems {
			out[i] = elems[i]
		}
		return out
	}

	// input 0: address slot (dummy).
	in0 := Input{
		Utxo: UtxoCircuitFields{
			Domain: spptest.Fe(protocol.UtxoDomain), Owner: programID, Asset: spptest.Fe(0),
			Amount: spptest.Fe(0), Blinding: spptest.Fe(0), DataHash: seed,
			Address: address, ZoneDataHash: spptest.Fe(0), ZoneProgramID: spptest.Fe(0),
		},
		IsDummy:                  spptest.Fe(1),
		StatePathElements:        spptest.ZeroVariables(protocol.StateTreeHeight),
		StatePathIndex:           spptest.Fe(0),
		NullifierLowValue:        addrWitness.LowValue,
		NullifierNextValue:       addrWitness.NextValue,
		NullifierLowPathElements: mkPath(protocol.NullifierTreeHeight, addrWitness.PathElements),
		NullifierLowPathIndex:    new(big.Int).SetUint64(addrWitness.LowIndex),
		UtxoTreeRoot:             stateRoot,
		NullifierTreeRoot:        nfRoot,
		Nullifier:                address,
		OwnerPkHash:              spptest.Fe(0),
		NullifierSecret:          spptest.Fe(0),
	}
	// input 1: program-owned reuse spend (real).
	in1 := Input{
		Utxo: UtxoCircuitFields{
			Domain: spptest.Fe(protocol.UtxoDomain), Owner: programID, Asset: solAsset,
			Amount: spptest.Fe(0), Blinding: reuse.Blinding, DataHash: reuse.DataHash,
			Address: address, ZoneDataHash: spptest.Fe(0), ZoneProgramID: spptest.Fe(0),
		},
		IsDummy:                  spptest.Fe(0),
		StatePathElements:        mkPath(protocol.StateTreeHeight, reuseProof.PathElements),
		StatePathIndex:           new(big.Int).SetUint64(reuseProof.PathIndex),
		NullifierLowValue:        reuseWitness.LowValue,
		NullifierNextValue:       reuseWitness.NextValue,
		NullifierLowPathElements: mkPath(protocol.NullifierTreeHeight, reuseWitness.PathElements),
		NullifierLowPathIndex:    new(big.Int).SetUint64(reuseWitness.LowIndex),
		UtxoTreeRoot:             stateRoot,
		NullifierTreeRoot:        nfRoot,
		Nullifier:                reuseNullifier,
		OwnerPkHash:              programID,
		NullifierSecret:          spptest.Fe(0),
	}

	// Two empty outputs so the transaction conserves value (0 in, 0 out).
	outUtxos := twoOutputUtxos(sampleUtxoWithAssetAndAmount(100, solAsset, spptest.Fe(0)))
	outputs := make([]Output, shape.NOutputs)
	for i := range outUtxos {
		outputs[i] = Output{
			Utxo:        fieldsFromUtxo(outUtxos[i]),
			IsDummy:     spptest.Fe(0),
			Hash:        spptest.MustUtxoHash(t, outUtxos[i]),
			OwnerPkHash: spptest.Fe(0),
			NullifierPk: spptest.Fe(0),
		}
	}

	p256Pub, p256Sig, err := spptest.UnusedP256Witness(make([]byte, 32))
	if err != nil {
		t.Fatalf("unused P256 witness: %v", err)
	}
	assignment := &Circuit{
		Shape:                  Shape(shape),
		Inputs:                 []Input{in0, in1},
		Outputs:                outputs,
		P256Pub:                p256Pub,
		P256Sig:                p256Sig,
		ExternalDataHash:       spptest.Fe(300),
		PrivateTxHash:          spptest.Fe(0),
		PublicSolAmount:        spptest.Fe(0),
		PublicSplAmount:        spptest.Fe(0),
		PublicSplAssetPubkey:   spptest.Fe(0),
		ProgramID:              programID,
		ZoneProgramID:          spptest.Fe(0),
		PayerPubkeyHash:        testPayerPubkeyHash(),
		AddressTreePubkeyField: treePubkey,
		P256SigningPkField:     spptest.Fe(0),
	}

	// Address chain: only the address slot contributes its utxo hash.
	addressHashes := []*big.Int{addressUtxoHash, big.NewInt(0)}
	inputHashes := []*big.Int{big.NewInt(0), reuseHash}
	outputHashes := spptest.ToBigInts(assignment.OutputHashes())
	privateTxHash := spptest.MustPrivateTxHash(t, inputHashes, outputHashes, addressHashes, spptest.AsBigInt(assignment.ExternalDataHash))
	assignment.PrivateTxHash = privateTxHash
	assignment.P256MessageHashLow = spptest.Fe(0)
	assignment.P256MessageHashHigh = spptest.Fe(0)
	refreshPublicInputHashVariant(t, assignment, false, false)
	return assignment
}
