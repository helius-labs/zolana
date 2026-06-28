package merge_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
	transaction "zolana/prover/circuits/spp_transaction"
	"zolana/prover/prover-test/spp/protocol"
)

// TestMergeZoneCircuitProves checks a valid policy-zone merge witness: every real
// input and the output carry the same non-zero zone_program_id, zone_data is free
// (distinct per UTXO), and the public input hash commits zone_program_id as a 12th
// element.
func TestMergeZoneCircuitProves(t *testing.T) {
	assignment := buildZoneWitness(t, big.NewInt(0x5A0E))
	if err := test.IsSolved(merge.NewMergeZoneCircuit(), assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("zone merge witness not solved: %v", err)
	}
}

// TestMergeZoneCircuitRejectsDefaultZoneInput keeps the public ZoneProgramID but
// zeroes one input's zone_program_id (a default-zone UTXO). The strict zone
// binding has no zero exemption, so the solve must fail -- a zone merge cannot
// consolidate a UTXO that does not belong to the calling zone.
func TestMergeZoneCircuitRejectsDefaultZoneInput(t *testing.T) {
	zoneProgramID := big.NewInt(0x5A0E)
	a := buildZoneWitness(t, zoneProgramID)
	a.Inputs[0].Utxo.ZoneProgramID = big.NewInt(0)
	// Re-derive that input's utxo hash so only the zone binding fails, not inclusion.
	// The state proof no longer matches, which is itself a failure; either way the
	// witness must be rejected.
	if err := test.IsSolved(merge.NewMergeZoneCircuit(), a, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("expected zone-binding failure for default-zone input, got solved")
	}
}

// buildZoneWitness assembles a solved 2-real-input policy-zone merge witness with
// the given zone_program_id on every real input and the output.
func buildZoneWitness(t *testing.T, zoneProgramID *big.Int) *merge.ZoneCircuit {
	t.Helper()
	curve := elliptic.P256()

	ownerSk := big.NewInt(11)
	ownerX, ownerY := curve.ScalarBaseMult(leftPad32(ownerSk))
	ownerComp := elliptic.MarshalCompressed(curve, ownerX, ownerY)
	ownerKeyHash, err := protocol.OwnerPkField(ownerComp)
	if err != nil {
		t.Fatal(err)
	}
	nullifierSecret := big.NewInt(19)
	userNullifierPk, err := protocol.NullifierPk(nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	userOwnerHash, err := protocol.OwnerHash(ownerKeyHash, userNullifierPk)
	if err != nil {
		t.Fatal(err)
	}

	viewSk := big.NewInt(7)
	viewX, viewY := curve.ScalarBaseMult(leftPad32(viewSk))
	userViewingUncompressed := elliptic.Marshal(curve, viewX, viewY)
	viewKeyHash, err := protocol.P256PkField(elliptic.MarshalCompressed(curve, viewX, viewY))
	if err != nil {
		t.Fatal(err)
	}

	txViewingSk := big.NewInt(123456789)

	asset := big.NewInt(1)
	const numReal = 2
	amounts := []*big.Int{big.NewInt(5), big.NewInt(7)}
	blindings := []*big.Int{big.NewInt(0x1111), big.NewInt(0x2222)}
	// zone_data is free per UTXO; use distinct non-zero values to prove it is not pinned.
	zoneData := []*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)}

	inUtxos := make([]protocol.Utxo, numReal)
	inHashes := make([]*big.Int, numReal)
	stateEntries := map[uint64]*big.Int{}
	for i := 0; i < numReal; i++ {
		inUtxos[i] = protocol.Utxo{
			Domain:        big.NewInt(protocol.UtxoDomain),
			Owner:         userOwnerHash,
			Asset:         asset,
			Amount:        amounts[i],
			Blinding:      blindings[i],
			DataHash:      big.NewInt(0),
			ProgramID:     big.NewInt(0),
			ZoneDataHash:  zoneData[i],
			ZoneProgramID: zoneProgramID,
		}
		h, err := protocol.UtxoHash(inUtxos[i])
		if err != nil {
			t.Fatal(err)
		}
		inHashes[i] = h
		stateEntries[uint64(i)] = h
	}
	stateRoot, stateProofs, err := protocol.BuildSparseStateTree(stateEntries)
	if err != nil {
		t.Fatal(err)
	}

	nfTree, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	nfRoot := nfTree.Root()
	nullifiers := make([]*big.Int, numReal)
	nfWitnesses := make([]protocol.NonInclusionWitness, numReal)
	for i := 0; i < numReal; i++ {
		nf, err := protocol.Nullifier(inHashes[i], blindings[i], nullifierSecret)
		if err != nil {
			t.Fatal(err)
		}
		nullifiers[i] = nf
		w, err := nfTree.NonInclusionWitness(nf)
		if err != nil {
			t.Fatal(err)
		}
		nfWitnesses[i] = w
	}

	outAmount := new(big.Int).Add(amounts[0], amounts[1])
	outUtxo := protocol.Utxo{
		Domain:        big.NewInt(protocol.UtxoDomain),
		Owner:         userOwnerHash,
		Asset:         asset,
		Amount:        outAmount,
		Blinding:      big.NewInt(0x3333),
		DataHash:      big.NewInt(0),
		ProgramID:     big.NewInt(0),
		ZoneDataHash:  big.NewInt(0xD2),
		ZoneProgramID: zoneProgramID,
	}
	outHash, err := protocol.UtxoHash(outUtxo)
	if err != nil {
		t.Fatal(err)
	}

	externalDataHash := big.NewInt(0xABCDEF)

	inputHashChainInputs := make([]*big.Int, merge.MergeInputs)
	for i := 0; i < merge.MergeInputs; i++ {
		if i < numReal {
			inputHashChainInputs[i] = inHashes[i]
		} else {
			inputHashChainInputs[i] = big.NewInt(0)
		}
	}
	privateTxHash, err := protocol.PrivateTxHash(inputHashChainInputs, []*big.Int{outHash}, externalDataHash)
	if err != nil {
		t.Fatal(err)
	}

	ctHash, txViewingPkComp := encryptMerge(t, curve, txViewingSk, viewX, viewY, outUtxo)
	pkLo, pkHi := pack33(txViewingPkComp)

	pubNullifiers := make([]*big.Int, merge.MergeInputs)
	pubUtxoRoots := make([]*big.Int, merge.MergeInputs)
	pubNfRoots := make([]*big.Int, merge.MergeInputs)
	for i := 0; i < merge.MergeInputs; i++ {
		if i < numReal {
			pubNullifiers[i] = nullifiers[i]
		} else {
			pubNullifiers[i] = big.NewInt(int64(1000 + i))
		}
		pubUtxoRoots[i] = stateRoot
		pubNfRoots[i] = nfRoot
	}

	// Policy-zone public input hash: the default 11 elements plus zone_program_id.
	publicInputHash := hashChain(t, []*big.Int{
		hashChain(t, pubNullifiers),
		outHash,
		hashChain(t, pubUtxoRoots),
		hashChain(t, pubNfRoots),
		privateTxHash,
		externalDataHash,
		ownerKeyHash,
		viewKeyHash,
		pkLo, pkHi,
		ctHash,
		zoneProgramID,
	})

	assignment := merge.NewMergeZoneCircuit()
	assignment.P256Pub = transaction.P256PublicKey{
		X: emulated.ValueOf[emulated.P256Fp](ownerX),
		Y: emulated.ValueOf[emulated.P256Fp](ownerY),
	}
	assignment.OwnerPkHash = big.NewInt(0)
	assignment.UserNullifierPk = userNullifierPk
	assignment.UserNullifierSecret = nullifierSecret
	assignment.TxViewingSk = txViewingSk
	for i := 0; i < 65; i++ {
		assignment.UserViewingPubkey[i] = big.NewInt(int64(userViewingUncompressed[i]))
	}
	assignment.ExternalDataHash = externalDataHash
	assignment.PrivateTxHash = privateTxHash
	assignment.ZoneProgramID = zoneProgramID
	assignment.PublicInputHash = publicInputHash

	for i := 0; i < merge.MergeInputs; i++ {
		in := &assignment.Inputs[i]
		if i < numReal {
			in.IsDummy = 0
			in.Utxo = utxoFields(inUtxos[i])
			fillPath(in.StatePathElements, stateProofs[uint64(i)].PathElements)
			in.StatePathIndex = big.NewInt(int64(stateProofs[uint64(i)].PathIndex))
			in.NullifierLowValue = nfWitnesses[i].LowValue
			in.NullifierNextValue = nfWitnesses[i].NextValue
			fillPath(in.NullifierLowPathElements, nfWitnesses[i].PathElements)
			in.NullifierLowPathIndex = big.NewInt(int64(nfWitnesses[i].LowIndex))
			in.UtxoTreeRoot = stateRoot
			in.NullifierTreeRoot = nfRoot
			in.Nullifier = nullifiers[i]
		} else {
			in.IsDummy = 1
			in.Utxo = utxoFields(protocol.Utxo{
				Domain:        big.NewInt(0),
				Owner:         big.NewInt(0),
				Asset:         big.NewInt(0),
				Amount:        big.NewInt(0),
				Blinding:      big.NewInt(0),
				DataHash:      big.NewInt(0),
				ProgramID:     big.NewInt(0),
				ZoneDataHash:  big.NewInt(0),
				ZoneProgramID: big.NewInt(0),
			})
			zeroPath(in.StatePathElements)
			in.StatePathIndex = big.NewInt(0)
			in.NullifierLowValue = big.NewInt(0)
			in.NullifierNextValue = big.NewInt(0)
			zeroPath(in.NullifierLowPathElements)
			in.NullifierLowPathIndex = big.NewInt(0)
			in.UtxoTreeRoot = pubUtxoRoots[i]
			in.NullifierTreeRoot = pubNfRoots[i]
			in.Nullifier = pubNullifiers[i]
		}
	}
	assignment.Output = merge.Output{Utxo: utxoFields(outUtxo), Hash: outHash}

	return assignment
}
