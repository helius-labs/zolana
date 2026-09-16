package custom_ring

import (
	"math/big"
	"testing"

	"zolana/prover/circuits/custom_ring/base/audittest"
	"zolana/prover/circuits/custom_ring/policy"
	"zolana/prover/prover-test/spp/spptest"
	"zolana/prover/prover/common"
)

// groth16.Prove pins the host nullifier_pk, ct_hash and roots to the circuit's own.
func TestKeyRegisterProofVerifiesEndToEnd(t *testing.T) {
	member := big.NewInt(0xbeef)
	var nullifierSecret [scalarLen]byte
	for i := 1; i < scalarLen; i++ {
		nullifierSecret[i] = byte(0x40 ^ i)
	}
	nullifierPk := spptest.MustNullifierPk(t, new(big.Int).SetBytes(nullifierSecret[:]))
	keys := audittest.DefaultKeys(t)
	sealed := keys.Seal(t, nullifierSecret[:], policy.NfKeyEncInfo)

	genesis := spptest.MustPoseidon(t, 3, []*big.Int{nullifierPk, sealed.CiphertextHash})
	insertion := spptest.NewHeadMap(t, policy.HeadMapHeight).Register(t, member, genesis)
	chain := func(ctHash *big.Int) *big.Int {
		return spptest.MustHashChain(t, []*big.Int{
			insertion.OldRoot, insertion.NewRoot, member, nullifierPk,
			sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, ctHash,
			new(big.Int).SetUint64(insertion.NewIndex),
		})
	}
	params := &KeyRegisterParameters{
		PublicInputHash: chain(sealed.CiphertextHash),
		headInsertion:   fixtureInsertion(insertion, member),
		NullifierSecret: nullifierSecret,
		EphSk:           keys.EphSk(),
		AuditorPk:       keys.AuditorPk(),
	}

	registerSystem := loadRingSystem(t, common.CustomRingKeyRegisterKeyFile)
	var decoded KeyRegisterParameters
	roundTripProofParameters(t, params, &decoded)

	proof, err := Prove(registerSystem, &decoded)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	assignment, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	verifyInstalledProof(t, registerSystem, proof, assignment)

	// A flipped ct_hash moves the sole public input.
	tampered, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	tampered.PublicInputHash = chain(new(big.Int).Add(sealed.CiphertextHash, big.NewInt(1)))
	rejectInstalledProof(t, registerSystem, proof, tampered)
}
