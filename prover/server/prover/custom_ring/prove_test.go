package custom_ring

import (
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Every accepted fixture proves under its installed key, and only for its own statement.
func TestGoldenRequestsProveWithTheInstalledKeys(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if goldenUnsolved[filepath.Base(file)] {
			continue
		}
		t.Run(filepath.Base(file), func(t *testing.T) {
			payload, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			meta, err := common.ParseProofRequestMeta(payload)
			if err != nil {
				t.Fatal(err)
			}
			ps := loadRingSystem(t, meta.CircuitType)
			assignment := goldenAssignment(t, meta.CircuitType, payload)
			proof, err := Prove(ps, assignment, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyProof(ps, proof, assignment); err != nil {
				t.Fatal(err)
			}
			if verifyProof(ps, proof, withPublicInputHash(assignment, big.NewInt(1))) == nil {
				t.Fatal("proof admitted under a different statement")
			}
		})
	}
}

// withPublicInputHash replaces the one public input, wherever the circuit nests it.
func withPublicInputHash(assignment frontend.Circuit, value *big.Int) frontend.Circuit {
	copied := reflect.New(reflect.TypeOf(assignment).Elem())
	copied.Elem().Set(reflect.ValueOf(assignment).Elem())
	target := copied.Elem()
	for !target.FieldByName("PublicInputHash").IsValid() {
		target = target.Field(0)
	}
	target.FieldByName("PublicInputHash").Set(reflect.ValueOf(frontend.Variable(value)))
	return copied.Interface().(frontend.Circuit)
}

func TestDelegateProofDoesNotVerifyOnTheMemberRail(t *testing.T) {
	payload, err := os.ReadFile("testdata/custom-ring-delegate-policy.json")
	if err != nil {
		t.Fatal(err)
	}
	ps := loadRingSystem(t, common.CustomRingDelegatePolicyCircuitType)
	member := loadRingSystem(t, common.CustomRingPolicyCircuitType)
	assignment := goldenAssignment(t, common.CustomRingDelegatePolicyCircuitType, payload)
	proof, err := Prove(ps, assignment, nil)
	if err != nil {
		t.Fatal(err)
	}
	if verifyProof(member, proof, assignment) == nil {
		t.Fatal("a delegate proof verified on the member rail")
	}
}

func TestCompressedProofResetsExpiredCountersWithoutTheirOpening(t *testing.T) {
	unknownCounters := func(p *PolicyParams) {
		p.Record.Version = 3
		p.Record.Commitment = fb(proofCounters(t, big.NewInt(71), p.Velocity[0].Asset.Int, p.Velocity[0].Cap.Int))
	}
	ps := loadRingSystem(t, common.CustomRingCompressedPolicyCircuitType)
	expired := compressedProofParameters(t, func(p *PolicyParams) {
		unknownCounters(p)
		p.Record.Window--
	})
	assignment := decodeParams(t, common.CustomRingCompressedPolicyCircuitType, expired)
	proof, err := Prove(ps, assignment, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyProof(ps, proof, assignment); err != nil {
		t.Fatal(err)
	}

	expired.Policy.WindowIndex = expired.Policy.Record.Window
	bindRulesFreeStatement(t, &expired.Policy, compressedDisclosure(t, expired))
	stale := decodeParams(t, common.CustomRingCompressedPolicyCircuitType, expired)
	if verifyProof(ps, proof, stale) == nil {
		t.Fatal("proof admitted under the predecessor window")
	}
	if _, err := Prove(ps, stale, nil); err == nil {
		t.Fatal("an expired successor was proven under the predecessor window")
	}
	live := compressedProofParameters(t, unknownCounters)
	if _, err := Prove(ps, decodeParams(t, common.CustomRingCompressedPolicyCircuitType, live), nil); err == nil {
		t.Fatal("a live record was proven without its counter opening")
	}
}

func compressedProofParameters(t *testing.T, configure func(*PolicyParams)) *CompressedPolicyParams {
	t.Helper()
	p := rulesFreeParams(t)
	zero := big.NewInt(0)
	member := p.Inputs[0].OwnerPkHash.Int
	ownerPk, nullifierPk := big.NewInt(0xf1), spptest.MustNullifierPk(t, zero)
	p.NamespaceOwnerHash = fb(spptest.MustOwnerHash(t, ownerPk, nullifierPk))
	p.NIn, p.NOut, p.WindowSlots, p.WindowIndex, p.VelocityCount = 2, 2, 100, 7, 1
	p.AddressChain = fb(spptest.MustNonZeroHashChain(t, spptest.RepeatBigInt(zero, int(p.NIn))))
	p.Velocity[0] = VelocityRow{Asset: p.Inputs[0].Asset, Cap: fi(5000), CosignAbove: fi(2000)}
	p.Record.Window = p.WindowIndex
	p.Record.NextSalt = fi(99)
	p.Record.Commitment = fb(proofCounters(t, p.Record.Salt.Int, zero, zero))
	if configure != nil {
		configure(p)
	}
	nextCommitment := proofCounters(t, p.Record.NextSalt.Int, p.Velocity[0].Asset.Int, p.Inputs[0].Amount.Int)
	seed := spptest.MustPoseidon(t, 3, []*big.Int{policy.SpendAddressDomain, member})
	addressLeaf := spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.AddressDomain), Owner: p.NamespaceOwnerHash.Int,
		Asset: zero, Amount: zero, Blinding: seed, DataHash: zero, RingDataHash: zero, RingProgramID: zero,
	}, p.AddressTreeID.Int)
	address := spptest.MustNullifier(t, addressLeaf, seed, zero)
	opening := func(version uint64, commitment *big.Int, blinding int64) Opening {
		window := p.WindowIndex
		if version == p.Record.Version {
			window = p.Record.Window
		}
		return Opening{
			Domain: fi(protocol.UtxoDomain), TreeID: p.AddressTreeID,
			OwnerPkHash: fb(ownerPk), NullifierPk: fb(nullifierPk), Asset: fb(protocol.SolAsset()), Amount: fi(0),
			Blinding: fi(blinding), RingProgramID: fi(0), RingDataHash: fi(0),
			DataHash: fb(spptest.MustPoseidon(t, 7, []*big.Int{
				policy.SpendRecordDomain, address, member,
				new(big.Int).SetUint64(version), new(big.Int).SetUint64(window), commitment,
			})),
		}
	}
	p.Inputs[1] = opening(p.Record.Version, p.Record.Commitment.Int, 101)
	p.Outputs[1] = OutputOpening{Opening: opening(p.Record.Version+1, nextCommitment, 102)}
	compressed := &CompressedPolicyParams{
		CircuitType: string(common.CustomRingCompressedPolicyCircuitType), Policy: *p, TransactionSalt: make(Bytes, 16),
	}
	bindRulesFreeStatement(t, &compressed.Policy, compressedDisclosure(t, compressed))
	return compressed
}

func proofCounters(t *testing.T, salt, asset, spent *big.Int) *big.Int {
	t.Helper()
	elements := []*big.Int{salt, asset, spent}
	for i := 1; i < policy.NVelocityAssets; i++ {
		elements = append(elements, big.NewInt(0), big.NewInt(0))
	}
	return spptest.MustHashChain(t, elements)
}

func compressedDisclosure(t *testing.T, p *CompressedPolicyParams) *big.Int {
	return (spptest.CounterDisclosure{Secret: [32]byte(p.Policy.TxViewingSk), TransactionSalt: [16]byte(p.TransactionSalt),
		CounterSalt: p.Policy.Record.NextSalt.Int, Assets: []*big.Int{p.Policy.Velocity[0].Asset.Int},
		Spent: []uint64{p.Policy.Inputs[0].Amount.Uint64()}}).Hash(t)
}
