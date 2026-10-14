package custom_ring

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base/audittest"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const goldenDigests = "testdata/witness.sha256"

// Every fixture but these is a statement its circuit accepts.
var goldenUnsolved = map[string]bool{"custom-ring-policy-sample.json": true}

// The fixtures are frozen request bytes; a decoder change must assign the
// recorded witness, and UPDATE_RING_GOLDENS=1 rewrites only the digests.
func TestGoldenRequestsAssignTheRecordedWitness(t *testing.T) {
	if os.Getenv("WRITE_RING_GOLDEN_REQUESTS") != "" {
		writeGoldenRequests(t)
	}
	files, err := filepath.Glob("testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	digests := map[string]string{}
	systems := map[common.CircuitType]constraint.ConstraintSystem{}
	for _, file := range files {
		name := filepath.Base(file)
		payload, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := common.ParseProofRequestMeta(payload)
		if err != nil {
			t.Fatal(err)
		}
		assignment := goldenAssignment(t, meta.CircuitType, payload)
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		encoded, err := witness.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		digests[name] = hex.EncodeToString(digest[:])
		if goldenUnsolved[name] {
			continue
		}
		cs := systems[meta.CircuitType]
		if cs == nil {
			cs = compileRing(t, meta.CircuitType)
			systems[meta.CircuitType] = cs
		}
		if _, err := cs.Solve(witness); err != nil {
			t.Errorf("%s does not solve: %v", name, err)
		}
	}
	if os.Getenv("UPDATE_RING_GOLDENS") != "" {
		writeDigests(t, digests)
		return
	}
	want := readDigests(t)
	if len(want) != len(digests) {
		t.Fatalf("%d fixtures against %d digests", len(digests), len(want))
	}
	for name, digest := range digests {
		if want[name] != digest {
			t.Errorf("%s assigns a different witness", name)
		}
	}
}

func goldenAssignment(t *testing.T, circuit common.CircuitType, payload []byte) frontend.Circuit {
	t.Helper()
	request, err := DecodeRequest(circuit, payload)
	if err != nil {
		t.Fatalf("%s: %v", circuit, err)
	}
	assignment, err := request.assignment()
	if err != nil {
		t.Fatalf("%s: %v", circuit, err)
	}
	return assignment
}

func compileRing(t *testing.T, circuit common.CircuitType) constraint.ConstraintSystem {
	t.Helper()
	for _, ring := range RingCircuits {
		if ring.Type == circuit {
			cs, err := ring.R1CS()
			if err != nil {
				t.Fatal(err)
			}
			return cs
		}
	}
	t.Fatalf("unknown circuit %s", circuit)
	return nil
}

func readDigests(t *testing.T) map[string]string {
	t.Helper()
	file, err := os.Open(goldenDigests)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digests := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		digest, name, ok := strings.Cut(scanner.Text(), "  ")
		if !ok {
			t.Fatalf("malformed digest line %q", scanner.Text())
		}
		digests[name] = digest
	}
	return digests
}

func writeDigests(t *testing.T, digests map[string]string) {
	t.Helper()
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	for _, name := range names {
		fmt.Fprintf(&out, "%s  %s\n", digests[name], name)
	}
	if err := os.WriteFile(goldenDigests, []byte(out.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Captures the requests the original encoders wrote.
func writeGoldenRequests(t *testing.T) {
	t.Helper()
	delegate := rulesFreeParams(t)
	delegate.WindowSlots, delegate.VelocityCount = 100, 1
	delegate.Velocity[0] = VelocityRow{Asset: delegate.Inputs[0].Asset, Cap: big.NewInt(1), CosignAbove: big.NewInt(1)}
	keys := spptest.NewKeyRegistry(t, registry.Height)
	delegate.Outputs[0].Key = registryKey(keys, keys.Register(t, delegate.Outputs[0].OwnerPkHash, delegate.Outputs[0].NullifierPk, big.NewInt(0x4b)))
	delegate.KeyEscrow = KeyEscrow{Enabled: true, Root: keys.Root()}
	bindRulesFreeStatement(t, delegate)

	deposit, _ := depositFixture(t, 3)
	escrowDeposits(t, deposit.Params)
	encryptDepositVector(t, deposit.Params)

	fixtures := map[string]any{
		"custom-ring-base.json":              baseParams(t),
		"custom-ring-policy.json":            rulesFreeParams(t),
		"custom-ring-policy-sample.json":     sampleParams(),
		"custom-ring-delegate-policy.json":   &DelegatePolicyParameters{Policy: *delegate},
		"custom-ring-compressed-policy.json": compressedProofParameters(t, nil),
		"custom-ring-register-key.json":      keyRegisterParams(t),
		"custom-ring-deposit.json":           deposit.Params,
	}
	for name, params := range fixtures {
		encoded, err := json.MarshalIndent(params, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join("testdata", name), append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func keyRegisterParams(t *testing.T) *KeyRegisterParameters {
	t.Helper()
	member := big.NewInt(0xbeef)
	var nullifierSecret [scalarLen]byte
	for i := 1; i < scalarLen; i++ {
		nullifierSecret[i] = byte(0x40 ^ i)
	}
	nullifierPk := spptest.MustNullifierPk(t, new(big.Int).SetBytes(nullifierSecret[:]))
	keys := audittest.DefaultKeys(t)
	sealed := keys.Seal(t, nullifierSecret[:], policy.NfKeyEncInfo)
	keyHash := spptest.MustPoseidon(t, 3, []*big.Int{nullifierPk, sealed.CiphertextHash})
	insertion := spptest.NewKeyRegistryTree(t, registry.Height).Register(t, member, keyHash)
	return &KeyRegisterParameters{
		PublicInputHash: spptest.MustHashChain(t, []*big.Int{
			insertion.OldRoot, insertion.NewRoot, member, nullifierPk,
			sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
			new(big.Int).SetUint64(insertion.NewIndex),
		}),
		registryInsertion: fixtureInsertion(insertion, member),
		NullifierSecret:   nullifierSecret,
		EphSk:             keys.EphSk(),
		AuditorPk:         keys.AuditorPk(),
	}
}
