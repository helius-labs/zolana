package custom_ring

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringdeposit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringmerge"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringpolicy"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// WRITE_RING_GOLDENS=1 rewrites the committed testdata/<circuit>.json fixtures.
func TestWriteGoldenRequests(t *testing.T) {
	if os.Getenv("WRITE_RING_GOLDENS") == "" {
		t.Skip("WRITE_RING_GOLDENS=1 rewrites the request fixtures")
	}
	committed, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[common.CircuitType]string{}
	for _, path := range committed {
		paths[common.CircuitType(strings.TrimSuffix(filepath.Base(path), ".json"))] = path
	}
	writeSolved(t, paths)
}

// REQUEST_FIXTURES=<dir> writes one request per ring key to dir, named after its key file.
func TestWriteRequestFixtures(t *testing.T) {
	dir := os.Getenv("REQUEST_FIXTURES")
	if dir == "" {
		t.Skip("REQUEST_FIXTURES=<dir> writes a request per ring key")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	paths := map[common.CircuitType]string{}
	for _, key := range common.RingKeys {
		paths[key.Circuit] = filepath.Join(dir, strings.TrimSuffix(common.RingKeyFile(key.Circuit), ".key")+".json")
	}
	writeSolved(t, paths)
}

// writeSolved writes each request only once the server's decoding of it solves the compiled key.
func writeSolved(t *testing.T, paths map[common.CircuitType]string) {
	requests := hostRequests(t)
	for circuit, path := range paths {
		t.Run(string(circuit), func(t *testing.T) {
			t.Parallel()
			request, ok := requests[circuit]
			if !ok {
				t.Fatalf("%s names no ring key", path)
			}
			encoded, err := json.MarshalIndent(request, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if meta, err := common.ParseProofRequestMeta(encoded); err != nil || meta.CircuitType != circuit {
				t.Fatalf("%s routes to %q: %v", circuit, meta.CircuitType, err)
			}
			witness, err := frontend.NewWitness(decodePayload(t, circuit, encoded), ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := compileRing(t, circuit).Solve(witness); err != nil {
				t.Fatalf("%s does not solve: %v", circuit, err)
			}
			if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func hostRequests(t testing.TB) map[common.CircuitType]any {
	t.Helper()
	requests := map[common.CircuitType]any{}
	for _, key := range common.RingKeys {
		switch key.Family {
		case common.RingPackedAudit:
			requests[key.Circuit] = requestOf(t, key.Circuit, ringaudit.NewPackedAudit(t, key.Outputs).Circuit(t))
		case common.RingDeliveredAudit:
			requests[key.Circuit] = requestOf(t, key.Circuit, ringaudit.NewDeliveredAudit(t, key.Outputs).Circuit(t))
		case common.RingAnonymousAudit, common.RingAnonymousEntryAudit:
			requests[key.Circuit] = requestOf(t, key.Circuit, ringaudit.NewAnonymousAudit(t, anonymousShape(key)).Circuit(t))
		case common.RingMemberPolicy:
			world, ok := ringpolicy.MemberWorlds[key.Outputs]
			if !ok {
				t.Fatalf("no member world for %d outputs", key.Outputs)
			}
			requests[key.Circuit] = requestOf(t, key.Circuit, world().Build(t).Assignment())
		case common.RingDelegatePolicy:
			shape := shared.Shape{NInputs: key.Inputs, NOutputs: key.Outputs}
			requests[key.Circuit] = requestOf(t, key.Circuit, ringpolicy.Delegate(shape).Build(t).Assignment())
		case common.RingApplyRecords:
			requests[key.Circuit] = applyRequest(t, key, applyEntries(key.Inputs))
		case common.RingRegisterKey:
			requests[key.Circuit] = keyRegisterRequest(t, big.NewInt(0x0b))
		case common.RingDeposit:
			requests[key.Circuit] = requestOf(t, key.Circuit, ringdeposit.Build(t, 2, ringdeposit.ModeRegistry).Circuit)
		case common.RingAnonymousMerge:
			requests[key.Circuit] = requestOf(t, key.Circuit, ringmerge.Build(t, key.Inputs).Circuit)
		}
	}
	return requests
}

// applyEntries inserts members up to the key's capacity, a full batch then rewrites one of them and skips an empty record.
func applyEntries(capacity int) []ringrecords.Entry {
	entry := func(member, mask, escrow int64) ringrecords.Entry {
		return ringrecords.Entry{Member: big.NewInt(member), Mask: big.NewInt(mask), Value: big.NewInt(mask), EscrowKey: big.NewInt(escrow)}
	}
	if capacity == 1 {
		return []ringrecords.Entry{entry(0x100, ringrecords.AllowBit, 0)}
	}
	entries := []ringrecords.Entry{}
	for i := range capacity - 2 {
		entries = append(entries, entry(int64(0x100+i), ringrecords.AllowBit, 0))
	}
	empty := ringrecords.Entry{Member: big.NewInt(0x200), Mask: big.NewInt(ringrecords.AllowBit), Value: big.NewInt(0), EscrowKey: big.NewInt(0)}
	return append(entries, entry(0x100, ringrecords.EscrowBit, 0xe0), empty)
}

// applyRequest starts from a nonzero chain checkpoint, as a queue past its first batch does.
func applyRequest(t testing.TB, key common.RingKey, entries []ringrecords.Entry) *ApplyRecordsParams {
	t.Helper()
	members := ringrecords.New(t)
	p := &ApplyRecordsParams{
		CircuitType: string(key.Circuit), OldRoot: fb(members.Root()), OldNextIndex: uint32(members.NextIndex()),
		ChainStart: fi(0x5eed), Count: uint8(len(entries)), Writes: make([]*RecordWrite, key.Inputs),
	}
	chain := p.ChainStart.Int
	for i, e := range entries {
		w := members.Apply(t, e)
		entry := spptest.MustPoseidon(t, 6, []*big.Int{big.NewInt(base.QueueWriteDomain), e.Member, e.Mask, e.Value, e.EscrowKey})
		chain = spptest.MustPoseidon(t, 3, []*big.Int{chain, entry})
		p.Writes[i] = &RecordWrite{
			Entry:  QueueEntry{Member: fb(e.Member), Mask: e.Mask.Uint64(), Value: e.Value.Uint64(), EscrowKey: fb(e.EscrowKey)},
			Exists: w.Exists, OldNext: fb(w.OldNext), OldLists: w.OldLists.Uint64(), OldEscrow: fb(w.OldEscrow),
			Index: w.Slot.Index, Path: flatPath(w.Slot),
			LowMember: fb(w.Low.Member), LowNext: fb(w.Low.Next), LowLists: w.Low.Lists.Uint64(), LowEscrow: fb(w.Low.EscrowKey),
			LowIndex: w.LowPath.Index, LowPath: flatPath(w.LowPath),
		}
	}
	p.NewRoot, p.NewNextIndex, p.ChainEnd = fb(members.Root()), uint32(members.NextIndex()), fb(chain)
	p.PublicInputHash = fb(spptest.MustHashChain4(t, []*big.Int{
		big.NewInt(base.ApplyRecordsDomain), p.OldRoot.Int, p.NewRoot.Int, big.NewInt(int64(p.OldNextIndex)),
		big.NewInt(int64(p.NewNextIndex)), p.ChainStart.Int, p.ChainEnd.Int, big.NewInt(int64(p.Count)),
	}))
	return p
}

// flatPath lists every level's siblings from the leaf up.
func flatPath(path ringrecords.Path) []Field {
	var flat []Field
	for _, row := range path.Siblings {
		for _, sibling := range row {
			flat = append(flat, fb(sibling))
		}
	}
	return flat
}

func keyRegisterRequest(t testing.TB, member *big.Int) *KeyRegisterParams {
	t.Helper()
	keys := ringaudit.DefaultKeys(t)
	secret := ringaudit.Scalar(0x07)
	secret[0] = 0
	sealed := keys.Seal(t, secret[:], policy.NfKeyEncInfo)
	nullifierPk := spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:]))
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	return &KeyRegisterParams{
		CircuitType: string(common.CustomRingKeyRegisterCircuitType),
		PublicInputHash: fb(spptest.MustHashChain4(t, []*big.Int{
			big.NewInt(base.RegisterKeyDomain), member, nullifierPk,
			sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
		})),
		Member: fb(member), NullifierSecret: secret[:], EphSk: eph[:], AuditorPk: auditor[:],
	}
}

func fi(v int64) Field    { return Field{big.NewInt(v)} }
func fb(v *big.Int) Field { return Field{new(big.Int).Set(v)} }
