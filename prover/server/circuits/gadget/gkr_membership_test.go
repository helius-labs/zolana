package gadget_test

import (
	"bytes"
	"fmt"
	"math/big"
	"math/rand/v2"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	pprof "github.com/google/pprof/profile"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/transcript"
	"zolana/prover/prover-test/spp/protocol"
)

type membershipPath struct {
	Leaf, Index frontend.Variable
	Siblings    [32]frontend.Variable
}

type scatteredMembership struct {
	Paths      []membershipPath
	Root       frontend.Variable `gnark:",public"`
	GKR        bool              `gnark:"-"`
	Transcript string            `gnark:"-"`
}

func (c *scatteredMembership) Define(api frontend.API) error {
	hash := func(left, right frontend.Variable) frontend.Variable {
		return gadget.PoseidonHash(api, []frontend.Variable{left, right})
	}
	if c.GKR {
		name := c.Transcript
		if name == "" {
			name = "POSEIDON2"
		}
		compressor, err := gadget.NewGKRCompressorWithTranscript(api, name)
		if err != nil {
			return err
		}
		hash = compressor.Compress
	}
	for _, path := range c.Paths {
		bits := api.ToBinary(path.Index, 32)
		current := path.Leaf
		for level, sibling := range path.Siblings {
			left := api.Select(bits[level], sibling, current)
			right := api.Select(bits[level], current, sibling)
			current = hash(left, right)
		}
		api.AssertIsEqual(current, c.Root)
	}
	return nil
}

func TestGKRWideTranscriptConstraints(t *testing.T) {
	if os.Getenv("GKR_WIDE_TRANSCRIPT") == "" {
		t.Skip("set GKR_WIDE_TRANSCRIPT for experimental transcript compilation")
	}
	transcript.Register()
	for _, width := range []int{4, 8, 12, 16} {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			name := transcript.NameForWidth(width)
			c := &scatteredMembership{Paths: make([]membershipPath, 4), GKR: true, Transcript: name}
			if err := test.IsSolved(c, scatteredMembershipWitness(t, 4), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			c.Paths = make([]membershipPath, 512)
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("GKR_WIDE_TRANSCRIPT width=%d inputs=512 constraints=%d", width, cs.GetNbConstraints())
		})
		debug.FreeOSMemory()
	}
}

func scatteredMembershipWitness(t *testing.T, n int) *scatteredMembership {
	t.Helper()
	w := &scatteredMembership{Paths: make([]membershipPath, n)}
	rng := rand.New(rand.NewPCG(417, 999))
	leaves := make(map[uint64]*big.Int, n)
	for i := range w.Paths {
		index := uint64(rng.Uint32())
		for leaves[index] != nil {
			index = uint64(rng.Uint32())
		}
		leaf := new(big.Int).SetUint64(rng.Uint64())
		leaves[index] = leaf
		w.Paths[i].Index, w.Paths[i].Leaf = index, leaf
	}
	root, paths, err := protocol.BuildSparseStateTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	w.Root = root
	for i := range w.Paths {
		path := paths[w.Paths[i].Index.(uint64)]
		for j, sibling := range path.PathElements {
			w.Paths[i].Siblings[j] = sibling
		}
	}
	return w
}

func TestScatteredMembershipGKR(t *testing.T) {
	c := &scatteredMembership{Paths: make([]membershipPath, 4), GKR: true}
	w := scatteredMembershipWitness(t, 4)
	if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*scatteredMembership){
		"root":    func(w *scatteredMembership) { w.Root = 1 },
		"leaf":    func(w *scatteredMembership) { w.Paths[0].Leaf = 1 },
		"index":   func(w *scatteredMembership) { w.Paths[1].Index = uint64(13) },
		"sibling": func(w *scatteredMembership) { w.Paths[2].Siblings[7] = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			w := scatteredMembershipWitness(t, 4)
			mutate(w)
			if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("accepted corrupted membership")
			}
		})
	}
}

func TestScatteredMembershipProving(t *testing.T) {
	n, err := strconv.Atoi(os.Getenv("GKR_INPUTS"))
	if err != nil || n < 1 || n > 512 {
		t.Skip("set GKR_INPUTS to 1..512 for the proving experiment")
	}
	t.Logf("go=%s arch=%s gomaxprocs=%d inputs=%d depth=32", runtime.Version(), runtime.GOARCH, runtime.GOMAXPROCS(0), n)
	start := time.Now()
	assignment := scatteredMembershipWitness(t, n)
	t.Logf("MEMBERSHIP_WITNESS inputs=%d build_ms=%d", n, time.Since(start).Milliseconds())
	for _, accelerated := range []bool{false, true} {
		t.Run(fmt.Sprintf("gkr=%t", accelerated), func(t *testing.T) {
			start := time.Now()
			c := &scatteredMembership{Paths: make([]membershipPath, n), GKR: accelerated}
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("MEMBERSHIP_COMPILE inputs=%d gkr=%t constraints=%d compile_ms=%d", n, accelerated, cs.GetNbConstraints(), time.Since(start).Milliseconds())
			if os.Getenv("GKR_COMPILE_ONLY") != "" {
				return
			}
			start = time.Now()
			pk, vk, err := groth16.Setup(cs)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("MEMBERSHIP_SETUP inputs=%d gkr=%t setup_ms=%d", n, accelerated, time.Since(start).Milliseconds())
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			public, err := witness.Public()
			if err != nil {
				t.Fatal(err)
			}
			for trial := range 3 {
				start := time.Now()
				proof, err := groth16.Prove(cs, pk, witness)
				elapsed := time.Since(start)
				if err != nil {
					t.Fatal(err)
				}
				start = time.Now()
				if err := groth16.Verify(proof, vk, public); err != nil {
					t.Fatal(err)
				}
				verification := time.Since(start)
				var encoded bytes.Buffer
				if _, err := proof.WriteTo(&encoded); err != nil {
					t.Fatal(err)
				}
				var memory runtime.MemStats
				runtime.ReadMemStats(&memory)
				t.Logf("MEMBERSHIP_PROVE inputs=%d gkr=%t trial=%d prove_ms=%.3f verify_ms=%.3f proof_bytes=%d heap_bytes=%d", n, accelerated, trial, float64(elapsed.Microseconds())/1000, float64(verification.Microseconds())/1000, encoded.Len(), memory.HeapAlloc)
				bad := &scatteredMembership{Root: 1, Paths: assignment.Paths}
				badPublic, err := frontend.NewWitness(bad, ecc.BN254.ScalarField(), frontend.PublicOnly())
				if err != nil {
					t.Fatal(err)
				}
				if err := groth16.Verify(proof, vk, badPublic); err == nil {
					t.Fatal("proof verified against an incorrect public root")
				}
			}
		})
		debug.FreeOSMemory()
	}
}

func TestGKRTranscriptConstraints(t *testing.T) {
	path := os.Getenv("GKR_CONSTRAINT_PROFILE")
	if path == "" {
		t.Skip("set GKR_CONSTRAINT_PROFILE to a pprof output path")
	}
	p := profile.Start(profile.WithPath(path))
	c := &scatteredMembership{Paths: make([]membershipPath, 512), GKR: true}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
	p.Stop()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	parsed, err := pprof.Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	transcript := int64(0)
	for _, sample := range parsed.Sample {
		found := false
		for _, location := range sample.Location {
			for _, line := range location.Line {
				if strings.Contains(line.Function.Filename, "std/permutation/poseidon2/") {
					found = true
				}
			}
		}
		if found {
			transcript += sample.Value[0]
		}
	}
	t.Logf("GKR_CONSTRAINT_PROFILE inputs=512 total=%d transcript_poseidon2=%d remainder=%d", cs.GetNbConstraints(), transcript, int64(cs.GetNbConstraints())-transcript)
}
