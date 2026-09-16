package directspend_test

import (
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	direct "zolana/prover/circuits/direct_spend"
	"zolana/prover/circuits/gadget"
	merge "zolana/prover/circuits/spp_merge"
	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover-test/spp/protocol"
)

// Experimental full payment statement: one private nullifier predecessor,
// optionally one complete private state subtree. No deployment/key changes.
type compactPayment struct {
	*direct.PaymentCircuit
	Subtree           bool `gnark:"-"`
	ClusterSize       int  `gnark:"-"`
	ExternalAdmission bool `gnark:"-"`
}

func newCompactPayment(n int, subtree bool) *compactPayment {
	c := &compactPayment{PaymentCircuit: direct.NewPayment(n, 1), Subtree: subtree}
	c.Freshness.Witnesses = c.Freshness.Witnesses[:1]
	if subtree {
		c.setClusters(n)
	}
	return c
}

func (c *compactPayment) setClusters(size int) {
	if size <= 0 || size&(size-1) != 0 || len(c.Certificate.Notes)%size != 0 {
		panic("invalid complete subtree shape")
	}
	c.Subtree, c.ClusterSize = true, size
	for i := range c.Certificate.Notes {
		c.Certificate.Notes[i].Path = nil
		if i%size == 0 {
			c.Certificate.Notes[i].Path = make([]frontend.Variable, 32-bits.TrailingZeros(uint(size)))
		}
	}
}

func (c *compactPayment) Define(api frontend.API) error {
	p, f, b := &c.Certificate, &c.Freshness, &c.Balance
	certFields := []frontend.Variable{direct.CertificateDomain, p.ID, p.TreeID, p.StateRoot, p.Owner, p.Count, gadget.HashChain4(api, p.Nullifiers), p.ValueCommitment}
	freshFields := []frontend.Variable{direct.FreshnessDomain, f.TreeID, f.Root, f.Count, certFields[6]}
	values, outputs := []frontend.Variable{}, []frontend.Variable{}
	for _, v := range b.Values {
		values = append(values, v.ID, v.Commitment)
	}
	for _, o := range b.Outputs {
		outputs = append(outputs, o.Hash, o.OwnerKey)
	}
	balanceFields := []frontend.Variable{direct.BalanceDomain, b.Intent, b.OutputTreeID, gadget.HashChain4(api, values), gadget.HashChain4(api, outputs)}
	if c.Subtree {
		c.constrainSubtree(api)
	} else if err := (&direct.CertificateCircuit{Certificate: *p, PublicInputHash: gadget.HashChain4(api, certFields)}).Define(api); err != nil {
		return err
	}
	if err := (&direct.BalanceCircuit{Balance: *b, PublicInputHash: gadget.HashChain4(api, balanceFields)}).Define(api); err != nil {
		return err
	}
	api.AssertIsEqual(p.TreeID, f.TreeID)
	api.AssertIsEqual(p.Count, f.Count)
	api.AssertIsEqual(p.Asset, b.Asset)
	api.AssertIsEqual(p.ID, b.Values[0].ID)
	api.AssertIsEqual(p.ValueCommitment, b.Values[0].Commitment)
	for i, nf := range p.Nullifiers {
		api.AssertIsEqual(nf, f.Nullifiers[i])
	}
	if !c.ExternalAdmission {
		w := f.Witnesses[0]
		root := abstractor.Call(api, gadget.MerkleRootGadget{
			Hash: gadget.IndexedLeafHash(api, w.Low, w.Next), Index: api.ToBinary(w.Index, 40), Path: w.Path, Height: 40,
		})
		api.AssertIsEqual(root, f.Root)
		gadget.AssertIsLessFullField(api, w.Low, w.Next)
		span := gadget.CanonicalLimbs(api, api.Sub(w.Next, w.Low))
		for _, nf := range p.Nullifiers {
			active := api.Sub(1, api.IsZero(nf))
			delta := api.Sub(nf, w.Low)
			api.AssertIsEqual(api.Mul(active, api.IsZero(delta)), 0)
			api.AssertIsEqual(api.Mul(active, api.Sub(1, gadget.IsLessLimbs(api, gadget.CanonicalLimbs(api, delta), span))), 0)
		}
	}
	fields := append([]frontend.Variable{direct.PaymentDomain}, certFields...)
	fields = append(fields, freshFields...)
	fields = append(fields, balanceFields...)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, fields))
	return nil
}

func (c *compactPayment) constrainSubtree(api frontend.API) {
	p := &c.Certificate
	api.ToBinary(p.TreeID, 16)
	api.AssertIsDifferent(p.Asset, 0)
	api.AssertIsEqual(p.Count, len(p.Notes))
	owner := gadget.PoseidonHash(api, []frontend.Variable{p.Owner, gadget.PoseidonHash(api, []frontend.Variable{p.NullifierSecret})})
	total := frontend.Variable(0)
	depth := bits.TrailingZeros(uint(c.ClusterSize))
	for start := 0; start < len(p.Notes); start += c.ClusterSize {
		baseBits := api.ToBinary(p.Notes[start].Index, 32)
		for _, bit := range baseBits[:depth] {
			api.AssertIsEqual(bit, 0)
		}
		hashes := make([]frontend.Variable, c.ClusterSize)
		for i, note := range p.Notes[start : start+c.ClusterSize] {
			api.AssertIsEqual(note.Index, api.Add(p.Notes[start].Index, i))
			api.ToBinary(note.Amount, 64)
			total = api.Add(total, note.Amount)
			hashes[i] = transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
				Domain: transaction.UtxoDomain, Owner: owner, Asset: p.Asset, Amount: note.Amount,
				Blinding: note.Blinding, DataHash: 0, RingDataHash: 0, RingProgramID: 0,
			}, p.TreeID)
			nf := abstractor.Call(api, transaction.NullifierGadget{UtxoHash: hashes[i], Blinding: note.Blinding, NullifierSecret: p.NullifierSecret})
			api.AssertIsEqual(nf, p.Nullifiers[start+i])
			api.AssertIsDifferent(nf, 0)
		}
		for len(hashes) > 1 {
			parents := make([]frontend.Variable, len(hashes)/2)
			for i := range parents {
				parents[i] = gadget.PoseidonHash(api, hashes[2*i:2*i+2])
			}
			hashes = parents
		}
		root := abstractor.Call(api, gadget.MerkleRootGadget{
			Hash: hashes[0], Index: baseBits[depth:], Path: p.Notes[start].Path, Height: 32 - depth,
		})
		api.AssertIsEqual(root, p.StateRoot)
	}
	api.AssertIsEqual(p.ValueCommitment, gadget.PoseidonHash(api, []frontend.Variable{direct.ValueDomain, p.ID, p.Asset, total, p.ValueRandomness}))
}

func compactWitness(t *testing.T, n int, subtree bool) *compactPayment {
	w := payment(t, n, n)
	w.Freshness.Witnesses = w.Freshness.Witnesses[:1]
	if subtree {
		path := w.Certificate.Notes[0].Path[bits.TrailingZeros(uint(n)):]
		for i := range w.Certificate.Notes {
			w.Certificate.Notes[i].Path = nil
		}
		w.Certificate.Notes[0].Path = path
	}
	return &compactPayment{PaymentCircuit: w, Subtree: subtree, ClusterSize: n}
}

func TestCompactClusters(t *testing.T) {
	w := compactWitness(t, 8, false)
	c := newCompactPayment(8, false)
	c.setClusters(4)
	w.Subtree, w.ClusterSize = true, 4
	leaves := make(map[uint64]*big.Int)
	owner := hash(t, w.Certificate.Owner, hash(t, w.Certificate.NullifierSecret))
	for i := range w.Certificate.Notes {
		index := i
		if i >= 4 {
			index += 1020
		}
		note := &w.Certificate.Notes[i]
		note.Index = index
		leaves[uint64(index)] = hash(t, transaction.UtxoDomain, w.Certificate.TreeID, w.Certificate.Asset, note.Amount, 0, hash(t, 0, 0), hash(t, owner, note.Blinding))
	}
	root, paths, err := protocol.BuildSparseStateTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	w.Certificate.StateRoot = root
	for i := range w.Certificate.Notes {
		if i%4 == 0 {
			w.Certificate.Notes[i].Path = variables(paths[uint64(w.Certificate.Notes[i].Index.(int))].PathElements[2:])
		} else {
			w.Certificate.Notes[i].Path = nil
		}
	}
	bindPayment(t, w.PaymentCircuit)
	if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	w.Certificate.Notes[4].Index = 8
	if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted a moved cluster")
	}
}

func TestCompactClusterConstraints(t *testing.T) {
	if os.Getenv("COMPACT_CONSTRAINT_BENCH") == "" {
		t.Skip("set COMPACT_CONSTRAINT_BENCH=1")
	}
	for _, size := range []int{8, 16, 32} {
		c := newCompactPayment(512, false)
		c.setClusters(size)
		c.ExternalAdmission, c.Freshness.Witnesses = true, nil
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("CLUSTER_BENCH inputs=512 outputs=1 cluster_size=%d constraints=%d fft_domain=%d", size, cs.GetNbConstraints(), uint64(1)<<bits.Len64(uint64(cs.GetNbConstraints()-1)))
		runtime.GC()
	}
}

func TestCompactPaymentWitness(t *testing.T) {
	for _, subtree := range []bool{false, true} {
		c := newCompactPayment(4, subtree)
		w := compactWitness(t, 4, subtree)
		if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
		for _, mutate := range []func(*compactPayment){
			func(w *compactPayment) { w.Certificate.StateRoot = 1 },
			func(w *compactPayment) { w.Freshness.Witnesses[0].Low = w.Freshness.Nullifiers[2] },
			func(w *compactPayment) { w.Certificate.Notes[1].Amount = 11 },
			func(w *compactPayment) { w.Balance.Outputs[0].OwnerKey = 99 },
			func(w *compactPayment) { w.Certificate.Notes[0].Index = 1 },
		} {
			w := compactWitness(t, 4, subtree)
			mutate(w)
			bindPayment(t, w.PaymentCircuit)
			if err := test.IsSolved(c, w, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("accepted invalid compact payment")
			}
		}
	}
}

func TestCompactPaymentConstraints(t *testing.T) {
	if os.Getenv("COMPACT_CONSTRAINT_BENCH") == "" {
		t.Skip("set COMPACT_CONSTRAINT_BENCH=1")
	}
	for _, n := range []int{36, 144, 512} {
		shapes := []struct {
			name string
			c    frontend.Circuit
		}{
			{"payment", direct.NewPayment(n, 1)},
			{"shared_predecessor", newCompactPayment(n, false)},
		}
		if n&(n-1) == 0 {
			shapes = append(shapes, struct {
				name string
				c    frontend.Circuit
			}{"subtree_shared_predecessor", newCompactPayment(n, true)})
			admitted := newCompactPayment(n, true)
			admitted.ExternalAdmission = true
			admitted.Freshness.Witnesses = nil
			shapes = append(shapes, struct {
				name string
				c    frontend.Circuit
			}{"subtree_external_admission", admitted})
		}
		if n == 36 {
			shapes = append(shapes, struct {
				name string
				c    frontend.Circuit
			}{"merge", merge.NewMergeCircuit(36)})
		}
		for _, shape := range shapes {
			t.Run(fmt.Sprintf("%s/%d", shape.name, n), func(t *testing.T) {
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, shape.c, frontend.WithCompressThreshold(300))
				if err != nil {
					t.Fatal(err)
				}
				constraints := cs.GetNbConstraints()
				domain := uint64(1) << bits.Len64(uint64(constraints-1))
				t.Logf("COMPACT_BENCH shape=%s inputs=%d constraints=%d fft_domain=%d", shape.name, n, constraints, domain)
			})
			runtime.GC()
		}
	}
}

func TestCompactPaymentProving(t *testing.T) {
	if os.Getenv("COMPACT_PROVING_BENCH") == "" {
		t.Skip("set COMPACT_PROVING_BENCH=1")
	}
	const n = 32
	t.Logf("go=%s arch=%s cpus=%d gomaxprocs=%d", runtime.Version(), runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0))
	for _, mode := range []string{"original", "shared_predecessor", "subtree_shared_predecessor", "subtree_external_admission"} {
		t.Run(mode, func(t *testing.T) {
			var circuit, assignment frontend.Circuit
			if mode == "original" {
				circuit, assignment = direct.NewPayment(n, 1), payment(t, n, n)
			} else {
				subtree := mode != "shared_predecessor"
				c, w := newCompactPayment(n, subtree), compactWitness(t, n, subtree)
				if mode == "subtree_external_admission" {
					c.ExternalAdmission, w.ExternalAdmission = true, true
					c.Freshness.Witnesses, w.Freshness.Witnesses = nil, nil
				}
				circuit, assignment = c, w
			}
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			pk, vk, err := groth16.Setup(ccs)
			if err != nil {
				t.Fatal(err)
			}
			provePayment(t, mode, n, 1, ccs, pk, vk, assignment)
		})
		runtime.GC()
	}
}
