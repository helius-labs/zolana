package base_test

import (
	"encoding/json"
	"math/big"
	"os"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
)

type packDisclosureCircuit struct {
	Bytes  [40]frontend.Variable
	Fields [2]frontend.Variable `gnark:",public"`
}

func (c *packDisclosureCircuit) Define(api frontend.API) error {
	for i, field := range base.PackDisclosure(api, c.Bytes[:]) {
		api.AssertIsEqual(field, c.Fields[i])
	}
	return nil
}

// A 40-byte slot fills one chunk and leaves its last 9 bytes first in the second chunk, the zero padding after them.
func TestPackDisclosureLeftAlignsTheTail(t *testing.T) {
	var raw [40]byte
	witness := &packDisclosureCircuit{}
	for i := range raw {
		raw[i] = byte(0xc0 + i)
		witness.Bytes[i] = raw[i]
	}
	witness.Fields[0] = new(big.Int).SetBytes(raw[:31])
	witness.Fields[1] = new(big.Int).Lsh(new(big.Int).SetBytes(raw[31:]), 8*22)
	if err := test.IsSolved(&packDisclosureCircuit{}, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("left-aligned tail refused: %v", err)
	}
	witness.Fields[1] = new(big.Int).SetBytes(raw[31:])
	if test.IsSolved(&packDisclosureCircuit{}, witness, ecc.BN254.ScalarField()) == nil {
		t.Fatal("right-aligned tail accepted")
	}
}

const fieldCountVector = "ring-disclosure-counts.json"

const fieldCountDescription = "Published field counts of the audit disclosures, one record per layout, each a host disclosure the base circuit solves. " +
	"packed takes the published outputs and the exits, key_escrow and data_free flags, delivered the capacity and the exits and key_escrow flags, " +
	"anonymous the audit key, its input class, the published input count, the output count and the exits flag. " +
	"Produced by prover/server/custom_rings/circuits/base/disclosure_test.go with WRITE_AUDIT_VECTORS=1."

type fieldCounts struct {
	Description string                `json:"description"`
	Packed      []packedFieldCount    `json:"packed"`
	Delivered   []deliveredFieldCount `json:"delivered"`
	Anonymous   []anonymousFieldCount `json:"anonymous"`
}

type packedFieldCount struct {
	Outputs   int  `json:"outputs"`
	Exits     bool `json:"exits"`
	KeyEscrow bool `json:"key_escrow"`
	DataFree  bool `json:"data_free"`
	Fields    int  `json:"fields"`
}

type deliveredFieldCount struct {
	Outputs   int  `json:"outputs"`
	Exits     bool `json:"exits"`
	KeyEscrow bool `json:"key_escrow"`
	Fields    int  `json:"fields"`
}

type anonymousFieldCount struct {
	Key     string `json:"key"`
	Class   int    `json:"class"`
	Inputs  int    `json:"inputs"`
	Outputs int    `json:"outputs"`
	Exits   bool   `json:"exits"`
	Fields  int    `json:"fields"`
}

// The Rust layouts pin the counts of solved host disclosures, WRITE_AUDIT_VECTORS=1 rewrites the file.
func TestDisclosureFieldCountsAreTheSharedVector(t *testing.T) {
	want := fieldCounts{Description: fieldCountDescription}
	packed := compilePacked(t, 4)
	for _, layout := range []ringaudit.Layout{{Exits: true}, {}, {Exits: true, Escrow: true}, {Escrow: true, DataFree: true}} {
		p := ringaudit.PackedAuditOf(t, 4, 3)
		if layout.Exits {
			p = ringaudit.PackedAuditOf(t, 4, 3, 2)
		}
		if layout.DataFree {
			withoutData(&p)
		}
		p.Layout = layout
		packed.requireSolved(t, p.Circuit(t))
		want.Packed = append(want.Packed, packedFieldCount{Outputs: p.NOut, Exits: layout.Exits, KeyEscrow: layout.Escrow, DataFree: layout.DataFree, Fields: len(p.Disclosure(t))})
	}
	for _, capacity := range []int{8, 16} {
		delivered := compileDelivered(t, capacity)
		for _, layout := range []ringaudit.Layout{{Exits: true}, {}, {Exits: true, Escrow: true}, {Escrow: true}} {
			d := ringaudit.DeliveredAuditOf(t, capacity)
			if layout.Exits {
				d = ringaudit.NewDeliveredAudit(t, capacity)
			}
			d.Layout = layout
			delivered.requireSolved(t, d.Circuit(t))
			want.Delivered = append(want.Delivered, deliveredFieldCount{Outputs: capacity, Exits: layout.Exits, KeyEscrow: layout.Escrow, Fields: len(d.Disclosure(t))})
		}
	}
	type anonymousCounts struct {
		shape  base.AnonymousAuditShape
		counts []int
	}
	anonymous := []anonymousCounts{
		{base.AnonymousAuditShape{InputClass: 4, Outputs: 2}, []int{1, 2, 3, 4}},
		{base.AnonymousAuditShape{InputClass: 4, Outputs: 4}, []int{2}},
		{base.AnonymousAuditShape{InputClass: 4, Outputs: 8}, []int{2}},
		{base.AnonymousAuditShape{InputClass: 32, Outputs: 2}, []int{31, 32}},
		{base.AnonymousAuditShape{InputClass: 1, Outputs: 16}, []int{1}},
	}
	for _, shape := range base.AnonymousEntryShapes {
		anonymous = append(anonymous, anonymousCounts{shape, []int{2}})
	}
	for _, tc := range anonymous {
		c := compileAnonymous(t, tc.shape)
		key := "commitment"
		if tc.shape.FullOpenings {
			key = "entry"
		}
		for _, count := range tc.counts {
			a := ringaudit.NewAnonymousAudit(t, tc.shape).AtInputCount(count)
			c.requireSolved(t, a.Circuit(t))
			want.Anonymous = append(want.Anonymous, anonymousFieldCount{Key: key, Class: tc.shape.InputClass, Inputs: count, Outputs: tc.shape.Outputs, Exits: a.Layout.Exits, Fields: len(a.Disclosure(t))})
		}
	}
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, '\n')
	path := ringVectorPath(t, fieldCountVector)
	if os.Getenv("WRITE_AUDIT_VECTORS") != "" {
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(raw, encoded) {
		t.Fatalf("the host disclosures disagree with test-vectors/%s, rewrite it with WRITE_AUDIT_VECTORS=1", fieldCountVector)
	}
}

// Every prefix of a canonical hash lies below 2^InputPrefixBits and a pair of them below q.
func TestInputPrefixesPackBelowTheModulus(t *testing.T) {
	q := ecc.BN254.ScalarField()
	if top := new(big.Int).Rsh(q, 8*(32-base.InputPrefixLen)); top.BitLen() > base.InputPrefixBits {
		t.Fatalf("the prefix of q takes %d bits", top.BitLen())
	}
	if 2*base.InputPrefixBits >= q.BitLen() {
		t.Fatalf("a pair of %d-bit prefixes reaches q", base.InputPrefixBits)
	}
}

type anonymousDisclosureVectors struct {
	Cases []struct {
		Name   string `json:"name"`
		Key    string `json:"key"`
		Inputs []struct {
			Commitment string `json:"commitment"`
		} `json:"inputs"`
		Plaintext []string `json:"plaintext"`
	} `json:"cases"`
}

// The Rust auditor reads the commitment tail the Go host publishes, every commitment case of its vector ends in it.
func TestCommitmentTailIsTheRustDisclosure(t *testing.T) {
	var vectors anonymousDisclosureVectors
	readRingVector(t, "audit-disclosure-anonymous.json", &vectors)
	covered := 0
	for _, c := range vectors.Cases {
		if c.Key != "commitment" {
			continue
		}
		hashes := make([]*big.Int, len(c.Inputs))
		for i, input := range c.Inputs {
			hashes[i] = vectorField(t, input.Commitment)
		}
		tail := ringaudit.CommitmentRecords(hashes)
		written := c.Plaintext[len(c.Plaintext)-len(tail):]
		for i, field := range tail {
			if field.Cmp(vectorField(t, written[i])) != 0 {
				t.Errorf("%s tail field %d is %x, the vector holds %s", c.Name, i, field, written[i])
			}
		}
		covered++
	}
	if covered == 0 {
		t.Fatal("the vector holds no commitment case")
	}
}
