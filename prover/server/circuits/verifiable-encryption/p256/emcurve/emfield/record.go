package emfield

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// Recorder and RecordBasis receive the compile-time parameters of every
// checkPolynomial, Lazy and AssertCanonical call. They are nil in production;
// the hooks only read values the circuit code already computed and never add
// constraints. They are package globals, so callers that set them must not
// compile circuits concurrently.
var (
	Recorder    func(CheckRecord)
	RecordBasis func(BasisRecord)
)

type CheckKind string

const (
	KindEval              CheckKind = "eval"
	KindAssertZero        CheckKind = "assert_zero"
	KindLazy              CheckKind = "lazy"
	KindCanonicalLimbwise CheckKind = "canonical_limbwise"
	KindCanonicalGap      CheckKind = "canonical_gap"
)

type TermRecord struct {
	Coef    *big.Int
	Factors []int
}

type ElementRecord struct {
	Lo, Hi             []*big.Int
	ValueMin, ValueMax *big.Int
}

type CarryGroupRecord struct {
	Start, End, CarryBits int
	GroupBound            *big.Int
}

// CheckRecord is one certificate record. Polynomial checks fill the fields up
// to CarryGroups, Lazy fills the term data plus Out*, canonical checks fill
// the term-free fields at the end.
type CheckRecord struct {
	Kind         CheckKind
	Modulus      *big.Int
	NbLimbs      int
	LimbBits     int
	PieceBits    int
	ModulusLimbs []*big.Int
	ResultWidths []int

	Terms             []TermRecord
	Elements          []ElementRecord
	CoefficientBounds []*big.Int
	Degree            int
	CheckModulus      []*big.Int
	Folded            bool
	UsesCRT           bool
	FoldedBounds      []*big.Int
	FoldedMin         *big.Int
	FoldedMax         *big.Int

	RemainderMax   *big.Int
	QuotientMin    *big.Int
	QuotientMax    *big.Int
	Offset         *big.Int
	QuotientBits   int
	QuotientWidths []int
	OffsetLimbs    []*big.Int
	QuotientBounds []*big.Int
	ResidualBounds []*big.Int
	Positions      int
	CarryPositions int
	CheckTop       bool
	CarryGroups    []CarryGroupRecord
	Projected      bool

	CoefficientMin []*big.Int
	CoefficientMax []*big.Int
	OutLo, OutHi   []*big.Int
	OutMin, OutMax *big.Int

	Kinds        []int
	MaximumLimbs []*big.Int
	LowLimbCount int
	MaximumLow   *big.Int
	MaximumHigh  *big.Int
	GapWidths    []int
}

// BasisRecord holds the matrices shared by every check of one field: the
// fold rows (nil when the modulus does not fold), the inverse Vandermonde
// matrices built so far keyed by degree, and the CRT basis, with its square
// products, when one exists.
type BasisRecord struct {
	Modulus            *big.Int
	NativeModulus      *big.Int
	NbLimbs            int
	LimbBits           int
	PieceBits          int
	FoldDigits         []*big.Int
	FoldRows           [][]*big.Int
	InverseVandermonde map[int][][]*big.Int
	CRTForms           [][]*big.Int
	CRTCombine         [][]*big.Int
	CRTSquareLeft      [][]*big.Int
	CRTSquareRight     [][]*big.Int
	CRTSquareCombine   [][]*big.Int
}

// CanonicalEncoding is the byte string Key hashes. It covers exactly the
// parameters that determine the constraints of one check, in this order and
// with decimal integers:
//
//	kind=<kind>;modulus=<m>;
//	projected;                       only for the projected variants
//	t=<coef>:<f0>,<f1>,...;          one per term, in call order
//	e=<lo0>,<lo1>,...|<hi0>,...|<valueMin>|<valueMax>;   one per element, first-use order
//
// Canonical checks have no terms and one element. The extraction gadget for a
// check must hash the same string so that cert_<key> pairs with its gadget.
func (r CheckRecord) CanonicalEncoding() string {
	var b strings.Builder
	fmt.Fprintf(&b, "kind=%s;modulus=%s;", r.Kind, r.Modulus.String())
	if r.Projected {
		b.WriteString("projected;")
	}
	for _, t := range r.Terms {
		fmt.Fprintf(&b, "t=%s:%s;", t.Coef.String(), joinInts(t.Factors))
	}
	for _, e := range r.Elements {
		fmt.Fprintf(&b, "e=%s|%s|%s|%s;", joinBig(e.Lo), joinBig(e.Hi), e.ValueMin.String(), e.ValueMax.String())
	}
	return b.String()
}

// Key is the first 8 hex digits of sha256(CanonicalEncoding()).
func (r CheckRecord) Key() string {
	sum := sha256.Sum256([]byte(r.CanonicalEncoding()))
	return hex.EncodeToString(sum[:4])
}

// Degrees lists the inverse Vandermonde degrees recorded so far, ascending.
func (b BasisRecord) Degrees() []int {
	out := make([]int, 0, len(b.InverseVandermonde))
	for d := range b.InverseVandermonde {
		out = append(out, d)
	}
	sort.Ints(out)
	return out
}

func joinInts(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ",")
}

func joinBig(v []*big.Int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = x.String()
	}
	return strings.Join(parts, ",")
}

func cloneBig(v []*big.Int) []*big.Int {
	out := make([]*big.Int, len(v))
	for i, x := range v {
		out[i] = new(big.Int).Set(x)
	}
	return out
}

func elementRecords(elements []*Element) []ElementRecord {
	out := make([]ElementRecord, len(elements))
	for i, e := range elements {
		out[i] = ElementRecord{Lo: cloneBig(e.lo), Hi: cloneBig(e.hi), ValueMin: new(big.Int).Set(e.valueMin), ValueMax: new(big.Int).Set(e.valueMax)}
	}
	return out
}

func termRecords(terms []term, indices map[*Element]int) []TermRecord {
	out := make([]TermRecord, len(terms))
	for i, t := range terms {
		factors := make([]int, len(t.factors))
		for j, e := range t.factors {
			factors[j] = indices[e]
		}
		out[i] = TermRecord{Coef: new(big.Int).Set(t.coef), Factors: factors}
	}
	return out
}

func distinctElements(terms []term) ([]*Element, map[*Element]int) {
	var elements []*Element
	indices := map[*Element]int{}
	for _, t := range terms {
		for _, e := range t.factors {
			if _, ok := indices[e]; !ok {
				indices[e] = len(elements)
				elements = append(elements, e)
			}
		}
	}
	return elements, indices
}

func (f *Field) baseRecord(kind CheckKind) CheckRecord {
	return CheckRecord{
		Kind:         kind,
		Modulus:      new(big.Int).Set(f.mod),
		NbLimbs:      f.layout.NbLimbs,
		LimbBits:     f.layout.LimbBits,
		PieceBits:    f.layout.PieceBits,
		ModulusLimbs: cloneBig(f.modulusLimbs),
		ResultWidths: append([]int{}, f.widths...),
	}
}

func (f *Field) recordBasis() {
	if RecordBasis == nil {
		return
	}
	s := f.arithmetic
	b := BasisRecord{
		Modulus:            new(big.Int).Set(f.mod),
		NativeModulus:      new(big.Int).Set(f.api.Compiler().Field()),
		NbLimbs:            f.layout.NbLimbs,
		LimbBits:           f.layout.LimbBits,
		PieceBits:          f.layout.PieceBits,
		InverseVandermonde: map[int][][]*big.Int{},
	}
	if s == nil {
		RecordBasis(b)
		return
	}
	b.FoldDigits = cloneBig(s.foldDigits)
	for _, row := range s.foldRows {
		b.FoldRows = append(b.FoldRows, cloneBig(row))
	}
	for d, m := range s.inverseMatrices {
		rows := make([][]*big.Int, len(m))
		for i, row := range m {
			rows[i] = cloneBig(row)
		}
		b.InverseVandermonde[d] = rows
	}
	if s.crt != nil {
		for _, row := range s.crt.forms {
			b.CRTForms = append(b.CRTForms, cloneBig(row))
		}
		for _, row := range s.crt.combine {
			b.CRTCombine = append(b.CRTCombine, cloneBig(row))
		}
		for k := range s.crt.squareLeft {
			b.CRTSquareLeft = append(b.CRTSquareLeft, cloneBig(s.crt.squareLeft[k]))
			b.CRTSquareRight = append(b.CRTSquareRight, cloneBig(s.crt.squareRight[k]))
		}
		for _, row := range s.crt.squareCombine {
			b.CRTSquareCombine = append(b.CRTSquareCombine, cloneBig(row))
		}
	}
	RecordBasis(b)
}
