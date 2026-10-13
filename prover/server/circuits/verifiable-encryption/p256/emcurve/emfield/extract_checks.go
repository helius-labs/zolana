package emfield

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// CheckPolynomial is one Eval (WithResult) or AssertZero call as a named Lean
// definition. Limbs concatenates the limbs of the distinct elements in
// first-use order; Bounds holds each element's metadata (see Element.Bounds),
// which also fixes its limb count; term i is Coefs[i] times the elements
// indexed by Factors[i].
type CheckPolynomial struct {
	Limbs      []frontend.Variable
	Bounds     [][]*big.Int
	Coefs      []*big.Int
	Factors    [][]int
	Modulus    *big.Int
	WithResult bool
}

// Lazy is one Field.Lazy call as a named Lean definition, laid out like
// CheckPolynomial.
type Lazy struct {
	Limbs   []frontend.Variable
	Bounds  [][]*big.Int
	Coefs   []*big.Int
	Factors [][]int
	Modulus *big.Int
}

func (g CheckPolynomial) GadgetHash() string {
	kind := "assert_zero"
	if g.WithResult {
		kind = "eval"
	}
	return checkKey(kind, g.Modulus, g.Coefs, g.Factors, g.Bounds)
}

func (g Lazy) GadgetHash() string {
	return checkKey("lazy", g.Modulus, g.Coefs, g.Factors, g.Bounds)
}

// checkKey is the first 8 hex digits of the SHA-256 of the canonical check
// encoding the certificate records use:
//
//	kind=<kind>;modulus=<m>;
//	t=<coef>:<f0>,<f1>,...;                              one per term
//	e=<lo0>,...|<hi0>,...|<valueMin>|<valueMax>;         one per element
//
// so the certificate cert_<key> pairs with the definition <Name>_h<key>.
func checkKey(kind string, modulus *big.Int, coefs []*big.Int, factors [][]int, bounds [][]*big.Int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "kind=%s;modulus=%s;", kind, modulus.String())
	for i, c := range coefs {
		indices := make([]string, len(factors[i]))
		for j, f := range factors[i] {
			indices[j] = strconv.Itoa(f)
		}
		fmt.Fprintf(&b, "t=%s:%s;", c.String(), strings.Join(indices, ","))
	}
	for _, e := range bounds {
		n := (len(e) - 3) / 2
		fmt.Fprintf(&b, "e=%s|%s|%s|%s;", joinDecimal(e[3:3+n]), joinDecimal(e[3+n:]), e[0].String(), e[1].String())
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:4])
}

func joinDecimal(v []*big.Int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = x.String()
	}
	return strings.Join(parts, ",")
}

type checkInputs struct {
	limbs   []frontend.Variable
	bounds  [][]*big.Int
	coefs   []*big.Int
	factors [][]int
}

func encodeTerms(terms []Term) checkInputs {
	var in checkInputs
	indices := map[*Element]int{}
	for _, t := range terms {
		in.coefs = append(in.coefs, big.NewInt(t.Coef))
		factors := make([]int, len(t.Factors))
		for j, e := range t.Factors {
			index, ok := indices[e]
			if !ok {
				index = len(in.bounds)
				indices[e] = index
				in.bounds = append(in.bounds, e.Bounds())
				in.limbs = append(in.limbs, e.limbs...)
			}
			factors[j] = index
		}
		in.factors = append(in.factors, factors)
	}
	return in
}

func (f *Field) decodeTerms(limbs []frontend.Variable, bounds [][]*big.Int, coefs []*big.Int, factors [][]int) []Term {
	elements := make([]*Element, len(bounds))
	for i, b := range bounds {
		n := (len(b) - 3) / 2
		elements[i] = f.FromBounds(limbs[:n], b)
		limbs = limbs[n:]
	}
	if len(limbs) != 0 {
		panic("limbs do not match the element bounds")
	}
	terms := make([]Term, len(coefs))
	for i, c := range coefs {
		if !c.IsInt64() {
			panic("term coefficient out of range")
		}
		terms[i] = Term{Coef: c.Int64()}
		for _, index := range factors[i] {
			terms[i].Factors = append(terms[i].Factors, elements[index])
		}
	}
	return terms
}

func (g CheckPolynomial) DefineGadget(api frontend.API) interface{} {
	f := New(api, g.Modulus)
	terms := f.decodeTerms(g.Limbs, g.Bounds, g.Coefs, g.Factors)
	if !g.WithResult {
		f.AssertZero(terms...)
		return nil
	}
	r := f.Eval(terms...)
	if !SameBounds(r, f.Reduced(r.limbs)) {
		panic("eval result is not reduced")
	}
	return r.limbs
}

func (g Lazy) DefineGadget(api frontend.API) interface{} {
	f := New(api, g.Modulus)
	terms := f.decodeTerms(g.Limbs, g.Bounds, g.Coefs, g.Factors)
	r := f.Lazy(terms...)
	if !SameBounds(r, f.FromBounds(r.limbs, f.lazyBounds(terms))) {
		panic("lazy bounds diverge from Field.Lazy")
	}
	return r.limbs
}

func (f *Field) extractsChecks() bool {
	return abstractor.Extracting(f.api)
}

// GadgetEval is Eval; under the Lean extractor it is the CheckPolynomial gadget.
func (f *Field) GadgetEval(terms ...Term) *Element {
	if !f.extractsChecks() {
		return f.Eval(terms...)
	}
	in := encodeTerms(terms)
	limbs := abstractor.Call1(f.api, CheckPolynomial{Limbs: in.limbs, Bounds: in.bounds, Coefs: in.coefs, Factors: in.factors, Modulus: f.Modulus(), WithResult: true})
	return f.Reduced(limbs)
}

// GadgetAssertZero is AssertZero; under the Lean extractor it is the
// CheckPolynomial gadget.
func (f *Field) GadgetAssertZero(terms ...Term) {
	if !f.extractsChecks() {
		f.AssertZero(terms...)
		return
	}
	in := encodeTerms(terms)
	abstractor.CallVoid(f.api, CheckPolynomial{Limbs: in.limbs, Bounds: in.bounds, Coefs: in.coefs, Factors: in.factors, Modulus: f.Modulus()})
}

// GadgetLazy is Lazy; under the Lean extractor it is the Lazy gadget.
func (f *Field) GadgetLazy(terms ...Term) *Element {
	if !f.extractsChecks() {
		return f.Lazy(terms...)
	}
	in := encodeTerms(terms)
	limbs := abstractor.Call1(f.api, Lazy{Limbs: in.limbs, Bounds: in.bounds, Coefs: in.coefs, Factors: in.factors, Modulus: f.Modulus()})
	return f.FromBounds(limbs, f.lazyBounds(terms))
}

// lazyBounds recomputes the output metadata of Lazy without building
// constraints; the Lazy gadget checks it against Field.Lazy.
func (f *Field) lazyBounds(inputTerms []Term) []*big.Int {
	limbCount, limbBits := f.layout.NbLimbs, f.layout.LimbBits
	terms := make([]term, len(inputTerms))
	for i, t := range inputTerms {
		terms[i] = term{coef: big.NewInt(t.Coef), factors: t.Factors}
	}
	coefficientMin, coefficientMax := f.lazyCoefficientIntervals(terms)
	fold := f.arithmetic.fold(limbCount, len(coefficientMin)-1)
	valueMin, valueMax := new(big.Int), new(big.Int)
	los, his := make([]*big.Int, limbCount), make([]*big.Int, limbCount)
	for j := 0; j < limbCount; j++ {
		lo, hi := new(big.Int), new(big.Int)
		for i := range coefficientMin {
			c := fold[i][j]
			switch c.Sign() {
			case 1:
				lo.Add(lo, new(big.Int).Mul(c, coefficientMin[i]))
				hi.Add(hi, new(big.Int).Mul(c, coefficientMax[i]))
			case -1:
				lo.Add(lo, new(big.Int).Mul(c, coefficientMax[i]))
				hi.Add(hi, new(big.Int).Mul(c, coefficientMin[i]))
			}
		}
		los[j], his[j] = lo, hi
		valueMin.Add(valueMin, new(big.Int).Lsh(lo, uint(limbBits*j)))
		valueMax.Add(valueMax, new(big.Int).Lsh(hi, uint(limbBits*j)))
	}
	return append(append([]*big.Int{valueMin, valueMax, big.NewInt(0)}, los...), his...)
}
