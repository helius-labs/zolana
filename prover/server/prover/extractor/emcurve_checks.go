package extractor

import (
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/circuits/formal/ve"
	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// EmcurveChecks is the deduplicated set of field-layer certificate records of
// the P-256 key-agreement and public-key circuits.
type EmcurveChecks struct {
	Records []emfield.CheckRecord
	Basis   emfield.BasisRecord
	// Calls counts the recorder invocations before deduplication.
	Calls int
}

// emcurveCircuits are the extraction circuits that use the emulated field;
// their records pair one to one with the extracted CheckPolynomial and Lazy
// definitions.
func emcurveCircuits() []frontend.Circuit {
	return []frontend.Circuit{&ve.FieldMulCheck{}, &ve.GuardedAdd{}, &ve.AgreeKey{}, &ve.DerivePublicKey{}, &ve.Envelope{}}
}

// CollectEmcurveChecks compiles the extraction circuits that use the emulated
// field with the production builder and the field recorders installed.
func CollectEmcurveChecks() (*EmcurveChecks, error) {
	out := &EmcurveChecks{}
	byKey := map[string]emfield.CheckRecord{}
	var bases []emfield.BasisRecord
	emfield.Recorder = func(r emfield.CheckRecord) {
		out.Calls++
		key := r.Key()
		if prev, ok := byKey[key]; ok {
			if renderRecord(prev) != renderRecord(r) {
				panic(fmt.Sprintf("emcurve checks: key %s maps to two different records", key))
			}
			return
		}
		byKey[key] = r
	}
	emfield.RecordBasis = func(b emfield.BasisRecord) {
		bases = append(bases, b)
	}
	defer func() {
		emfield.Recorder = nil
		emfield.RecordBasis = nil
	}()
	for _, circuit := range emcurveCircuits() {
		if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Records = append(out.Records, byKey[k])
	}
	basis, err := mergeBases(bases)
	if err != nil {
		return nil, err
	}
	out.Basis = basis
	return out, nil
}

// mergeBases joins every basis snapshot seen across compiles: the inverse
// Vandermonde matrices only depend on the native field and must agree, the
// fold rows and CRT basis come from the one modulus that folds, keeping the
// longest fold prefix.
func mergeBases(bases []emfield.BasisRecord) (emfield.BasisRecord, error) {
	merged := emfield.BasisRecord{InverseVandermonde: map[int][][]*big.Int{}}
	for _, b := range bases {
		if merged.NativeModulus != nil && merged.NativeModulus.Cmp(b.NativeModulus) != 0 {
			return merged, fmt.Errorf("two native moduli")
		}
		merged.NativeModulus, merged.NbLimbs, merged.LimbBits, merged.PieceBits = b.NativeModulus, b.NbLimbs, b.LimbBits, b.PieceBits
		if b.FoldRows != nil {
			if merged.FoldRows != nil {
				shorter := min(len(merged.FoldRows), len(b.FoldRows))
				if merged.Modulus.Cmp(b.Modulus) != 0 || renderMatrix(merged.FoldRows[:shorter]) != renderMatrix(b.FoldRows[:shorter]) {
					return merged, fmt.Errorf("two folding moduli")
				}
				if (merged.CRTForms != nil) == (b.CRTForms != nil) && renderMatrix(merged.CRTForms) != renderMatrix(b.CRTForms) {
					return merged, fmt.Errorf("CRT bases disagree")
				}
			}
			if len(b.FoldRows) > len(merged.FoldRows) {
				merged.Modulus, merged.FoldDigits, merged.FoldRows = b.Modulus, b.FoldDigits, b.FoldRows
			}
			if b.CRTForms != nil {
				merged.CRTForms, merged.CRTCombine = b.CRTForms, b.CRTCombine
			}
		}
		for d, rows := range b.InverseVandermonde {
			if prev, ok := merged.InverseVandermonde[d]; ok && renderMatrix(prev) != renderMatrix(rows) {
				return merged, fmt.Errorf("inverse Vandermonde matrices of degree %d disagree", d)
			}
			merged.InverseVandermonde[d] = rows
		}
	}
	if merged.FoldRows == nil {
		return merged, fmt.Errorf("no folding modulus recorded")
	}
	return merged, nil
}

// ExtractEmcurveChecks renders the records as formal-verification/VerifiableEncryption/EmcurveChecks.lean.
func ExtractEmcurveChecks() (string, error) {
	checks, err := CollectEmcurveChecks()
	if err != nil {
		return "", err
	}
	return RenderEmcurveChecks(checks), nil
}

// ExtractEmcurveCertificate renders formal-verification/VerifiableEncryption/Field/Certificate.lean:
// one kernel-checked soundness lemma per record.
func ExtractEmcurveCertificate() (string, error) {
	checks, err := CollectEmcurveChecks()
	if err != nil {
		return "", err
	}
	return RenderEmcurveCertificate(checks), nil
}

func recordName(r emfield.CheckRecord) string {
	switch r.Kind {
	case emfield.KindLazy:
		return "lazy_h" + r.Key()
	case emfield.KindCanonicalLimbwise, emfield.KindCanonicalGap:
		return "canonical_h" + r.Key()
	default:
		return "cert_h" + r.Key()
	}
}

func RenderEmcurveChecks(c *EmcurveChecks) string {
	var b strings.Builder
	b.WriteString("import VerifiableEncryption.Field.CheckPolynomial\n")
	b.WriteString("import VerifiableEncryption.Field.Canonical\n\n")
	b.WriteString("-- GENERATED by prover/extractor/emcurve_checks.go; do not edit.\n\n")
	b.WriteString("namespace ZolanaVE.EmcurveChecks\n\nopen ZolanaVE.Field\n\n")
	fmt.Fprintf(&b, "def basis : BasisParams := %s\n\n", renderBasis(c.Basis))
	var polys, lazies, canonicals []string
	for _, r := range c.Records {
		name := recordName(r)
		switch r.Kind {
		case emfield.KindLazy:
			lazies = append(lazies, name)
			fmt.Fprintf(&b, "def %s : LazyParams := %s\n\n", name, renderRecord(r))
		case emfield.KindCanonicalLimbwise, emfield.KindCanonicalGap:
			canonicals = append(canonicals, name)
			fmt.Fprintf(&b, "def %s : CanonicalCheckParams := %s\n\n", name, renderRecord(r))
		default:
			polys = append(polys, name)
			fmt.Fprintf(&b, "def %s : PlainCheckParams := %s\n\n", name, renderRecord(r))
		}
	}
	fmt.Fprintf(&b, "def checks : List PlainCheckParams := [%s]\n\n", strings.Join(polys, ", "))
	fmt.Fprintf(&b, "def lazies : List LazyParams := [%s]\n\n", strings.Join(lazies, ", "))
	fmt.Fprintf(&b, "def canonicals : List CanonicalCheckParams := [%s]\n\n", strings.Join(canonicals, ", "))
	b.WriteString("end ZolanaVE.EmcurveChecks\n")
	return b.String()
}

func RenderEmcurveCertificate(c *EmcurveChecks) string {
	var b strings.Builder
	b.WriteString("import VerifiableEncryption.EmcurveChecks\n\n")
	b.WriteString("-- GENERATED by prover/extractor/emcurve_checks.go; do not edit.\n\n")
	b.WriteString("namespace ZolanaVE.EmcurveChecks\n\nopen ZolanaVE.Field\n\n")
	b.WriteString("theorem basis_sound : basis.sound = true := by decide +kernel\n\n")
	for _, r := range c.Records {
		name := recordName(r)
		switch r.Kind {
		case emfield.KindCanonicalLimbwise, emfield.KindCanonicalGap:
			fmt.Fprintf(&b, "theorem %s_sound : %s.sound = true := by decide +kernel\n\n", name, name)
		default:
			fmt.Fprintf(&b, "theorem %s_sound : %s.sound basis = true := by decide +kernel\n\n", name, name)
		}
	}
	b.WriteString("end ZolanaVE.EmcurveChecks\n")
	return b.String()
}

var nativeModulus = ecc.BN254.ScalarField()

func leanInt(v *big.Int) string {
	if v.Sign() < 0 {
		return "(" + v.String() + ")"
	}
	return v.String()
}

func leanIntList(v []*big.Int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = leanInt(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func leanNatList(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprint(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func renderMatrix(rows [][]*big.Int) string {
	parts := make([]string, len(rows))
	for i, row := range rows {
		parts[i] = leanIntList(row)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

func renderBasis(b emfield.BasisRecord) string {
	degrees := b.Degrees()
	vinv := make([]string, len(degrees))
	for i, d := range degrees {
		vinv[i] = fmt.Sprintf("(%d, %s)", d, renderMatrix(b.InverseVandermonde[d]))
	}
	return fmt.Sprintf("{\n  foldModulus := %s\n  foldRows := %s\n  vinv := [%s]\n  crtForms := %s\n  crtCombine := %s }",
		b.Modulus.String(), renderMatrix(b.FoldRows), strings.Join(vinv, ",\n    "), renderMatrix(b.CRTForms), renderMatrix(b.CRTCombine))
}

func leanBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func renderShape(r emfield.CheckRecord) string {
	terms := make([]string, len(r.Terms))
	for i, t := range r.Terms {
		terms[i] = fmt.Sprintf("⟨%s, %s⟩", leanInt(t.Coef), leanNatList(t.Factors))
	}
	elems := make([]string, len(r.Elements))
	for i, e := range r.Elements {
		elems[i] = fmt.Sprintf("⟨%s, %s, %s, %s⟩", leanIntList(e.Lo), leanIntList(e.Hi), leanInt(e.ValueMin), leanInt(e.ValueMax))
	}
	return fmt.Sprintf("elems := [%s]\n  terms := [%s]\n  degree := %d\n  fold := %s\n  useCrt := %s",
		strings.Join(elems, ",\n    "), strings.Join(terms, ", "), r.Degree, leanBool(r.Folded), leanBool(r.UsesCRT))
}

func renderRecord(r emfield.CheckRecord) string {
	switch r.Kind {
	case emfield.KindLazy:
		return fmt.Sprintf("{\n  %s\n  m := %s\n  outLo := %s\n  outHi := %s\n  outVlo := %s\n  outVhi := %s }",
			renderShape(r), r.Modulus.String(), leanIntList(r.OutLo), leanIntList(r.OutHi), leanInt(r.OutMin), leanInt(r.OutMax))
	case emfield.KindCanonicalLimbwise, emfield.KindCanonicalGap:
		e := r.Elements[0]
		return fmt.Sprintf("{\n  m := %s\n  limbwise := %s\n  widths := %s\n  lo := %s\n  hi := %s }",
			r.Modulus.String(), leanBool(r.Kind == emfield.KindCanonicalLimbwise), leanNatList(r.ResultWidths), leanIntList(e.Lo), leanIntList(e.Hi))
	}
	groups := make([]string, len(r.CarryGroups))
	for i, g := range r.CarryGroups {
		inv := new(big.Int).ModInverse(new(big.Int).Lsh(big.NewInt(1), uint(r.LimbBits*(g.End-g.Start))), nativeModulus)
		groups[i] = fmt.Sprintf("⟨%d, %d, %d, %s⟩", g.Start, g.End, g.CarryBits, inv.String())
	}
	mInv := new(big.Int).ModInverse(new(big.Int).Mod(r.Modulus, nativeModulus), nativeModulus)
	return fmt.Sprintf("{\n  %s\n  m := %s\n  mInv := %s\n  modulusLimbs := %s\n  pieceBits := %d\n  withResult := %s\n  resultWidths := %s\n"+
		"  positions := %d\n  quotientBits := %d\n  quotientWidths := %s\n  offset := %s\n  offsetLimbs := %s\n"+
		"  remainderMax := %s\n  carryPositions := %d\n  groups := [%s]\n  checkTop := %s }",
		renderShape(r), r.Modulus.String(), mInv.String(), leanIntList(r.ModulusLimbs), r.PieceBits, leanBool(r.Kind == emfield.KindEval),
		leanNatList(r.ResultWidths), r.Positions, r.QuotientBits, leanNatList(r.QuotientWidths), r.Offset.String(),
		leanIntList(r.OffsetLimbs), r.RemainderMax.String(), r.CarryPositions, strings.Join(groups, ", "), leanBool(r.CheckTop))
}
