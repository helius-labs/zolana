package extractor

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// These renderers compose actual native wrappers from explicit primitive
// witnesses. They do not discharge those premises and are not completeness
// claims. The outer mathematical pipeline constructs all hints and primitives.

type nativeCompositionPart struct {
	name   string
	lines  []string
	ranges int
}

type nativeCompositionShape struct {
	parts  []nativeCompositionPart
	checks []string
	evals  []string
	lazies []string
}

func nativeCompositionParts(defs map[string]extractedDef, name string) ([]nativeCompositionPart, error) {
	call := regexp.MustCompile(`^(` + regexp.QuoteMeta(name) + `_p\d+) `)
	seen := map[string]bool{}
	var parts []nativeCompositionPart
	for current := name; current != ""; {
		if seen[current] {
			return nil, fmt.Errorf("%s: cyclic native continuation", name)
		}
		seen[current] = true
		d, ok := defs[current]
		if !ok {
			return nil, fmt.Errorf("%s: missing native fragment %s", name, current)
		}
		part := nativeCompositionPart{name: current}
		next := ""
		for _, line := range d.body {
			l := strings.TrimSpace(strings.TrimSuffix(line, " ∧"))
			if call.MatchString(l) {
				if next != "" {
					return nil, fmt.Errorf("%s: multiple native fragment continuations", current)
				}
				next = call.FindStringSubmatch(l)[1]
				continue
			}
			part.lines = append(part.lines, l)
			if rangeLine.MatchString(l) {
				part.ranges++
			}
		}
		parts = append(parts, part)
		current = next
	}
	return parts, nil
}

func nativeCompositionSchema(defs map[string]extractedDef, name string, triple bool) (nativeCompositionShape, error) {
	s := nativeCompositionShape{}
	parts, err := nativeCompositionParts(defs, name)
	if err != nil {
		return s, err
	}
	s.parts = parts
	check := regexp.MustCompile(`^(CheckPolynomial_(\d+)_h[0-9a-f]{8}) vec!\[`)
	lazy := regexp.MustCompile(`^(Lazy_(\d+)_h[0-9a-f]{8}) vec!\[`)
	vectors, ranges, continuations := 0, 0, 0
	for _, part := range parts {
		for _, l := range part.lines {
			switch {
			case vectorLine.MatchString(l):
				n, _ := strconv.Atoi(vectorLine.FindStringSubmatch(l)[1])
				want := 48
				if triple {
					want = 24
				}
				if n != want {
					return s, fmt.Errorf("%s: unexpected native hint arity", name)
				}
				vectors++
			case gateEqLine.MatchString(l):
			case rangeLine.MatchString(l):
				n, _ := strconv.Atoi(rangeLine.FindStringSubmatch(l)[1])
				want := 11
				if ranges%3 == 2 {
					want = 10
				}
				if n != want {
					return s, fmt.Errorf("%s: unexpected native range width", name)
				}
				ranges++
			case check.MatchString(l):
				m := check.FindStringSubmatch(l)
				if strings.Contains(l, "] fun gate_") {
					s.evals = append(s.evals, m[1])
				} else {
					s.checks = append(s.checks, m[1])
				}
			case lazy.MatchString(l):
				s.lazies = append(s.lazies, lazy.FindStringSubmatch(l)[1])
			case strings.HasPrefix(l, "k vec!["):
				continuations++
			default:
				return s, fmt.Errorf("%s: unsupported native composition line %q", part.name, l)
			}
		}
	}
	valid := ranges == 48 && continuations == 1 && len(s.checks) == 2 && len(s.lazies) == 1 && len(parts) == 2
	if triple {
		valid = valid && vectors == 4 && len(s.evals) == 2 && parts[0].ranges >= 24 && parts[0].ranges < 48 &&
			strings.HasPrefix(s.checks[0], "CheckPolynomial_32_") && strings.HasPrefix(s.checks[1], "CheckPolynomial_24_") &&
			strings.HasPrefix(s.evals[0], "CheckPolynomial_24_") && strings.HasPrefix(s.evals[1], "CheckPolynomial_24_") &&
			strings.HasPrefix(s.lazies[0], "Lazy_16_")
	} else {
		valid = valid && vectors == 1 && len(s.evals) == 0 && parts[0].ranges == 48 &&
			strings.HasPrefix(s.checks[0], "CheckPolynomial_24_") && strings.HasPrefix(s.checks[1], "CheckPolynomial_32_") &&
			strings.HasPrefix(s.lazies[0], "Lazy_8_")
	}
	if !valid {
		return s, fmt.Errorf("%s: native composition schema or fragment cut changed", name)
	}
	return s, nil
}

func nativeWireSimp(w *instanceWriter, indent string) {
	w.line("%ssimp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,", indent)
	w.line("%s  GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left,", indent)
	w.line("%s  mul_one, one_mul, zero_add, add_zero, mul_neg_one, neg_one_mul, sub_eq_add_neg, mul_comm]", indent)
}

func nativeRangeFacts(prefix string, start, stop int) []string {
	var facts []string
	for j := start; j < stop; j++ {
		projection := ".1"
		if j%3 == 1 {
			projection = ".2.1"
		} else if j%3 == 2 {
			projection = ".2.2"
		}
		facts = append(facts, fmt.Sprintf("(%s %d)%s", prefix, j/3, projection))
	}
	return facts
}

func renderTripleComposition(name string, s nativeCompositionShape) string {
	w := &instanceWriter{}
	w.line("/-- Native composition only; every primitive premise is supplied by the mathematical pipeline. -/")
	w.line("theorem %s_compose (X Y L R DX RX RY : List.Vector F 8)", name)
	w.line("    (rawL rawR piecesL piecesR : List.Vector F 24)")
	for _, v := range []string{"L", "R"} {
		w.line("    (hr%s : ∀ i : Fin 8, RangeCheck 11 (pieces%s.get ⟨3 * i.val, by omega⟩) ∧", v, v)
		w.line("      RangeCheck 11 (pieces%s.get ⟨3 * i.val + 1, by omega⟩) ∧", v)
		w.line("      RangeCheck 10 (pieces%s.get ⟨3 * i.val + 2, by omega⟩))", v)
		w.line("    (h%s : ∀ i : Fin 8, %s.get i =", v, v)
		w.line("      pieces%s.get ⟨3 * i.val, by omega⟩ + pieces%s.get ⟨3 * i.val + 1, by omega⟩ * 2048 +", v, v)
		w.line("      pieces%s.get ⟨3 * i.val + 2, by omega⟩ * 4194304 - 2147483648)", v)
	}
	w.line("    (hTangent : %s (quadTangentInput L Y X))", s.checks[0])
	w.line("    (hDX : ∀ k : List.Vector F 8 → Prop, k DX → %s (quadDoubleXInput L X) k)", s.lazies[0])
	w.line("    (hRatio : %s (tripleRatioInput R X DX Y))", s.checks[1])
	w.line("    (hRX : ∀ k : List.Vector F 8 → Prop, k RX → %s (tripleXInput R L X DX) k)", s.evals[0])
	w.line("    (hRY : ∀ k : List.Vector F 8 → Prop, k RY → %s (tripleYInput R L X RX Y) k)", s.evals[1])
	w.line("    (k : List.Vector (List.Vector F 8) 2 → Prop) (hk : k (RX ::ᵥ RY ::ᵥ List.Vector.nil)) :")
	w.line("    %s X Y k := by", name)
	for _, v := range []string{"L", "R"} {
		for j := 0; j < 8; j++ {
			w.line("  have h%s%d := h%s (%d : Fin 8)", v, j, v, j)
		}
		var fs []string
		for j := 0; j < 8; j++ {
			fs = append(fs, fmt.Sprintf("h%s%d", v, j))
		}
		w.line("  simp only [sub_eq_add_neg, mul_comm] at %s", strings.Join(fs, " "))
		for j := 0; j < 8; j++ {
			w.line("  change %s.get %d = pieces%s.get %d + 2048 * pieces%s.get %d + 4194304 * pieces%s.get %d + -(2147483648 : F) at h%s%d", v, j, v, 3*j, v, 3*j+1, v, 3*j+2, v, j)
		}
	}
	w.line("  have hDXNative := hDX")
	w.line("  have hRXNative := hRX")
	w.line("  have hRYNative := hRY")
	w.line("  simp only [quadDoubleXInput, sub_eq_add_neg, mul_comm] at hDXNative")
	w.line("  simp only [tripleXInput, sub_eq_add_neg, mul_comm] at hRXNative")
	w.line("  simp only [tripleYInput, sub_eq_add_neg, mul_comm] at hRYNative")
	w.line("  unfold %s", s.parts[0].name)
	nativeWireSimp(w, "  ")
	items := append([]string{"rawL", "piecesL"}, nativeRangeFacts("hrL", 0, 24)...)
	items = append(items, "?_", "?_")
	w.line("  refine %s", tupleOf(items))
	const rewriteL = "try simp only [← hL0, ← hL1, ← hL2, ← hL3, ← hL4, ← hL5, ← hL6, ← hL7]"
	const rewriteR = "try simp only [← hR0, ← hR1, ← hR2, ← hR3, ← hR4, ← hR5, ← hR6, ← hR7]"
	w.line("  · %s", rewriteL)
	w.line("    simpa only [quadTangentInput, quadCompositionA] using hTangent")
	w.line("  · %s", rewriteL)
	w.line("    apply hDXNative")
	firstR := s.parts[0].ranges - 24
	items = append([]string{"rawR", "piecesR"}, nativeRangeFacts("hrR", 0, firstR)...)
	items = append(items, "?_")
	w.line("    refine %s", tupleOf(items))
	w.line("    unfold %s", s.parts[1].name)
	nativeWireSimp(w, "    ")
	items = append(nativeRangeFacts("hrR", firstR, 24), "?_", "?_")
	w.line("    refine %s", tupleOf(items))
	w.line("    · %s", rewriteR)
	w.line("      simpa only [tripleRatioInput, sub_eq_add_neg, mul_comm] using hRatio")
	w.line("    · %s", rewriteR)
	w.line("      apply hRXNative")
	w.line("      apply hRYNative")
	w.line("      exact hk")
	w.line("")
	return w.b.String()
}

func renderAddComposition(name string, s nativeCompositionShape) string {
	w := &instanceWriter{}
	w.line("/-- Native composition only, preserving every output-hint piece and assertion. -/")
	w.line("theorem %s_compose (PX PY QX QY SX SY D2 : List.Vector F 8)", name)
	w.line("    (pieces : List.Vector F 48)")
	w.line("    (hr : ∀ i : Fin 16, RangeCheck 11 (pieces.get ⟨3 * i.val, by omega⟩) ∧")
	w.line("      RangeCheck 11 (pieces.get ⟨3 * i.val + 1, by omega⟩) ∧")
	w.line("      RangeCheck 10 (pieces.get ⟨3 * i.val + 2, by omega⟩))")
	for j, v := range []string{"SX", "SY"} {
		w.line("    (h%s : ∀ i : Fin 8, %s.get i =", v, v)
		w.line("      pieces.get ⟨%d + 3 * i.val, by omega⟩ +", 24*j)
		w.line("      pieces.get ⟨%d + 3 * i.val + 1, by omega⟩ * 2048 +", 24*j)
		w.line("      pieces.get ⟨%d + 3 * i.val + 2, by omega⟩ * 4194304)", 24*j)
	}
	w.line("    (hD2 : ∀ k : List.Vector F 8 → Prop, k D2 → %s (addDifferenceInput QX PX) k)", s.lazies[0])
	w.line("    (hFirst : %s (addFirstInput SX PX QX D2 QY PY))", s.checks[0])
	w.line("    (hSecond : %s (addSecondInput QY PY SX PX SY QX))", s.checks[1])
	w.line("    (k : List.Vector (List.Vector F 8) 2 → Prop) (hk : k (SX ::ᵥ SY ::ᵥ List.Vector.nil)) :")
	w.line("    %s PX PY QX QY k := by", name)
	var fs []string
	for _, v := range []string{"SX", "SY"} {
		for j := 0; j < 8; j++ {
			f := fmt.Sprintf("h%s%d", v, j)
			fs = append(fs, f)
			w.line("  have %s := h%s (%d : Fin 8)", f, v, j)
		}
	}
	w.line("  simp only [sub_eq_add_neg, mul_comm] at %s", strings.Join(fs, " "))
	for vi, v := range []string{"SX", "SY"} {
		for j := 0; j < 8; j++ {
			i := 24*vi + 3*j
			w.line("  change %s.get %d = pieces.get %d + 2048 * pieces.get %d + 4194304 * pieces.get %d at h%s%d", v, j, i, i+1, i+2, v, j)
		}
	}
	w.line("  have hD2Native := hD2")
	w.line("  simp only [addDifferenceInput, sub_eq_add_neg, mul_comm] at hD2Native")
	w.line("  unfold %s", s.parts[0].name)
	nativeWireSimp(w, "  ")
	items := append([]string{"pieces"}, nativeRangeFacts("hr", 0, 48)...)
	items = append(items, "?_")
	w.line("  refine %s", tupleOf(items))
	var rewrites []string
	for _, f := range fs {
		rewrites = append(rewrites, "← "+f)
	}
	w.line("  unfold %s", s.parts[1].name)
	nativeWireSimp(w, "  ")
	w.line("  simp only [%s]", strings.Join(rewrites, ", "))
	w.line("  apply hD2Native")
	w.line("  refine ⟨?_, ?_, ?_⟩")
	w.line("  · simpa only [addFirstInput, sub_eq_add_neg, mul_comm] using hFirst")
	w.line("  · simpa only [addSecondInput, sub_eq_add_neg, mul_comm] using hSecond")
	w.line("  · simpa only [vec8_eta] using hk")
	w.line("")
	return w.b.String()
}

func RenderNativeCurveCompositions(defs map[string]extractedDef) (map[string]string, error) {
	tripleKey := regexp.MustCompile(`^Triple_8_8_h[0-9a-f]{8}$`)
	addKey := regexp.MustCompile(`^Add_8_8_8_8_h[0-9a-f]{8}$`)
	var names []string
	for name := range defs {
		if tripleKey.MatchString(name) || addKey.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	w := &instanceWriter{}
	w.line("import VerifiableEncryption.Curve.CompletenessGeneratedQuadComposition")
	w.line("")
	w.line("-- GENERATED by prover/extractor/emcurve_native_compositions.go; do not edit.")
	w.line("-- Composition bridges only; mathematical constructors discharge all premises.")
	w.line("")
	w.line("namespace ZolanaVE.P256.Completeness")
	w.line("")
	w.line("open ZolanaVE.Field")
	w.line("")
	w.line("set_option maxHeartbeats 0")
	w.line("set_option maxRecDepth 100000")
	w.line("")
	inputs := []struct {
		name, params string
		runs         []string
	}{
		{"tripleRatioInput", "R X DX Y", []string{"R.get %d", "X.get %d - DX.get %d", "2 * Y.get %d"}},
		{"tripleXInput", "R L X DX", []string{"R.get %d - L.get %d", "X.get %d", "DX.get %d"}},
		{"tripleYInput", "R L X RX Y", []string{"R.get %d - L.get %d", "X.get %d - RX.get %d", "Y.get %d"}},
		{"addDifferenceInput", "QX PX", []string{"QX.get %d - PX.get %d"}},
		{"addFirstInput", "SX PX QX D2 QY PY", []string{"SX.get %d + PX.get %d + QX.get %d", "D2.get %d", "QY.get %d - PY.get %d"}},
		{"addSecondInput", "QY PY SX PX SY QX", []string{"QY.get %d - PY.get %d", "SX.get %d - PX.get %d", "SY.get %d + PY.get %d", "QX.get %d - PX.get %d"}},
	}
	for _, in := range inputs {
		var atoms []string
		for _, run := range in.runs {
			for i := 0; i < 8; i++ {
				args := make([]any, strings.Count(run, "%d"))
				for j := range args {
					args[j] = i
				}
				atoms = append(atoms, fmt.Sprintf(run, args...))
			}
		}
		w.line("def %s (%s : List.Vector F 8) : List.Vector F %d :=", in.name, in.params, len(atoms))
		w.line("  vec![%s]", strings.Join(atoms, ", "))
		w.line("")
	}
	for _, name := range names {
		triple := tripleKey.MatchString(name)
		s, err := nativeCompositionSchema(defs, name, triple)
		if err != nil {
			return nil, err
		}
		for _, primitive := range append(append(append([]string{}, s.checks...), s.evals...), s.lazies...) {
			if _, ok := defs[primitive]; !ok {
				return nil, fmt.Errorf("%s: missing native primitive %s", name, primitive)
			}
		}
		if triple {
			w.b.WriteString(renderTripleComposition(name, s))
		} else {
			w.b.WriteString(renderAddComposition(name, s))
		}
	}
	w.line("end ZolanaVE.P256.Completeness")
	prefix, err := renderScalarPrefixComposition(defs)
	if err != nil {
		return nil, err
	}
	core, err := renderScalarCoreCompositions(defs)
	if err != nil {
		return nil, err
	}
	return map[string]string{
		"VerifiableEncryption.Curve.CompletenessGeneratedTripleAddComposition": w.b.String(),
		"VerifiableEncryption.Curve.CompletenessGeneratedScalarPrefix": prefix,
		"VerifiableEncryption.Curve.CompletenessGeneratedScalarCore": core,
	}, nil
}
