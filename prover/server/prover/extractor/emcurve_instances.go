package extractor

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// The instance files link every extracted CheckPolynomial and Lazy definition
// to the generic field-layer theorems. For each definition the generator
// reads the extracted conjunct sequence (hint vectors, range checks, equations,
// the final continuation), matches it against the shape the certificate
// record predicts, and emits a mirror proof: destructure the limbs and hints
// into atoms, substitute the gate equations (elim_gates), then discharge every
// value identity by kernel reflection (ex_refl).

type conjunctKind int

const (
	conjVector conjunctKind = iota
	conjRange
	conjEq
	conjBool
	conjK
	conjTrue
)

type conjunct struct {
	kind conjunctKind
	n    int
}

type extractedDef struct {
	module string
	header string
	body   []string
}

var (
	defLine     = regexp.MustCompile(`^def (\S+) `)
	gateEqLine  = regexp.MustCompile(`^∃gate_\d+, gate_\d+ = `)
	vectorLine  = regexp.MustCompile(`^∃gate_\d+ : List\.Vector F (\d+), -- hint`)
	rangeLine   = regexp.MustCompile(`^RangeCheck (\d+) `)
	checkDefKey = regexp.MustCompile(`^(CheckPolynomial|Lazy)_(\d+)_h([0-9a-f]{8})$`)
)

func parseExtractedDefs(modules map[string]string) map[string]extractedDef {
	defs := map[string]extractedDef{}
	for module, source := range modules {
		var current string
		for _, raw := range strings.Split(source, "\n") {
			if m := defLine.FindStringSubmatch(raw); m != nil {
				current = m[1]
				defs[current] = extractedDef{module: module, header: strings.TrimSpace(raw)}
				continue
			}
			line := strings.TrimSpace(raw)
			if line == "" || strings.HasPrefix(raw, "opaque") || strings.HasPrefix(raw, "abbrev") || strings.HasPrefix(raw, "end ") {
				if line == "" {
					current = ""
				}
				continue
			}
			if current != "" {
				d := defs[current]
				d.body = append(d.body, line)
				defs[current] = d
			}
		}
	}
	return defs
}

// conjuncts follows the continuation parts of a definition and returns its
// non-equation conjuncts in order, together with the part names.
func conjuncts(defs map[string]extractedDef, name string) ([]conjunct, []string, error) {
	var seq []conjunct
	parts := []string{name}
	partCall := regexp.MustCompile(`^(` + regexp.QuoteMeta(name) + `_p\d+) `)
	current := name
	for {
		next := ""
		for _, line := range defs[current].body {
			l := strings.TrimSpace(strings.TrimSuffix(line, " ∧"))
			switch {
			case gateEqLine.MatchString(l):
			case vectorLine.MatchString(line):
				n, _ := strconv.Atoi(vectorLine.FindStringSubmatch(line)[1])
				seq = append(seq, conjunct{conjVector, n})
			case rangeLine.MatchString(l):
				n, _ := strconv.Atoi(rangeLine.FindStringSubmatch(l)[1])
				seq = append(seq, conjunct{conjRange, n})
			case strings.HasPrefix(l, "Gates.eq "):
				seq = append(seq, conjunct{kind: conjEq})
			case strings.HasPrefix(l, "Gates.is_bool "):
				seq = append(seq, conjunct{kind: conjBool})
			case strings.HasPrefix(l, "k "):
				seq = append(seq, conjunct{kind: conjK})
			case l == "True":
				seq = append(seq, conjunct{kind: conjTrue})
			case partCall.MatchString(l):
				next = partCall.FindStringSubmatch(l)[1]
			default:
				return nil, nil, fmt.Errorf("%s: unexpected line %q", current, l)
			}
		}
		if next == "" {
			return seq, parts, nil
		}
		parts = append(parts, next)
		current = next
	}
}

func nbPieces(pb, w int) int { return (w + pb - 1) / pb }

func pieceBits(pb, w int) []int {
	var out []int
	for r := w; r > 0; r -= pb {
		out = append(out, min(pb, r))
	}
	return out
}

type instanceWriter struct {
	b         strings.Builder
	seq       []conjunct
	pos       int
	pattern   []string
	vecNames  [][]string
	vecIdx    [][]int
	atomCount int
	facts     int
	err       error
}

func (w *instanceWriter) take(kind conjunctKind, n int) {
	if w.err != nil {
		return
	}
	if w.pos >= len(w.seq) || w.seq[w.pos].kind != kind || (kind != conjEq && kind != conjBool && kind != conjK && kind != conjTrue && w.seq[w.pos].n != n) {
		got := "end"
		if w.pos < len(w.seq) {
			got = fmt.Sprintf("%v", w.seq[w.pos])
		}
		w.err = fmt.Errorf("conjunct %d: expected kind %d/%d, got %s", w.pos, kind, n, got)
		return
	}
	w.pos++
}

func (w *instanceWriter) vector(n int) int {
	w.take(conjVector, n)
	i := len(w.vecNames)
	var names []string
	var idx []int
	for j := 0; j < n; j++ {
		names = append(names, fmt.Sprintf("(g%d.get (%d : Fin %d))", i, j, n))
		idx = append(idx, w.atomCount+j)
	}
	w.atomCount += n
	w.vecNames = append(w.vecNames, names)
	w.vecIdx = append(w.vecIdx, idx)
	w.pattern = append(w.pattern, fmt.Sprintf("g%d", i))
	return i
}

func (w *instanceWriter) fact(kind conjunctKind, n int) string {
	w.take(kind, n)
	name := fmt.Sprintf("h%d", w.facts)
	w.facts++
	w.pattern = append(w.pattern, name)
	return name
}

type rangeCheckPlan struct {
	kind string
	vec  int
	rcs  []string
	eq   string
	fact string
}

func (w *instanceWriter) check(pb, bits int) rangeCheckPlan {
	switch {
	case bits > pb:
		v := w.vector(nbPieces(pb, bits))
		var rcs []string
		for _, b := range pieceBits(pb, bits) {
			rcs = append(rcs, w.pieceFact(b))
		}
		return rangeCheckPlan{kind: "big", vec: v, rcs: rcs, eq: w.fact(conjEq, 0)}
	case bits == 1:
		return rangeCheckPlan{kind: "bool", fact: w.fact(conjBool, 0)}
	default:
		return rangeCheckPlan{kind: "small", fact: w.fact(conjRange, bits)}
	}
}

func (w *instanceWriter) pieceFact(b int) string {
	if b == 1 {
		return w.fact(conjBool, 0)
	}
	return w.fact(conjRange, b)
}

func joinInt(v []int) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = strconv.Itoa(x)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

type limbLayout struct {
	xs, xsAtoms, iss string
	atoms            []string
	n                int
}

func layoutFor(r emfield.CheckRecord) limbLayout {
	var l limbLayout
	total := 0
	for _, e := range r.Elements {
		total += len(e.Lo)
	}
	var xs, xa, is []string
	for _, e := range r.Elements {
		var a, b, c []string
		for range e.Lo {
			atom := fmt.Sprintf("(L.get (%d : Fin %d))", l.n, total)
			a = append(a, fmt.Sprintf("L.get %d", l.n))
			b = append(b, atom)
			c = append(c, strconv.Itoa(l.n))
			l.atoms = append(l.atoms, atom)
			l.n++
		}
		xs = append(xs, "["+strings.Join(a, ", ")+"]")
		xa = append(xa, "["+strings.Join(b, ", ")+"]")
		is = append(is, "["+strings.Join(c, ", ")+"]")
	}
	l.xs = "[" + strings.Join(xs, ", ") + "]"
	l.xsAtoms = "[" + strings.Join(xa, ", ") + "]"
	l.iss = "[" + strings.Join(is, ", ") + "]"
	return l
}

func (w *instanceWriter) line(format string, args ...any) {
	fmt.Fprintf(&w.b, format+"\n", args...)
}

func groupedFacts(pb int, widths []int, rcs []string) string {
	var groups []string
	k := 0
	for _, wd := range widths {
		n := nbPieces(pb, wd)
		if n > 1 {
			groups = append(groups, "⟨"+strings.Join(rcs[k:k+n], ", ")+"⟩")
		} else {
			groups = append(groups, rcs[k])
		}
		k += n
	}
	return tupleOf(groups)
}

// consEqChain8 proves an equation between two eight-element lists elementwise.
const consEqChain8 = "refine List.cons_eq_cons.mpr ⟨by ex_refl, List.cons_eq_cons.mpr ⟨by ex_refl, List.cons_eq_cons.mpr ⟨by ex_refl, " +
	"List.cons_eq_cons.mpr ⟨by ex_refl, List.cons_eq_cons.mpr ⟨by ex_refl, List.cons_eq_cons.mpr ⟨by ex_refl, " +
	"List.cons_eq_cons.mpr ⟨by ex_refl, List.cons_eq_cons.mpr ⟨by ex_refl, rfl⟩⟩⟩⟩⟩⟩⟩⟩"

func tupleOf(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return "⟨" + strings.Join(items, ", ") + "⟩"
}

func (w *instanceWriter) emitCheck(p rangeCheckPlan, pb int, cert, indent string) {
	switch p.kind {
	case "big":
		names := w.vecNames[p.vec]
		w.line("%srefine lookupCheck_big_of (by decide) [%s] ?_ ?_ %s ?_", indent, strings.Join(names, ", "), p.eq)
		w.line("%s· simp (config := {decide := true}) only [ComposeOk, SmallCheck, LookupCheck, %s, if_true, if_false,", indent, cert)
		w.line("%s    true_and, and_true]", indent)
		w.line("%s  exact %s", indent, tupleOf(p.rcs))
		w.line("%s· ex_refl", indent)
		w.line("%s· rw [show composeValue %d [%s] = (eComposeValue %d ((%s : List ℕ).map Ex.atom)).eval env", indent, pb, strings.Join(names, ", "), pb, joinInt(w.vecIdx[p.vec]))
		w.line("%s    from composeValue_atomsE env %d %s]", indent, pb, joinInt(w.vecIdx[p.vec]))
		w.line("%s  symm; ex_refl", indent)
	case "bool":
		w.line("%srefine lookupCheck_bool_of (by decide) ?_ %s", indent, p.fact)
		w.line("%sex_refl", indent)
	default:
		w.line("%srefine lookupCheck_small_of (by decide) ?_ %s", indent, p.fact)
		w.line("%sex_refl", indent)
	}
}

func (w *instanceWriter) destructure(lay limbLayout, parts []string) {
	w.line("  delta %s at h", parts[0])
	w.line("  elim_gates h")
}

func renderCheckInstance(defs map[string]extractedDef, name string, r emfield.CheckRecord) (string, error) {
	seq, parts, err := conjuncts(defs, name)
	if err != nil {
		return "", err
	}
	lay := layoutFor(r)
	cert := recordName(r)
	pb := r.PieceBits
	withResult := r.Kind == emfield.KindEval
	w := &instanceWriter{seq: seq, atomCount: lay.n}
	var hint int = -1
	var hintRcs []string
	nrem := 0
	if withResult {
		for _, wd := range r.ResultWidths {
			nrem += nbPieces(pb, wd)
		}
	}
	nq := 0
	if !r.Folded {
		for _, wd := range r.QuotientWidths {
			nq += nbPieces(pb, wd)
		}
	}
	if nrem+nq > 0 {
		hint = w.vector(nrem + nq)
		var bits []int
		if withResult {
			for _, wd := range r.ResultWidths {
				bits = append(bits, pieceBits(pb, wd)...)
			}
		}
		if !r.Folded {
			for _, wd := range r.QuotientWidths {
				bits = append(bits, pieceBits(pb, wd)...)
			}
		}
		for _, b := range bits {
			hintRcs = append(hintRcs, w.pieceFact(b))
		}
	}
	var quotient rangeCheckPlan
	if r.Folded {
		quotient = w.check(pb, r.QuotientBits)
	}
	native := ""
	if !r.Folded && !r.CheckTop {
		native = w.fact(conjEq, 0)
	}
	var groups []rangeCheckPlan
	for _, g := range r.CarryGroups {
		groups = append(groups, w.check(pb, g.CarryBits+1))
	}
	top := ""
	if r.CheckTop {
		top = w.fact(conjEq, 0)
	}
	if withResult {
		w.take(conjK, 0)
		w.pattern = append(w.pattern, "hk")
	} else {
		w.take(conjTrue, 0)
		w.pattern = append(w.pattern, "-")
	}
	if w.err == nil && w.pos != len(seq) {
		w.err = fmt.Errorf("%d unmatched conjuncts", len(seq)-w.pos)
	}
	if w.err != nil {
		return "", fmt.Errorf("%s: %w", name, w.err)
	}
	kParam, kApp, kWrap := "", "", "(fun _ => True)"
	if withResult {
		kParam, kApp, kWrap = " (k : List.Vector F 8 → Prop)", " k", "(fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)"
	}
	w.line("theorem %s_mirror (L : List.Vector F %d)%s (h : %s L%s) :", name, lay.n, kParam, name, kApp)
	w.line("    CheckPolynomial.circuit basis %s %s (LookupCheck RangeCheck 11)", cert, lay.xs)
	w.line("      %s := by", kWrap)
	w.destructure(lay, parts)
	w.line("  obtain ⟨%s⟩ := h", strings.Join(w.pattern, ", "))
	atoms := append([]string{}, lay.atoms...)
	for _, names := range w.vecNames {
		atoms = append(atoms, names...)
	}
	w.line("  let env : ℕ → F := fun i => [%s].getD i 0", strings.Join(atoms, ", "))
	w.line("  show CheckPolynomial.circuit basis %s %s _ _", cert, lay.xsAtoms)
	w.line("  rw [show %s = (%s : List (List ℕ)).map (fun is => is.map env) from rfl,", lay.xsAtoms, lay.iss)
	w.line("    ← evalLE_atoms env]")
	var prp, pqp []int
	if hint >= 0 {
		prp = w.vecIdx[hint][:nrem]
		pqp = w.vecIdx[hint][nrem:]
	}
	w.line("  apply circuit_of_exs env basis %s _ ((%s : List ℕ).map Ex.atom) ((%s : List ℕ).map Ex.atom)", cert, joinInt(prp), joinInt(pqp))
	pieces := func(names []string, rcs []string, widths []int) {
		w.line("  · show PiecesOk _ _ _ _")
		w.line("    rw [evalE_atoms]")
		w.line("    show PiecesOk _ _ _ [%s]", strings.Join(names, ", "))
		w.line("    simp (config := {decide := true}) only [PiecesOk, nbPieces, %s, List.take, List.drop, List.length_cons,", cert)
		w.line("      List.length_nil, Nat.reduceAdd, Nat.reduceSub, Nat.reduceDiv, ComposeOk, LookupCheck, SmallCheck,")
		w.line("      if_true, if_false, true_and, and_true]")
		w.line("    exact %s", groupedFacts(pb, widths, rcs))
	}
	if withResult {
		pieces(w.vecNames[hint][:nrem], hintRcs[:nrem], r.ResultWidths)
	} else {
		w.line("  · rfl")
	}
	if !r.Folded {
		pieces(w.vecNames[hint][nrem:], hintRcs[nrem:], r.QuotientWidths)
	} else {
		w.line("  · rfl")
	}
	if r.Folded {
		w.line("  · intro _")
		w.emitCheck(quotient, pb, cert, "    ")
	} else {
		w.line("  · intro h; exact absurd h (by decide)")
	}
	if native != "" {
		w.line("  · intro _")
		w.line("    refine eq_zero_of ?_ %s", native)
		w.line("    ex_refl")
	} else {
		w.line("  · intro h; exact absurd h (by decide)")
	}
	w.line("  · rw [show %s.groups = [%s] from rfl]", cert, strings.Join(carryGroupLiterals(r), ", "))
	w.line("    simp only [carryChainE]")
	for _, g := range groups {
		w.line("    refine ⟨?_, ?_⟩")
		var sub instanceWriter
		sub.vecNames, sub.vecIdx = w.vecNames, w.vecIdx
		sub.emitCheck(g, pb, cert, "      ")
		text := strings.TrimRight(sub.b.String(), "\n")
		lines := strings.Split(text, "\n")
		lines[0] = "    · " + strings.TrimLeft(lines[0], " ")
		for _, l := range lines {
			w.line("%s", l)
		}
	}
	if top != "" {
		w.line("    refine ⟨fun _ => eq_zero_of ?_ %s, ?_⟩", top)
		w.line("    · ex_refl")
	} else {
		w.line("    refine ⟨fun h => absurd h (by decide), ?_⟩")
	}
	if withResult {
		w.line("    refine ⟨_, ?_, hk⟩")
		w.line("    simp only [%s, if_true, eLimbsOfPieces, nbPieces, List.take, List.drop, List.map, evalE,", cert)
		w.line("      Option.some.injEq, Nat.reduceAdd, Nat.reduceSub, Nat.reduceDiv]")
		w.line("    %s", consEqChain8)
	} else {
		w.line("    trivial")
	}
	w.line("")
	if withResult {
		w.line("theorem %s_sound (hl : LookupSound RangeCheck 11) (es : List (Σ w, ElemVal w))", name)
		w.line("    (hb : ElemsMatch es %s.elems) (L : List.Vector F %d) (hxs : limbLists es = %s)", cert, lay.n, lay.xs)
		w.line("    {k : List.Vector F 8 → Prop} (h : %s L k) : EvalSound %s es k :=", name, cert)
		w.line("  eval_instance_sound basis %s basis_sound %s_sound rfl hl es hb hxs (%s_mirror L k h)", cert, cert, name)
	} else {
		w.line("theorem %s_sound (hl : LookupSound RangeCheck 11) (es : List (Σ w, ElemVal w))", name)
		w.line("    (hb : ElemsMatch es %s.elems) (L : List.Vector F %d) (hxs : limbLists es = %s)", cert, lay.n, lay.xs)
		w.line("    (h : %s L) : %s.exprValue (values es) ≡ 0 [ZMOD %s.m] :=", name, cert, cert)
		w.line("  assertZero_instance_sound basis %s basis_sound %s_sound rfl hl es hb hxs (%s_mirror L h)", cert, cert, name)
	}
	return w.b.String(), nil
}

func renderLazyInstance(defs map[string]extractedDef, name string, r emfield.CheckRecord) (string, error) {
	seq, parts, err := conjuncts(defs, name)
	if err != nil {
		return "", err
	}
	if len(seq) != 1 || seq[0].kind != conjK {
		return "", fmt.Errorf("%s: lazy definition has constraints", name)
	}
	lay := layoutFor(r)
	c := recordName(r)
	w := &instanceWriter{}
	w.line("theorem %s_mirror (L : List.Vector F %d) (k : List.Vector F 8 → Prop) (h : %s L k) :", name, lay.n, name)
	w.line("    Lazy.circuit basis %s %s (fun o => ∃ v : List.Vector F 8, o = v.toList ∧ k v) := by", c, lay.xs)
	w.destructure(lay, parts)
	w.line("  let env : ℕ → F := fun i => [%s].getD i 0", strings.Join(lay.atoms, ", "))
	w.line("  show Lazy.circuit basis %s %s _", c, lay.xsAtoms)
	w.line("  rw [show %s = (%s : List (List ℕ)).map (fun is => is.map env) from rfl,", lay.xsAtoms, lay.iss)
	w.line("    ← evalLE_atoms env]")
	w.line("  refine ⟨_, ?_, h⟩")
	w.line("  rw [map_exprVal_eq]")
	w.line("  simp only [limbCount, List.range, List.range.loop, List.map]")
	w.line("  %s", consEqChain8)
	w.line("")
	w.line("theorem %s_sound (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es %s.elems)", name, c)
	w.line("    (L : List.Vector F %d) (hxs : limbLists es = %s)", lay.n, lay.xs)
	w.line("    {k : List.Vector F 8 → Prop} (h : %s L k) : LazySound %s es k :=", name, c)
	w.line("  lazy_instance_sound basis %s basis_sound %s_sound es hb hxs (%s_mirror L k h)", c, c, name)
	return w.b.String(), nil
}

// foldedAssertCompletenessRecord selects the literal arithmetic model supported
// by foldedAssert_of_expr. Input arity and individual element widths come from
// the actual record, including one-limb flags. Every selected native primitive
// is separately matched against its extracted conjunct sequence.
func chainCompletenessRecord(name string, r emfield.CheckRecord) bool {
	if !strings.HasPrefix(name, "CheckPolynomial_48_") || r.Kind != emfield.KindAssertZero ||
		!r.Folded || r.CheckTop || r.PieceBits != 11 || r.LimbBits != 32 ||
		len(r.Elements) != 6 || len(r.CarryGroups) != 1 {
		return false
	}
	for _, e := range r.Elements {
		if len(e.Lo) != 8 || len(e.Hi) != 8 {
			return false
		}
	}
	return true
}

func foldedAssertCompletenessRecord(name string, r emfield.CheckRecord) bool {
	if !strings.HasPrefix(name, "CheckPolynomial_") || r.Kind != emfield.KindAssertZero ||
		!r.Folded || r.CheckTop || r.PieceBits != 11 || r.LimbBits != 32 ||
		len(r.ResultWidths) != 8 || len(r.CarryGroups) == 0 {
		return false
	}
	for _, width := range r.ResultWidths {
		if width != 32 {
			return false
		}
	}
	return true
}

// constructFoldedGates emits ordinary proof terms, retaining the native gate
// DAG in local lets. Only the current extracted continuation is unfolded.
// This avoids substituting the entire existential circuit into one simp goal.
type foldedGateResult struct {
	pieces, vector, continuation string
	ranges                       []string
}

func constructFoldedGates(w *instanceWriter, defs map[string]extractedDef, parts []string,
	plans []rangeCheckPlan, prefixes []string, facts [][]string, expressions, modelLets []string,
	result ...foldedGateResult) error {
	type obligation struct {
		kind  conjunctKind
		proof string
		plan  int
	}
	var obligations []obligation
	if len(result) > 1 {
		return fmt.Errorf("%s: multiple constructive result vectors", parts[0])
	}
	if len(result) == 1 {
		if len(result[0].ranges) != 24 || result[0].pieces == "" || result[0].vector == "" || result[0].continuation == "" {
			return fmt.Errorf("%s: malformed constructive remainder", parts[0])
		}
		obligations = append(obligations, obligation{conjVector, result[0].pieces, -1})
		for _, fact := range result[0].ranges {
			obligations = append(obligations, obligation{conjRange, fact, -1})
		}
	}
	for i, p := range plans {
		if p.kind == "big" {
			obligations = append(obligations, obligation{conjVector, "p" + prefixes[i], -1})
			for _, f := range facts[i] {
				kind := conjRange
				if w.seq[len(obligations)].kind == conjBool {
					kind = conjBool
				}
				obligations = append(obligations, obligation{kind, f, -1})
			}
			obligations = append(obligations, obligation{conjEq, "h" + prefixes[i] + "Ref", i})
		} else {
			kind := conjRange
			if p.kind == "bool" {
				kind = conjBool
			}
			obligations = append(obligations, obligation{kind, "h" + prefixes[i] + "Ref", i})
		}
	}
	gate := regexp.MustCompile(`^∃(gate_\d+), (gate_\d+) = (.+)$`)
	hint := regexp.MustCompile(`^∃(gate_\d+) : List\.Vector F \d+, -- hint`)
	limbs := regexp.MustCompile(`\bLimbs\b`)
	var locals []string
	index := 0
	for partIndex, part := range parts {
		w.line("  unfold %s", part)
		for _, raw := range defs[part].body {
			line := strings.TrimSpace(strings.TrimSuffix(raw, " ∧"))
			line = limbs.ReplaceAllString(line, "L")
			if m := gate.FindStringSubmatch(line); m != nil {
				if m[1] != m[2] {
					return fmt.Errorf("%s: nonfunctional constructive gate", part)
				}
				w.line("  let %s : F := %s", m[1], m[3])
				w.line("  refine ⟨%s, rfl, ?_⟩", m[1])
				locals = append(locals, m[1])
				continue
			}
			if partIndex+1 < len(parts) && strings.HasPrefix(line, parts[partIndex+1]+" ") {
				continue
			}
			if line == "True" {
				if index != len(obligations) || partIndex != len(parts)-1 || len(result) != 0 {
					return fmt.Errorf("%s: premature constructive endpoint", part)
				}
				w.line("  trivial")
				continue
			}
			if strings.HasPrefix(line, "k vec![") {
				if index != len(obligations) || partIndex != len(parts)-1 || len(result) != 1 {
					return fmt.Errorf("%s: unmatched constructive result continuation", part)
				}
				output := strings.TrimPrefix(line, "k ")
				w.line("  have nativeOutput : %s = %s := by", output, result[0].vector)
				w.line("    apply List.Vector.toList_injective")
				unfolds := append(append([]string{}, locals...), "Gates", "GatesGnark12", "GatesGnark9", "GatesGnark8", "GatesDef.add", "GatesDef.mul", "remainder24_output")
				w.line("    dsimp only [%s]", strings.Join(unfolds, ", "))
				w.line("    simp only [mul_one, zero_add]")
				w.line("  rw [nativeOutput]")
				w.line("  exact %s", result[0].continuation)
				continue
			}
			if index >= len(obligations) {
				return fmt.Errorf("%s: extra constructive obligation %q", part, line)
			}
			o := obligations[index]
			index++
			if m := hint.FindStringSubmatch(line); m != nil {
				if o.kind != conjVector {
					return fmt.Errorf("%s: unmatched constructive hint", part)
				}
				w.line("  let %s := %s", m[1], o.proof)
				w.line("  refine ⟨%s, ?_⟩", m[1])
				locals = append(locals, m[1])
				continue
			}
			actualKind := conjRange
			if strings.HasPrefix(line, "Gates.eq ") {
				actualKind = conjEq
			} else if strings.HasPrefix(line, "Gates.is_bool ") {
				actualKind = conjBool
			} else if !rangeLine.MatchString(line) {
				return fmt.Errorf("%s: unsupported constructive constraint %q", part, line)
			}
			if actualKind != o.kind {
				return fmt.Errorf("%s: constructive constraint order mismatch", part)
			}
			w.line("  have nativeFact%d : %s := by", index, line)
			if o.plan < 0 {
				w.line("    exact %s", o.proof)
			} else {
				unfolds := append(append([]string{}, locals...), "Gates", "GatesGnark12", "GatesGnark9", "GatesGnark8", "GatesDef.add", "GatesDef.mul", "GatesDef.eq")
				tokens := strings.Fields(line)
				if len(tokens) != 3 && !(actualKind == conjBool && len(tokens) == 2) {
					return fmt.Errorf("%s: non-atomic constructive constraint operands", part)
				}
				left := tokens[len(tokens)-1]
				if plans[o.plan].kind == "big" {
					left = tokens[1]
				}
				w.line("    have nativeEq : (%s).eval env = %s := by", expressions[o.plan], left)
				w.line("      dsimp only [%s]", strings.Join(append(append([]string{}, unfolds...), modelLets...), ", "))
				w.line("      ex_refl")
				if plans[o.plan].kind == "big" {
					w.line("    have piecesEq : composeValue 11 p%s.toList = %s := by", prefixes[o.plan], tokens[2])
					w.line("      dsimp only [%s]", strings.Join(unfolds, ", "))
					w.line("      rcases p%s with ⟨ps, hlen⟩", prefixes[o.plan])
					w.line("      match ps, hlen with")
					var atoms []string
					for j := range w.vecNames[plans[o.plan].vec] {
						atoms = append(atoms, fmt.Sprintf("a%d", j))
					}
					w.line("      | [%s], _ => norm_num [composeValue, evalAt, List.Vector.get, List.Vector.head, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod] <;> ring", strings.Join(atoms, ", "))
					w.line("    exact (nativeEq.symm.trans %s).trans piecesEq", o.proof)
				} else {
					predicate := "RangeCheck " + tokens[1]
					if actualKind == conjBool {
						predicate = "GatesDef.is_bool"
					}
					w.line("    exact Eq.mp (congrArg (%s) nativeEq) %s", predicate, o.proof)
				}
			}
			w.line("  refine ⟨nativeFact%d, ?_⟩", index)
		}
	}
	if index != len(obligations) {
		return fmt.Errorf("%s: missing constructive obligations", parts[0])
	}
	return nil
}

func renderFoldedAssertCompleteness(defs map[string]extractedDef, name string, r emfield.CheckRecord) (string, error) {
	if r.QuotientBits < 1 {
		return "", fmt.Errorf("%s: zero-width quotient needs an equality constructor", name)
	}
	seq, parts, err := conjuncts(defs, name)
	if err != nil {
		return "", err
	}
	lay := layoutFor(r)
	w := &instanceWriter{seq: seq, atomCount: lay.n}
	// Parse all actual range forms, including a direct lookup, Boolean, or
	// arbitrarily long hint vector. No piece-count limit is imposed.
	qp := w.check(11, r.QuotientBits)
	plans := []rangeCheckPlan{qp}
	widths := []int{r.QuotientBits}
	prefixes := []string{"q"}
	pos := 0
	for i, g := range r.CarryGroups {
		if g.Start != pos || g.End <= g.Start || g.End > r.Positions {
			return "", fmt.Errorf("%s: discontinuous folded carry layout", name)
		}
		plans = append(plans, w.check(11, g.CarryBits+1))
		widths = append(widths, g.CarryBits+1)
		prefixes = append(prefixes, fmt.Sprintf("c%d", i))
		pos = g.End
	}
	if pos != r.CarryPositions {
		return "", fmt.Errorf("%s: folded carry endpoint mismatch", name)
	}
	w.take(conjTrue, 0)
	if w.err != nil {
		return "", fmt.Errorf("%s reverse bridge: %w", name, w.err)
	}
	if w.pos != len(seq) {
		return "", fmt.Errorf("%s: unmatched reverse-bridge conjuncts", name)
	}
	cert := recordName(r)
	groups := carryGroupLiterals(r)
	w.line("theorem %s_of_model (L : List.Vector F %d)", name, lay.n)
	w.line("    (h : CheckPolynomial.circuit basis %s %s", cert, lay.xs)
	w.line("      (LookupCheck RangeCheck 11) (fun _ => True)) : %s L := by", name)
	w.line("  unfold CheckPolynomial.circuit at h")
	w.line("  obtain ⟨rp, qp, hrp, hqp, h⟩ := h")
	w.line("  have hr : rp = [] := hrp")
	w.line("  have hq : qp = [] := hqp")
	w.line("  subst rp")
	w.line("  subst qp")
	w.line("  let q := CheckPolynomial.foldQuotient basis %s %s []", cert, lay.xs)
	w.line("  let res := CheckPolynomial.residual basis %s %s [] [] q", cert, lay.xs)
	var carryNames, eCarryNames []string
	for i, g := range r.CarryGroups {
		prev := "0"
		if i > 0 {
			prev = carryNames[i-1]
		}
		carry := fmt.Sprintf("carry%d", i)
		carryNames = append(carryNames, carry)
		w.line("  let %s := (sumRange %d (fun j => res (%d + j) * pow32 j) + %s) *", carry, g.End-g.Start, g.Start, prev)
		w.line("    ((%s : CarryGroup).inv : F)", groups[i])
	}
	w.line("  have hqModel : LookupCheck RangeCheck 11 %d (q + (%s : F)) := h.1 rfl", r.QuotientBits, leanInt(r.Offset))
	w.line("  have hcChain := h.2.2")
	for i, g := range r.CarryGroups {
		w.line("  change LookupCheck RangeCheck 11 %d (%s + (2 : F) ^ %d) ∧ _ at hcChain", g.CarryBits+1, carryNames[i], g.CarryBits)
		w.line("  obtain ⟨hc%dModel, hcChain⟩ := hcChain", i)
	}
	var facts [][]string
	refExpressions := make([]string, len(plans))
	for i, p := range plans {
		prefix, width := prefixes[i], widths[i]
		if p.kind == "big" {
			n := len(w.vecNames[p.vec])
			w.line("  obtain ⟨p%s, hp%s, h%sValue⟩ :=", prefix, prefix, prefix)
			w.line("    lookupCheck_vector_pieces %d %d (by decide) (by decide) _ h%sModel", width, n, prefix)
			var fs []string
			for j, bits := range pieceBits(11, width) {
				fact := fmt.Sprintf("h%s_%d", prefix, j)
				fs = append(fs, fact)
				pred := fmt.Sprintf("RangeCheck %d", bits)
				if bits == 1 {
					pred = "GatesDef.is_bool"
				}
				w.line("  have %s : %s (p%s.get %d) := by", fact, pred, prefix, j)
				w.line("    simpa [SmallCheck] using hp%s (%d : Fin %d)", prefix, j, n)
			}
			facts = append(facts, fs)
		} else {
			pred := fmt.Sprintf("RangeCheck %d", width)
			if p.kind == "bool" {
				pred = "GatesDef.is_bool"
			}
			value := fmt.Sprintf("q + (%s : F)", leanInt(r.Offset))
			if i > 0 {
				value = fmt.Sprintf("%s + (2 : F) ^ %d", carryNames[i-1], r.CarryGroups[i-1].CarryBits)
			}
			w.line("  have h%sDirect : %s (%s) := by", prefix, pred, value)
			w.line("    simpa [LookupCheck, SmallCheck] using h%sModel", prefix)
			facts = append(facts, nil)
		}
	}
	w.line("  let env : ℕ → F := fun i => [%s].getD i 0", strings.Join(lay.atoms, ", "))
	w.line("  let pxs : List (List Ex) := (%s : List (List ℕ)).map (fun is => is.map Ex.atom)", lay.iss)
	w.line("  have hxs : evalLE pxs env = %s := rfl", lay.xs)
	w.line("  let eq := eFoldQuotient basis %s pxs []", cert)
	w.line("  let er := eResidual basis %s pxs [] [] eq", cert)
	for i := range r.CarryGroups {
		eCarry := fmt.Sprintf("ec%d", i)
		prev := ".zero"
		if i > 0 {
			prev = eCarryNames[i-1]
		}
		eCarryNames = append(eCarryNames, eCarry)
		w.line("  let %s := eCarry er %s %s", eCarry, groups[i], prev)
	}
	for i, p := range plans {
		prefix := prefixes[i]
		expr := fmt.Sprintf("Ex.add eq (.lit %s)", leanInt(r.Offset))
		value := fmt.Sprintf("q + (%s : F)", leanInt(r.Offset))
		if i > 0 {
			expr = fmt.Sprintf("Ex.add %s (.lit (2 ^ %d))", eCarryNames[i-1], r.CarryGroups[i-1].CarryBits)
			value = fmt.Sprintf("%s + (2 : F) ^ %d", carryNames[i-1], r.CarryGroups[i-1].CarryBits)
		}
		refExpressions[i] = expr
		w.line("  have h%sEval : (%s).eval env = %s := by", prefix, expr, value)
		if i == 0 {
			w.line("    simp only [Ex.eval, eq, eval_eFoldQuotient, hxs] <;> rfl")
		} else {
			w.line("    simp only [Ex.eval, %s, eCarry, eval_eSumRange, eval_ePow32,", strings.Join(eCarryNames[:i], ", "))
			w.line("      er, eval_eResidual, eq, eval_eFoldQuotient, hxs, evalE, List.map_nil] <;> rfl")
		}
		if p.kind == "big" {
			w.line("  have h%sRef : (%s).eval env = composeValue 11 p%s.toList := by", prefix, expr, prefix)
			w.line("    rw [h%sEval]", prefix)
			w.line("    exact h%sValue", prefix)
		} else {
			pred := fmt.Sprintf("RangeCheck %d", widths[i])
			if p.kind == "bool" {
				pred = "GatesDef.is_bool"
			}
			w.line("  have h%sRef : %s ((%s).eval env) := by", prefix, pred, expr)
			w.line("    rw [h%sEval]", prefix)
			w.line("    exact h%sDirect", prefix)
		}
	}
	modelLets := append([]string{"eq", "er", "pxs"}, eCarryNames...)
	if err := constructFoldedGates(w, defs, parts, plans, prefixes, facts, refExpressions, modelLets); err != nil {
		return "", err
	}
	w.line("")
	w.line("theorem %s_quotient_lower :", name)
	w.line("    foldedMagnitude basis %s ≤ (%s.offset : ℤ) * %s.m := by", cert, cert, cert)
	w.line("  decide +kernel")
	w.line("")
	w.line("theorem %s_quotient_upper :", name)
	w.line("    foldedMagnitude basis %s <", cert)
	w.line("      ((2 : ℤ) ^ %s.quotientBits - %s.offset) * %s.m := by", cert, cert, cert)
	w.line("  decide +kernel")
	w.line("")
	w.line("theorem %s_carry_capacity :", name)
	w.line("    CarryCapacity (%s.residualBound basis) %s.positions", cert, cert)
	w.line("      %s.carryPositions %s.groups 0 none := by", cert, cert)
	w.line("  change CarryCapacity (%s.residualBound basis) %d %d [%s] 0 none", cert, r.Positions, r.CarryPositions, strings.Join(groups, ", "))
	for range r.CarryGroups {
		w.line("  refine CarryCapacity.cons _ _ _ _ rfl (by norm_num) (by norm_num)")
		w.line("    (by norm_num) (by decide +kernel) (by decide +kernel) ?_")
	}
	w.line("  exact CarryCapacity.nil _")
	w.line("")
	w.line("theorem %s_complete (es : List (Σ w, ElemVal w))", name)
	w.line("    (hb : ElemsMatch es %s.elems) (L : List.Vector F %d)", cert, lay.n)
	w.line("    (hxs : limbLists es = %s)", lay.xs)
	w.line("    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))")
	w.line("    (hzero : %s.exprValue (values es) ≡ 0 [ZMOD (%s.m : ℤ)]) : %s L := by", cert, cert, name)
	w.line("  apply %s_of_model L", name)
	w.line("  rw [← hxs]")
	w.line("  exact foldedAssert_of_expr basis %s basis_sound %s_sound", cert, cert)
	w.line("    rfl rfl rfl rfl (by norm_num [%s]) %s_quotient_lower", cert, name)
	w.line("    %s_quotient_upper %s_carry_capacity hl es hb hzero _ trivial", name, name)
	w.line("")
	return w.b.String(), nil
}

func renderLazyCompleteness(defs map[string]extractedDef, name string, r emfield.CheckRecord) (string, error) {
	seq, parts, err := conjuncts(defs, name)
	if err != nil {
		return "", err
	}
	if len(seq) != 1 || seq[0].kind != conjK {
		return "", fmt.Errorf("%s: lazy constructor has nonfunctional constraints", name)
	}
	lay := layoutFor(r)
	c := recordName(r)
	type pureGate struct {
		part, name, expression string
	}
	gatePattern := regexp.MustCompile(`^∃(gate_\d+), (gate_\d+) = (.+)$`)
	limbsPattern := regexp.MustCompile(`\bLimbs\b`)
	var gates []pureGate
	partInputs := map[string][]string{parts[0]: nil}
	gateNamePattern := regexp.MustCompile(`^gate_\d+$`)
	output := ""
	for partIndex, part := range parts {
		for _, raw := range defs[part].body {
			line := strings.TrimSpace(strings.TrimSuffix(raw, " ∧"))
			line = limbsPattern.ReplaceAllString(line, "L")
			if m := gatePattern.FindStringSubmatch(line); m != nil {
				if m[1] != m[2] || output != "" {
					return "", fmt.Errorf("%s: malformed functional gate order", part)
				}
				gates = append(gates, pureGate{part, m[1], m[3]})
				continue
			}
			if partIndex+1 < len(parts) && strings.HasPrefix(line, parts[partIndex+1]+" ") {
				args := strings.Fields(line)
				if len(args) < 3 || args[1] != "L" || args[len(args)-1] != "k" {
					return "", fmt.Errorf("%s: unsupported functional fragment arguments", part)
				}
				for _, arg := range args[2 : len(args)-1] {
					if !gateNamePattern.MatchString(arg) {
						return "", fmt.Errorf("%s: non-scalar functional fragment argument %s", part, arg)
					}
				}
				if _, exists := partInputs[parts[partIndex+1]]; exists {
					return "", fmt.Errorf("%s: repeated functional fragment continuation", part)
				}
				partInputs[parts[partIndex+1]] = args[2 : len(args)-1]
				continue
			}
			if strings.HasPrefix(line, "k vec![") && partIndex == len(parts)-1 && output == "" {
				output = strings.TrimPrefix(line, "k ")
				continue
			}
			return "", fmt.Errorf("%s: unsupported functional continuation %q", part, line)
		}
	}
	if output == "" {
		return "", fmt.Errorf("%s: missing functional output", name)
	}
	w := &instanceWriter{}
	// Each existing native fragment gets a closed constructive witness and
	// continuation-preservation proof. Keeping its pure DAG local bounds the
	// elaborator information context; no new tactic or target-success premise.
	for pi := len(parts) - 1; pi >= 0; pi-- {
		part := parts[pi]
		inputs, exists := partInputs[part]
		if !exists {
			return "", fmt.Errorf("%s: missing functional fragment parameters", part)
		}
		expectedHeader := fmt.Sprintf("def %s (Limbs: List.Vector F %d)", part, lay.n)
		for _, input := range inputs {
			expectedHeader += fmt.Sprintf(" (%s: F)", input)
		}
		expectedHeader += " (k: List.Vector F 8 -> Prop): Prop :="
		if defs[part].header != expectedHeader {
			return "", fmt.Errorf("%s: functional fragment header does not match continuation arguments", part)
		}
		binder := ""
		args := ""
		if len(inputs) != 0 {
			binder = fmt.Sprintf(" (%s : F)", strings.Join(inputs, " "))
			args = " " + strings.Join(inputs, " ")
		}
		w.line("theorem %s_witness (L : List.Vector F %d)%s :", part, lay.n, binder)
		w.line("    ∃ out : List.Vector F 8, %s L%s (fun v => v = out) := by", part, args)
		for _, gate := range gates {
			if gate.part == part {
				w.line("  let %s : F := %s", gate.name, gate.expression)
			}
		}
		if pi+1 == len(parts) {
			w.line("  let out : List.Vector F 8 := %s", output)
		} else {
			next := parts[pi+1]
			w.line("  obtain ⟨out, hout⟩ := %s_witness L %s", next, strings.Join(partInputs[next], " "))
		}
		w.line("  refine ⟨out, ?_⟩")
		w.line("  unfold %s", part)
		for _, gate := range gates {
			if gate.part == part {
				w.line("  refine ⟨%s, rfl, ?_⟩", gate.name)
			}
		}
		if pi+1 == len(parts) {
			w.line("  rfl")
		} else {
			w.line("  exact hout")
		}
		w.line("")
		w.line("theorem %s_mono (L : List.Vector F %d)%s {k k' : List.Vector F 8 → Prop}", part, lay.n, binder)
		w.line("    (hk : ∀ out, k out → k' out) (h : %s L%s k) : %s L%s k' := by", part, args, part, args)
		w.line("  unfold %s at h ⊢", part)
		for _, gate := range gates {
			if gate.part == part {
				w.line("  obtain ⟨%s, h%s, h⟩ := h", gate.name, gate.name)
				w.line("  refine ⟨%s, h%s, ?_⟩", gate.name, gate.name)
			}
		}
		if pi+1 == len(parts) {
			w.line("  exact hk _ h")
		} else {
			next := parts[pi+1]
			w.line("  exact %s_mono L %s hk h", next, strings.Join(partInputs[next], " "))
		}
		w.line("")
	}
	w.line("theorem %s_complete (es : List (Σ w, ElemVal w))", name)
	w.line("    (hb : ElemsMatch es %s.elems) (L : List.Vector F %d)", c, lay.n)
	w.line("    (hxs : limbLists es = %s) :", lay.xs)
	w.line("    ∃ out : ElemVal 8, out.bnd = ⟨%s.outLo, %s.outHi, %s.outVlo, %s.outVhi⟩ ∧", c, c, c, c)
	w.line("      out.value ≡ %s.exprValue (values es) [ZMOD (%s.m : ℤ)] ∧", c, c)
	w.line("      ∀ k : List.Vector F 8 → Prop, k out.limbs → %s L k := by", name)
	w.line("  obtain ⟨v, hv⟩ := %s_witness L", name)
	w.line("  obtain ⟨out, hlo, hhi, hvlo, hvhi, he, hvalue⟩ := %s_sound es hb L hxs hv", name)
	w.line("  refine ⟨out, ?_, hvalue, ?_⟩")
	w.line("  · simp [ElemVal.bnd, hlo, hhi, hvlo, hvhi]")
	w.line("  · intro k hk")
	w.line("    apply %s_mono L _ hv", name)
	w.line("    intro o ho")
	w.line("    rw [ho, ← he]")
	w.line("    exact hk")
	w.line("")
	return w.b.String(), nil
}

// chainCompositionBindings reads only the native fixed-base chain wrapper.
// The arithmetic primitive calls remain premises of a composition lemma;
// the separately generated constructors discharge them from mathematics.
// Unexpected constraints fail closed rather than being ignored.
func chainCompositionBindings(d extractedDef, name string) (string, string, bool, error) {
	check := regexp.MustCompile(`^(CheckPolynomial_(32|48)_h[0-9a-f]{8}) vec!\[`)
	lazy := regexp.MustCompile(`^(Lazy_24_h[0-9a-f]{8}) vec!\[`)
	var slope, update string
	vectors, ranges, continuations := 0, 0, 0
	for _, line := range d.body {
		l := strings.TrimSpace(strings.TrimSuffix(line, " ∧"))
		switch {
		case vectorLine.MatchString(line):
			n, _ := strconv.Atoi(vectorLine.FindStringSubmatch(line)[1])
			if n != 24 || vectors >= 2 {
				return "", "", false, fmt.Errorf("%s: unexpected composition hint", name)
			}
			vectors++
		case gateEqLine.MatchString(l):
		case rangeLine.MatchString(l):
			n, _ := strconv.Atoi(rangeLine.FindStringSubmatch(l)[1])
			want := 11
			if ranges%3 == 2 {
				want = 10
			}
			if n != want || ranges >= 24 {
				return "", "", false, fmt.Errorf("%s: unexpected composition range", name)
			}
			ranges++
		case check.MatchString(l):
			m := check.FindStringSubmatch(l)
			if m[2] == "32" {
				// The first step has a different y formula and its hand bridge.
				return "", "", false, nil
			}
			if slope != "" {
				return "", "", false, fmt.Errorf("%s: multiple slope primitives", name)
			}
			slope = m[1]
		case lazy.MatchString(l):
			if update != "" {
				return "", "", false, fmt.Errorf("%s: multiple lazy primitives", name)
			}
			update = lazy.FindStringSubmatch(l)[1]
		case strings.HasPrefix(l, "k vec!["):
			continuations++
		default:
			return "", "", false, fmt.Errorf("%s: unexpected composition line %q", name, l)
		}
	}
	if vectors != 2 || ranges != 24 || slope == "" || update == "" || continuations != 1 {
		return "", "", false, fmt.Errorf("%s: incomplete composition layout", name)
	}
	return slope, update, true, nil
}

func renderChainComposition(name, slope, update string) string {
	w := &instanceWriter{}
	w.line("/-- Composition only: the slope and lazy premises are discharged by the")
	w.line("separate arithmetic constructors in the outer mathematical witness proof. -/")
	w.line("theorem %s_compose", name)
	w.line("    (X PreviousSlope PreviousWindowX PreviousWindowY WindowX WindowY FirstWindowY Lambda : List.Vector F 8)")
	w.line("    (raw pieces : List.Vector F 24)")
	w.line("    (hr : ∀ i : Fin 8, RangeCheck 11 (pieces.get ⟨3 * i.val, by omega⟩) ∧")
	w.line("      RangeCheck 11 (pieces.get ⟨3 * i.val + 1, by omega⟩) ∧")
	w.line("      RangeCheck 10 (pieces.get ⟨3 * i.val + 2, by omega⟩))")
	w.line("    (hLambda : ∀ i : Fin 8, Lambda.get i =")
	w.line("      pieces.get ⟨3 * i.val, by omega⟩ + pieces.get ⟨3 * i.val + 1, by omega⟩ * 2048 +")
	w.line("      pieces.get ⟨3 * i.val + 2, by omega⟩ * 4194304 - 2147483648)")
	w.line("    (k : List.Vector (List.Vector F 8) 2 → Prop)")
	w.line("    (hs : %s (chainCompositionSlopeInput Lambda X PreviousSlope PreviousWindowX WindowX WindowY PreviousWindowY))", slope)
	w.line("    (hn : %s (chainCompositionLazyInput Lambda X WindowX)", update)
	w.line("      (fun out => k (out ::ᵥ Lambda ::ᵥ List.Vector.nil))) :")
	w.line("    %s X PreviousSlope PreviousWindowX PreviousWindowY WindowX WindowY FirstWindowY k := by", name)
	for i := 0; i < 8; i++ {
		w.line("  have h%d := hLambda (%d : Fin 8)", i, i)
	}
	for i := 0; i < 8; i++ {
		w.line("  change Lambda.get %d = pieces.get %d + pieces.get %d * 2048 + pieces.get %d * 4194304 - 2147483648 at h%d", i, 3*i, 3*i+1, 3*i+2, i)
	}
	w.line("  unfold %s", name)
	w.line("  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,")
	w.line("    GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left]")
	proofs := []string{"raw", "pieces"}
	for i := 0; i < 8; i++ {
		proofs = append(proofs, fmt.Sprintf("(hr %d).1", i), fmt.Sprintf("(hr %d).2.1", i), fmt.Sprintf("(hr %d).2.2", i))
	}
	proofs = append(proofs, "?_", "?_")
	w.line("  refine %s", tupleOf(proofs))
	for i := 0; i < 2; i++ {
		w.line("  · simp only [mul_one, zero_add]")
		w.line("    rw [← h0, ← h1, ← h2, ← h3, ← h4, ← h5, ← h6, ← h7]")
		if i == 0 {
			w.line("    simpa only [chainCompositionSlopeInput, sub_eq_add_neg, mul_neg_one] using hs")
		} else {
			w.line("    simpa only [chainCompositionLazyInput, vec8_eta] using hn")
		}
	}
	w.line("")
	return w.b.String()
}

func renderCompleteChainStep(name, slope, update, cert, lazy string) string {
	w := &instanceWriter{}
	w.line("theorem %s_slope_match (L X L0 PWX PWY WX WY : ElemVal 8)", name)
	w.line("    (hL : L.bnd = balC) (hX : X.bnd = %s.elems.getD 1 default)", lazy)
	w.line("    (hL0 : L0.bnd = %s.elems.getD 2 default) (hPWX : PWX.bnd = reducedC)", cert)
	w.line("    (hPWY : PWY.bnd = %s.elems.getD 5 default)", cert)
	w.line("    (hWX : WX.bnd = %s.elems.getD 2 default) (hWY : WY.bnd = %s.elems.getD 4 default) :", lazy, cert)
	w.line("    ElemsMatch [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, X)]⟩, ⟨8, L0⟩,")
	w.line("      ⟨8, linElem [(1, PWX), (-1, X)]⟩, ⟨8, WY⟩, ⟨8, PWY⟩] %s.elems := by", cert)
	w.line("  apply elemsMatch_of")
	w.line("  show [L.bnd, (linElem [(1, WX), (-1, X)]).bnd, L0.bnd,")
	w.line("    (linElem [(1, PWX), (-1, X)]).bnd, WY.bnd, PWY.bnd] = _")
	w.line("  rw [linElem_bnd, linElem_bnd]")
	w.line("  simp only [List.map]")
	w.line("  rw [hL, hX, hL0, hPWX, hPWY, hWX, hWY]")
	w.line("  rfl")
	w.line("")
	w.line("theorem %s_lazy_match (L X WX : ElemVal 8)", name)
	w.line("    (hL : L.bnd = balC) (hX : X.bnd = %s.elems.getD 1 default)", lazy)
	w.line("    (hWX : WX.bnd = %s.elems.getD 2 default) :", lazy)
	w.line("    ElemsMatch [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩] %s.elems :=", lazy)
	w.line("  elemsMatch_of (by show [L.bnd, X.bnd, WX.bnd] = _; rw [hL, hX, hWX]; rfl)")
	w.line("")
	w.line("theorem %s_lazy_complete (L X WX : ElemVal 8)", name)
	w.line("    (hL : L.bnd = balC) (hX : X.bnd = %s.elems.getD 1 default)", lazy)
	w.line("    (hWX : WX.bnd = %s.elems.getD 2 default) :", lazy)
	w.line("    ∃ NX : ElemVal 8, NX.bnd = ⟨%s.outLo, %s.outHi, %s.outVlo, %s.outVhi⟩ ∧", lazy, lazy, lazy, lazy)
	w.line("      NX.value ≡ L.value * L.value - X.value - WX.value [ZMOD p] ∧")
	w.line("      ∀ k : List.Vector F 8 → Prop, k NX.limbs →")
	w.line("        %s (chainCompositionLazyInput L.limbs X.limbs WX.limbs) k := by", update)
	w.line("  exact combLazy_arithmetic %s rfl rfl L X WX %s", lazy, update)
	w.line("    (fun k => %s_eq _ k)", lazy)
	w.line("    (fun k h => %s_sound _ (%s_lazy_match L X WX hL hX hWX)", update, name)
	w.line("      _ (combLazy_layout L X WX) h)")
	w.line("")
	w.line("/-- A complete individual step from finite noncolliding mathematical")
	w.line("points, literal input bounds, and small-table completeness. All primitive")
	w.line("constraints are constructed; no subgadget success is a premise. -/")
	w.line("theorem %s_complete (hr : RangeComplete) (X L0 PWX PWY WX WY : ElemVal 8)", name)
	w.line("    (hX : X.bnd = %s.elems.getD 1 default)", lazy)
	w.line("    (hL0 : L0.bnd = %s.elems.getD 2 default) (hPWX : PWX.bnd = reducedC)", cert)
	w.line("    (hPWY : PWY.bnd = %s.elems.getD 5 default)", cert)
	w.line("    (hWX : WX.bnd = %s.elems.getD 2 default) (hWY : WY.bnd = %s.elems.getD 4 default)", lazy, cert)
	w.line("    (hA : OnCurve (X.value : Fp) ((L0.value * (PWX.value - X.value) - PWY.value : ℤ) : Fp))")
	w.line("    (hW : OnCurve (WX.value : Fp) (WY.value : Fp))")
	w.line("    (hne : mkPoint hA ≠ mkPoint hW ∧ mkPoint hA ≠ -mkPoint hW) :")
	w.line("    ∃ NX L : ElemVal 8, NX.bnd = ⟨%s.outLo, %s.outHi, %s.outVlo, %s.outVhi⟩ ∧", lazy, lazy, lazy, lazy)
	w.line("      L.bnd = balC ∧")
	w.line("      ChainRel X.value L0.value PWX.value PWY.value WX.value WY.value L.value NX.value ∧")
	w.line("      (∃ hN : OnCurve (NX.value : Fp) ((L.value * (WX.value - NX.value) - WY.value : ℤ) : Fp),")
	w.line("        mkPoint hN = mkPoint hA + mkPoint hW) ∧")
	w.line("      ∀ (firstY : List.Vector F 8) (k : List.Vector (List.Vector F 8) 2 → Prop),")
	w.line("        k (NX.limbs ::ᵥ L.limbs ::ᵥ List.Vector.nil) →")
	w.line("        %s X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs firstY k := by", name)
	w.line("  obtain ⟨l, hz, hgroup⟩ := combChain_slope_math X L0 PWX PWY WX WY hA hW hne")
	w.line("  let L := slopeElem l")
	w.line("  have hbS := %s_slope_match L X L0 PWX PWY WX WY rfl hX hL0 hPWX hPWY hWX hWY", name)
	w.line("  have hs := %s_complete _ hbS", slope)
	w.line("    (chainCompositionSlopeInput L.limbs X.limbs L0.limbs PWX.limbs WX.limbs WY.limbs PWY.limbs)")
	w.line("    (combSecondSlope_layout L X L0 PWX PWY WX WY) hr")
	w.line("    (combChain_slope_expr %s rfl rfl L X L0 PWX WY PWY WX hz)", cert)
	w.line("  obtain ⟨NX, hNX, vNX, hactual⟩ := %s_lazy_complete L X WX rfl hX hWX", name)
	w.line("  obtain ⟨rel, hN⟩ := hgroup NX vNX")
	w.line("  refine ⟨NX, L, hNX, rfl, rel, hN, ?_⟩")
	w.line("  intro firstY k hk")
	w.line("  apply %s_compose X.limbs L0.limbs PWX.limbs PWY.limbs WX.limbs WY.limbs firstY L.limbs", name)
	w.line("    (rawSlopePieces l) (slopePieces l) (slopePieces_ranges hr l) (slopePieces_limb l) k hs")
	w.line("  exact hactual (fun out => k (out ::ᵥ L.limbs ::ᵥ List.Vector.nil)) hk")
	w.line("")
	return w.b.String()
}

type quadComposition struct {
	parts     []string
	rangeCuts []int
	checks    []string
	lazies    []string
	middle    bool
}

// quadCompositionBindings traverses the actual continuation fragments. It
// validates every nonfunctional constraint before emitting a composition-only
// bridge. The eventual Lean proof checks all arithmetic wiring against the
// supplied primitive inputs; an unrecognised constraint is never discarded.
func quadCompositionBindings(defs map[string]extractedDef, name string) (quadComposition, error) {
	q := quadComposition{}
	partCall := regexp.MustCompile(`^(` + regexp.QuoteMeta(name) + `_p\d+) `)
	check := regexp.MustCompile(`^(CheckPolynomial_(\d+)_h[0-9a-f]{8}) vec!\[`)
	lazy := regexp.MustCompile(`^(Lazy_(\d+)_h[0-9a-f]{8}) vec!\[`)
	isZero := regexp.MustCompile(`^∃gate_\d+, Gates\.is_zero `)
	vectors, ranges, zeros, continuations := 0, 0, 0, 0
	current := name
	seen := map[string]bool{}
	for current != "" {
		if seen[current] {
			return q, fmt.Errorf("%s: cyclic quad continuation", name)
		}
		seen[current] = true
		d, ok := defs[current]
		if !ok {
			return q, fmt.Errorf("%s: missing quad fragment %s", name, current)
		}
		q.parts = append(q.parts, current)
		next := ""
		for _, line := range d.body {
			l := strings.TrimSpace(strings.TrimSuffix(line, " ∧"))
			switch {
			case vectorLine.MatchString(line):
				n, _ := strconv.Atoi(vectorLine.FindStringSubmatch(line)[1])
				if n != 24 || vectors >= 6 {
					return q, fmt.Errorf("%s: unexpected quad hint", name)
				}
				vectors++
			case gateEqLine.MatchString(l):
			case rangeLine.MatchString(l):
				n, _ := strconv.Atoi(rangeLine.FindStringSubmatch(l)[1])
				want := 11
				if ranges%3 == 2 {
					want = 10
				}
				if n != want || ranges >= 72 {
					return q, fmt.Errorf("%s: unexpected quad range", name)
				}
				ranges++
			case check.MatchString(l):
				m := check.FindStringSubmatch(l)
				n, _ := strconv.Atoi(m[2])
				index := len(q.checks)
				valid := (index < 2 && n == 32) || (index == 2 && (n == 48 || n == 49)) || (index == 3 && n == 40)
				if !valid {
					return q, fmt.Errorf("%s: unexpected quad check primitive", name)
				}
				if index == 2 {
					q.middle = n == 49
				}
				q.checks = append(q.checks, m[1])
			case lazy.MatchString(l):
				m := lazy.FindStringSubmatch(l)
				n, _ := strconv.Atoi(m[2])
				index := len(q.lazies)
				valid := (index == 0 && n == 16) || (index >= 1 && index <= 3 && n == 24) || (index == 4 && n == 40)
				if !valid {
					return q, fmt.Errorf("%s: unexpected quad lazy primitive", name)
				}
				q.lazies = append(q.lazies, m[1])
			case isZero.MatchString(l):
				zeros++
			case strings.HasPrefix(l, "k vec!["):
				continuations++
			case partCall.MatchString(l):
				if next != "" {
					return q, fmt.Errorf("%s: multiple quad continuations", name)
				}
				next = partCall.FindStringSubmatch(l)[1]
			default:
				return q, fmt.Errorf("%s: unexpected quad composition line %q", current, l)
			}
		}
		q.rangeCuts = append(q.rangeCuts, ranges)
		current = next
	}
	if vectors != 6 || ranges != 72 || len(q.checks) != 4 || len(q.lazies) != 5 || continuations != 1 ||
		(q.middle && zeros != 1) || (!q.middle && zeros != 0) {
		return q, fmt.Errorf("%s: incomplete quad composition layout", name)
	}
	if len(q.parts) != 3 || q.rangeCuts[0] <= 24 || q.rangeCuts[0] >= 48 ||
		q.rangeCuts[1] <= 48 || q.rangeCuts[1] > 72 || q.rangeCuts[2] != 72 {
		return q, fmt.Errorf("%s: unsupported quad fragment cuts %v", name, q.rangeCuts)
	}
	return q, nil
}

func renderQuadInputHelpers() string {
	w := &instanceWriter{}
	w.line("def quadCompositionA : List.Vector F 8 :=")
	w.line("  vec![4294967292, 4294967295, 4294967295, 0, 0, 0, 1, 4294967295]")
	w.line("")
	type input struct {
		name, params string
		runs         []string
		flag         bool
	}
	inputs := []input{
		{"quadTangentInput", "L AY AX", []string{"L.get %d", "AY.get %d", "AX.get %d", "quadCompositionA.get %d"}, false},
		{"quadDoubleXInput", "L AX", []string{"L.get %d", "AX.get %d"}, false},
		{"quadDoubleYInput", "L AX DX AY", []string{"L.get %d", "AX.get %d - DX.get %d", "AY.get %d"}, false},
		{"quadChordInput", "M SX DX SY DY", []string{"M.get %d", "SX.get %d - DX.get %d", "SY.get %d", "DY.get %d"}, false},
		{"quadFlagInput", "M DY SY DX SX", []string{"M.get %d", "DY.get %d + SY.get %d", "DX.get %d + SX.get %d", "DX.get %d", "SX.get %d", "quadCompositionA.get %d"}, true},
		{"quadLastInput", "M DY SY DX SX", []string{"M.get %d", "DY.get %d + SY.get %d", "DX.get %d + SX.get %d", "DX.get %d", "SX.get %d", "quadCompositionA.get %d"}, false},
		{"quadIntermediateInput", "M DX SX", []string{"M.get %d", "DX.get %d", "SX.get %d"}, false},
		{"quadSecondInput", "N IX DX M SX SY", []string{"N.get %d", "IX.get %d - DX.get %d", "M.get %d", "SX.get %d - DX.get %d", "SY.get %d"}, false},
		{"quadOutXInput", "N M SX", []string{"N.get %d", "N.get %d + 2 * M.get %d", "SX.get %d"}, false},
		{"quadOutYInput", "M N OX DX SX SY", []string{"M.get %d + N.get %d", "OX.get %d - DX.get %d", "M.get %d", "SX.get %d - DX.get %d", "SY.get %d"}, false},
	}
	for _, in := range inputs {
		var atoms []string
		flagParam := ""
		if in.flag {
			flagParam = " (b : Bool)"
			atoms = append(atoms, "(if b then 1 else 0)")
		}
		for _, run := range in.runs {
			for i := 0; i < 8; i++ {
				args := make([]any, strings.Count(run, "%d"))
				for j := range args {
					args[j] = i
				}
				atoms = append(atoms, fmt.Sprintf(run, args...))
			}
		}
		w.line("def %s%s (%s : List.Vector F 8) : List.Vector F %d :=", in.name, flagParam, in.params, len(atoms))
		w.line("  vec![%s]", strings.Join(atoms, ", "))
		w.line("")
	}
	w.line("def quadNativeValue (L : List.Vector F 8) : F :=")
	w.line("  L.get 0 + L.get 1 * 4294967296 + L.get 2 * K_390 + L.get 3 * K_391 +")
	w.line("    L.get 4 * K_392 + L.get 5 * K_393 + L.get 6 * K_394 + L.get 7 * K_395")
	w.line("")
	w.line("def quadNativeProduct (L : List.Vector F 8) (hs : F) : F :=")
	w.line("  let v := quadNativeValue L")
	w.line("  ((v - hs) * ((v - hs) * (v - hs) - K_1176)) *")
	w.line("    ((v + hs) * ((v + hs) * (v + hs) - K_1176))")
	w.line("")
	return w.b.String()
}

func renderQuadComposition(name string, q quadComposition) string {
	w := &instanceWriter{}
	w.line("/-- Composition only. All hints, ranges and primitive continuations are")
	w.line("explicit; the mathematical constructor must supply every premise. -/")
	w.line("theorem %s_compose (AX AY SX SY : List.Vector F 8) (hs : F)", name)
	w.line("    (L M N DX DY IX OX OY : List.Vector F 8)")
	if q.middle {
		w.line("    (b : Bool)")
	}
	w.line("    (rawL rawM rawN piecesL piecesM piecesN : List.Vector F 24)")
	for _, s := range []string{"L", "M", "N"} {
		w.line("    (hr%s : ∀ i : Fin 8, RangeCheck 11 (pieces%s.get ⟨3 * i.val, by omega⟩) ∧", s, s)
		w.line("      RangeCheck 11 (pieces%s.get ⟨3 * i.val + 1, by omega⟩) ∧", s)
		w.line("      RangeCheck 10 (pieces%s.get ⟨3 * i.val + 2, by omega⟩))", s)
	}
	for _, s := range []string{"L", "M", "N"} {
		w.line("    (h%s : ∀ i : Fin 8, %s.get i =", s, s)
		w.line("      pieces%s.get ⟨3 * i.val, by omega⟩ + pieces%s.get ⟨3 * i.val + 1, by omega⟩ * 2048 +", s, s)
		w.line("      pieces%s.get ⟨3 * i.val + 2, by omega⟩ * 4194304 - 2147483648)", s)
	}
	if q.middle {
		w.line("    (hzero : GatesDef.is_zero (quadNativeProduct L hs) (if b then 1 else 0))")
	}
	w.line("    (hTangent : %s (quadTangentInput L AY AX))", q.checks[0])
	w.line("    (hChord : %s (quadChordInput M SX DX SY DY))", q.checks[1])
	if q.middle {
		w.line("    (hFallback : %s (quadFlagInput b M DY SY DX SX))", q.checks[2])
	} else {
		w.line("    (hFallback : %s (quadLastInput M DY SY DX SX))", q.checks[2])
	}
	w.line("    (hSecond : %s (quadSecondInput N IX DX M SX SY))", q.checks[3])
	helpers := []string{"quadDoubleXInput L AX", "quadDoubleYInput L AX DX AY", "quadIntermediateInput M DX SX", "quadOutXInput N M SX", "quadOutYInput M N OX DX SX SY"}
	helperNames := []string{"quadDoubleXInput", "quadDoubleYInput", "quadIntermediateInput", "quadOutXInput", "quadOutYInput"}
	outNames := []string{"DX", "DY", "IX", "OX", "OY"}
	for i, out := range outNames {
		w.line("    (h%s : ∀ k : List.Vector F 8 → Prop, k %s → %s (%s) k)", out, out, q.lazies[i], helpers[i])
	}
	w.line("    (k : List.Vector (List.Vector F 8) 2 → Prop) (hk : k (OX ::ᵥ OY ::ᵥ List.Vector.nil)) :")
	w.line("    %s AX AY SX SY hs k := by", name)
	var limbFacts []string
	for _, s := range []string{"L", "M", "N"} {
		for i := 0; i < 8; i++ {
			fact := fmt.Sprintf("h%s%d", s, i)
			limbFacts = append(limbFacts, fact)
			w.line("  have %s := h%s (%d : Fin 8)", fact, s, i)
		}
	}
	w.line("  simp only [sub_eq_add_neg, mul_comm] at %s", strings.Join(limbFacts, " "))
	for _, s := range []string{"L", "M", "N"} {
		for i := 0; i < 8; i++ {
			w.line("  change %s.get %d = pieces%s.get %d + 2048 * pieces%s.get %d + 4194304 * pieces%s.get %d + -(2147483648 : F) at h%s%d", s, i, s, 3*i, s, 3*i+1, s, 3*i+2, s, i)
		}
	}
	for i, out := range outNames {
		w.line("  have h%sNative := h%s", out, out)
		w.line("  simp only [%s, sub_eq_add_neg, mul_comm] at h%sNative", helperNames[i], out)
	}
	if q.middle {
		w.line("  have hzeroNative := hzero")
		w.line("  simp only [quadNativeProduct, quadNativeValue, sub_eq_add_neg, mul_comm] at hzeroNative")
	}
	w.line("  unfold %s", q.parts[0])
	nativeWireSimp(w, "  ")
	partIndex, rangeIndex := 1, 0
	hints := func(s, indent string) {
		items := []string{"raw" + s, "pieces" + s}
		projections := []string{".1", ".2.1", ".2.2"}
		for i := 0; i < 24; i++ {
			items = append(items, fmt.Sprintf("(hr%s %d)%s", s, i/3, projections[i%3]))
			rangeIndex++
			if partIndex < len(q.parts) && rangeIndex == q.rangeCuts[partIndex-1] {
				w.line("%srefine %s", indent, tupleOf(append(items, "?_")))
				w.line("%sunfold %s", indent, q.parts[partIndex])
				nativeWireSimp(w, indent)
				partIndex++
				items = nil
			}
		}
		items = append(items, "?_", "?_")
		w.line("%srefine %s", indent, tupleOf(items))
	}
	rewriteLimbs := func(s, indent string) {
		var rewrites []string
		for i := 0; i < 8; i++ {
			rewrites = append(rewrites, fmt.Sprintf("← h%s%d", s, i))
		}
		w.line("%ssimp only [%s]", indent, strings.Join(rewrites, ", "))
	}
	hints("L", "  ")
	w.line("  ·")
	rewriteLimbs("L", "    ")
	w.line("    simpa only [quadTangentInput, quadCompositionA] using hTangent")
	w.line("  ·")
	rewriteLimbs("L", "    ")
	w.line("    apply hDXNative")
	w.line("    apply hDYNative")
	hints("M", "    ")
	w.line("    ·")
	rewriteLimbs("M", "      ")
	w.line("      simpa only [quadChordInput, sub_eq_add_neg, mul_comm] using hChord")
	w.line("    ·")
	rewriteLimbs("M", "      ")
	indent := "      "
	if q.middle {
		w.line("      refine ⟨(if b then 1 else 0), ?_, ?_, ?_⟩")
		w.line("      · exact hzeroNative")
		w.line("      · simpa only [quadFlagInput, quadCompositionA, sub_eq_add_neg, mul_comm] using hFallback")
		w.line("      ·")
		indent = "        "
	} else {
		w.line("      refine ⟨?_, ?_⟩")
		w.line("      · simpa only [quadLastInput, quadCompositionA, sub_eq_add_neg, mul_comm] using hFallback")
		w.line("      ·")
		indent = "        "
	}
	w.line("%sapply hIXNative", indent)
	hints("N", indent)
	w.line("%s·", indent)
	rewriteLimbs("N", indent+"  ")
	w.line("%s  simpa only [quadSecondInput, sub_eq_add_neg, mul_comm] using hSecond", indent)
	w.line("%s·", indent)
	rewriteLimbs("N", indent+"  ")
	w.line("%s  apply hOXNative", indent)
	w.line("%s  apply hOYNative", indent)
	w.line("%s  exact hk", indent)
	w.line("")
	return w.b.String()
}

// InstanceWeightBudget caps the extracted body lines whose instance proofs
// share one module. Elaboration memory grows with the proofs a module holds;
// the cap keeps every module within a CI runner.
var InstanceWeightBudget = 2500

// instanceModuleFor names the instance module that covers an extracted module:
// VerifiableEncryption.Circuit.Field2 -> VerifiableEncryption.Field.Instances2.
func instanceModuleFor(extracted string) string {
	suffix := strings.TrimPrefix(extracted[strings.LastIndex(extracted, ".")+1:], "Field")
	return "VerifiableEncryption.Field.Instances" + suffix
}

// ExtractEmcurveInstances renders the field soundness instances and the
// fixed-base primitive/composition/completeness proof-source modules,
// keyed by Lean module name. Rendering does not elaborate Lean proofs.
func ExtractEmcurveInstances() (map[string]string, error) {
	checks, err := CollectEmcurveChecks()
	if err != nil {
		return nil, err
	}
	modules, err := extractVE()
	if err != nil {
		return nil, err
	}
	return RenderEmcurveInstances(checks, modules)
}

// RenderEmcurveInstances preserves the soundness modules per extracted field
// module and also emits the separately named completeness proof-source modules.
func RenderEmcurveInstances(checks *EmcurveChecks, modules map[string]string) (map[string]string, error) {
	defs := parseExtractedDefs(modules)
	byKey := map[string]emfield.CheckRecord{}
	for _, r := range checks.Records {
		byKey[r.Key()] = r
	}
	var names []string
	for name := range defs {
		if checkDefKey.MatchString(name) {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	type instance struct {
		text   string
		weight int
	}
	bodies := map[string][]instance{}
	for _, name := range names {
		m := checkDefKey.FindStringSubmatch(name)
		r, ok := byKey[m[3]]
		if !ok {
			return nil, fmt.Errorf("%s: no certificate record", name)
		}
		var text string
		var err error
		if m[1] == "Lazy" {
			text, err = renderLazyInstance(defs, name, r)
		} else {
			text, err = renderCheckInstance(defs, name, r)
		}
		if err != nil {
			return nil, err
		}
		_, parts, err := conjuncts(defs, name)
		if err != nil {
			return nil, err
		}
		weight := 0
		for _, p := range parts {
			weight += len(defs[p].body)
		}
		mod := defs[name].module
		bodies[mod] = append(bodies[mod], instance{text, weight})
	}
	out := map[string]string{}
	for mod, insts := range bodies {
		aggregate := instanceModuleFor(mod)
		var chunks [][]string
		load := 0
		for _, in := range insts {
			if len(chunks) == 0 || (load > 0 && load+in.weight > InstanceWeightBudget) {
				chunks = append(chunks, nil)
				load = 0
			}
			chunks[len(chunks)-1] = append(chunks[len(chunks)-1], in.text)
			load += in.weight
		}
		var agg strings.Builder
		agg.WriteString("-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n")
		for i, texts := range chunks {
			part := fmt.Sprintf("%s_%d", aggregate, i+1)
			fmt.Fprintf(&agg, "import %s\n", part)
			var b strings.Builder
			b.WriteString("import VerifiableEncryption.Field.Certificate\nimport VerifiableEncryption.Field.InstanceKit\n")
			fmt.Fprintf(&b, "import %s\n\n", mod)
			b.WriteString("-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n\n")
			b.WriteString("namespace ZolanaVE\n\nopen ZolanaVE.Field ZolanaVE.EmcurveChecks\n\n")
			b.WriteString("set_option maxHeartbeats 0\nset_option maxRecDepth 100000\n\n")
			b.WriteString(strings.Join(texts, "\n"))
			b.WriteString("\nend ZolanaVE\n")
			out[part] = b.String()
		}
		out[aggregate] = agg.String()
	}
	var complete strings.Builder
	complete.WriteString("import VerifiableEncryption.Field.CompletenessEval\n")
	complete.WriteString("import VerifiableEncryption.Field.CompletenessVector\n\n")
	complete.WriteString("import VerifiableEncryption.Field.Certificate\n")
	complete.WriteString("import VerifiableEncryption.Field.InstanceKit\n")
	for _, mod := range []string{"Field", "Field2", "Field3", "Field4", "Field5", "Field6"} {
		fmt.Fprintf(&complete, "import VerifiableEncryption.Circuit.%s\n", mod)
	}
	complete.WriteString("\n")
	complete.WriteString("-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n")
	complete.WriteString("-- Generation does not perform Lean checking; validation is recorded separately.\n\n")
	complete.WriteString("namespace ZolanaVE.Field\n\nopen ZolanaVE.EmcurveChecks\n\n")
	complete.WriteString("set_option maxHeartbeats 0\nset_option maxRecDepth 100000\n\n")
	completeHeader := complete.String()
	var completeChunks [][]string
	assertLeaf := map[string]string{}
	completeLoad := 0
	for _, name := range names {
		m := checkDefKey.FindStringSubmatch(name)
		r := byKey[m[3]]
		if !foldedAssertCompletenessRecord(name, r) {
			continue
		}
		text, err := renderFoldedAssertCompleteness(defs, name, r)
		if err != nil {
			return nil, err
		}
		_, parts, err := conjuncts(defs, name)
		if err != nil {
			return nil, err
		}
		weight := 0
		for _, part := range parts {
			weight += len(defs[part].body)
		}
		if len(completeChunks) == 0 || (completeLoad > 0 && completeLoad+weight > 1000) {
			completeChunks = append(completeChunks, nil)
			completeLoad = 0
		}
		last := len(completeChunks) - 1
		completeChunks[last] = append(completeChunks[last], text)
		assertLeaf[name] = fmt.Sprintf("VerifiableEncryption.Field.CompletenessGeneratedChain_%d", last+1)
		completeLoad += weight
	}
	var completeAggregate strings.Builder
	completeAggregate.WriteString("-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n")
	for i, texts := range completeChunks {
		part := fmt.Sprintf("VerifiableEncryption.Field.CompletenessGeneratedChain_%d", i+1)
		fmt.Fprintf(&completeAggregate, "import %s\n", part)
		out[part] = completeHeader + strings.Join(texts, "\n") + "\nend ZolanaVE.Field\n"
	}
	out["VerifiableEncryption.Field.CompletenessGeneratedChain"] = completeAggregate.String()
	var lazy strings.Builder
	lazy.WriteString("import VerifiableEncryption.Field.AllInstances\n")
	lazy.WriteString("import VerifiableEncryption.Curve.Elem\n\n")
	lazy.WriteString("-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n")
	lazy.WriteString("-- Generation does not perform Lean checking; validation is recorded separately.\n\n")
	lazy.WriteString("namespace ZolanaVE.Field\n\nopen ZolanaVE.EmcurveChecks\n\n")
	lazy.WriteString("set_option maxHeartbeats 0\nset_option maxRecDepth 100000\n\n")
	lazyHeader := lazy.String()
	var lazyChunks [][]string
	lazyLoad := 0
	for _, name := range names {
		m := checkDefKey.FindStringSubmatch(name)
		r := byKey[m[3]]
		if m[1] != "Lazy" {
			continue
		}
		text, err := renderLazyCompleteness(defs, name, r)
		if err != nil {
			return nil, err
		}
		_, parts, err := conjuncts(defs, name)
		if err != nil {
			return nil, err
		}
		weight := 0
		for _, part := range parts {
			weight += len(defs[part].body)
		}
		if len(lazyChunks) == 0 || lazyLoad+weight > 1000 {
			lazyChunks = append(lazyChunks, nil)
			lazyLoad = 0
		}
		last := len(lazyChunks) - 1
		lazyChunks[last] = append(lazyChunks[last], text)
		lazyLoad += weight
	}
	var lazyAggregate strings.Builder
	lazyAggregate.WriteString("-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n")
	for i, texts := range lazyChunks {
		part := fmt.Sprintf("VerifiableEncryption.Field.CompletenessGeneratedLazy_%d", i+1)
		fmt.Fprintf(&lazyAggregate, "import %s\n", part)
		out[part] = lazyHeader + strings.Join(texts, "\n") + "\nend ZolanaVE.Field\n"
	}
	out["VerifiableEncryption.Field.CompletenessGeneratedLazy"] = lazyAggregate.String()
	var chainNames []string
	chainStepKey := regexp.MustCompile(`^CombChainStep_8_8_8_8_8_8_8_h[0-9a-f]{8}$`)
	for name := range defs {
		if chainStepKey.MatchString(name) {
			chainNames = append(chainNames, name)
		}
	}
	sort.Strings(chainNames)
	var composition strings.Builder
	composition.WriteString("import VerifiableEncryption.Curve.LadderAux\n")
	composition.WriteString("import VerifiableEncryption.Circuit.Curve\n\n")
	composition.WriteString("-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n")
	composition.WriteString("-- Generation does not perform Lean checking; validation is recorded separately.\n\n")
	composition.WriteString("namespace ZolanaVE.P256.Completeness\n\nopen ZolanaVE.Field\n\n")
	composition.WriteString("set_option maxHeartbeats 0\nset_option maxRecDepth 100000\n\n")
	composition.WriteString("def chainCompositionSlopeInput (L X PS PX WX WY PY : List.Vector F 8) : List.Vector F 48 :=\n  vec![")
	var slopeAtoms []string
	for _, expr := range []string{"L.get %d", "WX.get %d - X.get %d", "PS.get %d", "PX.get %d - X.get %d", "WY.get %d", "PY.get %d"} {
		for i := 0; i < 8; i++ {
			if strings.Count(expr, "%d") == 2 {
				slopeAtoms = append(slopeAtoms, fmt.Sprintf(expr, i, i))
			} else {
				slopeAtoms = append(slopeAtoms, fmt.Sprintf(expr, i))
			}
		}
	}
	composition.WriteString(strings.Join(slopeAtoms, ", ") + "]\n\n")
	composition.WriteString("def chainCompositionLazyInput (L X WX : List.Vector F 8) : List.Vector F 24 :=\n  vec![")
	var lazyAtoms []string
	for _, v := range []string{"L", "X", "WX"} {
		for i := 0; i < 8; i++ {
			lazyAtoms = append(lazyAtoms, fmt.Sprintf("%s.get %d", v, i))
		}
	}
	composition.WriteString(strings.Join(lazyAtoms, ", ") + "]\n\n")
	var completeSteps strings.Builder
	completeSteps.WriteString("import VerifiableEncryption.Curve.CompletenessCombMath\n")
	completeSteps.WriteString("import VerifiableEncryption.Curve.CompletenessCombLayout\n")
	completeStepImports := map[string]bool{}
	var completeStepBodies strings.Builder
	completeSteps.WriteString("-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n")
	completeSteps.WriteString("-- Generation does not perform Lean checking; validation is recorded separately.\n\n")
	completeSteps.WriteString("namespace ZolanaVE.P256.Completeness\n\nopen ZolanaVE.Field ZolanaVE.EmcurveChecks\n\n")
	completeSteps.WriteString("set_option maxHeartbeats 0\nset_option maxRecDepth 100000\n\n")
	for _, name := range chainNames {
		slope, update, eligible, err := chainCompositionBindings(defs[name], name)
		if err != nil {
			return nil, err
		}
		if !eligible {
			continue
		}
		if _, ok := defs[slope]; !ok {
			return nil, fmt.Errorf("%s: missing slope definition %s", name, slope)
		}
		if _, ok := defs[update]; !ok {
			return nil, fmt.Errorf("%s: missing lazy definition %s", name, update)
		}
		composition.WriteString(renderChainComposition(name, slope, update))
		mSlope := checkDefKey.FindStringSubmatch(slope)
		mUpdate := checkDefKey.FindStringSubmatch(update)
		rSlope, okSlope := byKey[mSlope[3]]
		rUpdate, okUpdate := byKey[mUpdate[3]]
		if !okSlope || !okUpdate || !chainCompletenessRecord(slope, rSlope) ||
			rUpdate.Kind != emfield.KindLazy || len(rUpdate.Elements) != 3 {
			return nil, fmt.Errorf("%s: missing complete primitive certificate", name)
		}
		leaf, ok := assertLeaf[slope]
		if !ok {
			return nil, fmt.Errorf("%s: missing assertion completeness leaf for %s", name, slope)
		}
		completeStepImports[leaf] = true
		completeStepBodies.WriteString(renderCompleteChainStep(name, slope, update, recordName(rSlope), recordName(rUpdate)))
	}
	composition.WriteString("end ZolanaVE.P256.Completeness\n")
	out["VerifiableEncryption.Curve.CompletenessGeneratedChainComposition"] = composition.String()
	var selectedImports []string
	for mod := range completeStepImports {
		selectedImports = append(selectedImports, mod)
	}
	sort.Strings(selectedImports)
	var importText strings.Builder
	for _, mod := range selectedImports {
		fmt.Fprintf(&importText, "import %s\n", mod)
	}
	header := completeSteps.String()
	importAt := strings.Index(header, "-- GENERATED")
	if importAt < 0 {
		return nil, fmt.Errorf("missing comb completeness header boundary")
	}
	out["VerifiableEncryption.Curve.CompletenessGeneratedCombSteps"] =
		header[:importAt] + importText.String() + "\n" + header[importAt:] +
			completeStepBodies.String() + "end ZolanaVE.P256.Completeness\n"
	var quadNames []string
	quadKey := regexp.MustCompile(`^QuadrupleAndAddLazy_8_8_8_8_h[0-9a-f]{8}$`)
	quadModules := map[string]bool{}
	for name, d := range defs {
		if quadKey.MatchString(name) {
			quadNames = append(quadNames, name)
			quadModules[d.module] = true
		}
	}
	sort.Strings(quadNames)
	var quadImports []string
	for mod := range quadModules {
		quadImports = append(quadImports, mod)
	}
	sort.Strings(quadImports)
	var quads strings.Builder
	quads.WriteString("import VerifiableEncryption.Curve.LadderAux\n")
	for _, mod := range quadImports {
		fmt.Fprintf(&quads, "import %s\n", mod)
	}
	quads.WriteString("\n-- GENERATED by prover/extractor/emcurve_instances.go; do not edit.\n")
	quads.WriteString("-- Quad composition only; all primitive premises must be constructed independently.\n\n")
	quads.WriteString("namespace ZolanaVE.P256.Completeness\n\nopen ZolanaVE.Field\n\n")
	quads.WriteString("set_option maxHeartbeats 0\nset_option maxRecDepth 100000\n\n")
	quads.WriteString(renderQuadInputHelpers())
	for _, name := range quadNames {
		q, err := quadCompositionBindings(defs, name)
		if err != nil {
			return nil, err
		}
		for _, primitive := range append(append([]string{}, q.checks...), q.lazies...) {
			if _, ok := defs[primitive]; !ok {
				return nil, fmt.Errorf("%s: missing quad primitive %s", name, primitive)
			}
		}
		quads.WriteString(renderQuadComposition(name, q))
	}
	quads.WriteString("end ZolanaVE.P256.Completeness\n")
	out["VerifiableEncryption.Curve.CompletenessGeneratedQuadComposition"] = quads.String()
	if err := renderFoldedEvalModules(defs, names, byKey, out); err != nil {
		return nil, err
	}
	if err := renderWholeScalarModules(defs, names, byKey, out); err != nil {
		return nil, err
	}
	nativeCompositions, err := RenderNativeCurveCompositions(defs)
	if err != nil {
		return nil, err
	}
	for module, source := range nativeCompositions {
		if _, exists := out[module]; exists {
			return nil, fmt.Errorf("duplicate native composition module %s", module)
		}
		out[module] = source
	}
	return out, nil
}
