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
				defs[current] = extractedDef{module: module}
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
	atoms          []string
	n              int
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

// ExtractEmcurveInstances renders formal-verification/VerifiableEncryption/Field/Instances*.lean,
// keyed by Lean module name.
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

// RenderEmcurveInstances renders one instance module per extracted field module.
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
	return out, nil
}
