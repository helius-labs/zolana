package extractor

import (
	"fmt"
	"regexp"
	"strings"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// The three scalar checks have a combined remainder/quotient hint followed
// by a native whole equation and carry checks. This renderer reads that exact
// constraint order; it neither executes a hint nor assumes its success.
func wholeScalarRole(name string, r emfield.CheckRecord) string {
	if r.Folded || r.CheckTop || r.PieceBits != 11 || r.LimbBits != 32 {
		return ""
	}
	switch name {
	case "CheckPolynomial_8_h57d6a69c":
		if r.Kind == emfield.KindEval {
			return "scalarEval"
		}
	case "CheckPolynomial_16_h93312e5c":
		if r.Kind == emfield.KindEval {
			return "halfScalarEval"
		}
	case "CheckPolynomial_18_hb0ad1306":
		if r.Kind == emfield.KindAssertZero {
			return "scalarDecomp"
		}
	}
	return ""
}

type wholeGateObligation struct {
	kind  conjunctKind
	n     int
	proof string
	plan  int // -1: initial piece; -2: native whole equation; >=0: carry plan
}

// Replay the functional gate DAG in local lets. Every nonfunctional source
// line must consume exactly one expected obligation of the same kind/size.
// The native whole equation is a separate obligation from every carry range.
func constructWholeGates(w *instanceWriter, defs map[string]extractedDef, parts []string,
	initialCount int, initialBits []int, initialFacts []string,
	plans []rangeCheckPlan, prefixes []string, facts [][]string, expressions, modelLets []string,
	evalResult bool) error {
	if len(initialBits) != initialCount || len(initialFacts) != initialCount {
		return fmt.Errorf("%s: malformed whole hint layout", parts[0])
	}
	obligations := []wholeGateObligation{{kind: conjVector, n: initialCount, proof: "initial", plan: -1}}
	for i, bits := range initialBits {
		if bits < 2 || bits > 11 {
			return fmt.Errorf("%s: unsupported whole initial piece width", parts[0])
		}
		obligations = append(obligations, wholeGateObligation{conjRange, bits, initialFacts[i], -1})
	}
	obligations = append(obligations, wholeGateObligation{kind: conjEq, proof: "hWholeRef", plan: -2})
	for i, plan := range plans {
		if plan.kind == "big" {
			obligations = append(obligations, wholeGateObligation{kind: conjVector,
				n: len(w.vecNames[plan.vec]), proof: "p" + prefixes[i], plan: -1})
			for j, fact := range facts[i] {
				bits := w.seq[len(obligations)].n
				kind := w.seq[len(obligations)].kind
				if kind != conjRange && kind != conjBool {
					return fmt.Errorf("%s: invalid whole carry piece %d", parts[0], j)
				}
				obligations = append(obligations, wholeGateObligation{kind, bits, fact, -1})
			}
			obligations = append(obligations, wholeGateObligation{kind: conjEq, proof: "h" + prefixes[i] + "Ref", plan: i})
		} else {
			kind := conjRange
			if plan.kind == "bool" {
				kind = conjBool
			}
			obligations = append(obligations, wholeGateObligation{kind: kind,
				n: w.seq[len(obligations)].n, proof: "h" + prefixes[i] + "Ref", plan: i})
		}
	}
	gate := regexp.MustCompile(`^∃(gate_\d+), (gate_\d+) = (.+)$`)
	hint := regexp.MustCompile(`^∃(gate_\d+) : List\.Vector F (\d+), -- hint`)
	limbs := regexp.MustCompile(`\bLimbs\b`)
	var locals []string
	index := 0
	ended := false
	for partIndex, part := range parts {
		w.line("  unfold %s", part)
		for _, raw := range defs[part].body {
			line := limbs.ReplaceAllString(strings.TrimSpace(strings.TrimSuffix(raw, " ∧")), "L")
			if ended {
				return fmt.Errorf("%s: source after whole endpoint", part)
			}
			if match := gate.FindStringSubmatch(line); match != nil {
				if match[1] != match[2] {
					return fmt.Errorf("%s: nonfunctional whole gate", part)
				}
				w.line("  let %s : F := %s", match[1], match[3])
				w.line("  refine ⟨%s, rfl, ?_⟩", match[1])
				locals = append(locals, match[1])
				continue
			}
			if partIndex+1 < len(parts) && strings.HasPrefix(line, parts[partIndex+1]+" ") {
				continue
			}
			if line == "True" {
				if evalResult || index != len(obligations) || partIndex != len(parts)-1 {
					return fmt.Errorf("%s: premature whole endpoint", part)
				}
				w.line("  trivial")
				ended = true
				continue
			}
			if strings.HasPrefix(line, "k vec![") {
				if !evalResult || index != len(obligations) || partIndex != len(parts)-1 {
					return fmt.Errorf("%s: unmatched whole output", part)
				}
				w.line("  have nativeOutput : %s = remainder24_output pr := by", strings.TrimPrefix(line, "k "))
				w.line("    apply List.Vector.toList_injective")
				unfolds := append(append([]string{}, locals...), "Gates", "GatesGnark12", "GatesGnark9", "GatesGnark8", "GatesDef.add", "GatesDef.mul", "remainder24_output")
				w.line("    dsimp only [%s]", strings.Join(unfolds, ", "))
				var initialEqualities []string
				for i := 0; i < initialCount; i++ {
					initialEqualities = append(initialEqualities, fmt.Sprintf("hInitial%d", i))
				}
				w.line("    simp only [%s, mul_one, zero_add]", strings.Join(initialEqualities, ", "))
				w.line("  rw [nativeOutput]")
				w.line("  exact hkv")
				ended = true
				continue
			}
			if index >= len(obligations) {
				return fmt.Errorf("%s: extra whole obligation %q", part, line)
			}
			obligation := obligations[index]
			index++
			if match := hint.FindStringSubmatch(line); match != nil {
				if obligation.kind != conjVector || match[2] != fmt.Sprint(obligation.n) {
					return fmt.Errorf("%s: wrong whole hint size/order", part)
				}
				w.line("  let %s := %s", match[1], obligation.proof)
				w.line("  refine ⟨%s, ?_⟩", match[1])
				locals = append(locals, match[1])
				continue
			}
			actualKind := conjRange
			if strings.HasPrefix(line, "Gates.eq ") {
				actualKind = conjEq
			} else if strings.HasPrefix(line, "Gates.is_bool ") {
				actualKind = conjBool
			} else if match := rangeLine.FindStringSubmatch(line); match != nil {
				if match[1] != fmt.Sprint(obligation.n) {
					return fmt.Errorf("%s: wrong whole range width", part)
				}
			} else {
				return fmt.Errorf("%s: unsupported whole constraint %q", part, line)
			}
			if actualKind != obligation.kind {
				return fmt.Errorf("%s: whole constraint order mismatch", part)
			}
			w.line("  have nativeFact%d : %s := by", index, line)
			if obligation.plan == -1 {
				w.line("    exact %s", obligation.proof)
			} else {
				tokens := strings.Fields(line)
				if len(tokens) != 3 && !(actualKind == conjBool && len(tokens) == 2) {
					return fmt.Errorf("%s: nonatomic whole operands", part)
				}
				unfolds := append(append([]string{}, locals...), "Gates", "GatesGnark12", "GatesGnark9", "GatesGnark8", "GatesDef.add", "GatesDef.mul", "GatesDef.eq")
				if obligation.plan == -2 {
					if tokens[2] != "(0:F)" {
						return fmt.Errorf("%s: whole equation has wrong zero operand", part)
					}
					w.line("    have nativeEq : ewhole.eval env = %s := by", tokens[1])
					w.line("      dsimp only [%s]", strings.Join(append(append([]string{}, unfolds...), modelLets...), ", "))
					w.line("      ex_refl")
					w.line("    exact nativeEq.symm.trans hWholeRef")
				} else {
					i := obligation.plan
					left := tokens[len(tokens)-1]
					if plans[i].kind == "big" {
						left = tokens[1]
					}
					w.line("    have nativeEq : (%s).eval env = %s := by", expressions[i], left)
					w.line("      dsimp only [%s]", strings.Join(append(append([]string{}, unfolds...), modelLets...), ", "))
					w.line("      ex_refl")
					if plans[i].kind == "big" {
						w.line("    have piecesEq : composeValue 11 p%s.toList = %s := by", prefixes[i], tokens[2])
						w.line("      dsimp only [%s]", strings.Join(unfolds, ", "))
						w.line("      rcases p%s with ⟨ps, hlen⟩", prefixes[i])
						w.line("      match ps, hlen with")
						var atoms []string
						for j := range w.vecNames[plans[i].vec] {
							atoms = append(atoms, fmt.Sprintf("a%d", j))
						}
						w.line("      | [%s], _ => norm_num [composeValue, evalAt, List.Vector.get, List.Vector.head, Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod] <;> ring", strings.Join(atoms, ", "))
						w.line("    exact (nativeEq.symm.trans %s).trans piecesEq", obligation.proof)
					} else {
						predicate := "RangeCheck " + tokens[1]
						if actualKind == conjBool {
							predicate = "GatesDef.is_bool"
						}
						w.line("    exact Eq.mp (congrArg (%s) nativeEq) %s", predicate, obligation.proof)
					}
				}
			}
			w.line("  refine ⟨nativeFact%d, ?_⟩", index)
		}
	}
	if index != len(obligations) || !ended {
		return fmt.Errorf("%s: missing whole obligations/endpoint", parts[0])
	}
	return nil
}

func renderWholeScalarCompleteness(defs map[string]extractedDef, name string, r emfield.CheckRecord) (string, error) {
	role := wholeScalarRole(name, r)
	if role == "" {
		return "", fmt.Errorf("%s: unsupported whole scalar record", name)
	}
	evalResult := r.Kind == emfield.KindEval
	seq, parts, err := conjuncts(defs, name)
	if err != nil {
		return "", err
	}
	lay := layoutFor(r)
	w := &instanceWriter{seq: seq, atomCount: lay.n}
	remCount := 0
	var initialBits, quotientBits []int
	if evalResult {
		if len(r.ResultWidths) != 8 {
			return "", fmt.Errorf("%s: wrong whole remainder size", name)
		}
		for _, width := range r.ResultWidths {
			if width != 32 {
				return "", fmt.Errorf("%s: wrong whole remainder width", name)
			}
			initialBits = append(initialBits, 11, 11, 10)
		}
		remCount = 24
	}
	for _, width := range r.QuotientWidths {
		quotientBits = append(quotientBits, pieceBits(11, width)...)
	}
	qCount := len(quotientBits)
	if qCount != 1 && qCount != 13 && qCount != 24 {
		return "", fmt.Errorf("%s: unsupported whole quotient layout", name)
	}
	initialBits = append(initialBits, quotientBits...)
	w.vector(len(initialBits))
	for _, bits := range initialBits {
		w.pieceFact(bits)
	}
	w.fact(conjEq, 0)
	var plans []rangeCheckPlan
	var prefixes []string
	pos := 0
	for i, group := range r.CarryGroups {
		if group.Start != pos || group.End <= group.Start || group.End > r.Positions {
			return "", fmt.Errorf("%s: discontinuous whole carries", name)
		}
		plans = append(plans, w.check(11, group.CarryBits+1))
		prefixes = append(prefixes, fmt.Sprintf("c%d", i))
		pos = group.End
	}
	if pos != r.CarryPositions {
		return "", fmt.Errorf("%s: wrong whole carry endpoint", name)
	}
	if evalResult {
		w.take(conjK, 0)
	} else {
		w.take(conjTrue, 0)
	}
	if w.err != nil || w.pos != len(seq) {
		return "", fmt.Errorf("%s: unmatched whole constraints: %v", name, w.err)
	}
	cert := recordName(r)
	groups := carryGroupLiterals(r)
	if evalResult {
		w.line("theorem %s_of_model (L : List.Vector F %d) (k : List.Vector F 8 → Prop)", name, lay.n)
		w.line("    (h : CheckPolynomial.circuit basis %s %s", cert, lay.xs)
		w.line("      (LookupCheck RangeCheck 11) (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) : %s L k := by", name)
	} else {
		w.line("theorem %s_of_model (L : List.Vector F %d)", name, lay.n)
		w.line("    (h : CheckPolynomial.circuit basis %s %s (LookupCheck RangeCheck 11) (fun _ => True)) : %s L := by", cert, lay.xs, name)
	}
	w.line("  unfold CheckPolynomial.circuit at h")
	w.line("  obtain ⟨rp, qp, hrp, hqp, h⟩ := h")
	if evalResult {
		w.line("  obtain ⟨pr, hpr, hrange⟩ := remainder24_pieces rp hrp")
		w.line("  rw [← hpr] at h")
	} else {
		w.line("  have hrNil : rp = [] := hrp")
		w.line("  subst rp")
	}
	if qCount == 24 {
		w.line("  obtain ⟨pq, hpq, hqrange⟩ := remainder24_pieces qp hqp")
	} else {
		w.line("  obtain ⟨pq, hpq, hqrange⟩ := quotient%d_pieces qp hqp", qCount)
	}
	w.line("  rw [← hpq] at h")
	if evalResult {
		w.line("  let rem := limbsOfPieces 11 widths8 pr.toList")
	} else {
		w.line("  let rem : List F := []")
	}
	w.line("  let ql := limbsOfPieces 11 %s.quotientWidths pq.toList", cert)
	w.line("  let res := CheckPolynomial.residual basis %s %s rem ql 0", cert, lay.xs)
	w.line("  have hWholeRaw := h.2.1 ⟨rfl, rfl⟩")
	w.line("  rw [whole_residual_nonfold basis %s _ _ _ _ rfl] at hWholeRaw", cert)
	w.line("  have hWholeModel : sumRange %d (fun j => res j * pow32 j) = 0 := hWholeRaw", r.Positions)
	var carries, eCarries []string
	for i, group := range r.CarryGroups {
		previous := "0"
		if i > 0 {
			previous = carries[i-1]
		}
		carry := fmt.Sprintf("carry%d", i)
		carries = append(carries, carry)
		w.line("  let %s := (sumRange %d (fun j => res (%d + j) * pow32 j) + %s) * ((%s : CarryGroup).inv : F)", carry, group.End-group.Start, group.Start, previous, groups[i])
	}
	w.line("  have hcChain := h.2.2")
	w.line("  rw [whole_residual_nonfold basis %s _ _ _ _ rfl] at hcChain", cert)
	for i, group := range r.CarryGroups {
		w.line("  change LookupCheck RangeCheck 11 %d (%s + (2 : F) ^ %d) ∧ _ at hcChain", group.CarryBits+1, carries[i], group.CarryBits)
		w.line("  obtain ⟨hc%dModel, hcChain⟩ := hcChain", i)
	}
	if evalResult {
		w.line("  have hOut : ∃ v : List.Vector F 8, some rem = some v.toList ∧ k v := hcChain.2")
		w.line("  obtain ⟨v, hv, hkv⟩ := hOut")
		w.line("  have hvOut : v = remainder24_output pr := by")
		w.line("    apply List.Vector.toList_injective")
		w.line("    rw [← Option.some.inj hv]")
		w.line("    exact remainder24_output_list pr")
		w.line("  rw [hvOut] at hkv")
	}
	var facts [][]string
	for i, plan := range plans {
		width, prefix := r.CarryGroups[i].CarryBits+1, prefixes[i]
		if plan.kind == "big" {
			count := len(w.vecNames[plan.vec])
			w.line("  obtain ⟨p%s, hp%s, h%sValue⟩ := lookupCheck_vector_pieces %d %d (by decide) (by decide) _ h%sModel", prefix, prefix, prefix, width, count, prefix)
			var pieceFacts []string
			for j, bits := range pieceBits(11, width) {
				fact := fmt.Sprintf("h%s_%d", prefix, j)
				pieceFacts = append(pieceFacts, fact)
				predicate := fmt.Sprintf("RangeCheck %d", bits)
				if bits == 1 {
					predicate = "GatesDef.is_bool"
				}
				w.line("  have %s : %s (p%s.get %d) := by simpa [SmallCheck] using hp%s (%d : Fin %d)", fact, predicate, prefix, j, prefix, j, count)
			}
			facts = append(facts, pieceFacts)
		} else {
			predicate := fmt.Sprintf("RangeCheck %d", width)
			if plan.kind == "bool" {
				predicate = "GatesDef.is_bool"
			}
			w.line("  have h%sDirect : %s (%s + (2 : F) ^ %d) := by simpa [LookupCheck, SmallCheck] using h%sModel", prefix, predicate, carries[i], r.CarryGroups[i].CarryBits, prefix)
			facts = append(facts, nil)
		}
	}
	var initial, initialFacts, environment []string
	for i := 0; i < remCount; i++ {
		initial = append(initial, fmt.Sprintf("pr.get %d", i))
		projection := []string{".1", ".2.1", ".2.2"}[i%3]
		initialFacts = append(initialFacts, fmt.Sprintf("(hrange %d)%s", i/3, projection))
	}
	for i := 0; i < qCount; i++ {
		initial = append(initial, fmt.Sprintf("pq.get %d", i))
		fact := "hqrange"
		if qCount == 24 {
			fact = fmt.Sprintf("(hqrange %d)%s", i/3, []string{".1", ".2.1", ".2.2"}[i%3])
		} else if qCount == 13 {
			fact = fmt.Sprintf("hqrange (%d : Fin 13)", i)
		}
		initialFacts = append(initialFacts, fact)
	}
	w.line("  let initial : List.Vector F %d := vec![%s]", len(initial), strings.Join(initial, ", "))
	for i, value := range initial {
		w.line("  have hInitial%d : initial.get %d = %s := rfl", i, i, value)
	}
	environment = append(environment, lay.atoms...)
	for i := range initial {
		environment = append(environment, fmt.Sprintf("initial.get %d", i))
	}
	w.line("  let env : ℕ → F := fun i => [%s].getD i 0", strings.Join(environment, ", "))
	w.line("  let pxs : List (List Ex) := (%s : List (List ℕ)).map (fun is => is.map Ex.atom)", lay.iss)
	var rAtoms, qAtoms []int
	for i := 0; i < remCount; i++ {
		rAtoms = append(rAtoms, lay.n+i)
	}
	for i := 0; i < qCount; i++ {
		qAtoms = append(qAtoms, lay.n+remCount+i)
	}
	w.line("  let prp := (%s : List ℕ).map Ex.atom", joinInt(rAtoms))
	w.line("  let pqp := (%s : List ℕ).map Ex.atom", joinInt(qAtoms))
	if evalResult {
		w.line("  let prr := eLimbsOfPieces 11 widths8 prp")
	} else {
		w.line("  let prr : List Ex := []")
	}
	w.line("  let pqr := eLimbsOfPieces 11 %s.quotientWidths pqp", cert)
	w.line("  have hxs : evalLE pxs env = %s := rfl", lay.xs)
	if evalResult {
		w.line("  have hprp : evalE env prp = pr.toList := by")
		w.line("    rw [evalE_atoms]")
		w.line("    dsimp only [env, initial]")
		w.line("    obtain ⟨ps, hl⟩ := pr")
		w.line("    match ps, hl with")
		var atoms []string
		for i := 0; i < 24; i++ {
			atoms = append(atoms, fmt.Sprintf("r%d", i))
		}
		w.line("    | [%s], _ => rfl", strings.Join(atoms, ", "))
		w.line("  have hprr : evalE env prr = rem := by rw [evalE_eLimbsOfPieces, hprp]")
	} else {
		w.line("  have hprr : evalE env prr = rem := rfl")
	}
	w.line("  have hpqp : evalE env pqp = pq.toList := by")
	w.line("    rw [evalE_atoms]")
	w.line("    dsimp only [env, initial]")
	w.line("    obtain ⟨ps, hl⟩ := pq")
	w.line("    match ps, hl with")
	var qNames []string
	for i := 0; i < qCount; i++ {
		qNames = append(qNames, fmt.Sprintf("q%d", i))
	}
	w.line("    | [%s], _ => rfl", strings.Join(qNames, ", "))
	w.line("  have hpqr : evalE env pqr = ql := by rw [evalE_eLimbsOfPieces, hpqp]")
	w.line("  let er := eResidual basis %s pxs prr pqr .zero", cert)
	w.line("  have hResEval (j : ℕ) : (er j).eval env = res j := by")
	w.line("    dsimp only [er]")
	w.line("    rw [eval_eResidual, hxs, hprr, hpqr]")
	w.line("    rfl")
	w.line("  let ewhole := eSumRange %d (fun j => Ex.mul (er j) (ePow32 j))", r.Positions)
	w.line("  have hWholeRef : ewhole.eval env = 0 := by")
	w.line("    dsimp only [ewhole]")
	w.line("    rw [eval_eSumRange]")
	w.line("    simp only [whole_ex_eval_mul, hResEval, eval_ePow32]")
	w.line("    exact hWholeModel")
	for i := range r.CarryGroups {
		previous := ".zero"
		if i > 0 {
			previous = eCarries[i-1]
		}
		eCarry := fmt.Sprintf("ec%d", i)
		eCarries = append(eCarries, eCarry)
		w.line("  let %s := eCarry er %s %s", eCarry, groups[i], previous)
		w.line("  have hCarry%dEval : %s.eval env = %s := by", i, eCarry, carries[i])
		w.line("    dsimp only [%s]", eCarry)
		w.line("    rw [whole_eCarry_eval]")
		if i == 0 {
			w.line("    simp only [hResEval, whole_ex_eval_zero]")
		} else {
			w.line("    simp only [hResEval, hCarry%dEval]", i-1)
		}
		w.line("    rfl")
	}
	var expressions []string
	for i, prefix := range prefixes {
		expression := fmt.Sprintf("Ex.add %s (.lit (2 ^ %d))", eCarries[i], r.CarryGroups[i].CarryBits)
		expressions = append(expressions, expression)
		w.line("  have h%sEval : (%s).eval env = %s + (2 : F) ^ %d := by", prefix, expression, carries[i], r.CarryGroups[i].CarryBits)
		w.line("    rw [whole_ex_eval_add, hCarry%dEval, whole_ex_eval_lit]", i)
		w.line("    simp only [Nat.cast_pow, Nat.cast_ofNat]")
		if plans[i].kind == "big" {
			w.line("  have h%sRef : (%s).eval env = composeValue 11 p%s.toList := by rw [h%sEval]; exact h%sValue", prefix, expression, prefix, prefix, prefix)
		} else {
			predicate := fmt.Sprintf("RangeCheck %d", r.CarryGroups[i].CarryBits+1)
			if plans[i].kind == "bool" {
				predicate = "GatesDef.is_bool"
			}
			w.line("  have h%sRef : %s ((%s).eval env) := by rw [h%sEval]; exact h%sDirect", prefix, predicate, expression, prefix, prefix)
		}
	}
	modelLets := append([]string{"er", "ewhole", "pxs", "prp", "pqp", "prr", "pqr"}, eCarries...)
	if err := constructWholeGates(w, defs, parts, len(initial), initialBits, initialFacts,
		plans, prefixes, facts, expressions, modelLets, evalResult); err != nil {
		return "", err
	}
	w.line("")
	w.line("theorem %s_complete (es : List (Σ w, ElemVal w))", name)
	w.line("    (hb : ElemsMatch es %s.elems) (L : List.Vector F %d)", cert, lay.n)
	w.line("    (hxs : limbLists es = %s)", lay.xs)
	w.line("    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))")
	if evalResult {
		w.line("    (k : List.Vector F 8 → Prop)")
		w.line("    (hk : k (natLimbVector8 ((%s.exprValue (values es) %% (%s.m : ℤ)).toNat))) : %s L k := by", cert, cert, name)
		w.line("  apply %s_of_model L k", name)
		w.line("  rw [← hxs]")
		w.line("  apply %s_model_complete es hb hl", role)
		w.line("  refine ⟨natLimbVector8 _, ?_, hk⟩")
		w.line("  rw [natLimbVector8_list]")
	} else {
		w.line("    (hzero : %s.exprValue (values es) ≡ 0 [ZMOD (%s.m : ℤ)]) : %s L := by", cert, cert, name)
		w.line("  apply %s_of_model L", name)
		w.line("  rw [← hxs]")
		w.line("  exact scalarDecomp_model_of_congr es hb hl hzero (fun _ => True) trivial")
	}
	w.line("")
	return w.b.String(), nil
}

// Called by the existing instance renderer after its ordinary soundness and
// folded completeness outputs. Root reviews/runs generation separately.
func renderWholeScalarModules(defs map[string]extractedDef, names []string,
	byKey map[string]emfield.CheckRecord, out map[string]string) error {
	var header strings.Builder
	for _, module := range []string{"CompletenessScalarChecks", "CompletenessWholePieces", "CompletenessVector", "InstanceKit"} {
		fmt.Fprintf(&header, "import VerifiableEncryption.Field.%s\n", module)
	}
	for _, module := range []string{"Field", "Field2", "Field3", "Field4", "Field5", "Field6"} {
		fmt.Fprintf(&header, "import VerifiableEncryption.Circuit.%s\n", module)
	}
	header.WriteString("\n")
	header.WriteString("-- GENERATED by prover/extractor/emcurve_complete_whole.go; do not edit.\n")
	header.WriteString("-- Generation does not run hints or check Lean.\n\nnamespace ZolanaVE.Field\n\nopen ZolanaVE.EmcurveChecks\n\n")
	var aggregate strings.Builder
	seen := make(map[string]bool)
	for _, name := range names {
		match := checkDefKey.FindStringSubmatch(name)
		if match == nil {
			continue
		}
		if name != "CheckPolynomial_8_h57d6a69c" && name != "CheckPolynomial_16_h93312e5c" &&
			name != "CheckPolynomial_18_hb0ad1306" {
			continue
		}
		r, exists := byKey[match[3]]
		if !exists || wholeScalarRole(name, r) == "" {
			return fmt.Errorf("%s: missing or changed whole scalar certificate", name)
		}
		seen[name] = true
		source, err := renderWholeScalarCompleteness(defs, name, r)
		if err != nil {
			return err
		}
		module := "VerifiableEncryption.Field.CompletenessGeneratedWhole_" + match[3]
		out[module] = header.String() + source + "\nend ZolanaVE.Field\n"
		fmt.Fprintf(&aggregate, "import %s\n", module)
	}
	if len(seen) != 3 {
		return fmt.Errorf("expected all three actual whole scalar primitives, found %d", len(seen))
	}
	out["VerifiableEncryption.Field.CompletenessGeneratedWhole"] = aggregate.String()
	return nil
}
