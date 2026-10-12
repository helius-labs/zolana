package extractor

import (
	"fmt"
	"strings"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// This extends the existing instance proof-source renderer with folded
// eight-limb reduced outputs. Every hint/range/continuation is matched to the
// extracted body; generation itself does not elaborate a proof or run a hint.
func foldedEvalCompletenessRecord(name string, r emfield.CheckRecord) bool {
	if !strings.HasPrefix(name, "CheckPolynomial_") || r.Kind != emfield.KindEval ||
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

func renderFoldedEvalCompleteness(defs map[string]extractedDef, name string, r emfield.CheckRecord) (string, error) {
	if r.QuotientBits < 1 {
		return "", fmt.Errorf("%s: zero-width quotient needs an equality constructor", name)
	}
	seq, parts, err := conjuncts(defs, name)
	if err != nil {
		return "", err
	}
	lay := layoutFor(r)
	w := &instanceWriter{seq: seq, atomCount: lay.n}
	w.vector(24)
	var remainderFacts []string
	for i := 0; i < 8; i++ {
		for _, bits := range []int{11, 11, 10} {
			w.pieceFact(bits)
		}
		remainderFacts = append(remainderFacts, fmt.Sprintf("(hrange %d).1", i),
			fmt.Sprintf("(hrange %d).2.1", i), fmt.Sprintf("(hrange %d).2.2", i))
	}
	plans := []rangeCheckPlan{w.check(11, r.QuotientBits)}
	widths := []int{r.QuotientBits}
	prefixes := []string{"q"}
	pos := 0
	for i, group := range r.CarryGroups {
		if group.Start != pos || group.End <= group.Start || group.End > r.Positions {
			return "", fmt.Errorf("%s: discontinuous folded evaluation carry layout", name)
		}
		plans = append(plans, w.check(11, group.CarryBits+1))
		widths = append(widths, group.CarryBits+1)
		prefixes = append(prefixes, fmt.Sprintf("c%d", i))
		pos = group.End
	}
	if pos != r.CarryPositions {
		return "", fmt.Errorf("%s: folded evaluation carry endpoint mismatch", name)
	}
	w.take(conjK, 0)
	if w.err != nil || w.pos != len(seq) {
		return "", fmt.Errorf("%s: unmatched folded evaluation constraints: %v", name, w.err)
	}
	cert := recordName(r)
	groups := carryGroupLiterals(r)
	w.line("theorem %s_of_model (L : List.Vector F %d) (k : List.Vector F 8 → Prop)", name, lay.n)
	w.line("    (h : CheckPolynomial.circuit basis %s %s", cert, lay.xs)
	w.line("      (LookupCheck RangeCheck 11) (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) :")
	w.line("    %s L k := by", name)
	w.line("  unfold CheckPolynomial.circuit at h")
	w.line("  obtain ⟨rp, qp, hrp, hqp, h⟩ := h")
	w.line("  have hqpNil : qp = [] := hqp")
	w.line("  subst qp")
	w.line("  obtain ⟨pr, hpr, hrange⟩ := remainder24_pieces rp hrp")
	w.line("  rw [← hpr] at h")
	w.line("  let rem := limbsOfPieces 11 widths8 pr.toList")
	w.line("  let q := CheckPolynomial.foldQuotient basis %s %s rem", cert, lay.xs)
	w.line("  let res := CheckPolynomial.residual basis %s %s rem [] q", cert, lay.xs)
	var carryNames, expressionCarries []string
	for i, group := range r.CarryGroups {
		previous := "0"
		if i != 0 {
			previous = carryNames[i-1]
		}
		carry := fmt.Sprintf("carry%d", i)
		carryNames = append(carryNames, carry)
		w.line("  let %s := (sumRange %d (fun j => res (%d + j) * pow32 j) + %s) *", carry, group.End-group.Start, group.Start, previous)
		w.line("    ((%s : CarryGroup).inv : F)", groups[i])
	}
	w.line("  have hqModel : LookupCheck RangeCheck 11 %d (q + (%s : F)) := h.1 rfl", r.QuotientBits, leanInt(r.Offset))
	w.line("  have hcChain := h.2.2")
	for i, group := range r.CarryGroups {
		w.line("  change LookupCheck RangeCheck 11 %d (%s + (2 : F) ^ %d) ∧ _ at hcChain", group.CarryBits+1, carryNames[i], group.CarryBits)
		w.line("  obtain ⟨hc%dModel, hcChain⟩ := hcChain", i)
	}
	w.line("  have hOut : ∃ v : List.Vector F 8, some rem = some v.toList ∧ k v := hcChain.2")
	w.line("  obtain ⟨v, hv, hkv⟩ := hOut")
	w.line("  have hvOut : v = remainder24_output pr := by")
	w.line("    apply List.Vector.toList_injective")
	w.line("    rw [← Option.some.inj hv]")
	w.line("    exact remainder24_output_list pr")
	w.line("  rw [hvOut] at hkv")
	var facts [][]string
	for i, plan := range plans {
		prefix, width := prefixes[i], widths[i]
		if plan.kind == "big" {
			count := len(w.vecNames[plan.vec])
			w.line("  obtain ⟨p%s, hp%s, h%sValue⟩ :=", prefix, prefix, prefix)
			w.line("    lookupCheck_vector_pieces %d %d (by decide) (by decide) _ h%sModel", width, count, prefix)
			var pieceFacts []string
			for j, bits := range pieceBits(11, width) {
				fact := fmt.Sprintf("h%s_%d", prefix, j)
				pieceFacts = append(pieceFacts, fact)
				predicate := fmt.Sprintf("RangeCheck %d", bits)
				if bits == 1 {
					predicate = "GatesDef.is_bool"
				}
				w.line("  have %s : %s (p%s.get %d) := by", fact, predicate, prefix, j)
				w.line("    simpa [SmallCheck] using hp%s (%d : Fin %d)", prefix, j, count)
			}
			facts = append(facts, pieceFacts)
		} else {
			predicate := fmt.Sprintf("RangeCheck %d", width)
			if plan.kind == "bool" {
				predicate = "GatesDef.is_bool"
			}
			value := fmt.Sprintf("q + (%s : F)", leanInt(r.Offset))
			if i != 0 {
				value = fmt.Sprintf("%s + (2 : F) ^ %d", carryNames[i-1], r.CarryGroups[i-1].CarryBits)
			}
			w.line("  have h%sDirect : %s (%s) := by", prefix, predicate, value)
			w.line("    simpa [LookupCheck, SmallCheck] using h%sModel", prefix)
			facts = append(facts, nil)
		}
	}
	var remainderAtoms []int
	for i := 0; i < 24; i++ {
		remainderAtoms = append(remainderAtoms, lay.n+i)
	}
	// Input atoms precede the actual remainder hint atoms in the expression model.
	// Both segments are literal source variables; no witness arithmetic is run.
	environment := append(append([]string{}, lay.atoms...), w.vecNames[0]...)
	// w.vecNames contains extractor labels g0; the chosen mathematical vector is pr.
	for i := len(lay.atoms); i < len(environment); i++ {
		environment[i] = strings.ReplaceAll(environment[i], "g0", "pr")
	}
	w.line("  let env : ℕ → F := fun i => [%s].getD i 0", strings.Join(environment, ", "))
	w.line("  let pxs : List (List Ex) := (%s : List (List ℕ)).map (fun is => is.map Ex.atom)", lay.iss)
	w.line("  let prp := (%s : List ℕ).map Ex.atom", joinInt(remainderAtoms))
	w.line("  let prr := eLimbsOfPieces 11 widths8 prp")
	w.line("  have hxs : evalLE pxs env = %s := rfl", lay.xs)
	w.line("  have hprp : evalE env prp = pr.toList := by")
	w.line("    dsimp only [env, prp]")
	w.line("    rw [evalE_atoms]")
	w.line("    obtain ⟨ps, hl⟩ := pr")
	w.line("    match ps, hl with")
	var remainderNames []string
	for i := 0; i < 24; i++ {
		remainderNames = append(remainderNames, fmt.Sprintf("r%d", i))
	}
	w.line("    | [%s], _ => rfl", strings.Join(remainderNames, ", "))
	w.line("  have hprr : evalE env prr = rem := by rw [evalE_eLimbsOfPieces, hprp]")
	w.line("  let eq := eFoldQuotient basis %s pxs prr", cert)
	w.line("  let er := eResidual basis %s pxs prr [] eq", cert)
	for i := range r.CarryGroups {
		eCarry := fmt.Sprintf("ec%d", i)
		previous := ".zero"
		if i != 0 {
			previous = expressionCarries[i-1]
		}
		expressionCarries = append(expressionCarries, eCarry)
		w.line("  let %s := eCarry er %s %s", eCarry, groups[i], previous)
	}
	w.line("  have hqPlainEval : eq.eval env = q := by")
	w.line("    change (eFoldQuotient basis %s pxs prr).eval env = q", cert)
	w.line("    rw [eval_eFoldQuotient, hxs, hprr]")
	w.line("  have hresEval (j : ℕ) : (er j).eval env = res j := by")
	w.line("    change (eResidual basis %s pxs prr [] eq j).eval env = res j", cert)
	w.line("    rw [eval_eResidual, hxs, hprr]")
	w.line("    change CheckPolynomial.residual basis %s %s rem [] (eq.eval env) j = res j", cert, lay.xs)
	w.line("    rw [hqPlainEval]")
	for i, group := range r.CarryGroups {
		previousExpr := "(.zero : Ex)"
		previousField := "0"
		if i != 0 {
			previousExpr = expressionCarries[i-1]
			previousField = carryNames[i-1]
		}
		w.line("  have hcarrySum%d :", i)
		w.line("      (eSumRange %d (fun j => .mul (er (%d + j)) (ePow32 j))).eval env =", group.End-group.Start, group.Start)
		w.line("        sumRange %d (fun j => res (%d + j) * pow32 j) := by", group.End-group.Start, group.Start)
		w.line("    rw [eval_eSumRange]")
		w.line("    apply sumRange_congr'; intro j")
		w.line("    change (er (%d + j)).eval env * (ePow32 j).eval env = res (%d + j) * pow32 j", group.Start, group.Start)
		w.line("    rw [hresEval, eval_ePow32]")
		w.line("  have hc%dPlainEval : %s.eval env = %s := by", i, expressionCarries[i], carryNames[i])
		w.line("    change ((eSumRange %d (fun j => .mul (er (%d + j)) (ePow32 j))).eval env +", group.End-group.Start, group.Start)
		w.line("      %s.eval env) * ((%s : CarryGroup).inv : F) = %s", previousExpr, groups[i], carryNames[i])
		if i == 0 {
			w.line("    rw [hcarrySum%d]", i)
		} else {
			w.line("    rw [hcarrySum%d, hc%dPlainEval]", i, i-1)
		}
		w.line("    change (sumRange %d (fun j => res (%d + j) * pow32 j) + %s) *", group.End-group.Start, group.Start, previousField)
		w.line("      ((%s : CarryGroup).inv : F) = %s", groups[i], carryNames[i])
		w.line("    rfl")
	}
	expressions := make([]string, len(plans))
	for i, plan := range plans {
		prefix := prefixes[i]
		expression := fmt.Sprintf("Ex.add eq (.lit %s)", leanInt(r.Offset))
		value := fmt.Sprintf("q + (%s : F)", leanInt(r.Offset))
		if i != 0 {
			expression = fmt.Sprintf("Ex.add %s (.lit (2 ^ %d))", expressionCarries[i-1], r.CarryGroups[i-1].CarryBits)
			value = fmt.Sprintf("%s + (2 : F) ^ %d", carryNames[i-1], r.CarryGroups[i-1].CarryBits)
		}
		expressions[i] = expression
		w.line("  have h%sEval : (%s).eval env = %s := by", prefix, expression, value)
		if i == 0 {
			w.line("    change eq.eval env + (%s : F) = q + (%s : F)", leanInt(r.Offset), leanInt(r.Offset))
			w.line("    rw [hqPlainEval]")
		} else {
			w.line("    rw [Ex.eval, hc%dPlainEval]", i-1)
			w.line("    simp only [Ex.eval, Nat.cast_pow, Nat.cast_ofNat]")
		}
		if plan.kind == "big" {
			w.line("  have h%sRef : (%s).eval env = composeValue 11 p%s.toList := by", prefix, expression, prefix)
			w.line("    rw [h%sEval]", prefix)
			w.line("    exact h%sValue", prefix)
		} else {
			predicate := fmt.Sprintf("RangeCheck %d", widths[i])
			if plan.kind == "bool" {
				predicate = "GatesDef.is_bool"
			}
			w.line("  have h%sRef : %s ((%s).eval env) := by", prefix, predicate, expression)
			w.line("    rw [h%sEval]", prefix)
			w.line("    exact h%sDirect", prefix)
		}
	}
	modelLets := append([]string{"eq", "er", "pxs", "prp", "prr"}, expressionCarries...)
	if err := constructFoldedGates(w, defs, parts, plans, prefixes, facts, expressions, modelLets,
		foldedGateResult{pieces: "pr", ranges: remainderFacts, vector: "remainder24_output pr", continuation: "hkv"}); err != nil {
		return "", err
	}
	w.line("")
	w.line("theorem %s_quotient_lower :", name)
	w.line("    foldedMagnitude basis %s + (%s.m : ℤ) - 1 ≤ (%s.offset : ℤ) * %s.m := by decide +kernel", cert, cert, cert, cert)
	w.line("theorem %s_quotient_upper :", name)
	w.line("    foldedMagnitude basis %s < ((2 : ℤ) ^ %s.quotientBits - %s.offset) * %s.m := by decide +kernel", cert, cert, cert, cert)
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
	w.line("    (k : List.Vector F 8 → Prop)")
	w.line("    (hk : k (natLimbVector8 ((foldedValue basis %s es %% (%s.m : ℤ)).toNat))) :", cert, cert)
	w.line("    %s L k := by", name)
	w.line("  apply %s_of_model L k", name)
	w.line("  rw [← hxs]")
	w.line("  apply foldedEval_complete basis %s basis_sound %s_sound", cert, cert)
	w.line("    rfl rfl rfl rfl (by norm_num [%s]) %s_quotient_lower", cert, name)
	w.line("    %s_quotient_upper %s_carry_capacity hl es hb", name, name)
	w.line("  refine ⟨natLimbVector8 _, ?_, hk⟩")
	w.line("  rw [natLimbVector8_list]")
	w.line("")
	return w.b.String(), nil
}

func renderFoldedEvalModules(defs map[string]extractedDef, names []string,
	byKey map[string]emfield.CheckRecord, out map[string]string) error {
	var header strings.Builder
	header.WriteString("import VerifiableEncryption.Field.CompletenessEval\n")
	header.WriteString("import VerifiableEncryption.Field.CompletenessRemainder\n")
	header.WriteString("import VerifiableEncryption.Field.CompletenessVector\n")
	header.WriteString("import VerifiableEncryption.Field.Certificate\n")
	header.WriteString("import VerifiableEncryption.Field.InstanceKit\n")
	for _, module := range []string{"Field", "Field2", "Field3", "Field4", "Field5", "Field6"} {
		fmt.Fprintf(&header, "import VerifiableEncryption.Circuit.%s\n", module)
	}
	header.WriteString("\n-- GENERATED by prover/extractor/emcurve_complete_eval.go; do not edit.\n")
	header.WriteString("-- Generation does not perform Lean checking; validation is recorded separately.\n\n")
	header.WriteString("namespace ZolanaVE.Field\n\nopen ZolanaVE.EmcurveChecks\n\n")
	header.WriteString("set_option maxHeartbeats 0\nset_option maxRecDepth 100000\n\n")
	var chunks [][]string
	load := 0
	for _, name := range names {
		match := checkDefKey.FindStringSubmatch(name)
		if match == nil {
			continue
		}
		record, exists := byKey[match[3]]
		if !exists || !foldedEvalCompletenessRecord(name, record) {
			continue
		}
		text, err := renderFoldedEvalCompleteness(defs, name, record)
		if err != nil {
			return err
		}
		_, parts, err := conjuncts(defs, name)
		if err != nil {
			return err
		}
		weight := 0
		for _, part := range parts {
			weight += len(defs[part].body)
		}
		if len(chunks) == 0 || load+weight > 1000 {
			chunks = append(chunks, nil)
			load = 0
		}
		chunks[len(chunks)-1] = append(chunks[len(chunks)-1], text)
		load += weight
	}
	var aggregate strings.Builder
	aggregate.WriteString("-- GENERATED by prover/extractor/emcurve_complete_eval.go; do not edit.\n")
	for i, declarations := range chunks {
		module := fmt.Sprintf("VerifiableEncryption.Field.CompletenessGeneratedEval_%d", i+1)
		fmt.Fprintf(&aggregate, "import %s\n", module)
		out[module] = header.String() + strings.Join(declarations, "\n") + "\nend ZolanaVE.Field\n"
	}
	out["VerifiableEncryption.Field.CompletenessGeneratedEval"] = aggregate.String()
	return nil
}
