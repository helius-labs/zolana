package extractor

import (
	"fmt"
	"regexp"
	"strings"
)

type scalarCoreParam struct{ name, ty string }

// scalarCoreParams reads only the actual explicit parameters. Nested vector
// type parentheses are retained; malformed or implicit binders fail closed.
func scalarCoreParams(d extractedDef, name string) ([]scalarCoreParam, error) {
	s := strings.TrimPrefix(d.header, "def "+name+" ")
	var out []scalarCoreParam
	for strings.HasPrefix(s, "(") {
		depth, end := 0, -1
		for j, c := range s {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					end = j
					break
				}
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("%s: unterminated input binder", name)
		}
		p := strings.SplitN(s[1:end], ":", 2)
		if len(p) != 2 || strings.ContainsAny(strings.TrimSpace(p[0]), " \t") {
			return nil, fmt.Errorf("%s: unsupported input binder", name)
		}
		out = append(out, scalarCoreParam{strings.TrimSpace(p[0]), strings.TrimSpace(p[1])})
		s = strings.TrimSpace(s[end+1:])
	}
	if s != ": Prop :=" || len(out) == 0 || out[len(out)-1].name != "k" {
		return nil, fmt.Errorf("%s: unsupported predicate header", name)
	}
	return out, nil
}

// scalarCoreArgs tokenizes a Lean application without splitting grouped
// vector literals or parenthesized vector getters.
func scalarCoreArgs(s string) ([]string, error) {
	var args []string
	depth, start := 0, -1
	for j, c := range s {
		if start < 0 && c != ' ' && c != '\t' {
			start = j
		}
		switch c {
		case '(', '[':
			depth++
		case ')', ']':
			depth--
		}
		if depth < 0 {
			return nil, fmt.Errorf("unbalanced scalar application %q", s)
		}
		if (c == ' ' || c == '\t') && depth == 0 && start >= 0 {
			args = append(args, s[start:j])
			start = -1
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced scalar application %q", s)
	}
	if start >= 0 {
		args = append(args, s[start:])
	}
	return args, nil
}

type scalarCoreNode struct {
	kind, gate, ty, expr, primitive string
	args                          []string
}

// scalarCoreNodes retains every assertion and functional gate. This is a
// source composition schema, not an evaluator or a cryptographic generator.
func scalarCoreNodes(defs map[string]extractedDef, name string) ([]scalarCoreNode, error) {
	d, ok := defs[name]
	if !ok {
		return nil, fmt.Errorf("missing scalar core fragment %s", name)
	}
	// Go's regexp deliberately has no backreferences: validate both captures.
	eq := regexp.MustCompile(`^∃(gate_\d+), (gate_\d+) = (.*)$`)
	hint := regexp.MustCompile(`^∃(gate_\d+) : (List\.Vector F \d+), -- hint`)
	funcGate := regexp.MustCompile(`^∃(gate_\d+), Gates\.(select|lookup|from_binary) (.*) (gate_\d+)$`)
	call := regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_]+) (.*) fun (gate_\d+) =>$`)
	assert := regexp.MustCompile(`^([A-Za-z][A-Za-z0-9_]*) (.*)$`)
	var out []scalarCoreNode
	for _, raw := range d.body {
		s := strings.TrimSpace(strings.TrimSuffix(raw, " ∧"))
		if m := eq.FindStringSubmatch(s); m != nil {
			if m[1] != m[2] {
				return nil, fmt.Errorf("%s: mismatched equation binder", name)
			}
			out = append(out, scalarCoreNode{kind: "eq", gate: m[1], ty: "F", expr: m[3]})
		} else if m := hint.FindStringSubmatch(s); m != nil {
			out = append(out, scalarCoreNode{kind: "hint", gate: m[1], ty: m[2]})
		} else if m := funcGate.FindStringSubmatch(s); m != nil {
			if m[1] != m[4] {
				return nil, fmt.Errorf("%s: mismatched functional binder", name)
			}
			args, err := scalarCoreArgs(m[3])
			if err != nil {
				return nil, err
			}
			want := map[string]int{"select": 3, "lookup": 6, "from_binary": 1}[m[2]]
			if len(args) != want {
				return nil, fmt.Errorf("%s: unexpected %s arity", name, m[2])
			}
			out = append(out, scalarCoreNode{kind: m[2], gate: m[1], ty: "F", args: args})
		} else if m := call.FindStringSubmatch(s); m != nil {
			if m[1] == "RowLookup_12_16" {
				out = append(out, scalarCoreNode{kind: "row", gate: m[3], ty: "List.Vector F 12", primitive: m[1], expr: m[2]})
			} else {
				pd, ok := defs[m[1]]
				if !ok {
					return nil, fmt.Errorf("%s: unknown core primitive %s", name, m[1])
				}
				ps, err := scalarCoreParams(pd, m[1])
				if err != nil {
					return nil, err
				}
				ty := strings.TrimSuffix(ps[len(ps)-1].ty, " -> Prop")
				if ty == ps[len(ps)-1].ty {
					return nil, fmt.Errorf("%s: unsupported primitive continuation", m[1])
				}
				out = append(out, scalarCoreNode{kind: "call", gate: m[3], ty: ty, primitive: m[1], expr: m[2]})
			}
		} else if m := assert.FindStringSubmatch(s); m != nil {
			op := m[1]
			kind := "assert"
			if strings.HasPrefix(op, "ScalarMulChecked_8_8_8_h903d3456_p") {
				kind = "next"
			} else if op == "k" {
				kind = "end"
			} else if op == "RangeCheck" {
				kind = "range"
			} else if _, ok := defs[op]; !ok {
				return nil, fmt.Errorf("%s: unsupported assertion %q", name, s)
			}
			out = append(out, scalarCoreNode{kind: kind, primitive: op, expr: m[2]})
		} else if strings.HasPrefix(s, "Gates.is_bool ") {
			out = append(out, scalarCoreNode{kind: "bool", expr: strings.TrimPrefix(s, "Gates.is_bool ")})
		} else if strings.HasPrefix(s, "Gates.ne ") {
			out = append(out, scalarCoreNode{kind: "ne", expr: strings.TrimPrefix(s, "Gates.ne ")})
		} else {
			return nil, fmt.Errorf("%s: unsupported core constraint %q", name, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: empty core fragment", name)
	}
	last := out[len(out)-1]
	for _, n := range out[:len(out)-1] {
		if n.kind == "next" || n.kind == "end" {
			return nil, fmt.Errorf("%s: premature continuation", name)
		}
	}
	if strings.HasSuffix(name, "_p9") {
		if last.kind != "end" || last.primitive != "k" {
			return nil, fmt.Errorf("%s: missing final continuation", name)
		}
	} else {
		var part int
		if _, err := fmt.Sscanf(name, "ScalarMulChecked_8_8_8_h903d3456_p%d", &part); err != nil ||
			last.kind != "next" || last.primitive != fmt.Sprintf("ScalarMulChecked_8_8_8_h903d3456_p%d", part+1) {
			return nil, fmt.Errorf("%s: changed next-fragment boundary", name)
		}
	}
	return out, nil
}

// renderScalarCoreFragment builds ordinary typed data records and pure wire
// functions, then a reverse composition proof. Primitive constructors remain
// individual CPS arguments; the final continuation is the exact next fragment.
func renderScalarCoreFragment(defs map[string]extractedDef, part int) (string, error) {
	name := fmt.Sprintf("ScalarMulChecked_8_8_8_h903d3456_p%d", part)
	ps, err := scalarCoreParams(defs[name], name)
	if err != nil {
		return "", err
	}
	ns, err := scalarCoreNodes(defs, name)
	if err != nil {
		return "", err
	}
	prefix := fmt.Sprintf("ScalarCore%d", part)
	w := &instanceWriter{}
	w.line("structure %sInputs where", prefix)
	refs := map[string]string{}
	for _, p := range ps[:len(ps)-1] {
		w.line("  %s : %s", p.name, p.ty)
		refs[p.name] = "i." + p.name
	}
	w.line("structure %sChoices where", prefix)
	for _, n := range ns {
		switch n.kind {
		case "hint", "call":
			w.line("  %s : %s", n.gate, n.ty)
			refs[n.gate] = "w." + n.gate
		case "row":
			w.line("  %s_index : Fin 16", n.gate)
			refs[n.gate] = fmt.Sprintf("(%s_%s i w)", prefix, n.gate)
		case "eq", "select", "lookup", "from_binary":
			refs[n.gate] = fmt.Sprintf("(%s_%s i w)", prefix, n.gate)
		}
	}
	identifier := regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
	rewrite := func(s string) string {
		return identifier.ReplaceAllStringFunc(s, func(token string) string {
			if v, ok := refs[token]; ok {
				return v
			}
			return token
		})
	}
	rowTables := map[string]string{}
	var rowTableOrder []string
	for _, n := range ns {
		if n.kind != "row" {
			continue
		}
		a, err := scalarCoreArgs(n.expr)
		if err != nil || len(a) != 2 {
			return "", fmt.Errorf("%s: unsupported row application", name)
		}
		if _, ok := rowTables[a[0]]; !ok {
			rowTables[a[0]] = fmt.Sprintf("%s_rows%d", prefix, len(rowTableOrder))
			rowTableOrder = append(rowTableOrder, a[0])
		}
	}
	emittedRows := map[string]bool{}
	for _, n := range ns {
		var expr string
		switch n.kind {
		case "eq":
			expr = rewrite(n.expr)
		case "select":
			a := n.args
			expr = fmt.Sprintf("%s - %s * (%s - %s)", rewrite(a[2]), rewrite(a[0]), rewrite(a[2]), rewrite(a[1]))
		case "lookup":
			a := n.args
			expr = fmt.Sprintf("(%s - %s) * %s + %s + (((%s - %s - %s + %s) * %s + %s - %s) * %s)",
				rewrite(a[4]), rewrite(a[2]), rewrite(a[1]), rewrite(a[2]), rewrite(a[5]), rewrite(a[4]), rewrite(a[3]), rewrite(a[2]), rewrite(a[1]), rewrite(a[3]), rewrite(a[2]), rewrite(a[0]))
		case "from_binary":
			expr = "recover_binary_zmod' (" + rewrite(n.args[0]) + ")"
		case "row":
			a, err := scalarCoreArgs(n.expr)
			if err != nil || len(a) != 2 {
				return "", fmt.Errorf("%s: unsupported row application", name)
			}
			if !emittedRows[a[0]] {
				w.line("def %s (i : %sInputs) (w : %sChoices) : List.Vector (List.Vector F 12) 16 :=", rowTables[a[0]], prefix, prefix)
				w.line("  %s", rewrite(a[0]))
				emittedRows[a[0]] = true
			}
			expr = fmt.Sprintf("(%s i w).get w.%s_index", rowTables[a[0]], n.gate)
		}
		if expr != "" {
			w.line("def %s_%s (i : %sInputs) (w : %sChoices) : %s :=", prefix, n.gate, prefix, prefix, n.ty)
			w.line("  %s", expr)
		}
	}
	// The next pass emits every nonfunctional constraint individually. No
	// whole-fragment or whole-circuit success predicate is introduced.
	w.line("theorem %s_compose (i : %sInputs) (w : %sChoices)", name, prefix, prefix)
	w.line("    (k : %s)", ps[len(ps)-1].ty)
	bits := refs["gate_402"]
	if bits == "" {
		return "", fmt.Errorf("%s: missing hinted bit vector", name)
	}
	w.line("    (hBits : AllBits %s)", bits)
	hasRows := false
	for _, n := range ns {
		hasRows = hasRows || n.kind == "row"
	}
	if hasRows {
		w.line("    (hRows : RowComplete)")
	}
	if part == 2 {
		w.line("    (hSigma : GatesDef.is_bool i.gate_259)")
	}
	bitExpr := regexp.MustCompile(`^\(gate_402\.get \((\d+) : Fin 259\)\)$`)
	bitProof := func(expr string) (string, error) {
		if expr == "gate_259" && part == 2 {
			return "hSigma", nil
		}
		m := bitExpr.FindStringSubmatch(expr)
		if m == nil {
			return "", fmt.Errorf("%s: unsupported Boolean source %s", name, expr)
		}
		return fmt.Sprintf("allBits_getNativeBool %s hBits (%s : Fin 259)", bits, m[1]), nil
	}
	var actions []string
	for index, n := range ns {
		h := fmt.Sprintf("h%d", index)
		if n.kind == "call" {
			h = "hCall_" + n.gate
		} else if n.kind == "row" {
			h = "hRow_" + n.gate
		}
		switch n.kind {
		case "eq":
			actions = append(actions, fmt.Sprintf("  refine ⟨%s, rfl, ?_⟩", refs[n.gate]))
		case "hint":
			actions = append(actions, fmt.Sprintf("  refine ⟨w.%s, ?_⟩", n.gate))
		case "range", "assert":
			w.line("    (%s : %s %s)", h, n.primitive, rewrite(n.expr))
			actions = append(actions, fmt.Sprintf("  refine ⟨%s, ?_⟩", h))
		case "bool":
			proof, err := bitProof(n.expr)
			if err != nil {
				return "", err
			}
			actions = append(actions, fmt.Sprintf("  refine ⟨%s, ?_⟩", proof))
		case "select", "lookup":
			count := 1
			if n.kind == "lookup" {
				count = 2
			}
			var bits []string
			for j := 0; j < count; j++ {
				proof, err := bitProof(n.args[j])
				if err != nil {
					return "", err
				}
				bits = append(bits, proof)
			}
			bits = append(bits, "rfl")
			actions = append(actions, fmt.Sprintf("  refine ⟨%s, %s, ?_⟩", refs[n.gate], tupleOf(bits)))
		case "from_binary":
			allBits := regexp.MustCompile(`gate_402\.get \((\d+) : Fin 259\)`).FindAllStringSubmatch(n.args[0], -1)
			if len(allBits) != 1 && len(allBits) != 32 {
				return "", fmt.Errorf("%s: unsupported binary slice", name)
			}
			var proofs []string
			for _, m := range allBits {
				proof, err := bitProof("(gate_402.get (" + m[1] + " : Fin 259))")
				if err != nil {
					return "", err
				}
				proofs = append(proofs, fmt.Sprintf("(is_bool_is_bit _).mp (%s)", proof))
			}
			proofs = append(proofs, "by simp [is_vector_binary]")
			actions = append(actions, fmt.Sprintf("  refine ⟨%s, ⟨rfl, ?_⟩, ?_⟩", refs[n.gate]), "  · simp only [is_vector_binary_cons]", "    exact "+tupleOf(proofs))
		case "call":
			w.line("    (%s : ∀ k : %s → Prop, k w.%s → %s %s k)", h, n.ty, n.gate, n.primitive, rewrite(n.expr))
			actions = append(actions, "  apply "+h)
		case "row":
			a, _ := scalarCoreArgs(n.expr)
			w.line("    (%s_index : %s = (w.%s_index.val : F))", h, rewrite(a[1]), n.gate)
			actions = append(actions, fmt.Sprintf("  rw [%s_index]", h), fmt.Sprintf("  apply hRows (%s i w) w.%s_index", rowTables[a[0]], n.gate))
		case "ne":
			// This narrow guard is later instantiated by ladderDenSum_nonzero,
			// not assumed as a whole-core success premise.
			w.line("    (%s : GatesDef.ne %s)", h, rewrite(n.expr))
			actions = append(actions, fmt.Sprintf("  refine ⟨%s, ?_⟩", h))
		case "next", "end":
			w.line("    (%s : %s %s) :", h, n.primitive, rewrite(n.expr))
			actions = append(actions, "  exact "+h)
		default:
			return "", fmt.Errorf("%s: unsupported emission node %s", name, n.kind)
		}
	}
	var args []string
	for _, p := range ps[:len(ps)-1] {
		args = append(args, "i."+p.name)
	}
	args = append(args, "k")
	w.line("    %s %s := by", name, strings.Join(args, " "))
	w.line("  unfold %s", name)
	for _, action := range actions {
		w.line("%s", action)
	}
	w.line("")
	return w.b.String(), nil
}

func renderScalarCoreCompositions(defs map[string]extractedDef) (string, error) {
	w := &instanceWriter{}
	w.line("import VerifiableEncryption.Curve.CompletenessLadderBinary")
	w.line("import VerifiableEncryption.Curve.CompletenessLadderLookup")
	w.line("import VerifiableEncryption.Circuit.Curve")
	w.line("-- GENERATED by prover/extractor/emcurve_scalar_core_compositions.go; do not edit.")
	w.line("-- Per-fragment native compositions only; outer mathematics discharges every constraint.")
	w.line("namespace ZolanaVE.P256.Completeness")
	w.line("open ZolanaVE.Field")
	w.line("set_option maxHeartbeats 0")
	w.line("set_option maxRecDepth 100000")
	for part := 2; part <= 9; part++ {
		source, err := renderScalarCoreFragment(defs, part)
		if err != nil {
			return "", err
		}
		w.b.WriteString(source)
	}
	for part := 2; part < 9; part++ {
		name := fmt.Sprintf("ScalarMulChecked_8_8_8_h903d3456_p%d", part)
		ps, err := scalarCoreParams(defs[name], name)
		if err != nil {
			return "", err
		}
		ns, err := scalarCoreNodes(defs, name)
		if err != nil {
			return "", err
		}
		last := ns[len(ns)-1]
		nextParams, err := scalarCoreParams(defs[last.primitive], last.primitive)
		if err != nil {
			return "", err
		}
		callArgs, err := scalarCoreArgs(last.expr)
		if err != nil || len(callArgs) != len(nextParams) || callArgs[len(callArgs)-1] != "k" {
			return "", fmt.Errorf("%s: next record argument count/order mismatch", name)
		}
		prefix := fmt.Sprintf("ScalarCore%d", part)
		refs := map[string]string{}
		for _, p := range ps[:len(ps)-1] {
			refs[p.name] = "i." + p.name
		}
		for _, n := range ns {
			switch n.kind {
			case "hint", "call":
				refs[n.gate] = "w." + n.gate
			case "eq", "select", "lookup", "from_binary", "row":
				refs[n.gate] = fmt.Sprintf("(%s_%s i w)", prefix, n.gate)
			}
		}
		identifier := regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
		rewrite := func(s string) string {
			return identifier.ReplaceAllStringFunc(s, func(token string) string {
				if v, ok := refs[token]; ok {
					return v
				}
				return token
			})
		}
		w.line("def %s_nextInputs (i : %sInputs) (w : %sChoices) : ScalarCore%dInputs where", prefix, prefix, prefix, part+1)
		var actual, record []string
		for j, p := range nextParams[:len(nextParams)-1] {
			if callArgs[j] != p.name {
				return "", fmt.Errorf("%s: next header field %s bound to unexpected source %s", name, p.name, callArgs[j])
			}
			if _, ok := refs[p.name]; !ok {
				return "", fmt.Errorf("%s: next header field %s has no typed source", name, p.name)
			}
			value := rewrite(callArgs[j])
			w.line("  %s := %s", p.name, value)
			actual = append(actual, value)
			record = append(record, fmt.Sprintf("(%s_nextInputs i w).%s", prefix, p.name))
		}
		actual = append(actual, "k")
		record = append(record, "k")
		w.line("theorem %s_nextInputs_eq (i : %sInputs) (w : %sChoices) (k : %s) :", prefix, prefix, prefix, ps[len(ps)-1].ty)
		w.line("    %s %s =", last.primitive, strings.Join(actual, " "))
		w.line("      %s %s := rfl", last.primitive, strings.Join(record, " "))
		w.line("")
	}
	w.line("end ZolanaVE.P256.Completeness")
	return w.b.String(), nil
}
