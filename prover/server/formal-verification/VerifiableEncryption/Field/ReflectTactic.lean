import VerifiableEncryption.Field.Factored

/-!
`poly_refl` closes `polyEval env P = e` where `env` is `fun i => [x₀, …, xₙ].getD i 0`
over free variables and `e` is built from `+`, `*`, `-`, negation, numerals,
reducible constants and terms that reduce to some `xⱼ`. It reifies `e` into
`Ex`, checks `P = e.norm` with `decide +kernel`, and closes the goal with
`eval_eq_of_norm_eq`; `Ex.eval env e` is definitionally `e`.
-/

namespace ZolanaVE.Field

open Lean Meta Elab Tactic

/-- The atoms of `fun i => List.getD [x₀, …] i 0`. -/
def envAtoms (env : Expr) : MetaM (Array Expr) := do
  let env ← whnfR env
  let .lam _ _ body _ := env | throwError "poly_refl: env is not a lambda"
  let body := body.getAppArgs
  let some lst := body[1]? | throwError "poly_refl: env body is not List.getD"
  let mut out := #[]
  let mut cur ← whnfD lst
  while true do
    match cur.getAppFnArgs with
    | (``List.cons, #[_, h, t]) =>
      out := out.push h
      cur ← whnfD t
    | (``List.nil, _) => break
    | _ => throwError "poly_refl: env list is not a literal"
  return out

partial def reifyEx (atoms : Array Expr) (e : Expr) : StateT (Std.HashMap Expr Expr) MetaM Expr := do
  if let some r := (← get)[e]? then return r
  let r ← go e
  modify (·.insert e r)
  return r
where
  go (e : Expr) : StateT (Std.HashMap Expr Expr) MetaM Expr := do
    match e.getAppFnArgs with
    | (``HAdd.hAdd, #[_, _, _, _, a, b]) =>
      return mkApp2 (mkConst ``Ex.add) (← reifyEx atoms a) (← reifyEx atoms b)
    | (``HMul.hMul, #[_, _, _, _, a, b]) =>
      return mkApp2 (mkConst ``Ex.mul) (← reifyEx atoms a) (← reifyEx atoms b)
    | (``HSub.hSub, #[_, _, _, _, a, b]) =>
      return mkApp2 (mkConst ``Ex.sub) (← reifyEx atoms a) (← reifyEx atoms b)
    | (``Neg.neg, #[_, _, a]) => return mkApp (mkConst ``Ex.neg) (← reifyEx atoms a)
    | (``Gates_base.add, #[_, _, a, b]) =>
      return mkApp2 (mkConst ``Ex.add) (← reifyEx atoms a) (← reifyEx atoms b)
    | (``Gates_base.mul, #[_, _, a, b]) =>
      return mkApp2 (mkConst ``Ex.mul) (← reifyEx atoms a) (← reifyEx atoms b)
    | (``Gates_base.sub, #[_, _, a, b]) =>
      return mkApp2 (mkConst ``Ex.sub) (← reifyEx atoms a) (← reifyEx atoms b)
    | (``OfNat.ofNat, #[_, n, _]) =>
      let some v := n.rawNatLit? | throwError "poly_refl: numeral {n} is not a literal"
      if v = 0 then return mkConst ``Ex.zero
      if v = 1 then return mkConst ``Ex.one
      return mkApp (mkConst ``Ex.lit) (mkNatLit v)
    | _ =>
      if e.getAppFn.isConst && !(e.isAppOf ``List.Vector.get) then
        if let some e' ← unfoldDefinition? e then return ← reifyEx atoms e'.headBeta
      let e' ← whnfD e
      for h : i in [0:atoms.size] do
        if atoms[i] == e' then return mkApp (mkConst ``Ex.atom) (mkNatLit i)
      throwError "poly_refl: unknown leaf {e}"

elab "poly_refl" : tactic => do
  let g ← getMainGoal
  g.withContext do
    let t ← instantiateMVars (← g.getType)
    let some (_, lhs, rhs) := t.eq? | throwError "poly_refl: goal is not an equation"
    let lhs ← instantiateMVars lhs
    let args := lhs.getAppArgs
    unless lhs.isAppOfArity ``polyEval 2 do throwError "poly_refl: left side is not polyEval env P"
    let env := args[0]!
    let P := args[1]!
    let atoms ← envAtoms env
    let (ex, _) ← (reifyEx atoms rhs).run {}
    let normEq ← mkEq P (mkApp (mkConst ``Ex.norm) ex)
    let hNorm ← mkFreshExprMVar normEq
    let [] ← Lean.Elab.Term.TermElabM.run' (Tactic.run hNorm.mvarId! (evalTactic (← `(tactic| decide +kernel))))
      | throwError "poly_refl: decide left goals"
    let pf := mkAppN (mkConst ``eval_eq_of_norm_eq) #[env, P, ex, hNorm]
    g.assign pf
    replaceMainGoal []

theorem exists_eq_and_elim {α : Sort _} {p : α → Prop} {e : α} (h : ∃ x, x = e ∧ p x) : p e := by
  obtain ⟨x, rfl, hp⟩ := h; exact hp

theorem and_map_right {a b c : Prop} (f : b → c) (h : a ∧ b) : a ∧ c := ⟨h.1, f h.2⟩

theorem exists_map' {α : Sort _} {p q : α → Prop} (f : ∀ x, p x → q x) (h : ∃ x, p x) : ∃ x, q x :=
  let ⟨x, hx⟩ := h; ⟨x, f x hx⟩

/-- Remove every `∃ g, g = e ∧ R g` layer of a conjunction chain, substituting `e`.
Given a proof `h : P`, returns the reduced proposition and a proof of it. -/
partial def elimGatesCore (P h : Expr) : MetaM (Expr × Expr) := do
  if P.isAppOfArity ``Exists 2 then
    let α := P.appFn!.appArg!
    let lam := P.appArg!
    if let .lam n ty body bi := lam then
      let lvl ← getLevel α
      if body.isAppOfArity ``And 2 then
        let eqPart := body.appFn!.appArg!
        let rest := body.appArg!
        if eqPart.isAppOfArity ``Eq 3 && eqPart.appFn!.appArg! == .bvar 0 && !eqPart.appArg!.hasLooseBVars then
          let e := eqPart.appArg!
          let pfun := Expr.lam n ty rest bi
          let h' := mkAppN (mkConst ``exists_eq_and_elim [lvl]) #[α, pfun, e, h]
          return ← elimGatesCore (rest.instantiate1 e) h'
      withLocalDecl n bi ty fun x => do
        let px := body.instantiate1 x
        withLocalDeclD `hx px fun hx => do
          let (q, pq) ← elimGatesCore px hx
          let qlam ← mkLambdaFVars #[x] q
          let fx ← mkLambdaFVars #[x, hx] pq
          let res := mkApp2 (mkConst ``Exists [lvl]) α qlam
          return (res, mkAppN (mkConst ``exists_map' [lvl]) #[α, lam, qlam, fx, h])
    else return (P, h)
  else if P.isAppOfArity ``And 2 then
    let a := P.appFn!.appArg!
    let b := P.appArg!
    let (q, pq) ← elimGatesCore b (mkAppN (mkConst ``And.right) #[a, b, h])
    return (mkApp2 (mkConst ``And) a q, mkAppN (mkConst ``And.intro) #[a, q, mkAppN (mkConst ``And.left) #[a, b, h], pq])
  else
    return (P, h)

/-- `elim_gates h` replaces `h` by the proposition with every gate equation substituted. -/
elab "elim_gates " h:ident : tactic => do
  let g ← getMainGoal
  g.withContext do
    let decl ← getLocalDeclFromUserName h.getId
    let P ← instantiateMVars decl.type
    let (q, pf) ← elimGatesCore P decl.toExpr
    let g' ← g.assert h.getId q pf
    let g'' ← g'.clear decl.fvarId
    let (_, g''') ← g''.intro1P
    replaceMainGoal [g''']

/-- `ex_refl` closes `Ex.eval env e = t` by reifying `t` and comparing factored
normal forms with `decide +kernel`. -/
elab "ex_refl" : tactic => do
  let g ← getMainGoal
  g.withContext do
    let t ← instantiateMVars (← g.getType)
    let some (_, lhs, rhs) := t.eq? | throwError "ex_refl: goal is not an equation"
    let lhs ← instantiateMVars lhs
    unless lhs.isAppOfArity ``Ex.eval 2 do throwError "ex_refl: left side is not Ex.eval env e"
    let args := lhs.getAppArgs
    let env := args[0]!
    let e := args[1]!
    let atoms ← envAtoms env
    let (ex, _) ← (reifyEx atoms rhs).run {}
    let normEq ← mkEq (mkApp (mkConst ``Ex.fnorm) e) (mkApp (mkConst ``Ex.fnorm) ex)
    let hNorm ← mkFreshExprMVar normEq
    let [] ← Lean.Elab.Term.TermElabM.run' (Tactic.run hNorm.mvarId! (evalTactic (← `(tactic| decide +kernel))))
      | throwError "ex_refl: decide left goals"
    let pf := mkAppN (mkConst ``Ex.eval_eq_of_fnorm) #[env, e, ex, hNorm]
    g.assign pf
    replaceMainGoal []

end ZolanaVE.Field
