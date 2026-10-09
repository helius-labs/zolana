import VerifiableEncryption.Field.Factored

/-!
Tactics for the instance proofs: `elim_gates` substitutes the gate equations
of an extracted definition, `ex_refl` closes `Ex.eval env e = t` where `env`
is `fun i => [x₀, …, xₙ].getD i 0` and `t` is built from `+`, `*`, `-`,
negation, numerals, reducible constants and the atoms `xⱼ`.
-/

namespace ZolanaVE.Field

open Lean Meta Elab Tactic

/-- The atoms of `fun i => List.getD [x₀, …] i 0`. -/
def envAtoms (env : Expr) : MetaM (Array Expr) := do
  let env ← whnfR env
  let .lam _ _ body _ := env | throwError "ex_refl: env is not a lambda"
  let body := body.getAppArgs
  let some lst := body[1]? | throwError "ex_refl: env body is not List.getD"
  let mut out := #[]
  let mut cur ← whnfD lst
  while true do
    match cur.getAppFnArgs with
    | (``List.cons, #[_, h, t]) =>
      out := out.push h
      cur ← whnfD t
    | (``List.nil, _) => break
    | _ => throwError "ex_refl: env list is not a literal"
  return out

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
    match P.getAppFn.constName? with
    | some n =>
      if isPartName n then
        if let some P' ← unfoldDefinition? P then
          return ← elimGatesCore P'.headBeta h
      return (P, h)
    | none => return (P, h)
where
  isPartName (n : Name) : Bool :=
    match n with
    | .str _ s =>
      match s.splitOn "_p" with
      | [] | [_] => false
      | parts => (parts.getLast!).all Char.isDigit && !(parts.getLast!).isEmpty
    | _ => false

/-- `elim_gates h` replaces `h` by the proposition with every gate equation
substituted. Continuation parts `<name>_p<j>` are unfolded only when the walk
reaches them, so each `∃` chain the kernel checks is one part long. -/
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

theorem rf_add {env : ℕ → F} {a b : F} {ea eb : Ex} (ha : a = ea.eval env) (hb : b = eb.eval env) :
    a + b = (Ex.add ea eb).eval env := by rw [ha, hb]; rfl

theorem rf_mul {env : ℕ → F} {a b : F} {ea eb : Ex} (ha : a = ea.eval env) (hb : b = eb.eval env) :
    a * b = (Ex.mul ea eb).eval env := by rw [ha, hb]; rfl

theorem rf_sub {env : ℕ → F} {a b : F} {ea eb : Ex} (ha : a = ea.eval env) (hb : b = eb.eval env) :
    a - b = (Ex.sub ea eb).eval env := by rw [ha, hb]; rfl

theorem rf_neg {env : ℕ → F} {a : F} {ea : Ex} (ha : a = ea.eval env) : -a = (Ex.neg ea).eval env := by
  rw [ha]; rfl

/-- `(v, k)` for `List.Vector.get v (k : Fin n)` with a numeral index. -/
def vecAtomKey? (e : Expr) : Option (Expr × Nat) :=
  if e.isAppOfArity ``List.Vector.get 4 then
    match e.appArg!.getAppFnArgs with
    | (``OfNat.ofNat, #[_, n, _]) => n.rawNatLit?.map (e.appFn!.appArg!, ·)
    | _ => none
  else none

/-- Reify `e` and prove `e = Ex.eval env ex` with one congruence step per node;
shared subterms are reified and proved once. -/
partial def reifyPf (env Fty : Expr) (atoms : Array Expr) (e : Expr) :
    StateT (Std.HashMap Expr (Expr × Expr)) MetaM (Expr × Expr) := do
  if let some r := (← get)[e]? then return r
  let r ← go e
  modify (·.insert e r)
  return r
where
  refl (e ex : Expr) : Expr × Expr := (ex, mkApp2 (mkConst ``Eq.refl [levelOne]) Fty e)
  bin (lem ctor : Name) (a b : Expr) : StateT (Std.HashMap Expr (Expr × Expr)) MetaM (Expr × Expr) := do
    let (ea, pa) ← reifyPf env Fty atoms a
    let (eb, pb) ← reifyPf env Fty atoms b
    return (mkApp2 (mkConst ctor) ea eb, mkAppN (mkConst lem) #[env, a, b, ea, eb, pa, pb])
  go (e : Expr) : StateT (Std.HashMap Expr (Expr × Expr)) MetaM (Expr × Expr) := do
    match e.getAppFnArgs with
    | (``HAdd.hAdd, #[_, _, _, _, a, b]) => bin ``rf_add ``Ex.add a b
    | (``HMul.hMul, #[_, _, _, _, a, b]) => bin ``rf_mul ``Ex.mul a b
    | (``HSub.hSub, #[_, _, _, _, a, b]) => bin ``rf_sub ``Ex.sub a b
    | (``Gates_base.add, #[_, _, a, b]) => bin ``rf_add ``Ex.add a b
    | (``Gates_base.mul, #[_, _, a, b]) => bin ``rf_mul ``Ex.mul a b
    | (``Gates_base.sub, #[_, _, a, b]) => bin ``rf_sub ``Ex.sub a b
    | (``Neg.neg, #[_, _, a]) =>
      let (ea, pa) ← reifyPf env Fty atoms a
      return (mkApp (mkConst ``Ex.neg) ea, mkAppN (mkConst ``rf_neg) #[env, a, ea, pa])
    | (``OfNat.ofNat, #[_, n, _]) =>
      let some v := n.rawNatLit? | throwError "ex_refl: numeral {n} is not a literal"
      if v = 0 then return refl e (mkConst ``Ex.zero)
      if v = 1 then return refl e (mkConst ``Ex.one)
      return refl e (mkApp (mkConst ``Ex.lit) (mkNatLit v))
    | _ =>
      if e.getAppFn.isConst && !(e.isAppOf ``List.Vector.get) then
        if let some e' ← unfoldDefinition? e then
          let (ex, _) ← reifyPf env Fty atoms e'.headBeta
          return refl e ex
      for h : i in [0:atoms.size] do
        if atoms[i] == e then return refl e (mkApp (mkConst ``Ex.atom) (mkNatLit i))
      if let some (v, k) := vecAtomKey? e then
        for h : i in [0:atoms.size] do
          if let some (v', k') := vecAtomKey? atoms[i] then
            if v == v' && k == k' then return refl e (mkApp (mkConst ``Ex.atom) (mkNatLit i))
      let e' ← whnfD e
      for h : i in [0:atoms.size] do
        if (← whnfD atoms[i]) == e' then return refl e (mkApp (mkConst ``Ex.atom) (mkNatLit i))
      throwError "ex_refl: unknown leaf {e}"

/-- `ex_refl` closes `Ex.eval env e = t`: it reifies `t` with a congruence
proof, checks that the factored normal forms agree in an auxiliary theorem
proved by kernel evaluation, and chains the two. -/
elab "ex_refl" : tactic => do
  let g ← getMainGoal
  g.withContext do
    let t ← instantiateMVars (← g.getType)
    let some (Fty, lhs, rhs) := t.eq? | throwError "ex_refl: goal is not an equation"
    let lhs ← instantiateMVars lhs
    unless lhs.isAppOfArity ``Ex.eval 2 do throwError "ex_refl: left side is not Ex.eval env e"
    let args := lhs.getAppArgs
    let env := args[0]!
    let e ← instantiateMVars args[1]!
    let atoms ← envAtoms env
    let ((ex, pfExt), _) ← (reifyPf env Fty atoms rhs).run {}
    let normEq ← mkEq (mkApp (mkConst ``Ex.fnorm) e) (mkApp (mkConst ``Ex.fnorm) ex)
    let hNorm ← mkFreshExprMVar normEq
    let [] ← Lean.Elab.Term.TermElabM.run' (Tactic.run hNorm.mvarId! (evalTactic (← `(tactic| decide +kernel))))
      | throwError "ex_refl: decide left goals"
    let evalE := mkAppN (mkConst ``Ex.eval) #[env, e]
    let evalX := mkAppN (mkConst ``Ex.eval) #[env, ex]
    let h1 := mkAppN (mkConst ``Ex.eval_eq_of_fnorm) #[env, e, ex, hNorm]
    let h2 := mkAppN (mkConst ``Eq.symm [levelOne]) #[Fty, rhs, evalX, pfExt]
    g.assign (mkAppN (mkConst ``Eq.trans [levelOne]) #[Fty, evalE, evalX, rhs, h1, h2])
    replaceMainGoal []

end ZolanaVE.Field
