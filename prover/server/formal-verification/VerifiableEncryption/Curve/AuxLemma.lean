import Lean

/-!
`aux_lemma => tac`: prove the main goal with `tac` as a separate auxiliary
theorem closed over the local context, so a long proof is instantiated and
kernel-checked in pieces.
-/

open Lean Meta Elab Tactic

elab "aux_lemma" " => " tac:tacticSeq : tactic => do
  let g ← getMainGoal
  g.withContext do
    let ty ← instantiateMVars (← g.getType)
    let g' ← mkFreshExprSyntheticOpaqueMVar ty
    setGoals [g'.mvarId!]
    evalTactic tac
    let rest ← getUnsolvedGoals
    unless rest.isEmpty do
      throwError "aux_lemma: unsolved goals remain"
    let pf ← instantiateMVars g'
    let base ← match (← Term.getDeclName?) with
      | some n => pure n
      | none => pure `aux
    let name ← mkAuxName (base ++ `aux_lemma) 1
    let e ← mkAuxTheorem name ty pf (zetaDelta := true)
    g.assign e
    setGoals []
