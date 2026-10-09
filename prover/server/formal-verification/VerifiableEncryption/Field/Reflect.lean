import VerifiableEncryption.Field.Layout

/-!
Kernel reflection for polynomial identities over the native field.

`Poly` is a sparse polynomial: a list of monomials (sorted lists of atom
indices) with nonzero coefficients reduced modulo `Order`. Every operation is
built from `insertTerm`, which is structural, so the kernel evaluates
normal forms in `decide +kernel` proofs. Two expressions with equal normal
forms evaluate to the same field element (`Ex.eval_norm`); the converse is not
needed.
-/

namespace ZolanaVE.Field

abbrev Mono := List ℕ

abbrev Poly := List (Mono × ℕ)

def monoInsert (a : ℕ) : Mono → Mono
  | [] => [a]
  | b :: m => if a ≤ b then a :: b :: m else b :: monoInsert a m

def monoMul (m m' : Mono) : Mono := m.foldr monoInsert m'

def monoLt : Mono → Mono → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | a :: m, b :: m' => if a < b then true else if b < a then false else monoLt m m'

def insertTerm (t : Mono × ℕ) : Poly → Poly
  | [] => if t.2 % Order = 0 then [] else [(t.1, t.2 % Order)]
  | (m, c) :: p =>
    if t.1 = m then
      let s := (c + t.2) % Order
      if s = 0 then p else (m, s) :: p
    else if monoLt t.1 m then
      if t.2 % Order = 0 then (m, c) :: p else (t.1, t.2 % Order) :: (m, c) :: p
    else (m, c) :: insertTerm t p

def padd (p q : Poly) : Poly := p.foldr insertTerm q

def pscale (t : Mono × ℕ) (q : Poly) : Poly := q.foldr (fun t' acc => insertTerm (monoMul t.1 t'.1, t.2 * t'.2) acc) []

def pmul (p q : Poly) : Poly := p.foldr (fun t acc => padd (pscale t q) acc) []

def pconst (c : ℕ) : Poly := insertTerm ([], c) []

def patom (i : ℕ) : Poly := [([i], 1)]

def pneg (p : Poly) : Poly := p.foldr (fun t acc => insertTerm (t.1, (Order - t.2 % Order) % Order) acc) []

def psub (p q : Poly) : Poly := padd p (pneg q)

def pint (c : ℤ) : Poly := if 0 ≤ c then pconst c.toNat else pneg (pconst (-c).toNat)

section Eval

variable (env : ℕ → F)

def monoEval (m : Mono) : F := (m.map env).prod

def termEval (t : Mono × ℕ) : F := (t.2 : F) * monoEval env t.1

def polyEval (p : Poly) : F := (p.map (termEval env)).sum

@[simp] theorem polyEval_nil : polyEval env [] = 0 := rfl

theorem monoEval_insert (a : ℕ) (m : Mono) : monoEval env (monoInsert a m) = env a * monoEval env m := by
  induction m with
  | nil => simp [monoInsert, monoEval]
  | cons b m ih =>
    unfold monoInsert
    split_ifs
    · simp [monoEval]
    · simp only [monoEval, List.map_cons, List.prod_cons] at ih ⊢
      rw [ih]; ring

theorem monoEval_mul (m m' : Mono) : monoEval env (monoMul m m') = monoEval env m * monoEval env m' := by
  induction m with
  | nil => simp [monoMul, monoEval]
  | cons a m ih =>
    simp only [monoMul, List.foldr_cons] at ih ⊢
    rw [monoEval_insert, ih]
    simp [monoEval, mul_assoc]

theorem natCast_mod_order (c : ℕ) : ((c % Order : ℕ) : F) = (c : F) := ZMod.natCast_mod c Order

theorem polyEval_insert (t : Mono × ℕ) (p : Poly) :
    polyEval env (insertTerm t p) = termEval env t + polyEval env p := by
  induction p with
  | nil =>
    unfold insertTerm
    split_ifs with h
    · have : ((t.2 : ℕ) : F) = 0 := by rw [← natCast_mod_order, h, Nat.cast_zero]
      simp [polyEval, termEval, this]
    · simp [polyEval, termEval, natCast_mod_order]
  | cons mc p ih =>
    obtain ⟨m, c⟩ := mc
    obtain ⟨tm, tc⟩ := t
    simp only [termEval] at ih ⊢
    by_cases h1 : tm = m
    · subst h1
      simp only [insertTerm, if_true]
      by_cases h2 : (c + tc) % Order = 0
      · have : ((c + tc : ℕ) : F) = 0 := by rw [← natCast_mod_order, h2, Nat.cast_zero]
        push_cast at this
        simp only [h2, if_true, polyEval, List.map_cons, List.sum_cons, termEval]
        linear_combination (-monoEval env tm) * this
      · simp only [h2, if_false, polyEval, List.map_cons, List.sum_cons, termEval, natCast_mod_order]
        push_cast; ring
    · simp only [insertTerm, h1, if_false]
      by_cases h3 : monoLt tm m = true
      · simp only [h3, if_true]
        by_cases h4 : tc % Order = 0
        · have : ((tc : ℕ) : F) = 0 := by rw [← natCast_mod_order, h4, Nat.cast_zero]
          simp [h4, polyEval, termEval, this]
        · simp only [h4, if_false, polyEval, List.map_cons, List.sum_cons, termEval, natCast_mod_order]
      · simp only [h3, Bool.false_eq_true, if_false, polyEval, List.map_cons, List.sum_cons] at ih ⊢
        rw [ih]; simp only [termEval]; ring

theorem polyEval_padd (p q : Poly) : polyEval env (padd p q) = polyEval env p + polyEval env q := by
  induction p with
  | nil => simp [padd, polyEval]
  | cons t p ih =>
    simp only [padd, List.foldr_cons] at ih ⊢
    rw [polyEval_insert, ih]
    simp [polyEval, add_assoc]

theorem polyEval_pscale (t : Mono × ℕ) (q : Poly) :
    polyEval env (pscale t q) = termEval env t * polyEval env q := by
  induction q with
  | nil => simp [pscale, polyEval]
  | cons t' q ih =>
    simp only [pscale, List.foldr_cons] at ih ⊢
    rw [polyEval_insert, ih]
    simp only [termEval, monoEval_mul, polyEval, List.map_cons, List.sum_cons]
    push_cast; ring

theorem polyEval_pmul (p q : Poly) : polyEval env (pmul p q) = polyEval env p * polyEval env q := by
  induction p with
  | nil => simp [pmul, polyEval]
  | cons t p ih =>
    simp only [pmul, List.foldr_cons] at ih ⊢
    rw [polyEval_padd, polyEval_pscale, ih]
    simp [polyEval]; ring

theorem polyEval_pconst (c : ℕ) : polyEval env (pconst c) = (c : F) := by
  rw [pconst, polyEval_insert]
  simp [polyEval, termEval, monoEval]

theorem polyEval_patom (i : ℕ) : polyEval env (patom i) = env i := by
  simp [patom, polyEval, termEval, monoEval]

theorem natCast_neg_mod (c : ℕ) : (((Order - c % Order) % Order : ℕ) : F) = -(c : F) := by
  rw [natCast_mod_order]
  have hlt : c % Order ≤ Order := (Nat.mod_lt _ order_pos).le
  rw [Nat.cast_sub hlt, ZMod.natCast_self, natCast_mod_order]; ring

theorem polyEval_pneg (p : Poly) : polyEval env (pneg p) = -polyEval env p := by
  induction p with
  | nil => simp [pneg, polyEval]
  | cons t p ih =>
    simp only [pneg, List.foldr_cons] at ih ⊢
    rw [polyEval_insert, ih]
    simp only [termEval, natCast_neg_mod, polyEval, List.map_cons, List.sum_cons]
    ring

theorem polyEval_psub (p q : Poly) : polyEval env (psub p q) = polyEval env p - polyEval env q := by
  simp [psub, polyEval_padd, polyEval_pneg, sub_eq_add_neg]

theorem polyEval_pint (c : ℤ) : polyEval env (pint c) = (c : F) := by
  unfold pint
  split_ifs with h
  · rw [polyEval_pconst]
    have : ((c.toNat : ℕ) : ℤ) = c := Int.toNat_of_nonneg h
    rw [← this]; push_cast; rfl
  · rw [polyEval_pneg, polyEval_pconst]
    have : (((-c).toNat : ℕ) : ℤ) = -c := Int.toNat_of_nonneg (by omega)
    have h2 : (((-c).toNat : ℕ) : F) = ((-c : ℤ) : F) := by rw [← this]; push_cast; rfl
    rw [h2]; push_cast; ring

end Eval

/-! ### Expressions -/

inductive Ex where
  | atom (i : ℕ)
  | lit (c : ℕ)
  | zero
  | one
  | add (a b : Ex)
  | mul (a b : Ex)
  | sub (a b : Ex)
  | neg (a : Ex)

def Ex.eval (env : ℕ → F) : Ex → F
  | .atom i => env i
  | .lit c => (c : F)
  | .zero => 0
  | .one => 1
  | .add a b => a.eval env + b.eval env
  | .mul a b => a.eval env * b.eval env
  | .sub a b => a.eval env - b.eval env
  | .neg a => -(a.eval env)

def Ex.norm : Ex → Poly
  | .atom i => patom i
  | .lit c => pconst c
  | .zero => []
  | .one => pconst 1
  | .add a b => padd a.norm b.norm
  | .mul a b => pmul a.norm b.norm
  | .sub a b => psub a.norm b.norm
  | .neg a => pneg a.norm

theorem Ex.eval_norm (env : ℕ → F) (e : Ex) : polyEval env e.norm = e.eval env := by
  induction e with
  | atom i => exact polyEval_patom env i
  | lit c => exact polyEval_pconst env c
  | zero => rfl
  | one => rw [Ex.norm, polyEval_pconst]; simp [Ex.eval]
  | add a b iha ihb => rw [Ex.norm, polyEval_padd, iha, ihb]; rfl
  | mul a b iha ihb => rw [Ex.norm, polyEval_pmul, iha, ihb]; rfl
  | sub a b iha ihb => rw [Ex.norm, polyEval_psub, iha, ihb]; rfl
  | neg a iha => rw [Ex.norm, polyEval_pneg, iha]; rfl

theorem eval_eq_of_norm_eq (env : ℕ → F) {p : Poly} {e : Ex} (h : p = e.norm) : polyEval env p = e.eval env := by
  rw [h, Ex.eval_norm]

end ZolanaVE.Field
