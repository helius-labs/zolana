import VerifiableEncryption.Field.Reflect

/-!
Factored normal form for reflection.

The constrained values of a check are linear combinations of products of
linear forms (CRT evaluation forms, Vandermonde evaluations). Expanding those
products makes kernel normalization slow, so `FP` keeps them factored: a
normalized linear part plus a sorted list of products, each a sorted list of
normalized nonconstant linear factors with a coefficient. Both sides of an
identity are built by the same arithmetic, so their factored forms agree;
equal factored forms evaluate equally (`Ex.eval_fnorm`).
-/

namespace ZolanaVE.Field

def polyCmpTerm : Mono × ℕ → Mono × ℕ → Ordering
  | (m, c), (m', c') =>
    if m = m' then compare c c' else if monoLt m m' then .lt else .gt

def polyLt : Poly → Poly → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | t :: p, t' :: p' =>
    match polyCmpTerm t t' with
    | .lt => true
    | .gt => false
    | .eq => polyLt p p'

def factorsLt : List Poly → List Poly → Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | f :: fs, f' :: fs' => if f = f' then factorsLt fs fs' else polyLt f f'

def insertFactor (f : Poly) : List Poly → List Poly
  | [] => [f]
  | g :: gs => if polyLt f g then f :: g :: gs else g :: insertFactor f gs

def mergeFactors (fs gs : List Poly) : List Poly := fs.foldr insertFactor gs

abbrev Prods := List (List Poly × ℕ)

def insertProd (t : List Poly × ℕ) : Prods → Prods
  | [] => if t.2 % Order = 0 then [] else [(t.1, t.2 % Order)]
  | (fs, c) :: p =>
    if t.1 = fs then
      let s := (c + t.2) % Order
      if s = 0 then p else (fs, s) :: p
    else if factorsLt t.1 fs then
      if t.2 % Order = 0 then (fs, c) :: p else (t.1, t.2 % Order) :: (fs, c) :: p
    else (fs, c) :: insertProd t p

def addProds (p q : Prods) : Prods := p.foldr insertProd q

def scaleProds (c : ℕ) (p : Prods) : Prods := p.foldr (fun t acc => insertProd (t.1, c * t.2) acc) []

structure FP where
  lin : Poly
  prods : Prods
deriving DecidableEq

/-- A polynomial of degree zero: its constant (`[]` is zero). -/
def constOf? : Poly → Option ℕ
  | [] => some 0
  | [([], c)] => some c
  | _ => none

def FP.add (a b : FP) : FP := ⟨padd a.lin b.lin, addProds a.prods b.prods⟩

def FP.neg (a : FP) : FP := ⟨pneg a.lin, scaleProds (Order - 1) a.prods⟩

def FP.scale (c : ℕ) (a : FP) : FP := ⟨pmul (pconst c) a.lin, scaleProds c a.prods⟩

/-- Multiply a product term by a linear polynomial. -/
def mulLinProd (l : Poly) (t : List Poly × ℕ) : FP :=
  match constOf? l with
  | some c => ⟨[], insertProd (t.1, c * t.2) []⟩
  | none => ⟨[], insertProd (insertFactor l t.1, t.2) []⟩

def mulProds (s t : List Poly × ℕ) : Prods := insertProd (mergeFactors s.1 t.1, s.2 * t.2) []

def linMul (al bl : Poly) : FP :=
  match constOf? al with
  | some c => ⟨pmul (pconst c) bl, []⟩
  | none =>
    match constOf? bl with
    | some c => ⟨pmul (pconst c) al, []⟩
    | none => ⟨[], insertProd (insertFactor al [bl], 1) []⟩

def prodsMul (ap bp : Prods) : Prods :=
  ap.foldr (fun s acc => bp.foldr (fun t acc' => addProds (mulProds s t) acc') acc) []

def linProds (l : Poly) (p : Prods) : FP := p.foldr (fun t acc => acc.add (mulLinProd l t)) ⟨[], []⟩

def FP.mulGeneral (a b : FP) : FP :=
  (((linMul a.lin b.lin).add (linProds a.lin b.prods)).add (linProds b.lin a.prods)).add ⟨[], prodsMul a.prods b.prods⟩

def FP.isConst? (a : FP) : Option ℕ :=
  match a.prods with
  | [] => constOf? a.lin
  | _ => none

def FP.mul (a b : FP) : FP :=
  match a.isConst? with
  | some c => b.scale c
  | none =>
    match b.isConst? with
    | some c => a.scale c
    | none => a.mulGeneral b

def Ex.fnorm : Ex → FP
  | .atom i => ⟨patom i, []⟩
  | .lit c => ⟨pconst c, []⟩
  | .zero => ⟨[], []⟩
  | .one => ⟨pconst 1, []⟩
  | .add a b => a.fnorm.add b.fnorm
  | .mul a b => a.fnorm.mul b.fnorm
  | .sub a b => a.fnorm.add b.fnorm.neg
  | .neg a => a.fnorm.neg

section Eval

variable (env : ℕ → F)

def prodEval (t : List Poly × ℕ) : F := (t.2 : F) * (t.1.map (polyEval env)).prod

def prodsEval (p : Prods) : F := (p.map (prodEval env)).sum

def FP.eval (a : FP) : F := polyEval env a.lin + prodsEval env a.prods

@[simp] theorem prodsEval_nil : prodsEval env [] = 0 := rfl

theorem prodsEval_insert (t : List Poly × ℕ) (p : Prods) :
    prodsEval env (insertProd t p) = prodEval env t + prodsEval env p := by
  induction p with
  | nil =>
    unfold insertProd
    split_ifs with h
    · have : ((t.2 : ℕ) : F) = 0 := by rw [← natCast_mod_order, h, Nat.cast_zero]
      simp [prodsEval, prodEval, this]
    · simp [prodsEval, prodEval, natCast_mod_order]
  | cons fc p ih =>
    obtain ⟨fs, c⟩ := fc
    obtain ⟨tf, tc⟩ := t
    simp only [prodEval] at ih ⊢
    by_cases h1 : tf = fs
    · subst h1
      simp only [insertProd, if_true]
      by_cases h2 : (c + tc) % Order = 0
      · have : ((c + tc : ℕ) : F) = 0 := by rw [← natCast_mod_order, h2, Nat.cast_zero]
        push_cast at this
        simp only [h2, if_true, prodsEval, List.map_cons, List.sum_cons, prodEval]
        linear_combination (-(tf.map (polyEval env)).prod) * this
      · simp only [h2, if_false, prodsEval, List.map_cons, List.sum_cons, prodEval, natCast_mod_order]
        push_cast; ring
    · simp only [insertProd, h1, if_false]
      by_cases h3 : factorsLt tf fs = true
      · simp only [h3, if_true]
        by_cases h4 : tc % Order = 0
        · have : ((tc : ℕ) : F) = 0 := by rw [← natCast_mod_order, h4, Nat.cast_zero]
          simp [h4, prodsEval, prodEval, this]
        · simp only [h4, if_false, prodsEval, List.map_cons, List.sum_cons, prodEval, natCast_mod_order]
      · simp only [h3, Bool.false_eq_true, if_false, prodsEval, List.map_cons, List.sum_cons] at ih ⊢
        rw [ih]; simp only [prodEval]; ring

theorem prodsEval_add (p q : Prods) : prodsEval env (addProds p q) = prodsEval env p + prodsEval env q := by
  induction p with
  | nil => simp [addProds]
  | cons t p ih =>
    simp only [addProds, List.foldr_cons] at ih ⊢
    rw [prodsEval_insert, ih]; simp [prodsEval, add_assoc]

theorem prodsEval_scale (c : ℕ) (p : Prods) : prodsEval env (scaleProds c p) = (c : F) * prodsEval env p := by
  induction p with
  | nil => simp [scaleProds, prodsEval]
  | cons t p ih =>
    simp only [scaleProds, List.foldr_cons] at ih ⊢
    rw [prodsEval_insert, ih]; simp [prodsEval, prodEval]; ring

theorem prodEval_insertFactor (f : Poly) (fs : List Poly) :
    ((insertFactor f fs).map (polyEval env)).prod = polyEval env f * (fs.map (polyEval env)).prod := by
  induction fs with
  | nil => simp [insertFactor]
  | cons g gs ih =>
    unfold insertFactor
    split_ifs
    · simp
    · simp only [List.map_cons, List.prod_cons, ih]; ring

theorem prodEval_mergeFactors (fs gs : List Poly) :
    ((mergeFactors fs gs).map (polyEval env)).prod = (fs.map (polyEval env)).prod * (gs.map (polyEval env)).prod := by
  induction fs with
  | nil => simp [mergeFactors]
  | cons f fs ih =>
    simp only [mergeFactors, List.foldr_cons] at ih ⊢
    rw [prodEval_insertFactor, ih]; simp; ring

theorem FP.eval_add (a b : FP) : (a.add b).eval env = a.eval env + b.eval env := by
  simp only [FP.add, FP.eval, polyEval_padd, prodsEval_add]; ring

theorem FP.eval_neg (a : FP) : a.neg.eval env = -a.eval env := by
  simp only [FP.neg, FP.eval, polyEval_pneg, prodsEval_scale]
  have : ((Order - 1 : ℕ) : F) = -1 := by
    rw [Nat.cast_sub order_pos, ZMod.natCast_self]; simp
  rw [this]; ring

theorem FP.eval_scale (c : ℕ) (a : FP) : (a.scale c).eval env = (c : F) * a.eval env := by
  simp only [FP.scale, FP.eval, polyEval_pmul, polyEval_pconst, prodsEval_scale]; ring

theorem constOf?_eval {l : Poly} {c : ℕ} (h : constOf? l = some c) : polyEval env l = (c : F) := by
  unfold constOf? at h
  split at h
  · simp only [Option.some.injEq] at h; subst h; simp
  · simp only [Option.some.injEq] at h; subst h; simp [polyEval, termEval, monoEval]
  · simp at h

theorem mulLinProd_eval (l : Poly) (t : List Poly × ℕ) :
    (mulLinProd l t).eval env = polyEval env l * prodEval env t := by
  unfold mulLinProd
  split
  · rename_i c hc
    rw [FP.eval, polyEval_nil, prodsEval_insert, prodsEval_nil, constOf?_eval env hc]
    simp only [prodEval]; push_cast; ring
  · rw [FP.eval, polyEval_nil, prodsEval_insert, prodsEval_nil]
    simp only [prodEval, prodEval_insertFactor]; ring

theorem linProds_eval (l : Poly) (p : Prods) :
    (linProds l p).eval env = polyEval env l * prodsEval env p := by
  induction p with
  | nil => simp [linProds, FP.eval]
  | cons t p ih =>
    simp only [linProds, List.foldr_cons] at ih ⊢
    rw [FP.eval_add, ih, mulLinProd_eval]
    simp only [prodsEval, List.map_cons, List.sum_cons]; ring

theorem linMul_eval (al bl : Poly) : (linMul al bl).eval env = polyEval env al * polyEval env bl := by
  unfold linMul
  split
  · rename_i c hc
    simp [FP.eval, polyEval_pmul, polyEval_pconst, constOf?_eval env hc]
  · split
    · rename_i c hc
      simp [FP.eval, polyEval_pmul, polyEval_pconst, constOf?_eval env hc]; ring
    · rw [FP.eval, polyEval_nil, prodsEval_insert, prodsEval_nil]
      simp [prodEval, prodEval_insertFactor]

theorem prodsMul_inner (s : List Poly × ℕ) (bp : Prods) (acc : Prods) :
    prodsEval env (bp.foldr (fun t acc' => addProds (mulProds s t) acc') acc) =
      prodEval env s * prodsEval env bp + prodsEval env acc := by
  induction bp with
  | nil => simp
  | cons t ts iht =>
    simp only [List.foldr_cons]
    rw [prodsEval_add, iht, mulProds, prodsEval_insert, prodsEval_nil]
    simp only [prodEval, prodEval_mergeFactors, prodsEval, List.map_cons, List.sum_cons]
    push_cast; ring

theorem prodsMul_eval (ap bp : Prods) : prodsEval env (prodsMul ap bp) = prodsEval env ap * prodsEval env bp := by
  unfold prodsMul
  induction ap with
  | nil => simp
  | cons s ps ih =>
    simp only [List.foldr_cons]
    rw [prodsMul_inner, ih]
    simp only [prodsEval, List.map_cons, List.sum_cons]; ring

theorem FP.eval_mulGeneral (a b : FP) : (a.mulGeneral b).eval env = a.eval env * b.eval env := by
  simp only [FP.mulGeneral, FP.eval_add, linMul_eval, linProds_eval]
  rw [FP.eval, polyEval_nil, prodsMul_eval]
  simp only [FP.eval]; ring

theorem FP.isConst?_eval {a : FP} {c : ℕ} (h : a.isConst? = some c) : a.eval env = (c : F) := by
  unfold FP.isConst? at h
  split at h
  · rename_i hp
    rw [FP.eval, hp, prodsEval_nil, add_zero, constOf?_eval env h]
  · simp at h

theorem FP.eval_mul (a b : FP) : (a.mul b).eval env = a.eval env * b.eval env := by
  unfold FP.mul
  split
  · rename_i c hc
    rw [FP.eval_scale, FP.isConst?_eval env hc]
  · split
    · rename_i c hc
      rw [FP.eval_scale, FP.isConst?_eval env hc, mul_comm]
    · exact FP.eval_mulGeneral env a b

theorem Ex.eval_fnorm (e : Ex) : e.fnorm.eval env = e.eval env := by
  induction e with
  | atom i => simp [Ex.fnorm, FP.eval, polyEval_patom, prodsEval, Ex.eval]
  | lit c => simp [Ex.fnorm, FP.eval, polyEval_pconst, prodsEval, Ex.eval]
  | zero => simp [Ex.fnorm, FP.eval, prodsEval, Ex.eval]
  | one => simp [Ex.fnorm, FP.eval, polyEval_pconst, prodsEval, Ex.eval]
  | add a b iha ihb => rw [Ex.fnorm, FP.eval_add, iha, ihb]; rfl
  | mul a b iha ihb => rw [Ex.fnorm, FP.eval_mul, iha, ihb]; rfl
  | sub a b iha ihb => rw [Ex.fnorm, FP.eval_add, FP.eval_neg, iha, ihb, Ex.eval, sub_eq_add_neg]
  | neg a iha => rw [Ex.fnorm, FP.eval_neg, iha]; rfl

end Eval

/-- Two expressions with the same factored normal form evaluate equally. -/
theorem Ex.eval_eq_of_fnorm (env : ℕ → F) {a b : Ex} (h : a.fnorm = b.fnorm) : a.eval env = b.eval env := by
  rw [← Ex.eval_fnorm, h, Ex.eval_fnorm]

end ZolanaVE.Field
