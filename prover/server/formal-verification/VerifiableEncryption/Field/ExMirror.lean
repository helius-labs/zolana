import VerifiableEncryption.Field.Factored
import VerifiableEncryption.Field.CheckPolynomial
import VerifiableEncryption.Field.Lin

/-!
Expression-valued copies of the values `CheckPolynomial.circuit` and
`Lazy.circuit` constrain. Inputs are lists of `Ex` (normally single atoms), so
the kernel builds every constrained value as an expression from the
certificate alone; `Ex.eval` maps each copy to its value-level definition, and
`Ex.fnorm` compares it with the reified extracted expression.
-/

namespace ZolanaVE.Field

def eSum (es : List Ex) : Ex := es.foldl Ex.add Ex.zero

def eSumRange (n : ℕ) (f : ℕ → Ex) : Ex := eSum ((List.range n).map f)

def eProd (es : List Ex) : Ex := es.foldr Ex.mul Ex.one

def eint (c : ℤ) : Ex := if 0 ≤ c then .lit c.toNat else .neg (.lit (-c).toNat)

def eGet (P : List Ex) (i : ℕ) : Ex := P.getD i .zero

def eLinNat (f : ℕ → ℕ) (P : List Ex) : Ex := eSumRange P.length (fun i => .mul (.lit (f i)) (eGet P i))

def eEvalAt (P : List Ex) (x : ℤ) : Ex := eSumRange P.length (fun i => .mul (eint (x ^ i)) (eGet P i))

section Eval

variable (env : ℕ → F)

def evalE (P : List Ex) : List F := P.map (Ex.eval env)

theorem eval_foldl_add (es : List Ex) (acc : Ex) :
    (es.foldl Ex.add acc).eval env = acc.eval env + (es.map (Ex.eval env)).sum := by
  induction es generalizing acc with
  | nil => simp
  | cons e es ih => simp only [List.foldl_cons, ih, Ex.eval, List.map_cons, List.sum_cons]; ring

theorem eval_eSum (es : List Ex) : (eSum es).eval env = (es.map (Ex.eval env)).sum := by
  rw [eSum, eval_foldl_add]; simp [Ex.eval]

theorem eval_eSumRange (n : ℕ) (f : ℕ → Ex) : (eSumRange n f).eval env = sumRange n (fun i => (f i).eval env) := by
  simp [eSumRange, eval_eSum, sumRange, List.map_map, Function.comp_def]

theorem eval_eProd (es : List Ex) : (eProd es).eval env = (es.map (Ex.eval env)).prod := by
  induction es with
  | nil => rfl
  | cons e es ih => simp only [eProd, List.foldr_cons] at ih ⊢; simp [Ex.eval, ih]

theorem eval_eint (c : ℤ) : (eint c).eval env = (c : F) := by
  unfold eint
  split_ifs with h
  · simp only [Ex.eval]
    have : ((c.toNat : ℕ) : ℤ) = c := Int.toNat_of_nonneg h
    rw [← this]; push_cast; rfl
  · simp only [Ex.eval]
    have : (((-c).toNat : ℕ) : ℤ) = -c := Int.toNat_of_nonneg (by omega)
    have h2 : (((-c).toNat : ℕ) : F) = ((-c : ℤ) : F) := by rw [← this]; push_cast; rfl
    rw [h2]; push_cast; ring

theorem eval_eGet (P : List Ex) (i : ℕ) : (eGet P i).eval env = (evalE env P).getD i 0 := by
  unfold evalE eGet
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases P[i]? <;> rfl

theorem eval_eLinNat (f : ℕ → ℕ) (P : List Ex) :
    (eLinNat f P).eval env = lin (fun i => (f i : F)) (evalE env P) := by
  rw [eLinNat, eval_eSumRange, lin_eq_sum, sumRange_eq]
  simp only [evalE, List.length_map]
  apply Finset.sum_congr rfl; intro i _
  simp only [Ex.eval, eval_eGet]; rfl

theorem eval_eEvalAt (P : List Ex) (x : ℤ) :
    (eEvalAt P x).eval env = evalAt (evalE env P) (x : F) := by
  rw [eEvalAt, eval_eSumRange, evalAt, lin_eq_sum, sumRange_eq]
  simp only [evalE, List.length_map]
  apply Finset.sum_congr rfl; intro i _
  simp only [Ex.eval, eval_eint, eval_eGet]; push_cast; rfl

theorem evalE_atoms (is : List ℕ) : evalE env (is.map Ex.atom) = is.map env := by
  simp [evalE, Ex.eval]

theorem evalLE_atoms (iss : List (List ℕ)) : (iss.map fun is => is.map Ex.atom).map (evalE env) =
    iss.map fun is => is.map env := by
  simp [evalE, Ex.eval]

end Eval

section Expr

variable (b : BasisParams) (s : PolyShape) (pxs : List (List Ex))

def eLimbsOf (f : ℕ) : List Ex := pxs.getD f []

def eTermCoefVal (t : TermC) (i : ℕ) : Ex :=
  match t.factors with
  | [] => if i = 0 then eint t.coef else .zero
  | [f] => .mul (eint t.coef) (eGet (eLimbsOf pxs f) i)
  | _ =>
    if s.isCrtTerm t then .zero
    else
      let d := s.termDegree t
      if i ≤ d then
        eSumRange (d + 1) fun k =>
          .mul (.mul (eint t.coef) (.lit (b.vinvAt d i k)))
            (eProd (t.factors.map fun f => eEvalAt (eLimbsOf pxs f) (evalPoint k)))
      else .zero

def eCoefVal (i : ℕ) : Ex := eSum (s.terms.map fun t => eTermCoefVal b s pxs t i)

def eCrtVal (j : ℕ) : Ex :=
  eSum (s.terms.map fun t =>
    if s.isCrtTerm t then
      let x := eLimbsOf pxs (t.factors.getD 0 0)
      let y := eLimbsOf pxs (t.factors.getD 1 0)
      eSumRange b.crtForms.length fun k =>
        .mul (.mul (eint t.coef) (.lit (b.combineAt j k)))
          (.mul (eLinNat (fun i => b.formAt k i) x) (eLinNat (fun i => b.formAt k i) y))
    else .zero)

/-- `exprVal` written term by term, one product per coefficient and point. -/
def eExprValRef (j : ℕ) : Ex :=
  if s.fold then
    .add (eSumRange (s.degree + 1) (fun i => .mul (eint (b.foldAt i j)) (eCoefVal b s pxs i))) (eCrtVal b s pxs j)
  else if j ≤ s.degree then eCoefVal b s pxs j
  else .zero

/-- A product of two or more factors that goes through the inverse Vandermonde matrix. -/
def PolyShape.isVand (t : TermC) : Bool := 2 ≤ t.factors.length && !s.isCrtTerm t

def eLowCoefVal (i : ℕ) : Ex :=
  eSum (s.terms.map fun t => if s.isVand t then .zero else eTermCoefVal b s pxs t i)

def vandProd (t : TermC) (k : ℕ) : Ex :=
  eProd (t.factors.map fun f => eEvalAt (eLimbsOf pxs f) (evalPoint k))

/-- The folded contribution of a Vandermonde term to limb `j`: each evaluation
product appears once, with its fold and interpolation coefficients combined. -/
def eVandFolded (t : TermC) (j : ℕ) : Ex :=
  let d := s.termDegree t
  eSumRange (d + 1) fun k =>
    .mul (eint (sumRange (min d s.degree + 1) (fun i => b.foldAt i j * t.coef * (b.vinvAt d i k : ℤ))))
      (vandProd pxs t k)

/-- `exprVal` as an expression. On the folded path every evaluation product
occurs once per limb, which keeps kernel normalization small. -/
def eExprVal (j : ℕ) : Ex :=
  if s.fold then
    .add (.add (eSumRange (s.degree + 1) (fun i => .mul (eint (b.foldAt i j)) (eLowCoefVal b s pxs i)))
      (eSum (s.terms.map fun t => if s.isVand t then eVandFolded b s pxs t j else .zero))) (eCrtVal b s pxs j)
  else if j ≤ s.degree then eCoefVal b s pxs j
  else .zero

variable (env : ℕ → F)

def evalLE : List (List F) := pxs.map (evalE env)

theorem evalLE_getD (f : ℕ) : (evalLE pxs env).getD f [] = evalE env (eLimbsOf pxs f) := by
  unfold evalLE eLimbsOf
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases pxs[f]? <;> simp [evalE]

theorem eval_eTermCoefVal (t : TermC) (i : ℕ) :
    (eTermCoefVal b s pxs t i).eval env = termCoefVal b s (evalLE pxs env) t i := by
  unfold eTermCoefVal termCoefVal
  match hfac : t.factors with
  | [] => by_cases hi : i = 0 <;> simp [hi, eval_eint, Ex.eval]
  | [f] =>
    simp only [Ex.eval, eval_eint, eval_eGet, limbsOf, evalLE_getD]
  | f1 :: f2 :: rest =>
    by_cases hc : s.isCrtTerm t = true
    · simp [hc, Ex.eval]
    · simp only [hc, Bool.false_eq_true, if_false]
      by_cases hi : i ≤ s.termDegree t
      · simp only [hi, if_true]
        rw [eval_eSumRange]
        apply sumRange_congr'; intro k
        simp only [Ex.eval, eval_eint, eval_eProd, List.map_map]
        congr 2
        apply List.map_congr_left; intro f _
        simp only [Function.comp_apply, eval_eEvalAt, limbsOf, evalLE_getD]
      · simp [hi, Ex.eval]

theorem eval_eCoefVal (i : ℕ) : (eCoefVal b s pxs i).eval env = coefVal b s (evalLE pxs env) i := by
  unfold eCoefVal coefVal
  rw [eval_eSum, List.map_map]
  congr 1; apply List.map_congr_left; intro t _
  simp only [Function.comp_apply, eval_eTermCoefVal]

theorem eval_eCrtVal (j : ℕ) : (eCrtVal b s pxs j).eval env = crtVal b s (evalLE pxs env) j := by
  unfold eCrtVal crtVal
  rw [eval_eSum, List.map_map]
  congr 1; apply List.map_congr_left; intro t _
  simp only [Function.comp_apply]
  split_ifs
  · rw [eval_eSumRange]
    apply sumRange_congr'; intro k
    simp only [Ex.eval, eval_eint, eval_eLinNat, limbsOf, evalLE_getD]
  · rfl

theorem eval_eExprValRef (j : ℕ) : (eExprValRef b s pxs j).eval env = exprVal b s (evalLE pxs env) j := by
  unfold eExprValRef exprVal
  split_ifs
  · simp only [Ex.eval]
    rw [eval_eSumRange, eval_eCrtVal]
    congr 1; apply sumRange_congr'; intro i
    simp only [Ex.eval, eval_eint, eval_eCoefVal]
  · exact eval_eCoefVal b s pxs env j
  · rfl

theorem vand_swap (D d : ℕ) (hD : 0 < D) (f : ℕ → F) (V : ℕ → ℕ → F) (P : ℕ → F) (c : F) :
    sumRange D (fun i => f i * (if i ≤ d then sumRange (d + 1) (fun k => c * V i k * P k) else 0)) =
      sumRange (d + 1) (fun k => sumRange (min d (D - 1) + 1) (fun i => f i * c * V i k) * P k) := by
  simp only [sumRange_eq]
  have hsub : Finset.range (min d (D - 1) + 1) ⊆ Finset.range D := by
    intro i hi; simp only [Finset.mem_range] at hi ⊢; omega
  rw [← Finset.sum_subset hsub (fun i hi hni => by
    simp only [Finset.mem_range] at hi hni
    rw [if_neg (by omega), mul_zero])]
  rw [Finset.sum_congr rfl (fun i hi => by
    simp only [Finset.mem_range] at hi
    rw [if_pos (by omega), Finset.mul_sum])]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl; intro k _
  rw [Finset.sum_mul]
  apply Finset.sum_congr rfl; intro i _
  ring

theorem eval_vand_term {t : TermC} (ht : s.isVand t = true) (i : ℕ) :
    (eTermCoefVal b s pxs t i).eval env =
      if i ≤ s.termDegree t then
        sumRange (s.termDegree t + 1) (fun k => (t.coef : F) * (b.vinvAt (s.termDegree t) i k : F) *
          (vandProd pxs t k).eval env)
      else 0 := by
  have hl : 2 ≤ t.factors.length ∧ s.isCrtTerm t = false := by
    simpa [PolyShape.isVand] using ht
  unfold eTermCoefVal
  match hfac : t.factors, hl.1 with
  | f1 :: f2 :: rest, _ =>
    simp only [hl.2, Bool.false_eq_true, if_false]
    split_ifs
    · rw [eval_eSumRange]
      apply sumRange_congr'; intro k
      simp only [Ex.eval, eval_eint, vandProd]
      rw [hfac]
    · rfl

theorem eval_eCoefVal_split (i : ℕ) : (eCoefVal b s pxs i).eval env = (eLowCoefVal b s pxs i).eval env +
    (s.terms.map fun t => if s.isVand t then (eTermCoefVal b s pxs t i).eval env else 0).sum := by
  unfold eCoefVal eLowCoefVal
  rw [eval_eSum, eval_eSum, List.map_map, List.map_map, ← List.sum_map_add]
  apply list_sum_congr; intro t _
  simp only [Function.comp_apply]
  split_ifs <;> simp [Ex.eval]

theorem eval_eVandSum (j : ℕ) :
    (eSum (s.terms.map fun t => if s.isVand t then eVandFolded b s pxs t j else .zero)).eval env =
      (s.terms.map fun t => if s.isVand t then
        sumRange (s.degree + 1) (fun i => (b.foldAt i j : F) * (eTermCoefVal b s pxs t i).eval env) else 0).sum := by
  rw [eval_eSum, List.map_map]
  apply list_sum_congr; intro t _
  simp only [Function.comp_apply]
  split_ifs with hv
  · rw [eVandFolded, eval_eSumRange]
    simp only [eval_vand_term b s pxs env hv]
    rw [vand_swap _ _ (Nat.succ_pos _)]
    apply sumRange_congr'; intro k
    simp only [Ex.eval, eval_eint, intCast_sumRange, Int.cast_mul, Int.cast_natCast, Nat.add_sub_cancel, Nat.succ_sub_one]
  · rfl

theorem eval_eExprVal (j : ℕ) : (eExprVal b s pxs j).eval env = exprVal b s (evalLE pxs env) j := by
  rw [← eval_eExprValRef]
  unfold eExprVal eExprValRef
  split_ifs
  · simp only [Ex.eval]
    congr 1
    rw [eval_eSumRange, eval_eSumRange, eval_eVandSum]
    simp only [Ex.eval, eval_eint, eval_eCoefVal_split, mul_add]
    rw [sumRange_add]
    congr 1
    simp only [← List.sum_map_mul_left]
    rw [sumRange_list_sum]
    apply list_sum_congr; intro t _
    split_ifs
    · rfl
    · simp [sumRange_eq]
  · rfl
  · rfl

theorem map_exprVal_eq (l : List ℕ) :
    l.map (exprVal b s (pxs.map (evalE env))) = l.map (fun j => (eExprVal b s pxs j).eval env) := by
  apply List.map_congr_left; intro j _; rw [eval_eExprVal]; rfl

end Expr

/-! ### Circuit values -/

section Circuit

variable (env : ℕ → F)

def eComposeValue (pb : ℕ) (ps : List Ex) : Ex := eEvalAt ps (2 ^ pb)

def eLimbsOfPieces (pb : ℕ) : List ℕ → List Ex → List Ex
  | [], _ => []
  | w :: ws, ps => eComposeValue pb (ps.take (nbPieces pb w)) :: eLimbsOfPieces pb ws (ps.drop (nbPieces pb w))

theorem eval_eComposeValue (pb : ℕ) (ps : List Ex) :
    (eComposeValue pb ps).eval env = composeValue pb (evalE env ps) := by
  rw [eComposeValue, eval_eEvalAt, composeValue]; push_cast; rfl

theorem evalE_eLimbsOfPieces (pb : ℕ) (ws : List ℕ) (ps : List Ex) :
    evalE env (eLimbsOfPieces pb ws ps) = limbsOfPieces pb ws (evalE env ps) := by
  induction ws generalizing ps with
  | nil => rfl
  | cons w ws ih =>
    simp only [eLimbsOfPieces, limbsOfPieces, evalE, List.map_cons] at ih ⊢
    rw [eval_eComposeValue, ih]
    simp [evalE, List.map_take, List.map_drop]

theorem composeValue_atomsE (pb : ℕ) (is : List ℕ) :
    composeValue pb (is.map env) = (eComposeValue pb (is.map Ex.atom)).eval env := by
  rw [eval_eComposeValue, evalE_atoms]

variable (b : BasisParams) (c : PlainCheckParams) (pxs : List (List Ex))

def eModLimb (j : ℕ) : Ex := .lit (c.modulusLimbs.getD j 0)

def ePow32 (j : ℕ) : Ex := eint (2 ^ (32 * j))

/-- `∑ j, exprVal j * 2^(32 j)` on the folded path with every evaluation and
CRT product occurring once: their fold, interpolation and limb weights are
combined into one constant per product. -/
def eNative (s : PolyShape) : Ex :=
  .add (.add (eSumRange limbCount (fun j =>
      .mul (eSumRange (s.degree + 1) (fun i => .mul (eint (b.foldAt i j)) (eLowCoefVal b s pxs i))) (ePow32 j)))
    (eSum (s.terms.map fun t => if s.isVand t then
      eSumRange (s.termDegree t + 1) (fun k =>
        .mul (eint (sumRange limbCount (fun j => 2 ^ (32 * j) *
          sumRange (min (s.termDegree t) s.degree + 1)
            (fun i => b.foldAt i j * t.coef * (b.vinvAt (s.termDegree t) i k : ℤ)))))
          (vandProd pxs t k))
      else .zero)))
    (eSum (s.terms.map fun t => if s.isCrtTerm t then
      eSumRange b.crtForms.length (fun k =>
        .mul (eint (sumRange limbCount (fun j => 2 ^ (32 * j) * (t.coef * (b.combineAt j k : ℤ)))))
          (.mul (eLinNat (fun i => b.formAt k i) (eLimbsOf pxs (t.factors.getD 0 0)))
            (eLinNat (fun i => b.formAt k i) (eLimbsOf pxs (t.factors.getD 1 0)))))
      else .zero))

def eFoldQuotient (pr : List Ex) : Ex :=
  .mul (.sub (if c.fold then eNative b pxs c.toPolyShape
      else eSumRange limbCount (fun j => .mul (eExprVal b c.toPolyShape pxs j) (ePow32 j)))
      (eSumRange limbCount (fun j => .mul (eGet pr j) (ePow32 j))))
    (.lit c.mInv)

def eResidual (pr pql : List Ex) (pkq : Ex) (pos : ℕ) : Ex :=
  .sub (.sub (eExprVal b c.toPolyShape pxs pos) (eGet pr pos))
    (if c.fold then (if pos < limbCount then .mul pkq (eModLimb c pos) else .zero)
     else eSumRange pql.length (fun a =>
       if a ≤ pos ∧ pos - a < limbCount then
         .mul (.sub (eGet pql a) (.lit (c.offsetLimbs.getD a 0))) (eModLimb c (pos - a))
       else .zero))

theorem eval_ePow32 (j : ℕ) : (ePow32 j).eval env = pow32 j := by
  rw [ePow32, eval_eint, pow32]; push_cast; rfl

theorem sumRange_swap_weighted (n m : ℕ) (a : ℕ → ℕ → F) (P w : ℕ → F) :
    sumRange n (fun j => sumRange m (fun k => a j k * P k) * w j) =
      sumRange m (fun k => sumRange n (fun j => w j * a j k) * P k) := by
  simp only [sumRange_eq, Finset.sum_mul]
  rw [Finset.sum_comm]
  apply Finset.sum_congr rfl; intro k _
  apply Finset.sum_congr rfl; intro j _
  ring

theorem eval_eNative (s : PolyShape) (hf : s.fold = true) :
    (eNative b pxs s).eval env = sumRange limbCount (fun j => (eExprVal b s pxs j).eval env * pow32 j) := by
  unfold eNative eExprVal
  simp only [hf, if_true, Ex.eval]
  simp only [add_mul]
  rw [sumRange_add, sumRange_add]
  congr 1
  congr 1
  · rw [eval_eSumRange]; apply sumRange_congr'; intro j; simp only [Ex.eval, eval_ePow32]
  · rw [eval_eSum, List.map_map]
    simp only [eval_eSum, List.map_map, ← List.sum_map_mul_right]
    rw [sumRange_list_sum]
    apply list_sum_congr; intro t _
    simp only [Function.comp_apply]
    split_ifs with hv
    · rw [eval_eSumRange]
      simp only [eVandFolded, eval_eSumRange, Ex.eval, eval_eint]
      rw [sumRange_swap_weighted]
      apply sumRange_congr'; intro k
      simp only [pow32, intCast_sumRange, Int.cast_mul, Int.cast_pow, Int.cast_ofNat]
    · simp [Ex.eval, sumRange_eq]
  · rw [eval_eSum, List.map_map]
    unfold eCrtVal
    simp only [eval_eSum, List.map_map, ← List.sum_map_mul_right]
    rw [sumRange_list_sum]
    apply list_sum_congr; intro t _
    simp only [Function.comp_apply]
    split_ifs with hc
    · rw [eval_eSumRange]
      simp only [eval_eSumRange, Ex.eval, eval_eint]
      rw [sumRange_swap_weighted]
      apply sumRange_congr'; intro k
      simp only [pow32, intCast_sumRange, Int.cast_mul, Int.cast_pow, Int.cast_ofNat, Int.cast_natCast]
    · simp [Ex.eval, sumRange_eq]

theorem eval_eFoldQuotient (pr : List Ex) :
    (eFoldQuotient b c pxs pr).eval env = CheckPolynomial.foldQuotient b c (evalLE pxs env) (evalE env pr) := by
  unfold eFoldQuotient CheckPolynomial.foldQuotient
  simp only [Ex.eval]
  rw [eval_eSumRange]
  congr 2
  · split_ifs with hf
    · rw [eval_eNative env b pxs _ hf]; apply sumRange_congr'; intro j; rw [eval_eExprVal]
    · rw [eval_eSumRange]; apply sumRange_congr'; intro j
      simp only [Ex.eval, eval_eExprVal, eval_ePow32]
  · apply sumRange_congr'; intro j
    simp only [Ex.eval, eval_eGet, eval_ePow32]

theorem eval_eResidual (pr pql : List Ex) (pkq : Ex) (pos : ℕ) :
    (eResidual b c pxs pr pql pkq pos).eval env =
      CheckPolynomial.residual b c (evalLE pxs env) (evalE env pr) (evalE env pql) (pkq.eval env) pos := by
  unfold eResidual CheckPolynomial.residual
  simp only [Ex.eval, eval_eExprVal, eval_eGet]
  congr 1
  split_ifs with h1 h2
  · simp only [Ex.eval, eModLimb]; rfl
  · rfl
  · rw [eval_eSumRange]
    simp only [evalE, List.length_map]
    apply sumRange_congr'; intro a
    split_ifs
    · simp only [Ex.eval, eModLimb, eval_eGet]; rfl
    · rfl

def eCarry (pres : ℕ → Ex) (g : CarryGroup) (pc : Ex) : Ex :=
  .mul (.add (eSumRange (g.stop - g.start) (fun t => .mul (pres (g.start + t)) (ePow32 t))) pc) (.lit g.inv)

/-- `carryChain` with every carry given as an expression. -/
def carryChainE (pres : ℕ → Ex) (rc : ℕ → F → Prop) : List CarryGroup → Ex → (F → Prop) → Prop
  | [], pc, k => k (pc.eval env)
  | g :: gs, pc, k =>
    rc (g.carryBits + 1) ((Ex.add (eCarry pres g pc) (.lit (2 ^ g.carryBits))).eval env) ∧
      carryChainE pres rc gs (eCarry pres g pc) k

theorem carryChain_of_exs {res : ℕ → F} {pres : ℕ → Ex} (hres : ∀ p, res p = (pres p).eval env)
    {rc : ℕ → F → Prop} :
    ∀ (gs : List CarryGroup) (pc : Ex) (k : F → Prop),
      carryChainE env pres rc gs pc k → carryChain res rc gs (pc.eval env) k
  | [], pc, k, h => h
  | g :: gs, pc, k, ⟨h1, h2⟩ => by
    have hc : (sumRange (g.stop - g.start) (fun t => res (g.start + t) * pow32 t) + pc.eval env) *
        (g.inv : F) = (eCarry pres g pc).eval env := by
      simp only [eCarry, Ex.eval]
      rw [eval_eSumRange]
      congr 2; apply sumRange_congr'; intro t
      simp only [Ex.eval, hres, eval_ePow32]
    simp only [carryChain]
    rw [hc]
    refine ⟨?_, carryChain_of_exs hres gs _ k h2⟩
    simpa [Ex.eval] using h1

/-- From facts about expression values to the generic constraint system. -/
theorem circuit_of_exs {rc : ℕ → F → Prop} {k : Option (List F) → Prop} (prp pqp : List Ex)
    (hrp : if c.withResult then PiecesOk rc c.pieceBits c.resultWidths (evalE env prp) else evalE env prp = [])
    (hqp : if c.fold then evalE env pqp = [] else PiecesOk rc c.pieceBits c.quotientWidths (evalE env pqp))
    (hfold : c.fold = true → rc c.quotientBits ((Ex.add (eFoldQuotient b c pxs
      (if c.withResult then eLimbsOfPieces c.pieceBits c.resultWidths prp else [])) (.lit c.offset)).eval env))
    (hnat : c.fold = false ∧ c.checkTop = false →
      (eSumRange c.positions (fun pos => .mul (eResidual b c pxs
        (if c.withResult then eLimbsOfPieces c.pieceBits c.resultWidths prp else [])
        (if c.fold then [] else eLimbsOfPieces c.pieceBits c.quotientWidths pqp)
        (eFoldQuotient b c pxs (if c.withResult then eLimbsOfPieces c.pieceBits c.resultWidths prp else []))
        pos) (ePow32 pos))).eval env = 0)
    (hchain : carryChainE env (eResidual b c pxs
        (if c.withResult then eLimbsOfPieces c.pieceBits c.resultWidths prp else [])
        (if c.fold then [] else eLimbsOfPieces c.pieceBits c.quotientWidths pqp)
        (eFoldQuotient b c pxs (if c.withResult then eLimbsOfPieces c.pieceBits c.resultWidths prp else [])))
      rc c.groups .zero (fun carry =>
        (c.checkTop = true → (eResidual b c pxs
          (if c.withResult then eLimbsOfPieces c.pieceBits c.resultWidths prp else [])
          (if c.fold then [] else eLimbsOfPieces c.pieceBits c.quotientWidths pqp)
          (eFoldQuotient b c pxs (if c.withResult then eLimbsOfPieces c.pieceBits c.resultWidths prp else []))
          c.carryPositions).eval env + carry = 0) ∧
        k (if c.withResult then some (evalE env (eLimbsOfPieces c.pieceBits c.resultWidths prp)) else none))) :
    CheckPolynomial.circuit b c (evalLE pxs env) rc k := by
  set prL := if c.withResult then eLimbsOfPieces c.pieceBits c.resultWidths prp else [] with hprL
  set pqL := if c.fold then [] else eLimbsOfPieces c.pieceBits c.quotientWidths pqp with hpqL
  have hr : (if c.withResult then limbsOfPieces c.pieceBits c.resultWidths (evalE env prp) else []) =
      evalE env prL := by
    rw [hprL]; split_ifs
    · rw [evalE_eLimbsOfPieces]
    · rfl
  have hq : (if c.fold then [] else limbsOfPieces c.pieceBits c.quotientWidths (evalE env pqp)) =
      evalE env pqL := by
    rw [hpqL]; split_ifs
    · rfl
    · rw [evalE_eLimbsOfPieces]
  refine ⟨evalE env prp, evalE env pqp, hrp, hqp, ?_⟩
  dsimp only
  rw [hr, hq]
  have hkq : CheckPolynomial.foldQuotient b c (evalLE pxs env) (evalE env prL) =
      (eFoldQuotient b c pxs prL).eval env := (eval_eFoldQuotient env b c pxs prL).symm
  have hres : ∀ pos, CheckPolynomial.residual b c (evalLE pxs env) (evalE env prL) (evalE env pqL)
      (CheckPolynomial.foldQuotient b c (evalLE pxs env) (evalE env prL)) pos =
      (eResidual b c pxs prL pqL (eFoldQuotient b c pxs prL) pos).eval env := by
    intro pos; rw [eval_eResidual, hkq]
  refine ⟨fun hf => ?_, fun hn => ?_, ?_⟩
  · have := hfold hf
    simp only [Ex.eval] at this
    rw [hkq]; exact this
  · have := hnat hn
    rw [eval_eSumRange] at this
    rw [← this]
    apply sumRange_congr'; intro pos
    simp only [Ex.eval, eval_ePow32, hres]
  · have h0 : (0 : F) = Ex.zero.eval env := rfl
    rw [h0]
    refine carryChain_of_exs env hres c.groups .zero _ ?_
    have hk : (if c.withResult then some (evalE env prL) else none) =
        (if c.withResult then some (evalE env (eLimbsOfPieces c.pieceBits c.resultWidths prp)) else none) := by
      rw [hprL]; split_ifs <;> rfl
    simp only [hk, hres]
    exact hchain

end Circuit

end ZolanaVE.Field
