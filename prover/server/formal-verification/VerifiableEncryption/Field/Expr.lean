import VerifiableEncryption.Field.CheckPolynomial
import VerifiableEncryption.Field.Lin

/-!
The native value of every expression form of a check is the cast of one
integer: a coefficient of the integer expression polynomial
`E = ∑ coef * ∏ ints` (general path) or its fold into eight limbs (folded path).
This is where the inverse Vandermonde matrices and the CRT basis are used.
-/

namespace ZolanaVE.Field

/-! ### Inputs -/

def intsOf (es : List (Σ w, ElemVal w)) (f : ℕ) : List ℤ := (es.map fun e => e.2.ints.toList).getD f []

theorem limbLists_getD (es : List (Σ w, ElemVal w)) (f : ℕ) :
    (limbLists es).getD f [] = (intsOf es f).map (Int.cast : ℤ → F) := by
  unfold limbLists intsOf
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_map]
  cases es[f]? with
  | none => rfl
  | some e => exact e.2.limbs_eq_map

theorem values_getD (es : List (Σ w, ElemVal w)) (f : ℕ) :
    (values es).getD f 0 = recompose (intsOf es f) := by
  unfold values intsOf
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_map]
  cases es[f]? with
  | none => rfl
  | some e => rfl

theorem abs_le_max_abs {l x h : ℤ} (hl : l ≤ x) (hh : x ≤ h) : |x| ≤ max |l| |h| := by
  rw [abs_le]
  have h1 := neg_abs_le l
  have h2 := le_abs_self h
  have h3 := le_max_left |l| |h|
  have h4 := le_max_right |l| |h|
  constructor <;> linarith

theorem ElemVal.absLe {w : ℕ} (e : ElemVal w) :
    AbsLe e.ints.toList (List.zipWith (fun l h => max |l| |h|) e.lo.toList e.hi.toList) := by
  rw [AbsLe, List.forall₂_iff_get]
  refine ⟨by simp, fun i h₁ h₂ => ?_⟩
  simp only [List.get_eq_getElem, List.getElem_zipWith]
  have hi : i < w := by simpa using h₁
  have hl := e.h_lo ⟨i, hi⟩
  have hh := e.h_hi ⟨i, hi⟩
  simp only [List.Vector.get_eq_get_toList, List.get_eq_getElem, Fin.coe_cast] at hl hh
  exact abs_le_max_abs hl hh

/-- What `ElemsMatch` gives about input `f`, for every index (out of range both sides are empty). -/
structure InputFacts (es : List (Σ w, ElemVal w)) (c : ElemC) (f : ℕ) : Prop where
  absLe : AbsLe (intsOf es f) c.absLimbs
  length : (intsOf es f).length = c.lo.length
  vlo : c.vlo ≤ recompose (intsOf es f)
  vhi : recompose (intsOf es f) ≤ c.vhi
  lo : c.lo = ((es.map fun e => e.2.lo.toList).getD f [])
  hi : c.hi = ((es.map fun e => e.2.hi.toList).getD f [])

theorem inputFacts_aux {es : List (Σ w, ElemVal w)} {cs : List ElemC} (hb : ElemsMatch es cs) (f : ℕ) :
    InputFacts es (cs.getD f default) f := by
  unfold ElemsMatch at hb
  induction hb generalizing f with
  | nil => exact ⟨List.Forall₂.nil, rfl, le_rfl, le_rfl, rfl, rfl⟩
  | @cons e c es cs hec _ ih =>
    cases f with
    | zero =>
      obtain ⟨hlo, hhi, hvlo, hvhi⟩ := hec
      refine ⟨?_, ?_, ?_, ?_, ?_, ?_⟩
      · have := e.2.absLe; rw [hlo, hhi] at this; exact this
      · simp [intsOf, ← hlo]
      · simp only [intsOf, List.map_cons, List.getD_cons_zero, List.getD_cons_zero, ← hvlo]
        exact e.2.h_vlo
      · simp only [intsOf, List.map_cons, List.getD_cons_zero, ← hvhi]
        exact e.2.h_vhi
      · simp [hlo]
      · simp [hhi]
    | succ f =>
      have := ih f
      exact ⟨this.1, this.2, this.3, this.4, by simpa using this.5, by simpa using this.6⟩

theorem inputFacts {es : List (Σ w, ElemVal w)} {s : PolyShape} (hb : ElemsMatch es s.elems) (f : ℕ) :
    InputFacts es (s.elem f) f := inputFacts_aux hb f

/-! ### The integer expression polynomial -/

section Expression

variable (es : List (Σ w, ElemVal w)) (s : PolyShape)

def termInt (t : TermC) : List ℤ := termPoly t.coef (t.factors.map (intsOf es))

def exprInt : List ℤ := polySum (s.terms.map (termInt es))

theorem evalAt_exprInt :
    evalAt (exprInt es s) limbBase = s.exprValue (values es) := by
  unfold exprInt PolyShape.exprValue
  rw [evalAt_polySum, List.map_map]
  congr 1
  apply List.map_congr_left
  intro t _
  simp only [Function.comp_apply, termInt, evalAt_termPoly, List.map_map]
  congr 2
  apply List.map_congr_left
  intro f _
  rw [values_getD]; rfl

end Expression

/-! ### Basis facts -/

theorem intCast_emod_order (a : ℤ) : (((a % (Order : ℤ)) : ℤ) : F) = (a : F) := ZMod.intCast_mod a Order

structure BasisFacts (b : BasisParams) : Prop where
  fm_pos : 0 < b.foldModulus
  rows : ∀ i < b.foldRows.length, (b.foldRows.getD i []).length = limbCount ∧
    (recompose (b.foldRows.getD i []) - 2 ^ (32 * i)) % (b.foldModulus : ℤ) = 0
  vinv : ∀ d, (b.vinv.lookup d).isSome → ∀ i ≤ d, ∀ i' ≤ d,
    sumRange (d + 1) (fun k => (b.vinvAt d i k : F) * ((evalPoint k : ℤ) : F) ^ i') = if i = i' then 1 else 0
  crt : b.crtForms ≠ [] → 2 * limbCount - 2 < b.foldRows.length ∧ b.crtCombine.length = limbCount ∧
    ∀ j < limbCount, ∀ a < limbCount, ∀ a' < limbCount,
      sumRange b.crtForms.length (fun k => (b.combineAt j k : F) * (b.formAt k a : F) * (b.formAt k a' : F)) =
        ((b.foldAt (a + a') j : ℤ) : F)

theorem basisFacts {b : BasisParams} (hbs : b.sound = true) : BasisFacts b := by
  simp only [BasisParams.sound, Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq, List.all_eq_true,
    List.mem_range, beq_iff_eq, List.isEmpty_iff] at hbs
  obtain ⟨⟨⟨hfm, hrows⟩, hvinv⟩, hcrt⟩ := hbs
  refine ⟨hfm, fun i hi => hrows i hi, ?_, ?_⟩
  · intro d hd i hi i' hi'
    rw [List.lookup_isSome_iff] at hd
    obtain ⟨⟨d', v⟩, hmem, hdd⟩ := hd
    simp only [beq_iff_eq] at hdd
    subst hdd
    have h := (hvinv _ hmem).2 i (by omega) i' (by omega)
    have hc := congrArg (fun z : ℤ => (z : F)) h
    simp only [intCast_emod_order, intCast_sumRange, Int.cast_mul, Int.cast_natCast, Int.cast_pow] at hc
    rw [hc]; split <;> simp
  · intro hne
    rcases hcrt with h | h
    · exact absurd h hne
    obtain ⟨⟨⟨⟨_, hcl⟩, _⟩, hlen⟩, hid⟩ := h
    refine ⟨hlen, hcl, fun j hj a ha a' ha' => ?_⟩
    have h := hid j hj a ha a' ha'
    have h0 : ((sumRange b.crtForms.length (fun k => ((b.combineAt j k : ℕ) : ℤ) * (b.formAt k a : ℤ) *
        (b.formAt k a' : ℤ)) - b.foldAt (a + a') j : ℤ) : F) = 0 := by
      rw [← intCast_emod_order, h]; simp
    rw [Int.cast_sub, sub_eq_zero, intCast_sumRange] at h0
    simpa using h0

/-! ### Shape facts -/

theorem ne_nil_of_isEmpty_false {α : Type*} {l : List α} (h : l.isEmpty = false) : l ≠ [] := by
  cases l <;> simp_all

structure ShapeFacts (b : BasisParams) (s : PolyShape) (m : ℕ) : Prop where
  elems : ∀ e ∈ s.elems, e.lo.length = e.hi.length ∧ e.lo ≠ []
  factors : ∀ t ∈ s.terms, ∀ f ∈ t.factors, f < s.elems.length
  degree : ∀ t ∈ s.terms, s.termDegree t ≤ s.degree
  fold : s.fold = true → m = b.foldModulus ∧ s.degree < b.foldRows.length
  crt : s.useCrt = true → b.crtForms ≠ []
  vinv : ∀ t ∈ s.terms, t.factors.length < 2 ∨ s.isCrtTerm t = true ∨ (b.vinv.lookup (s.termDegree t)).isSome

theorem shapeFacts {b : BasisParams} {s : PolyShape} {m : ℕ} (h : s.shapeSound b m = true) :
    ShapeFacts b s m := by
  simp only [PolyShape.shapeSound, Bool.and_eq_true] at h
  obtain ⟨⟨⟨⟨he, ht⟩, hf⟩, hc⟩, hv⟩ := h
  rw [List.all_eq_true] at he ht hv
  refine ⟨fun e he' => ?_, fun t ht' f hf' => ?_, fun t ht' => ?_, ?_, ?_, fun t ht' => ?_⟩
  · have := he e he'
    simp only [Bool.and_eq_true, beq_iff_eq, Bool.not_eq_true'] at this
    exact ⟨this.1, ne_nil_of_isEmpty_false this.2⟩
  · have := (ht t ht')
    simp only [Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at this
    exact this.1 f hf'
  · have := (ht t ht')
    simp only [Bool.and_eq_true, List.all_eq_true, decide_eq_true_eq] at this
    exact this.2
  · intro h1
    simp only [h1, Bool.not_true, Bool.false_or, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hf
    exact hf
  · intro h1
    simp only [h1, Bool.not_true, Bool.false_or, Bool.not_eq_true'] at hc
    exact ne_nil_of_isEmpty_false hc
  · have := hv t ht'
    simp only [Bool.or_eq_true, decide_eq_true_eq] at this
    rcases this with (h | h) | h
    · exact Or.inl h
    · exact Or.inr (Or.inl h)
    · exact Or.inr (Or.inr h)

/-! ### Coefficients of one term -/

section Terms

variable {es : List (Σ w, ElemVal w)} {b : BasisParams} {s : PolyShape} {m : ℕ}

theorem intsOf_ne_nil (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m) {f : ℕ}
    (hf : f < s.elems.length) : intsOf es f ≠ [] := by
  have hl := (inputFacts hb f).length
  have he := (hsf.elems (s.elem f) (by unfold PolyShape.elem; rw [List.getD_eq_getElem _ _ hf]; exact List.getElem_mem hf)).2
  intro h; rw [h] at hl
  exact he (List.eq_nil_of_length_eq_zero hl.symm)

theorem length_termInt (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m) {t : TermC}
    (ht : t ∈ s.terms) : (termInt es t).length = s.termDegree t + 1 := by
  unfold termInt termPoly PolyShape.termDegree
  rw [length_foldl_polyMul _ _ (by simp)]
  · simp only [List.length_singleton, List.map_map]
    rw [add_comm]; congr 1
    apply congrArg; apply List.map_congr_left
    intro f _
    simp only [Function.comp_apply, PolyShape.nLimbs, (inputFacts hb f).length]
  · intro p hp
    obtain ⟨f, hf, rfl⟩ := List.mem_map.mp hp
    exact intsOf_ne_nil hb hsf (hsf.factors t ht f hf)

theorem getD_polyMul_single {R : Type*} [CommRing R] (c : R) (x : List R) (i : ℕ) :
    (polyMul [c] x).getD i 0 = c * x.getD i 0 := by
  rw [getD_eq_lin_delta, lin_polyMul, getD_eq_lin_delta]
  simp only [lin_cons, lin_nil, add_zero, zero_add]
  ring

theorem vandermonde_recover {R : Type*} [CommRing R] {d i : ℕ} (V : ℕ → R) (x : ℕ → R)
    (hV : ∀ i' ≤ d, sumRange (d + 1) (fun k => V k * x k ^ i') = if i = i' then 1 else 0)
    (Q : List R) (hQ : Q.length ≤ d + 1) :
    sumRange (d + 1) (fun k => V k * evalAt Q (x k)) = Q.getD i 0 := by
  unfold evalAt
  have : (fun k => V k * lin (fun j => x k ^ j) Q) = fun k => lin (fun j => V k * x k ^ j) Q := by
    funext k; rw [lin_mul_fun_left]
  rw [this, ← lin_sumRange_fun, ← lin_delta]
  apply lin_congr
  intro j hj
  rw [hV j (by omega)]
  by_cases h : i = j <;> simp [h, eq_comm]

theorem termCoefVal_eq (hbf : BasisFacts b) (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m)
    {t : TermC} (ht : t ∈ s.terms) (hcrt : s.isCrtTerm t = false) (i : ℕ) :
    termCoefVal b s (limbLists es) t i = (((termInt es t).getD i 0 : ℤ) : F) := by
  unfold termCoefVal
  match hfac : t.factors with
  | [] =>
    simp only [termInt, hfac, List.map_nil, termPoly, List.foldl_nil]
    cases i <;> simp
  | [f] =>
    simp only [termInt, hfac, List.map_cons, List.map_nil, termPoly, List.foldl_cons, List.foldl_nil,
      getD_polyMul_single, limbsOf, limbLists_getD, Int.cast_mul, intCast_getD]
  | f1 :: f2 :: rest =>
    simp only [hcrt, if_false, Bool.false_eq_true]
    rw [← hfac]
    have hlen := length_termInt hb hsf ht
    split_ifs with hi
    · have hv : (b.vinv.lookup (s.termDegree t)).isSome := by
        rcases hsf.vinv t ht with h | h | h
        · rw [hfac] at h; simp at h; omega
        · rw [hcrt] at h; exact absurd h (by simp)
        · exact h
      have hV := hbf.vinv _ hv i hi
      set d := s.termDegree t
      set Q : List F := (termPoly (1 : ℤ) (t.factors.map (intsOf es))).map (Int.cast : ℤ → F)
      have hprod : ∀ k, (t.factors.map fun f => evalAt (limbsOf (limbLists es) f) ((evalPoint k : ℤ) : F)).prod =
          evalAt Q ((evalPoint k : ℤ) : F) := by
        intro k
        simp only [Q, ← intCast_evalAt, evalAt_termPoly, one_mul, limbsOf, limbLists_getD, intCast_list_prod,
          List.map_map]
        congr 1
      have hne : ∀ p ∈ t.factors.map (intsOf es), p ≠ [] := by
        intro p hp
        obtain ⟨f, hf, rfl⟩ := List.mem_map.mp hp
        exact intsOf_ne_nil hb hsf (hsf.factors t ht f hf)
      have hQ : Q.length ≤ d + 1 := by
        have h1 := length_foldl_polyMul (t.factors.map (intsOf es)) [(1 : ℤ)] (by simp) hne
        have h2 := length_foldl_polyMul (t.factors.map (intsOf es)) [t.coef] (by simp) hne
        simp only [Q, List.length_map, termPoly]
        unfold termInt termPoly at hlen
        rw [h1]; rw [h2] at hlen; simp only [List.length_singleton] at hlen ⊢; omega
      have : (fun k => (t.coef : F) * (b.vinvAt d i k : F) *
          (t.factors.map fun f => evalAt (limbsOf (limbLists es) f) ((evalPoint k : ℤ) : F)).prod) =
          fun k => (t.coef : F) * ((b.vinvAt d i k : F) * evalAt Q ((evalPoint k : ℤ) : F)) := by
        funext k; rw [hprod]; ring
      rw [this, ← sumRange_mul_left, vandermonde_recover _ _ hV Q hQ]
      simp only [Q, termInt, intCast_getD]
      rw [getD_eq_lin_delta (termPoly t.coef _), lin_termPoly, ← getD_eq_lin_delta]
      push_cast; ring
    · rw [getD_eq_zero_of_le (by omega)]; simp

theorem crtTerm_eq (hbf : BasisFacts b) (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m)
    {t : TermC} (hcrt : s.isCrtTerm t = true) {j : ℕ} (hj : j < limbCount) :
    sumRange b.crtForms.length (fun k =>
        (t.coef : F) * (b.combineAt j k : F) *
          (lin (fun i => (b.formAt k i : F)) (limbsOf (limbLists es) (t.factors.getD 0 0)) *
            lin (fun i => (b.formAt k i : F)) (limbsOf (limbLists es) (t.factors.getD 1 0)))) =
      ((lin (fun i => b.foldAt i j) (termInt es t) : ℤ) : F) := by
  have hc := hcrt
  simp only [PolyShape.isCrtTerm, Bool.and_eq_true, beq_iff_eq, List.all_eq_true] at hc
  obtain ⟨⟨⟨hfold, huse⟩, hlen2⟩, hall⟩ := hc
  match hfac : t.factors, hlen2 with
  | [f0, f1], _ =>
    have hne := (hbf.crt (hsf.crt huse))
    have h0 : (intsOf es f0).length = limbCount := by
      rw [(inputFacts hb f0).length]; exact hall f0 (by rw [hfac]; simp)
    have h1 : (intsOf es f1).length = limbCount := by
      rw [(inputFacts hb f1).length]; exact hall f1 (by rw [hfac]; simp)
    simp only [List.getD_cons_zero, List.getD_cons_succ, limbsOf, limbLists_getD]
    set X := (intsOf es f0).map (Int.cast : ℤ → F)
    set Y := (intsOf es f1).map (Int.cast : ℤ → F)
    have hX : X.length = limbCount := by simp [X, h0]
    have hY : Y.length = limbCount := by simp [Y, h1]
    have hl : ∀ k, (t.coef : F) * (b.combineAt j k : F) *
        (lin (fun i => (b.formAt k i : F)) X * lin (fun i => (b.formAt k i : F)) Y) =
        lin (fun a => lin (fun a' => (t.coef : F) * ((b.combineAt j k : F) * (b.formAt k a : F) *
          (b.formAt k a' : F))) Y) X := by
      intro k
      rw [lin_mul_lin, ← lin_mul_fun_left]
      congr 1; funext a; rw [← lin_mul_fun_left]; congr 1; funext a'; ring
    rw [show (fun k => (t.coef : F) * (b.combineAt j k : F) *
        (lin (fun i => (b.formAt k i : F)) X * lin (fun i => (b.formAt k i : F)) Y)) =
        fun k => lin (fun a => lin (fun a' => (t.coef : F) * ((b.combineAt j k : F) * (b.formAt k a : F) *
          (b.formAt k a' : F))) Y) X from funext hl]
    rw [← lin_sumRange_fun]
    have hinner : ∀ a < X.length, sumRange b.crtForms.length (fun k => lin (fun a' => (t.coef : F) *
        ((b.combineAt j k : F) * (b.formAt k a : F) * (b.formAt k a' : F))) Y) =
        lin (fun a' => (t.coef : F) * ((b.foldAt (a + a') j : ℤ) : F)) Y := by
      intro a ha
      rw [← lin_sumRange_fun]
      apply lin_congr
      intro a' ha'
      rw [← sumRange_mul_left, hne.2.2 j hj a (by omega) a' (by omega)]
    rw [lin_congr hinner]
    unfold termInt termPoly
    rw [hfac]
    simp only [List.map_cons, List.map_nil, List.foldl_cons, List.foldl_nil]
    rw [lin_polyMul, lin_single_polyMul, Int.cast_mul, intCast_lin, ← lin_mul_fun_left]
    congr 1; funext a
    rw [intCast_lin, ← lin_mul_fun_left]

theorem foldAt_ge (hbf : BasisFacts b) {i j : ℕ} (hj : limbCount ≤ j) : b.foldAt i j = 0 := by
  unfold BasisParams.foldAt
  by_cases hi : i < b.foldRows.length
  · exact getD_eq_zero_of_le ((hbf.rows i hi).1 ▸ hj)
  · rw [List.getD_eq_getElem?_getD b.foldRows i, List.getElem?_eq_none (by omega)]; simp

theorem crtTerm_eq_ge (hbf : BasisFacts b) (hsf : ShapeFacts b s m) {t : TermC}
    (hcrt : s.isCrtTerm t = true) {j : ℕ} (hj : limbCount ≤ j) (xs : List (List F)) :
    sumRange b.crtForms.length (fun k =>
        (t.coef : F) * (b.combineAt j k : F) *
          (lin (fun i => (b.formAt k i : F)) (limbsOf xs (t.factors.getD 0 0)) *
            lin (fun i => (b.formAt k i : F)) (limbsOf xs (t.factors.getD 1 0)))) =
      ((lin (fun i => b.foldAt i j) (termInt es t) : ℤ) : F) := by
  have hc := hcrt
  simp only [PolyShape.isCrtTerm, Bool.and_eq_true] at hc
  have hcl := (hbf.crt (hsf.crt hc.1.1.2)).2.1
  have h0 : ∀ k, b.combineAt j k = 0 := by
    intro k; unfold BasisParams.combineAt
    rw [List.getD_eq_getElem?_getD (b.crtCombine), List.getElem?_eq_none (by omega)]
    simp
  have : (fun i => b.foldAt i j) = fun _ => 0 := by funext i; exact foldAt_ge hbf hj
  rw [this, lin_zero_fun]
  simp [h0, sumRange_eq]

def foldedInt (b : BasisParams) (s : PolyShape) (es : List (Σ w, ElemVal w)) (j : ℕ) : ℤ :=
  if s.fold then lin (fun i => b.foldAt i j) (exprInt es s) else (exprInt es s).getD j 0

theorem termCoefVal_crt {t : TermC} (hcrt : s.isCrtTerm t = true) (xs : List (List F)) (i : ℕ) :
    termCoefVal b s xs t i = 0 := by
  have hc := hcrt
  simp only [PolyShape.isCrtTerm, Bool.and_eq_true, beq_iff_eq] at hc
  unfold termCoefVal
  match hfac : t.factors, hc.1.2 with
  | [f0, f1], _ => simp [hcrt]

theorem exprVal_eq (hbf : BasisFacts b) (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m)
    (j : ℕ) :
    exprVal b s (limbLists es) j = (foldedInt b s es j : F) := by
  unfold exprVal foldedInt
  by_cases hf : s.fold = true
  · simp only [hf, if_true]
    unfold exprInt coefVal crtVal
    rw [lin_polySum, intCast_list_sum]
    simp only [List.map_map]
    have hmul : ∀ i, (b.foldAt i j : F) * ((s.terms.map fun t => termCoefVal b s (limbLists es) t i).sum) =
        (s.terms.map fun t => (b.foldAt i j : F) * termCoefVal b s (limbLists es) t i).sum := by
      intro i; rw [List.sum_map_mul_left]
    simp only [hmul]
    rw [sumRange_list_sum, ← List.sum_map_add]
    apply list_sum_congr
    intro t ht
    simp only [Function.comp_apply]
    by_cases hc : s.isCrtTerm t = true
    · simp only [termCoefVal_crt hc, mul_zero, hc, if_true]
      rw [show sumRange (s.degree + 1) (fun _ => (0 : F)) = 0 by simp [sumRange_eq], zero_add]
      by_cases hj : j < limbCount
      · exact crtTerm_eq hbf hb hsf hc hj
      · exact crtTerm_eq_ge hbf hsf hc (by omega) _
    · have hc' : s.isCrtTerm t = false := by simpa using hc
      simp only [hc', Bool.false_eq_true, if_false, add_zero]
      simp only [termCoefVal_eq hbf hb hsf ht hc']
      rw [intCast_lin, lin_eq_sum_of_le _ _ (N := s.degree + 1)]
      · rw [sumRange_eq]
        apply Finset.sum_congr rfl; intro i _
        rw [intCast_getD]
      · rw [List.length_map, length_termInt hb hsf ht]; exact Nat.succ_le_succ (hsf.degree t ht)
  · have hf' : s.fold = false := by simpa using hf
    simp only [hf', Bool.false_eq_true, if_false]
    have hnc : ∀ t ∈ s.terms, s.isCrtTerm t = false := by
      intro t _; simp [PolyShape.isCrtTerm, hf']
    have hcoef : coefVal b s (limbLists es) j = (((exprInt es s).getD j 0 : ℤ) : F) := by
      unfold coefVal exprInt
      rw [getD_eq_lin_delta, lin_polySum, intCast_list_sum]
      simp only [List.map_map]
      apply list_sum_congr
      intro t ht
      simp only [Function.comp_apply, termCoefVal_eq hbf hb hsf ht (hnc t ht), ← getD_eq_lin_delta]
    split_ifs with hd
    · exact hcoef
    · rw [getD_eq_zero_of_le]
      · simp
      · unfold exprInt
        refine (length_polySum_le _ (s.degree + 1) ?_).trans (by omega)
        intro p hp
        obtain ⟨t, ht, rfl⟩ := List.mem_map.mp hp
        rw [length_termInt hb hsf ht]; exact Nat.succ_le_succ (hsf.degree t ht)

theorem forall₂_map_of {ι α β : Type*} {R : α → β → Prop} {l : List ι} {f : ι → α} {g : ι → β}
    (h : ∀ t ∈ l, R (f t) (g t)) : List.Forall₂ R (l.map f) (l.map g) := by
  induction l with
  | nil => exact List.Forall₂.nil
  | cons t l ih => exact List.Forall₂.cons (h t (by simp)) (ih (fun u hu => h u (by simp [hu])))

theorem absLe_exprInt (hb : ElemsMatch es s.elems) : AbsLe (exprInt es s) s.coefBounds := by
  unfold exprInt PolyShape.coefBounds
  apply AbsLe.polySum
  apply forall₂_map_of
  intro t _
  unfold termInt termPoly
  apply AbsLe.foldl_polyMul
  · apply forall₂_map_of
    intro f _
    exact (inputFacts hb f).absLe
  · exact List.Forall₂.cons le_rfl List.Forall₂.nil

theorem length_exprInt_le (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m) :
    (exprInt es s).length ≤ s.degree + 1 := by
  unfold exprInt
  refine length_polySum_le _ _ ?_
  intro p hp
  obtain ⟨t, ht, rfl⟩ := List.mem_map.mp hp
  rw [length_termInt hb hsf ht]; exact Nat.succ_le_succ (hsf.degree t ht)

theorem AbsLe.getD {P B : List ℤ} (h : AbsLe P B) (i : ℕ) : |P.getD i 0| ≤ B.getD i 0 := by
  induction h generalizing i with
  | nil => simp
  | cons hxX _ ih => cases i <;> simp_all

theorem foldedInt_bound (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m) (j : ℕ) :
    |foldedInt b s es j| ≤ if s.fold then s.foldedBound b j else s.coefBounds.getD j 0 := by
  have hab := absLe_exprInt hb
  unfold foldedInt
  split_ifs
  · refine (lin_abs_le hab _).trans (le_of_eq ?_)
    unfold PolyShape.foldedBound
    rw [lin_eq_sum_of_le _ _ (N := s.degree + 1), sumRange_eq]
    rw [← hab.length_eq]; exact length_exprInt_le hb hsf
  · exact hab.getD j

theorem lin_pow_eq_evalAt (P : List ℤ) :
    lin (fun i => (2 : ℤ) ^ (32 * i)) P = evalAt P limbBase := by
  unfold evalAt limbBase; congr 1; funext i; rw [pow_mul]

theorem recompose_eq_sumRange {row : List ℤ} {n : ℕ} (h : row.length ≤ n) :
    recompose row = sumRange n (fun j => row.getD j 0 * 2 ^ (32 * j)) := by
  rw [recompose, ← lin_pow_eq_evalAt, lin_eq_sum_of_le _ _ h, sumRange_eq]
  apply Finset.sum_congr rfl; intro j _; ring

theorem folded_congr (hbf : BasisFacts b) (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m)
    (hf : s.fold = true) :
    sumRange limbCount (fun j => foldedInt b s es j * 2 ^ (32 * j)) ≡
      evalAt (exprInt es s) limbBase [ZMOD (b.foldModulus : ℤ)] := by
  unfold foldedInt
  simp only [hf, if_true]
  have : (fun j => lin (fun i => b.foldAt i j) (exprInt es s) * 2 ^ (32 * j)) =
      fun j => lin (fun i => b.foldAt i j * 2 ^ (32 * j)) (exprInt es s) := by
    funext j; rw [lin_mul_fun]; ring
  rw [this, ← lin_sumRange_fun, ← lin_pow_eq_evalAt]
  apply lin_modEq
  intro i hi
  have hlen := length_exprInt_le hb hsf
  have hi' : i < b.foldRows.length := by have := (hsf.fold hf).2; omega
  obtain ⟨hrow, hmod⟩ := hbf.rows i hi'
  rw [recompose_eq_sumRange (n := limbCount) hrow.le] at hmod
  have hd := Int.dvd_of_emod_eq_zero hmod
  apply Int.modEq_iff_dvd.mpr
  rw [← neg_sub]
  exact dvd_neg.mpr (by simpa [BasisParams.foldAt] using hd)

theorem unfolded_eq (hb : ElemsMatch es s.elems) (hsf : ShapeFacts b s m) (hf : s.fold = false)
    {n : ℕ} (hn : s.degree + 1 ≤ n) :
    sumRange n (fun j => foldedInt b s es j * 2 ^ (32 * j)) = evalAt (exprInt es s) limbBase := by
  unfold foldedInt
  simp only [hf, Bool.false_eq_true, if_false]
  rw [← lin_pow_eq_evalAt, lin_eq_sum_of_le _ _ ((length_exprInt_le hb hsf).trans hn), sumRange_eq]
  apply Finset.sum_congr rfl; intro j _; ring

end Terms

end ZolanaVE.Field
