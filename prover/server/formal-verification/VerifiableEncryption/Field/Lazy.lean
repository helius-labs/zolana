import VerifiableEncryption.Field.PlainCheck

/-!
Soundness of `Field.Lazy`: no constraints are emitted, the limbs are the
folded expression forms, so the element is the folded expression itself. The
certified limb intervals follow from interval multiplication of the input
limb intervals and a sign-split fold.
-/

namespace ZolanaVE.Field

theorem ElemVal.inIv {w : ℕ} (e : ElemVal w) : InIv e.lo.toList e.ints.toList e.hi.toList := by
  obtain ⟨⟨lo, hlo⟩, ⟨x, hx⟩, ⟨hi, hhi⟩⟩ := (⟨e.lo, e.ints, e.hi⟩ : _ × _ × _)
  have key : ∀ (lo x hi : List ℤ), lo.length = x.length → x.length = hi.length →
      (∀ i (h1 : i < lo.length) (h2 : i < x.length) (h3 : i < hi.length), lo[i] ≤ x[i] ∧ x[i] ≤ hi[i]) →
      InIv lo x hi := by
    intro lo
    induction lo with
    | nil => intro x hi h1 h2 _; cases x <;> cases hi <;> simp_all [InIv]
    | cons l ls ih =>
      intro x hi h1 h2 h
      cases x with
      | nil => simp at h1
      | cons y ys =>
        cases hi with
        | nil => simp at h2
        | cons z zs =>
          refine ⟨(h 0 (by simp) (by simp) (by simp)).1, (h 0 (by simp) (by simp) (by simp)).2, ?_⟩
          exact ih ys zs (by simpa using h1) (by simpa using h2)
            (fun i a b c => h (i + 1) (by simpa using a) (by simpa using b) (by simpa using c))
  apply key _ _ _ (by simp) (by simp)
  intro i h1 h2 h3
  have hi : i < w := by simpa using h1
  have a := e.h_lo ⟨i, hi⟩
  have b := e.h_hi ⟨i, hi⟩
  simp only [List.Vector.get_eq_get_toList, List.get_eq_getElem, Fin.coe_cast] at a b
  exact ⟨a, b⟩

theorem InIv.lengths {lo x hi : List ℤ} (h : InIv lo x hi) : lo.length = x.length ∧ x.length = hi.length := by
  induction lo generalizing x hi with
  | nil => cases x <;> cases hi <;> simp_all [InIv]
  | cons l ls ih =>
    cases x with
    | nil => simp [InIv] at h
    | cons y ys =>
      cases hi with
      | nil => simp [InIv] at h
      | cons z zs =>
        have := ih h.2.2
        simp [this.1, this.2]

theorem InIv.getD {lo x hi : List ℤ} (h : InIv lo x hi) (i : ℕ) :
    lo.getD i 0 ≤ x.getD i 0 ∧ x.getD i 0 ≤ hi.getD i 0 := by
  induction lo generalizing x hi i with
  | nil => cases x <;> cases hi <;> simp_all [InIv]
  | cons l ls ih =>
    cases x with
    | nil => simp [InIv] at h
    | cons y ys =>
      cases hi with
      | nil => simp [InIv] at h
      | cons z zs =>
        cases i with
        | zero => simpa using ⟨h.1, h.2.1⟩
        | succ i => simpa using ih h.2.2 i

theorem inputInIv {es : List (Σ w, ElemVal w)} {s : PolyShape} (hb : ElemsMatch es s.elems) (f : ℕ) :
    InIv (s.elem f).lo (intsOf es f) (s.elem f).hi := by
  have hf := inputFacts hb f
  rw [hf.lo, hf.hi]
  unfold intsOf
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD,
    List.getElem?_map, List.getElem?_map, List.getElem?_map]
  cases es[f]? with
  | none => simp [InIv]
  | some e => exact e.2.inIv

theorem termInIv {es : List (Σ w, ElemVal w)} {s : PolyShape} (hb : ElemsMatch es s.elems) (t : TermC) :
    let p := t.factors.foldl (fun p f => polyMulIv p.1 p.2 (s.elem f).lo (s.elem f).hi) ([t.coef], [t.coef])
    InIv p.1 (termInt es t) p.2 := by
  intro p
  unfold termInt termPoly
  suffices ∀ (fs : List ℕ) (q : List ℤ × List ℤ) (x : List ℤ), InIv q.1 x q.2 →
      InIv (fs.foldl (fun p f => polyMulIv p.1 p.2 (s.elem f).lo (s.elem f).hi) q).1
        ((fs.map (intsOf es)).foldl polyMul x)
        (fs.foldl (fun p f => polyMulIv p.1 p.2 (s.elem f).lo (s.elem f).hi) q).2 from
    this t.factors _ _ ⟨le_rfl, le_rfl, trivial⟩
  intro fs
  induction fs with
  | nil => intro q x h; simpa using h
  | cons f fs ih =>
    intro q x h
    simp only [List.foldl_cons, List.map_cons]
    exact ih _ _ (InIv.polyMul h (inputInIv hb f))

/-- The coefficients the lazy element folds, accumulated left to right like `coefInterval`. -/
def lazyCoefs (es : List (Σ w, ElemVal w)) (s : PolyShape) : List ℤ :=
  s.terms.foldl (fun acc t => polyAdd acc (termInt es t)) []

theorem lin_lazyCoefs (es : List (Σ w, ElemVal w)) (s : PolyShape) (f : ℕ → ℤ) :
    lin f (lazyCoefs es s) = lin f (exprInt es s) := by
  unfold lazyCoefs exprInt
  suffices ∀ (ts : List TermC) (acc : List ℤ),
      lin f (ts.foldl (fun acc t => polyAdd acc (termInt es t)) acc) = lin f acc + lin f (polySum (ts.map (termInt es))) by
    rw [this]; simp
  intro ts
  induction ts with
  | nil => intro acc; simp [polySum]
  | cons t ts ih =>
    intro acc
    simp only [List.foldl_cons, ih, lin_polyAdd, List.map_cons, polySum, List.foldr_cons]
    simp only [polySum] at *
    ring

theorem coefInterval_inIv {es : List (Σ w, ElemVal w)} (c : LazyParams) (hb : ElemsMatch es c.elems) :
    InIv c.coefInterval.1 (lazyCoefs es c.toPolyShape) c.coefInterval.2 := by
  unfold LazyParams.coefInterval lazyCoefs
  suffices ∀ (ts : List TermC) (acc : List ℤ × List ℤ) (x : List ℤ), InIv acc.1 x acc.2 →
      InIv (ts.foldl (fun acc t =>
        let p := t.factors.foldl (fun p f => polyMulIv p.1 p.2 (c.elem f).lo (c.elem f).hi) ([t.coef], [t.coef])
        (polyAdd acc.1 p.1, polyAdd acc.2 p.2)) acc).1
      (ts.foldl (fun acc t => polyAdd acc (termInt es t)) x)
      (ts.foldl (fun acc t =>
        let p := t.factors.foldl (fun p f => polyMulIv p.1 p.2 (c.elem f).lo (c.elem f).hi) ([t.coef], [t.coef])
        (polyAdd acc.1 p.1, polyAdd acc.2 p.2)) acc).2 from
    this c.terms ([], []) [] trivial
  intro ts
  induction ts with
  | nil => intro acc x h; simpa using h
  | cons t ts ih =>
    intro acc x h
    simp only [List.foldl_cons]
    exact ih _ _ (InIv.polyAdd h (termInIv (s := c.toPolyShape) hb t))

theorem lin_between {lo x hi : List ℤ} (h : InIv lo x hi) (f : ℕ → ℤ) :
    sumRange lo.length (fun i => if 0 ≤ f i then f i * lo.getD i 0 else f i * hi.getD i 0) ≤ lin f x ∧
      lin f x ≤ sumRange lo.length (fun i => if 0 ≤ f i then f i * hi.getD i 0 else f i * lo.getD i 0) := by
  rw [lin_eq_sum, ← h.lengths.1, ← sumRange_eq]
  constructor <;> apply sumRange_le_sumRange <;> intro i _ <;> have := h.getD i <;> split_ifs with hf
  · exact mul_le_mul_of_nonneg_left this.1 hf
  · exact mul_le_mul_of_nonpos_left this.2 (le_of_lt (not_le.mp hf))
  · exact mul_le_mul_of_nonneg_left this.2 hf
  · exact mul_le_mul_of_nonpos_left this.1 (le_of_lt (not_le.mp hf))

theorem recompose_mono : ∀ {a b : List ℤ}, List.Forall₂ (· ≤ ·) a b → recompose a ≤ recompose b
  | [], [], _ => le_rfl
  | x :: a, y :: b, List.Forall₂.cons hxy h => by
    simp only [recompose_cons]
    have := recompose_mono h
    linarith

structure LazyFacts (b : BasisParams) (c : LazyParams) : Prop where
  shape : c.toPolyShape.shapeSound b c.m = true
  fold : c.fold = true
  lo_len : c.outLo.length = limbCount
  hi_len : c.outHi.length = limbCount
  limbs : ∀ j < limbCount, c.outLo.getD j 0 = (c.limbInterval b j).1 ∧ c.outHi.getD j 0 = (c.limbInterval b j).2
  vlo : c.outVlo = recompose c.outLo
  vhi : c.outVhi = recompose c.outHi

theorem lazyFacts {b : BasisParams} {c : LazyParams} (hc : c.sound b = true) : LazyFacts b c := by
  unfold LazyParams.sound at hc
  simp only [Bool.and_eq_true, and_assoc, beq_iff_eq, List.all_eq_true, List.mem_range] at hc
  obtain ⟨hs, hf, _, hlo, hhi, hl, hvlo, hvhi⟩ := hc
  exact ⟨hs, hf, hlo, hhi, hl, hvlo, hvhi⟩

theorem lazy_sound (b : BasisParams) (c : LazyParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {k : List F → Prop} (h : Lazy.circuit b c (limbLists es) k) :
    ∃ e : ElemVal limbCount,
      e.lo.toList = c.outLo ∧ e.hi.toList = c.outHi ∧ e.vlo = c.outVlo ∧ e.vhi = c.outVhi ∧
      k e.limbs.toList ∧
      e.value ≡ c.exprValue (values es) [ZMOD c.m] := by
  have hbf := basisFacts hbs
  have hlf := lazyFacts hc
  have hsf := shapeFacts hlf.shape
  set ints := (List.range limbCount).map (foldedInt b c.toPolyShape es) with hints
  have hbounds : ∀ j < limbCount, c.outLo.getD j 0 ≤ ints.getD j 0 ∧ ints.getD j 0 ≤ c.outHi.getD j 0 := by
    intro j hj
    have hget : ints.getD j 0 = foldedInt b c.toPolyShape es j := by
      rw [hints, List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hj]; rfl
    rw [hget, (hlf.limbs j hj).1, (hlf.limbs j hj).2]
    unfold foldedInt LazyParams.limbInterval
    simp only [hlf.fold, if_true]
    rw [← lin_lazyCoefs]
    exact lin_between (coefInterval_inIv c hb) _
  have hlen : ints.length = limbCount := by simp [hints]
  have hforall : ∀ (lo x hi : List ℤ), lo.length = limbCount → x.length = limbCount → hi.length = limbCount →
      (∀ j < limbCount, lo.getD j 0 ≤ x.getD j 0 ∧ x.getD j 0 ≤ hi.getD j 0) →
      List.Forall₂ (· ≤ ·) lo x ∧ List.Forall₂ (· ≤ ·) x hi := by
    intro lo x hi h1 h2 h3 h
    constructor <;> rw [List.forall₂_iff_get] <;> refine ⟨by omega, fun i a b => ?_⟩
    · have := (h i (by omega)).1
      rw [List.getD_eq_getElem _ _ a, List.getD_eq_getElem _ _ b] at this
      simpa using this
    · have := (h i (by omega)).2
      rw [List.getD_eq_getElem _ _ a, List.getD_eq_getElem _ _ b] at this
      simpa using this
  obtain ⟨hlx, hxh⟩ := hforall _ _ _ hlf.lo_len hlen hlf.hi_len hbounds
  let e : ElemVal limbCount :=
    { limbs := ⟨(List.range limbCount).map (exprVal b c.toPolyShape (limbLists es)), by simp⟩
      ints := ⟨ints, hlen⟩
      lo := ⟨c.outLo, hlf.lo_len⟩
      hi := ⟨c.outHi, hlf.hi_len⟩
      vlo := c.outVlo
      vhi := c.outVhi
      h_cast := by
        intro i
        simp only [List.Vector.get_eq_get_toList, List.Vector.toList_mk, List.get_eq_getElem, List.getElem_map,
          List.getElem_range, hints]
        exact exprVal_eq hbf hb hsf _
      h_lo := by
        intro i
        have := (List.forall₂_iff_get.mp hlx).2 i (by simp [hlf.lo_len]) (by simp [hlen])
        simpa [List.Vector.get_eq_get_toList] using this
      h_hi := by
        intro i
        have := (List.forall₂_iff_get.mp hxh).2 i (by simp [hlen]) (by simp [hlf.hi_len])
        simpa [List.Vector.get_eq_get_toList] using this
      h_vlo := by rw [hlf.vlo]; exact recompose_mono hlx
      h_vhi := by rw [hlf.vhi]; exact recompose_mono hxh }
  refine ⟨e, rfl, rfl, rfl, rfl, h, ?_⟩
  have hcong := folded_congr hbf hb hsf hlf.fold
  rw [evalAt_exprInt, ← (hsf.fold hlf.fold).1] at hcong
  show recompose ints ≡ _ [ZMOD c.m]
  rw [recompose_eq_sumRange (n := limbCount) hlen.le]
  have heq : sumRange limbCount (fun j => ints.getD j 0 * 2 ^ (32 * j)) =
      sumRange limbCount (fun j => foldedInt b c.toPolyShape es j * 2 ^ (32 * j)) := by
    apply sumRange_congr; intro j hj
    rw [hints, List.getD_eq_getElem?_getD, List.getElem?_map, List.getElem?_range hj]; rfl
  rw [heq]; exact hcong

end ZolanaVE.Field
