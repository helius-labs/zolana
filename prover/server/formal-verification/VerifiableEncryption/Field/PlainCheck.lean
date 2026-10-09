import VerifiableEncryption.Field.Carry

/-!
Soundness of `checkPolynomial`: the carry chain and the closing check force
the residual integer `∑ residual_j 2^(32 j)` to vanish, so the remainder is
congruent to the expression modulo the emulated modulus.
-/

namespace ZolanaVE.Field

open PlainCheckParams (carryIn)

/-! ### Helpers -/

theorem getD_polyMul {R : Type*} [CommRing R] (x y : List R) (p : ℕ) :
    (polyMul x y).getD p 0 = sumRange x.length (fun a => if a ≤ p then x.getD a 0 * y.getD (p - a) 0 else 0) := by
  rw [getD_eq_lin_delta, lin_polyMul, lin_eq_sum, sumRange_eq]
  apply Finset.sum_congr rfl
  intro a _
  split_ifs with h
  · rw [mul_comm]; congr 1
    rw [← lin_delta]; congr 1; funext b'
    by_cases hb : b' = p - a
    · simp [hb, Nat.add_sub_cancel' h]
    · have : a + b' ≠ p := by omega
      simp [hb, this]
  · have : (fun b' => if a + b' = p then (1 : R) else 0) = fun _ => 0 := by
      funext b'; have : a + b' ≠ p := by omega
      simp [this]
    rw [this, lin_zero_fun, zero_mul]

theorem length_polyMul_le {R : Type*} [CommRing R] (x y : List R) (hy : y ≠ []) :
    (polyMul x y).length ≤ x.length + y.length - 1 := by
  cases x with
  | nil => simp [polyMul]
  | cons a as => rw [length_polyMul _ _ (by simp) hy]

theorem recompose_cons (a : ℤ) (l : List ℤ) : recompose (a :: l) = a + 2 ^ 32 * recompose l := by
  simp [recompose, evalAt_cons, limbBase]

theorem natCast_lt_two_pow {v : F} {w : ℕ} (h : v.val < 2 ^ w) : ((v.val : ℕ) : ℤ) ≤ 2 ^ w - 1 := by
  have := Int.ofNat_lt.mpr h; push_cast at this; linarith

theorem recompose_bounds {r : List F} {ws : List ℕ} (h : List.Forall₂ (fun (l : F) w => l.val < 2 ^ w) r ws) :
    0 ≤ recompose (r.map fun l => (l.val : ℤ)) ∧
      recompose (r.map fun l => (l.val : ℤ)) ≤ recompose (ws.map fun w => (2 : ℤ) ^ w - 1) := by
  induction h with
  | nil => simp [recompose]
  | @cons a w l ws' hl _ ih =>
    simp only [List.map_cons, recompose_cons]
    have h1 := natCast_lt_two_pow hl
    have h0 : (0 : ℤ) ≤ (a.val : ℤ) := Int.natCast_nonneg _
    constructor
    · have := ih.1; positivity
    · nlinarith [ih.1, ih.2]

theorem getD_val_lt {r : List F} {ws : List ℕ} (h : List.Forall₂ (fun (l : F) w => l.val < 2 ^ w) r ws)
    (p : ℕ) : ((r.getD p 0).val : ℤ) ≤ 2 ^ (ws.getD p 0) - 1 := by
  induction h generalizing p with
  | nil => simp
  | cons hl _ ih => cases p with
    | zero => simpa using natCast_lt_two_pow hl
    | succ p => simpa using ih p

theorem two_ne_zero_F : (2 : F) ≠ 0 := by
  intro h
  have : ((2 : ℕ) : F) = 0 := by simpa using h
  rw [ZMod.natCast_zmod_eq_zero_iff_dvd] at this
  have := Nat.le_of_dvd (by norm_num) this
  have := two_pow_253_lt_order
  omega

/-! ### Unpacking the certificate -/

structure PlainFacts (b : BasisParams) (c : PlainCheckParams) : Prop where
  shape : c.toPolyShape.shapeSound b c.m = true
  m_pos : 0 < c.m
  m_inv : (c.m * c.mInv) % Order = 1
  limbs_len : c.modulusLimbs.length = limbCount
  limbs_rec : recompose (c.modulusLimbs.map (fun l : ℕ => (l : ℤ))) = c.m
  pb_pos : 0 < c.pieceBits
  pb_le : c.pieceBits ≤ 253
  rw_len : c.resultWidths.length = limbCount
  rw_le : ∀ w ∈ c.resultWidths, w ≤ 32
  rem : c.withResult = true → recompose (c.resultWidths.map fun w => (2 : ℤ) ^ w - 1) ≤ c.remainderMax
  folded : c.fold = true → c.positions = limbCount ∧ c.quotientBits ≤ 253
  general : c.fold = false → (∀ w ∈ c.quotientWidths, w ≤ 32) ∧
    c.offsetLimbs.length = c.quotientWidths.length ∧
    recompose (c.offsetLimbs.map (fun l : ℕ => (l : ℤ))) = c.offset ∧
    recompose (c.quotientWidths.map fun w => (2 : ℤ) ^ w - 1) ≤ 2 ^ c.quotientBits - 1 ∧
    c.degree < c.positions ∧ limbCount ≤ c.positions ∧ c.quotientWidths.length + limbCount ≤ c.positions + 1
  cp_lt : c.carryPositions < c.positions
  groups : ∃ prev, c.groupsSound b c.groups 0 none = some prev ∧
    (c.checkTop = true → c.carryPositions + 1 = c.positions ∧
      c.residualBound b c.carryPositions + carryIn prev < (Order : ℤ)) ∧
    (c.checkTop = false → c.residualMagnitude b < (Order : ℤ) * 2 ^ (32 * c.carryPositions))

theorem plainFacts {b : BasisParams} {c : PlainCheckParams} (hc : c.sound b = true) : PlainFacts b c := by
  unfold PlainCheckParams.sound at hc
  simp only [Bool.and_eq_true, and_assoc] at hc
  obtain ⟨hshape, hm, hinv, hlen, hrec, hpb, hpb', hrw, hrwle, hrem, hpath, hcp, hg⟩ := hc
  simp only [decide_eq_true_eq, beq_iff_eq, List.all_eq_true] at hm hinv hlen hrec hpb hpb' hrw hrwle hcp
  refine ⟨hshape, hm, hinv, hlen, by exact_mod_cast hrec, hpb, hpb', hrw, hrwle, ?_, ?_, ?_, hcp, ?_⟩
  · intro hw
    simp only [hw, Bool.not_true, Bool.false_or, decide_eq_true_eq] at hrem
    exact hrem
  · intro hf
    simp only [hf, if_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hpath
    exact hpath
  · intro hf
    simp only [hf, Bool.false_eq_true, if_false, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq,
      List.all_eq_true, and_assoc] at hpath
    obtain ⟨h1, h2, h3, h4, h5, h6, h7⟩ := hpath
    exact ⟨h1, h2, by exact_mod_cast h3, h4, h5, h6, h7⟩
  · revert hg
    cases hgs : c.groupsSound b c.groups 0 none with
    | none => simp
    | some prev =>
      intro hg
      refine ⟨prev, rfl, fun ht => ?_, fun ht => ?_⟩
      · simp only [ht, if_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at hg
        exact hg
      · simp only [ht, Bool.false_eq_true, if_false, decide_eq_true_eq] at hg
        exact hg

/-! ### Quotient -/

theorem shiftedBound_nonneg (o w : ℕ) : 0 ≤ PlainCheckParams.shiftedBound o w := by
  unfold PlainCheckParams.shiftedBound; exact (Int.natCast_nonneg o).trans (le_max_left _ _)

theorem recompose_zipWith_sub : ∀ (x y : List ℤ), x.length = y.length →
    recompose (List.zipWith (fun a b => a - b) x y) = recompose x - recompose y
  | [], [], _ => by simp [recompose]
  | a :: x, b :: y, h => by
    simp only [List.zipWith_cons_cons, recompose_cons]
    rw [recompose_zipWith_sub x y (by simpa using h)]; ring
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h

theorem getD_zipWith_sub : ∀ (x y : List ℤ) (a : ℕ), a < x.length → x.length = y.length →
    (List.zipWith (fun a b => a - b) x y).getD a 0 = x.getD a 0 - y.getD a 0
  | [], _, a, h, _ => by simp at h
  | _ :: _, [], _, _, h => by simp at h
  | p :: x, q :: y, 0, _, _ => by simp
  | p :: x, q :: y, a + 1, h, hl => by
    simp only [List.zipWith_cons_cons, List.getD_cons_succ]
    exact getD_zipWith_sub x y a (by simpa using h) (by simpa using hl)

theorem modulusLimbs_getD (c : PlainCheckParams) (hlen : c.modulusLimbs.length = limbCount) (pos : ℕ) :
    (((c.modulusLimbs.map (fun l : ℕ => (l : ℤ))).getD pos 0 : ℤ) : F) =
      if pos < limbCount then CheckPolynomial.modLimb c pos else 0 := by
  unfold CheckPolynomial.modLimb
  split_ifs with h
  · rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
    cases c.modulusLimbs[pos]? <;> simp
  · rw [getD_eq_zero_of_le (by simp [hlen]; omega)]; simp

theorem quotient_lift {b : BasisParams} {c : PlainCheckParams} (hpf : PlainFacts b c) {rc : ℕ → F → Prop}
    (hrc : RangeSound rc) {qp : List F} {kq : F}
    (hqp : if c.fold then qp = [] else PiecesOk rc c.pieceBits c.quotientWidths qp)
    (hfoldq : c.fold = true → rc c.quotientBits (kq + (c.offset : F))) :
    ∃ Kl : List ℤ,
      (∀ pos, (if c.fold then (if pos < limbCount then kq * CheckPolynomial.modLimb c pos else 0)
        else sumRange (if c.fold then [] else limbsOfPieces c.pieceBits c.quotientWidths qp).length (fun a =>
          if a ≤ pos ∧ pos - a < limbCount then
            ((if c.fold then [] else limbsOfPieces c.pieceBits c.quotientWidths qp).getD a 0 -
              (c.offsetLimbs.getD a 0 : F)) * CheckPolynomial.modLimb c (pos - a)
          else 0)) =
        (((polyMul Kl (c.modulusLimbs.map (fun l : ℕ => (l : ℤ)))).getD pos 0 : ℤ) : F)) ∧
      Kl.length ≤ c.quotientLimbCount ∧
      (∀ a, |Kl.getD a 0| ≤ c.quotientLimbBound a) ∧
      |recompose Kl| ≤ c.quotientMagnitude := by
  by_cases hf : c.fold = true
  · obtain ⟨hpos, hqb⟩ := hpf.folded hf
    obtain ⟨K, hKF, hK1, hK2⟩ := shifted_lift hrc hqb (hfoldq hf)
    have hKb : |K| ≤ c.quotientMagnitude := abs_le_shiftedBound hK1 hK2
    refine ⟨[K], fun pos => ?_, by simp [PlainCheckParams.quotientLimbCount, hf], fun a => ?_, ?_⟩
    · simp only [hf, if_true]
      rw [getD_polyMul_single, Int.cast_mul, modulusLimbs_getD c hpf.limbs_len, hKF]
      split_ifs <;> simp
    · unfold PlainCheckParams.quotientLimbBound
      simp only [hf, if_true]
      cases a with
      | zero => simpa using hKb
      | succ a => simpa using (abs_nonneg K).trans hKb
    · simpa [recompose, evalAt_cons] using hKb
  · have hf' : c.fold = false := by simpa using hf
    obtain ⟨hqw, hol, hor, hqmax, -, -, -⟩ := hpf.general hf'
    simp only [hf', Bool.false_eq_true, if_false] at hqp ⊢
    set ql := limbsOfPieces c.pieceBits c.quotientWidths qp
    have hql := piecesOk_limbs hrc hpf.pb_pos hpf.pb_le c.quotientWidths qp
      (fun w hw => (hqw w hw).trans (by norm_num)) hqp
    have hqll : ql.length = c.quotientWidths.length := hql.length_eq
    set Kl := List.zipWith (fun a b => a - b) (ql.map fun l => (l.val : ℤ)) (c.offsetLimbs.map fun l : ℕ => (l : ℤ))
    have hKll : Kl.length = ql.length := by simp [Kl, hqll, hol]
    have hKget : ∀ a < ql.length, Kl.getD a 0 = ((ql.getD a 0).val : ℤ) - c.offsetLimbs.getD a 0 := by
      intro a ha
      rw [getD_zipWith_sub _ _ _ (by simpa using ha) (by simp [hqll, hol])]
      congr 1
      · rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
        rw [List.getElem?_eq_getElem ha]; simp
      · rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
        cases c.offsetLimbs[a]? <;> simp
    refine ⟨Kl, fun pos => ?_, by simp [PlainCheckParams.quotientLimbCount, hf', hKll, hqll], fun a => ?_, ?_⟩
    · rw [getD_polyMul, hKll, intCast_sumRange, sumRange_eq, sumRange_eq]
      apply Finset.sum_congr rfl
      intro a ha
      have ha' : a < ql.length := Finset.mem_range.mp ha
      by_cases hap : a ≤ pos
      · have hm := modulusLimbs_getD c hpf.limbs_len (pos - a)
        by_cases hlt : pos - a < limbCount
        · simp only [hap, hlt, and_self, if_true, Int.cast_mul, hKget a ha', Int.cast_sub,
            natCast_val_eq] at hm ⊢
          rw [hm, Int.cast_natCast]
        · simp only [hap, hlt, and_false, if_false, true_and, if_true] at hm ⊢
          rw [Int.cast_mul, hm, mul_zero]
      · simp [hap]
    · unfold PlainCheckParams.quotientLimbBound
      simp only [hf', Bool.false_eq_true, if_false]
      by_cases ha : a < ql.length
      · rw [hKget a ha]
        have hv := getD_val_lt hql a
        apply abs_le_shiftedBound
        · have := Int.natCast_nonneg (ql.getD a 0).val
          have : (c.offsetLimbs.getD a 0 : ℤ) = ((c.offsetLimbs.getD a 0 : ℕ) : ℤ) := rfl
          linarith
        · linarith
      · rw [getD_eq_zero_of_le (by omega), abs_zero]; exact shiftedBound_nonneg _ _
    · unfold PlainCheckParams.quotientMagnitude
      have hb := recompose_bounds hql
      rw [recompose_zipWith_sub _ _ (by simp [hqll, hol]), hor]
      apply abs_le_shiftedBound <;> linarith [hb.1, hb.2]

/-! ### Main argument -/

theorem abs_sumRange_le (n : ℕ) (f : ℕ → ℤ) : |sumRange n f| ≤ sumRange n (fun i => |f i|) := by
  rw [sumRange_eq, sumRange_eq]; exact Finset.abs_sum_le_sum_abs _ _

theorem sumRange_le_sumRange {n : ℕ} {f g : ℕ → ℤ} (h : ∀ i < n, f i ≤ g i) : sumRange n f ≤ sumRange n g := by
  rw [sumRange_eq, sumRange_eq]
  exact Finset.sum_le_sum fun i hi => h i (Finset.mem_range.mp hi)

theorem sumRange_le_of_le {n N : ℕ} (hn : n ≤ N) {f : ℕ → ℤ} (hf : ∀ i, 0 ≤ f i) :
    sumRange n f ≤ sumRange N f := by
  rw [sumRange_eq, sumRange_eq]
  exact Finset.sum_le_sum_of_subset_of_nonneg (Finset.range_subset.mpr hn) fun i _ _ => hf i

theorem getD_map_natCast (l : List ℕ) (i : ℕ) :
    (l.map (fun x : ℕ => (x : ℤ))).getD i 0 = ((l.getD i 0 : ℕ) : ℤ) := by
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases l[i]? <;> simp

theorem quotientLimbBound_nonneg (c : PlainCheckParams) (a : ℕ) : 0 ≤ c.quotientLimbBound a := by
  unfold PlainCheckParams.quotientLimbBound PlainCheckParams.quotientMagnitude
  split_ifs <;> exact shiftedBound_nonneg _ _

theorem quotientTerm_bound (c : PlainCheckParams) (hlen : c.modulusLimbs.length = limbCount)
    {Kl : List ℤ} (hKlen : Kl.length ≤ c.quotientLimbCount) (hKb : ∀ a, |Kl.getD a 0| ≤ c.quotientLimbBound a)
    (p : ℕ) :
    |(polyMul Kl (c.modulusLimbs.map (fun l : ℕ => (l : ℤ)))).getD p 0| ≤
      sumRange c.quotientLimbCount (fun a =>
        if a ≤ p ∧ p - a < limbCount then c.quotientLimbBound a * c.modulusLimbs.getD (p - a) 0 else 0) := by
  rw [getD_polyMul]
  refine (abs_sumRange_le _ _).trans ((sumRange_le_sumRange fun a _ => ?_).trans
    (sumRange_le_of_le hKlen fun a => ?_))
  · split_ifs with h1 h2
    · rw [abs_mul, getD_map_natCast, abs_of_nonneg (Int.natCast_nonneg _)]
      exact mul_le_mul_of_nonneg_right (hKb a) (Int.natCast_nonneg _)
    · have hle : c.modulusLimbs.length ≤ p - a := by rw [hlen]; omega
      have hz : c.modulusLimbs.getD (p - a) 0 = 0 := List.getD_eq_default _ _ hle
      rw [getD_map_natCast, hz]; simp
    · exact absurd h1 (by omega)
    · simp
  · split_ifs
    · exact mul_nonneg (quotientLimbBound_nonneg c a) (Int.natCast_nonneg _)
    · exact le_rfl

theorem getD_map_val (r : List F) (p : ℕ) :
    (r.map fun l => (l.val : ℤ)).getD p 0 = ((r.getD p 0).val : ℤ) := by
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases r[p]? <;> simp

theorem exprValue_bounds {es : List (Σ w, ElemVal w)} {s : PolyShape} (hb : ElemsMatch es s.elems) :
    let bounds := fun f => ((s.elem f).vlo, (s.elem f).vhi)
    (s.terms.map fun t => (termRange bounds t.coef t.factors).1).sum ≤ s.exprValue (values es) ∧
      s.exprValue (values es) ≤ (s.terms.map fun t => (termRange bounds t.coef t.factors).2).sum := by
  intro bounds
  have hv : ∀ f, (bounds f).1 ≤ (values es).getD f 0 ∧ (values es).getD f 0 ≤ (bounds f).2 := by
    intro f; rw [values_getD]; exact ⟨(inputFacts hb f).vlo, (inputFacts hb f).vhi⟩
  unfold PolyShape.exprValue
  constructor
  · exact List.sum_le_sum fun t _ => (termRange_sound bounds _ hv t.coef t.factors).1
  · exact List.sum_le_sum fun t _ => (termRange_sound bounds _ hv t.coef t.factors).2

theorem sumRange_congr {R : Type*} [AddCommMonoid R] {n : ℕ} {f g : ℕ → R} (h : ∀ i < n, f i = g i) :
    sumRange n f = sumRange n g := by
  rw [sumRange_eq, sumRange_eq]
  exact Finset.sum_congr rfl fun i hi => h i (Finset.mem_range.mp hi)

theorem sumRange_sub_mul (n : ℕ) (a b d w : ℕ → ℤ) :
    sumRange n (fun p => (a p - b p - d p) * w p) =
      sumRange n (fun p => a p * w p) - sumRange n (fun p => b p * w p) - sumRange n (fun p => d p * w p) := by
  simp only [sumRange_eq, ← Finset.sum_sub_distrib]
  apply Finset.sum_congr rfl; intro p _; ring

theorem modulus_sum (c : PlainCheckParams) (hlen : c.modulusLimbs.length = limbCount)
    (hrec : recompose (c.modulusLimbs.map (fun l : ℕ => (l : ℤ))) = c.m) :
    sumRange limbCount (fun p => CheckPolynomial.modLimb c p * pow32 p) = (c.m : F) := by
  have h := recompose_eq_sumRange (row := c.modulusLimbs.map (fun l : ℕ => (l : ℤ))) (n := limbCount)
    (by simp [hlen])
  rw [hrec] at h
  have h2 := congrArg (fun z : ℤ => (z : F)) h
  simp only [Int.cast_natCast, intCast_sumRange, Int.cast_mul, Int.cast_pow, Int.cast_ofNat] at h2
  rw [h2]
  apply sumRange_congr; intro p _
  simp only [CheckPolynomial.modLimb, getD_map_natCast, Int.cast_natCast, pow32]

theorem checkPolynomial_core (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    {rc : ℕ → F → Prop} (hrc : RangeSound rc)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {k : Option (List F) → Prop} (h : CheckPolynomial.circuit b c (limbLists es) rc k) :
    ∃ r : List F,
      List.Forall₂ (fun (l : F) w => l.val < 2 ^ w) r (if c.withResult then c.resultWidths else []) ∧
      k (if c.withResult then some r else none) ∧
      recompose (r.map fun l => (l.val : ℤ)) ≡ c.exprValue (values es) [ZMOD c.m] := by
  have hbf := basisFacts hbs
  have hpf := plainFacts hc
  have hsf := shapeFacts hpf.shape
  obtain ⟨rp, qp, hrp, hqp, h⟩ := h
  dsimp only at h
  obtain ⟨hfoldq, hnative, hchain⟩ := h
  set xs := limbLists es
  set r : List F := if c.withResult then limbsOfPieces c.pieceBits c.resultWidths rp else [] with hr_def
  set ql : List F := if c.fold then [] else limbsOfPieces c.pieceBits c.quotientWidths qp with hql_def
  set kq := CheckPolynomial.foldQuotient b c xs r with hkq_def
  set res := CheckPolynomial.residual b c xs r ql kq with hres_def
  have hr : List.Forall₂ (fun (l : F) w => l.val < 2 ^ w) r (if c.withResult then c.resultWidths else []) := by
    by_cases hw : c.withResult = true
    · simp only [hr_def, hw, if_true] at hrp ⊢
      exact piecesOk_limbs hrc hpf.pb_pos hpf.pb_le _ _ (fun w hw => (hpf.rw_le w hw).trans (by norm_num)) hrp
    · simp [hr_def, hw]
  obtain ⟨Kl, hKq, hKlen, hKb, hKv⟩ := quotient_lift hpf hrc hqp hfoldq
  set Ml : List ℤ := c.modulusLimbs.map (fun l : ℕ => (l : ℤ)) with hMl
  set Res : ℕ → ℤ := fun p =>
    foldedInt b c.toPolyShape es p - ((r.getD p 0).val : ℤ) - (polyMul Kl Ml).getD p 0 with hRes_def
  have hResF : ∀ p, (Res p : F) = res p := by
    intro p
    simp only [hRes_def, hres_def, CheckPolynomial.residual, Int.cast_sub, natCast_val_eq,
      ← exprVal_eq hbf hb hsf p]
    rw [hKq p]
  have hResB : ∀ p, |Res p| ≤ c.residualBound b p := by
    intro p
    simp only [hRes_def, PlainCheckParams.residualBound]
    have h1 := foldedInt_bound hb hsf p
    have h2 : |((r.getD p 0).val : ℤ)| ≤ if c.withResult then 2 ^ (c.resultWidths.getD p 0) - 1 else 0 := by
      rw [abs_of_nonneg (Int.natCast_nonneg _)]
      by_cases hw : c.withResult = true
      · have := getD_val_lt hr p; simp only [hw, if_true] at this ⊢; exact this
      · simp only [hr_def, hw, Bool.false_eq_true, if_false, List.getD_nil, ZMod.val_zero, Nat.cast_zero,
          le_refl]
    have h3 := quotientTerm_bound c hpf.limbs_len hKlen hKb p
    calc |foldedInt b c.toPolyShape es p - ((r.getD p 0).val : ℤ) - (polyMul Kl Ml).getD p 0|
        ≤ |foldedInt b c.toPolyShape es p| + |((r.getD p 0).val : ℤ)| + |(polyMul Kl Ml).getD p 0| := by
          refine (abs_sub _ _).trans ?_
          exact add_le_add_right (abs_sub _ _) _
      _ ≤ _ := add_le_add (add_le_add h1 h2) h3
  obtain ⟨prev, hgs, htop, hmag⟩ := hpf.groups
  obtain ⟨C', hk', hC'b, hsumcp⟩ := carryChain_sound c b hrc hResF hResB c.groups 0 none prev 0 _ hgs
    (by simp [carryIn]) (by simp [sumRange]) (by simpa using hchain)
  have htopF : c.checkTop = true → res c.carryPositions + (C' : F) = 0 := hk'.1
  have hpos8 : limbCount ≤ c.positions := by
    by_cases hf : c.fold = true
    · exact (hpf.folded hf).1.ge
    · exact (hpf.general (by simpa using hf)).2.2.2.2.2.1
  have hrlen : r.length ≤ limbCount := by
    have := hr.length_eq
    split_ifs at this <;> simp [this, hpf.rw_len]
  set SFE := sumRange c.positions (fun p => foldedInt b c.toPolyShape es p * 2 ^ (32 * p)) with hSFE
  set R := recompose (r.map fun l => (l.val : ℤ)) with hR
  have hRsum : sumRange c.positions (fun p => ((r.getD p 0).val : ℤ) * 2 ^ (32 * p)) = R := by
    rw [hR, recompose_eq_sumRange (n := c.positions) (by simp; omega)]
    apply sumRange_congr; intro p _; rw [getD_map_val]
  have hKsum : sumRange c.positions (fun p => (polyMul Kl Ml).getD p 0 * 2 ^ (32 * p)) =
      recompose Kl * c.m := by
    have hlenP : (polyMul Kl Ml).length ≤ c.positions := by
      refine (length_polyMul_le _ _ (by simp [hMl, ← List.length_pos, hpf.limbs_len, limbCount])).trans ?_
      simp only [hMl, List.length_map, hpf.limbs_len]
      unfold PlainCheckParams.quotientLimbCount at hKlen
      by_cases hf : c.fold = true
      · simp only [hf, if_true] at hKlen; rw [(hpf.folded hf).1]; unfold limbCount at *; omega
      · simp only [hf, Bool.false_eq_true, if_false] at hKlen
        have := (hpf.general (by simpa using hf)).2.2.2.2.2.2
        unfold limbCount at *; omega
    rw [← recompose_eq_sumRange hlenP, recompose, evalAt_polyMul, ← recompose, ← recompose, hMl, hpf.limbs_rec]
  set T := sumRange c.positions (fun p => Res p * 2 ^ (32 * p)) with hT
  have hTeq : T = SFE - R - recompose Kl * c.m := by
    rw [hT, hRes_def]
    rw [sumRange_sub_mul, hRsum, hKsum]
  have hT0 : T = 0 := by
    by_cases ht : c.checkTop = true
    · obtain ⟨hcp1, hlift⟩ := (htop ht)
      have h1 : Res c.carryPositions + C' = 0 := by
        apply int_eq_zero_of_cast
        · rw [Int.cast_add, hResF]; exact htopF ht
        · calc |Res c.carryPositions + C'| ≤ |Res c.carryPositions| + |C'| := abs_add _ _
            _ ≤ c.residualBound b c.carryPositions + carryIn prev := add_le_add (hResB _) hC'b
            _ < _ := hlift
      rw [hT, ← hcp1, sumRange_split, hsumcp]
      have : sumRange 1 (fun t => Res (c.carryPositions + t) * 2 ^ (32 * (c.carryPositions + t))) =
          Res c.carryPositions * 2 ^ (32 * c.carryPositions) := by simp [sumRange, List.range_succ]
      rw [this, ← add_mul, add_comm, h1, zero_mul]
    · have ht' : c.checkTop = false := by simpa using ht
      have hTF : (T : F) = 0 := by
        have hc : (T : F) = sumRange c.positions (fun p => res p * pow32 p) := by
          rw [hT, intCast_sumRange]
          apply sumRange_congr; intro p _
          rw [Int.cast_mul, hResF]; simp [pow32]
        rw [hc]
        by_cases hf : c.fold = true
        · rw [(hpf.folded hf).1]
          have hr' : ∀ p < limbCount, res p = (exprVal b c.toPolyShape xs p - r.getD p 0) -
              kq * CheckPolynomial.modLimb c p := by
            intro p hp
            simp only [hres_def, CheckPolynomial.residual, hf, if_true, hp]
          rw [sumRange_congr (fun p hp => by rw [hr' p hp])]
          have hinvF : (c.m : F) * (c.mInv : F) = 1 := by
            have : (((c.m * c.mInv : ℕ)) : F) = 1 := by rw [← ZMod.natCast_mod, hpf.m_inv, Nat.cast_one]
            simpa using this
          have hsplit : sumRange limbCount (fun p => ((exprVal b c.toPolyShape xs p - r.getD p 0) -
              kq * CheckPolynomial.modLimb c p) * pow32 p) =
              (sumRange limbCount (fun j => exprVal b c.toPolyShape xs j * pow32 j) -
                sumRange limbCount (fun j => r.getD j 0 * pow32 j)) -
              kq * sumRange limbCount (fun p => CheckPolynomial.modLimb c p * pow32 p) := by
            simp only [sumRange_eq, Finset.mul_sum, ← Finset.sum_sub_distrib]
            apply Finset.sum_congr rfl; intro p _; ring
          rw [hsplit, modulus_sum c hpf.limbs_len hpf.limbs_rec, hkq_def, CheckPolynomial.foldQuotient]
          linear_combination -(sumRange limbCount (fun j => exprVal b c.toPolyShape xs j * pow32 j) -
            sumRange limbCount (fun j => r.getD j 0 * pow32 j)) * hinvF
        · exact hnative ⟨by simpa using hf, ht'⟩
      have hSFEb : |SFE| ≤ (if c.fold then sumRange limbCount (fun j => c.toPolyShape.foldedBound b j * 2 ^ (32 * j))
          else
            let bounds := fun f => ((c.elem f).vlo, (c.elem f).vhi)
            max |(c.terms.map fun t => (termRange bounds t.coef t.factors).1).sum|
              |(c.terms.map fun t => (termRange bounds t.coef t.factors).2).sum|) := by
        by_cases hf : c.fold = true
        · simp only [hf, if_true]
          rw [hSFE, (hpf.folded hf).1]
          refine (abs_sumRange_le _ _).trans (sumRange_le_sumRange fun j _ => ?_)
          rw [abs_mul, abs_of_pos (by positivity : (0 : ℤ) < 2 ^ (32 * j))]
          have := foldedInt_bound hb hsf j
          simp only [hf, if_true] at this
          exact mul_le_mul_of_nonneg_right this (by positivity)
        · have hf' : c.fold = false := by simpa using hf
          simp only [hf', Bool.false_eq_true, if_false]
          rw [hSFE, unfolded_eq hb hsf hf' (hpf.general hf').2.2.2.2.1, evalAt_exprInt]
          have := exprValue_bounds (s := c.toPolyShape) hb
          exact abs_le_max_abs this.1 this.2
      have hRb : |R| ≤ (if c.withResult then (c.remainderMax : ℤ) else 0) := by
        have hb' := recompose_bounds hr
        rw [abs_of_nonneg hb'.1]
        by_cases hw : c.withResult = true
        · simp only [hw, if_true] at hb' ⊢; exact hb'.2.trans (hpf.rem hw)
        · simp only [hw, Bool.false_eq_true, if_false] at hb' ⊢
          simpa [recompose] using hb'.2
      have hKmb : |recompose Kl * c.m| ≤ c.quotientMagnitude * c.m := by
        rw [abs_mul, abs_of_nonneg (Int.natCast_nonneg c.m)]
        exact mul_le_mul_of_nonneg_right hKv (Int.natCast_nonneg _)
      have hTb : |T| ≤ c.residualMagnitude b := by
        rw [hTeq]; unfold PlainCheckParams.residualMagnitude
        calc |SFE - R - recompose Kl * c.m| ≤ |SFE| + |R| + |recompose Kl * c.m| := by
              refine (abs_sub _ _).trans (add_le_add_right (abs_sub _ _) _)
          _ ≤ _ := add_le_add (add_le_add hSFEb hRb) hKmb
      have hmag' := hmag ht'
      set H := sumRange (c.positions - c.carryPositions)
        (fun t => Res (c.carryPositions + t) * 2 ^ (32 * t)) with hH
      have hsplit : T = 2 ^ (32 * c.carryPositions) * (C' + H) := by
        rw [hT, show c.positions = c.carryPositions + (c.positions - c.carryPositions) by
          have := hpf.cp_lt; omega, sumRange_split, hsumcp, hH, mul_add, sumRange_mul_left, mul_comm C']
        congr 1
        apply sumRange_congr; intro t _; rw [mul_add, pow_add]; ring
      have hCH : C' + H = 0 := by
        apply int_eq_zero_of_cast
        · have h2 : ((2 : F) ^ (32 * c.carryPositions)) * ((C' + H : ℤ) : F) = 0 := by
            have := hTF; rw [hsplit] at this; push_cast at this ⊢; exact this
          rcases mul_eq_zero.mp h2 with h3 | h3
          · exact absurd h3 (pow_ne_zero _ two_ne_zero_F)
          · exact h3
        · have hpos : (0 : ℤ) < 2 ^ (32 * c.carryPositions) := by positivity
          have h4 : |T| = 2 ^ (32 * c.carryPositions) * |C' + H| := by
            rw [hsplit, abs_mul, abs_of_pos hpos]
          have h5 : 2 ^ (32 * c.carryPositions) * |C' + H| < 2 ^ (32 * c.carryPositions) * (Order : ℤ) := by
            rw [← h4]; linarith
          exact lt_of_mul_lt_mul_left h5 hpos.le
      rw [hsplit, hCH, mul_zero]
  have hfin : SFE = R + recompose Kl * c.m := by linarith [hTeq, hT0]
  refine ⟨r, hr, hk'.2, ?_⟩
  apply Int.modEq_iff_dvd.mpr
  by_cases hf : c.fold = true
  · have hcong := folded_congr hbf hb hsf hf
    rw [evalAt_exprInt, ← (hsf.fold hf).1] at hcong
    have hS : SFE ≡ c.exprValue (values es) [ZMOD c.m] := by
      rw [hSFE, (hpf.folded hf).1]; exact hcong
    have hd := Int.modEq_iff_dvd.mp hS
    have : c.exprValue (values es) - R = (c.exprValue (values es) - SFE) + recompose Kl * c.m := by
      rw [hfin]; ring
    rw [this]
    exact dvd_add hd (dvd_mul_left _ _)
  · have hf' : c.fold = false := by simpa using hf
    have hS : SFE = c.exprValue (values es) := by
      rw [hSFE, unfolded_eq hb hsf hf' (hpf.general hf').2.2.2.2.1, evalAt_exprInt]
    have : c.exprValue (values es) - R = recompose Kl * c.m := by rw [← hS, hfin]; ring
    rw [this]
    exact dvd_mul_left _ _


/-! ### Public statements -/

/-- The reduced element whose limbs are `r`, each below `2^w` for its width. -/
def reducedElem (r : List F) (ws : List ℕ) (h : List.Forall₂ (fun (l : F) w => l.val < 2 ^ w) r ws)
    (hlen : ws.length = limbCount) : ElemVal limbCount where
  limbs := ⟨r, h.length_eq.trans hlen⟩
  ints := ⟨r.map fun l => (l.val : ℤ), by simp [h.length_eq, hlen]⟩
  lo := ⟨List.replicate limbCount 0, by simp⟩
  hi := ⟨ws.map fun w => (2 : ℤ) ^ w - 1, by simp [hlen]⟩
  vlo := 0
  vhi := recompose (ws.map fun w => (2 : ℤ) ^ w - 1)
  h_cast := by
    intro i
    simp only [List.Vector.get_eq_get_toList, List.Vector.toList_mk, List.get_eq_getElem, List.getElem_map]
    exact (natCast_val_eq _).symm
  h_lo := by
    intro i
    simp only [List.Vector.get_eq_get_toList, List.Vector.toList_mk, List.get_eq_getElem, List.getElem_map,
      List.getElem_replicate]
    exact Int.natCast_nonneg _
  h_hi := by
    intro i
    simp only [List.Vector.get_eq_get_toList, List.Vector.toList_mk, List.get_eq_getElem, List.getElem_map]
    have := List.forall₂_iff_get.mp h
    exact natCast_lt_two_pow (this.2 i _ _)
  h_vlo := (recompose_bounds h).1
  h_vhi := (recompose_bounds h).2

theorem checkPolynomial_eval_sound (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true) (hres : c.withResult = true)
    {rc : ℕ → F → Prop} (hrc : RangeSound rc)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {k : Option (List F) → Prop} (h : CheckPolynomial.circuit b c (limbLists es) rc k) :
    ∃ r : ElemVal limbCount,
      r.lo.toList = List.replicate limbCount 0 ∧
      r.hi.toList = c.resultWidths.map (fun w => (2 : ℤ) ^ w - 1) ∧
      r.vlo = 0 ∧ r.vhi = recompose (c.resultWidths.map fun w => (2 : ℤ) ^ w - 1) ∧
      k (some r.limbs.toList) ∧
      r.value ≡ c.exprValue (values es) [ZMOD c.m] := by
  obtain ⟨r, hr, hk, hcong⟩ := checkPolynomial_core b c hbs hc hrc es hb h
  simp only [hres, if_true] at hr hk
  exact ⟨reducedElem r c.resultWidths hr (plainFacts hc).rw_len, rfl, rfl, rfl, rfl, hk, hcong⟩

theorem checkPolynomial_assertZero_sound (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true) (hres : c.withResult = false)
    {rc : ℕ → F → Prop} (hrc : RangeSound rc)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {k : Option (List F) → Prop} (h : CheckPolynomial.circuit b c (limbLists es) rc k) :
    k none ∧ c.exprValue (values es) ≡ 0 [ZMOD c.m] := by
  obtain ⟨r, hr, hk, hcong⟩ := checkPolynomial_core b c hbs hc hrc es hb h
  simp only [hres, Bool.false_eq_true, if_false] at hr hk
  cases hr
  exact ⟨hk, by simpa [recompose] using hcong.symm⟩

end ZolanaVE.Field
