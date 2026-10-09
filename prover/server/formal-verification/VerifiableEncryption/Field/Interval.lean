import VerifiableEncryption.Field.Poly

/-!
Interval arithmetic of `emfield/bounds.go` (`intervalMul`, `termRange`) and
`arithmetic.go` (`polyMulInterval`), with soundness lemmas.
-/

namespace ZolanaVE.Field

def intervalMul (a b c d : ℤ) : ℤ × ℤ :=
  (min (min (a * c) (a * d)) (min (b * c) (b * d)),
   max (max (a * c) (a * d)) (max (b * c) (b * d)))

theorem mul_between {s u v t : ℤ} (hu : u ≤ t) (hv : t ≤ v) :
    min (s * u) (s * v) ≤ s * t ∧ s * t ≤ max (s * u) (s * v) := by
  rcases le_total 0 s with hs | hs
  · exact ⟨(min_le_left _ _).trans (mul_le_mul_of_nonneg_left hu hs),
      (mul_le_mul_of_nonneg_left hv hs).trans (le_max_right _ _)⟩
  · exact ⟨(min_le_right _ _).trans (mul_le_mul_of_nonpos_left hv hs),
      (mul_le_mul_of_nonpos_left hu hs).trans (le_max_left _ _)⟩

theorem intervalMul_sound {a b c d x y : ℤ} (ha : a ≤ x) (hb : x ≤ b) (hc : c ≤ y) (hd : y ≤ d) :
    (intervalMul a b c d).1 ≤ x * y ∧ x * y ≤ (intervalMul a b c d).2 := by
  obtain ⟨h1, h2⟩ := mul_between (s := y) ha hb
  obtain ⟨h3, h4⟩ := mul_between (s := a) hc hd
  obtain ⟨h5, h6⟩ := mul_between (s := b) hc hd
  simp only [intervalMul]
  constructor
  · rw [mul_comm x y]
    refine le_trans ?_ h1
    rw [mul_comm y a, mul_comm y b]
    exact le_min (min_le_left _ _ |>.trans h3) (min_le_right _ _ |>.trans h5)
  · rw [mul_comm x y]
    refine le_trans h2 ?_
    rw [mul_comm y a, mul_comm y b]
    exact max_le (h4.trans (le_max_left _ _)) (h6.trans (le_max_right _ _))

/-- The square case of `termRange`. -/
def squareRange (lo hi : ℤ) : ℤ × ℤ :=
  if 0 ≤ lo then (lo * lo, hi * hi)
  else if hi ≤ 0 then (hi * hi, lo * lo)
  else (0, max |lo| |hi| * max |lo| |hi|)

theorem squareRange_sound {lo hi x : ℤ} (hl : lo ≤ x) (hh : x ≤ hi) :
    (squareRange lo hi).1 ≤ x * x ∧ x * x ≤ (squareRange lo hi).2 := by
  unfold squareRange
  split_ifs with h1 h2
  · dsimp only; exact ⟨by nlinarith, by nlinarith⟩
  · dsimp only; exact ⟨by nlinarith, by nlinarith⟩
  · dsimp only; refine ⟨mul_self_nonneg x, ?_⟩
    have : |x| ≤ max |lo| |hi| := by
      rcases le_total 0 x with hx | hx
      · rw [abs_of_nonneg hx]; exact (le_abs_self hi |>.trans' hh).trans (le_max_right _ _)
      · rw [abs_of_nonpos hx]; exact (neg_le_neg hl |>.trans (neg_le_abs lo)).trans (le_max_left _ _)
    rw [← abs_mul_abs_self x]
    exact mul_le_mul this this (abs_nonneg _) ((abs_nonneg _).trans this)

/-- `termRange`: interval of `coef * ∏ factors` from the whole-value bounds of
the factors. `(vlo, vhi)` per factor index. -/
def termRangeRaw (bounds : ℕ → ℤ × ℤ) : List ℕ → ℤ × ℤ
  | [f, g] =>
    if f = g then squareRange (bounds f).1 (bounds f).2
    else
      let r := intervalMul 1 1 (bounds f).1 (bounds f).2
      intervalMul r.1 r.2 (bounds g).1 (bounds g).2
  | fs => fs.foldl (fun r f => intervalMul r.1 r.2 (bounds f).1 (bounds f).2) (1, 1)

def scaleRange (coef : ℤ) (r : ℤ × ℤ) : ℤ × ℤ :=
  if coef < 0 then (r.2 * coef, r.1 * coef) else (r.1 * coef, r.2 * coef)

def termRange (bounds : ℕ → ℤ × ℤ) (coef : ℤ) (fs : List ℕ) : ℤ × ℤ :=
  scaleRange coef (termRangeRaw bounds fs)

theorem foldl_intervalMul_sound (bounds : ℕ → ℤ × ℤ) (vals : ℕ → ℤ)
    (hv : ∀ f, (bounds f).1 ≤ vals f ∧ vals f ≤ (bounds f).2) :
    ∀ (fs : List ℕ) (r : ℤ × ℤ) (x : ℤ), r.1 ≤ x → x ≤ r.2 →
      (fs.foldl (fun r f => intervalMul r.1 r.2 (bounds f).1 (bounds f).2) r).1 ≤ x * (fs.map vals).prod ∧
      x * (fs.map vals).prod ≤ (fs.foldl (fun r f => intervalMul r.1 r.2 (bounds f).1 (bounds f).2) r).2
  | [], r, x, h1, h2 => by simpa using ⟨h1, h2⟩
  | f :: fs, r, x, h1, h2 => by
    have := intervalMul_sound h1 h2 (hv f).1 (hv f).2
    have := foldl_intervalMul_sound bounds vals hv fs _ (x * vals f) this.1 this.2
    simpa [mul_assoc] using this

theorem termRangeRaw_sound (bounds : ℕ → ℤ × ℤ) (vals : ℕ → ℤ)
    (hv : ∀ f, (bounds f).1 ≤ vals f ∧ vals f ≤ (bounds f).2) (fs : List ℕ) :
    (termRangeRaw bounds fs).1 ≤ (fs.map vals).prod ∧ (fs.map vals).prod ≤ (termRangeRaw bounds fs).2 := by
  have generic := foldl_intervalMul_sound bounds vals hv fs (1, 1) 1 le_rfl le_rfl
  simp only [one_mul] at generic
  match fs with
  | [f, g] =>
    simp only [termRangeRaw]
    split_ifs with hfg
    · subst hfg; simpa using squareRange_sound (hv f).1 (hv f).2
    · simpa using generic
  | [] => simp [termRangeRaw]
  | [f] => simp [termRangeRaw] at generic ⊢; exact generic
  | f :: g :: h :: fs => simpa [termRangeRaw] using generic

theorem scaleRange_sound {coef x : ℤ} {r : ℤ × ℤ} (h1 : r.1 ≤ x) (h2 : x ≤ r.2) :
    (scaleRange coef r).1 ≤ coef * x ∧ coef * x ≤ (scaleRange coef r).2 := by
  unfold scaleRange
  split_ifs with hc
  · dsimp only; constructor <;> nlinarith
  · dsimp only; constructor <;> nlinarith

theorem termRange_sound (bounds : ℕ → ℤ × ℤ) (vals : ℕ → ℤ)
    (hv : ∀ f, (bounds f).1 ≤ vals f ∧ vals f ≤ (bounds f).2) (coef : ℤ) (fs : List ℕ) :
    (termRange bounds coef fs).1 ≤ coef * (fs.map vals).prod ∧
      coef * (fs.map vals).prod ≤ (termRange bounds coef fs).2 := by
  have := termRangeRaw_sound bounds vals hv fs
  exact scaleRange_sound this.1 this.2

/-! ### Coefficient intervals of products (`polyMulInterval`) -/

/-- `InIv lo x hi`: same lengths, `lo ≤ x ≤ hi` position by position. -/
def InIv : List ℤ → List ℤ → List ℤ → Prop
  | [], [], [] => True
  | l :: ls, x :: xs, h :: hs => l ≤ x ∧ x ≤ h ∧ InIv ls xs hs
  | _, _, _ => False

def ivScale (al ah : ℤ) : List ℤ → List ℤ → List ℤ × List ℤ
  | bl :: bls, bh :: bhs =>
    let r := ivScale al ah bls bhs
    let p := intervalMul al ah bl bh
    (p.1 :: r.1, p.2 :: r.2)
  | _, _ => ([], [])

def polyMulIv : List ℤ → List ℤ → List ℤ → List ℤ → List ℤ × List ℤ
  | al :: als, ah :: ahs, bl, bh =>
    let r := polyMulIv als ahs bl bh
    let s := ivScale al ah bl bh
    (polyAdd s.1 (0 :: r.1), polyAdd s.2 (0 :: r.2))
  | _, _, _, _ => ([], [])

theorem InIv.polyAdd {l1 x1 h1 l2 x2 h2 : List ℤ} (a : InIv l1 x1 h1) (b : InIv l2 x2 h2) :
    InIv (polyAdd l1 l2) (polyAdd x1 x2) (polyAdd h1 h2) := by
  induction l1 generalizing x1 h1 l2 x2 h2 with
  | nil =>
    cases x1 <;> cases h1 <;> simp_all [InIv, ZolanaVE.Field.polyAdd]
  | cons l ls ih =>
    cases x1 with
    | nil => simp [InIv] at a
    | cons x xs =>
      cases h1 with
      | nil => simp [InIv] at a
      | cons h hs =>
        cases l2 with
        | nil =>
          cases x2 <;> cases h2 <;> simp_all [InIv, ZolanaVE.Field.polyAdd]
        | cons l' ls' =>
          cases x2 with
          | nil => simp [InIv] at b
          | cons x' xs' =>
            cases h2 with
            | nil => simp [InIv] at b
            | cons h' hs' =>
              simp only [InIv, ZolanaVE.Field.polyAdd] at a b ⊢
              exact ⟨add_le_add a.1 b.1, add_le_add a.2.1 b.2.1, ih a.2.2 b.2.2⟩

theorem InIv.ivScale {al ah x : ℤ} (hx1 : al ≤ x) (hx2 : x ≤ ah) :
    ∀ {bl b bh : List ℤ}, InIv bl b bh →
      InIv (ZolanaVE.Field.ivScale al ah bl bh).1 (polyScale x b) (ZolanaVE.Field.ivScale al ah bl bh).2
  | [], [], [], _ => trivial
  | l :: ls, y :: ys, h :: hs, hb => by
    simp only [InIv] at hb
    have := intervalMul_sound hx1 hx2 hb.1 hb.2.1
    have ih := InIv.ivScale hx1 hx2 hb.2.2
    simp only [ZolanaVE.Field.ivScale, polyScale, List.map_cons, InIv] at ih ⊢
    exact ⟨this.1, this.2, ih⟩
  | [], _ :: _, _, hb => by simp [InIv] at hb
  | [], [], _ :: _, hb => by simp [InIv] at hb
  | _ :: _, [], _, hb => by simp [InIv] at hb
  | _ :: _, _ :: _, [], hb => by simp [InIv] at hb

theorem InIv.polyMul :
    ∀ {al a ah bl b bh : List ℤ}, InIv al a ah → InIv bl b bh →
      InIv (polyMulIv al ah bl bh).1 (ZolanaVE.Field.polyMul a b) (polyMulIv al ah bl bh).2
  | [], [], [], _, _, _, _, _ => trivial
  | l :: ls, x :: xs, h :: hs, _, _, _, ha, hb => by
    simp only [InIv] at ha
    have ih := InIv.polyMul ha.2.2 hb
    simp only [polyMulIv, ZolanaVE.Field.polyMul]
    exact InIv.polyAdd (InIv.ivScale ha.1 ha.2.1 hb) ⟨le_rfl, le_rfl, ih⟩
  | [], _ :: _, _, _, _, _, ha, _ => by simp [InIv] at ha
  | [], [], _ :: _, _, _, _, ha, _ => by simp [InIv] at ha
  | _ :: _, [], _, _, _, _, ha, _ => by simp [InIv] at ha
  | _ :: _, _ :: _, [], _, _, _, ha, _ => by simp [InIv] at ha

end ZolanaVE.Field
