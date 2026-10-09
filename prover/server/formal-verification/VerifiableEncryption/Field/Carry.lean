import VerifiableEncryption.Field.Expr

/-!
Lifting native equations to integers, and the bounded carry chain of
`checkPolynomial` step 7.
-/

namespace ZolanaVE.Field

open PlainCheckParams (carryIn)

theorem order_odd_prime : Nat.Prime Order := Fact.out

/-- Two integers with equal casts and distance below the native modulus are equal. -/
theorem int_eq_of_cast_eq {x y : ℤ} (h : (x : F) = (y : F)) (hb : |x - y| < (Order : ℤ)) : x = y := by
  have hd : (Order : ℤ) ∣ x - y := by
    rw [← ZMod.intCast_zmod_eq_zero_iff_dvd, Int.cast_sub, h, sub_self]
  have := Int.eq_zero_of_abs_lt_dvd hd hb
  linarith

theorem int_eq_zero_of_cast {x : ℤ} (h : (x : F) = 0) (hb : |x| < (Order : ℤ)) : x = 0 := by
  have := int_eq_of_cast_eq (y := 0) (by simpa using h) (by simpa using hb)
  exact this

theorem natCast_val_eq (v : F) : (((v.val : ℕ) : ℤ) : F) = v := by
  rw [Int.cast_natCast, ZMod.natCast_zmod_val]

/-- A value range checked to `bits` and shifted down by `shift` lifts to an integer in `[-shift, 2^bits - shift)`. -/
theorem shifted_lift {rc : ℕ → F → Prop} (hrc : RangeSound rc) {bits : ℕ} (hbits : bits ≤ 253)
    {v : F} {shift : ℕ} (h : rc bits (v + (shift : F))) :
    ∃ z : ℤ, (z : F) = v ∧ -(shift : ℤ) ≤ z ∧ z ≤ 2 ^ bits - 1 - shift := by
  have hv := hrc bits _ hbits h
  refine ⟨((v + (shift : F)).val : ℤ) - shift, ?_, ?_, ?_⟩
  · push_cast; rw [ZMod.natCast_zmod_val]; ring
  · have : (0 : ℤ) ≤ ((v + (shift : F)).val : ℤ) := Int.natCast_nonneg _
    linarith
  · have : ((v + (shift : F)).val : ℤ) < 2 ^ bits := by exact_mod_cast hv
    linarith

theorem abs_le_shiftedBound {z : ℤ} {offset bits : ℕ} (h1 : -(offset : ℤ) ≤ z)
    (h2 : z ≤ 2 ^ bits - 1 - offset) : |z| ≤ PlainCheckParams.shiftedBound offset bits := by
  unfold PlainCheckParams.shiftedBound
  rw [abs_le]
  constructor
  · have := le_max_left (offset : ℤ) (2 ^ bits - 1 - offset); linarith
  · exact h2.trans (le_max_right _ _)

theorem carryIn_nonneg (p : Option ℕ) : 0 ≤ carryIn p := by
  cases p with
  | none => simp [carryIn]
  | some cb => simp only [carryIn]; positivity

section Chain

variable (c : PlainCheckParams) (b : BasisParams)

theorem sumRange_split {R : Type*} [AddCommMonoid R] (f : ℕ → R) (a l : ℕ) :
    sumRange (a + l) f = sumRange a f + sumRange l (fun t => f (a + t)) := by
  simp only [sumRange_eq, Finset.sum_range_add]

theorem carryChain_sound {rc : ℕ → F → Prop} (hrc : RangeSound rc) {res : ℕ → F} {Res : ℕ → ℤ}
    (hres : ∀ p, (Res p : F) = res p) (hbound : ∀ p, |Res p| ≤ c.residualBound b p) :
    ∀ (gs : List CarryGroup) (pos : ℕ) (prev : Option ℕ) (final : Option ℕ) (C : ℤ) (k : F → Prop),
      c.groupsSound b gs pos prev = some final →
      |C| ≤ carryIn prev →
      sumRange pos (fun p => Res p * 2 ^ (32 * p)) = C * 2 ^ (32 * pos) →
      carryChain res rc gs (C : F) k →
      ∃ C' : ℤ, k (C' : F) ∧ |C'| ≤ carryIn final ∧
        sumRange c.carryPositions (fun p => Res p * 2 ^ (32 * p)) = C' * 2 ^ (32 * c.carryPositions)
  | [], pos, prev, final, C, k, hg, hC, hsum, hk => by
    simp only [PlainCheckParams.groupsSound] at hg
    split_ifs at hg with hp
    simp only [Option.some.injEq] at hg
    subst hp hg
    exact ⟨C, hk, hC, hsum⟩
  | g :: gs, pos, prev, final, C, k, hg, hC, hsum, hk => by
    simp only [PlainCheckParams.groupsSound] at hg
    split_ifs at hg with hcond
    obtain ⟨hstart, hlt, hcb, hinv, hlift⟩ := hcond
    simp only [carryChain] at hk
    obtain ⟨hrange, hk⟩ := hk
    set len := g.stop - g.start
    set G : ℤ := sumRange len (fun t => Res (g.start + t) * 2 ^ (32 * t)) + C
    set c' : F := (sumRange len (fun t => res (g.start + t) * pow32 t) + (C : F)) * (g.inv : F)
    obtain ⟨C', hC'F, hC'lo, hC'hi⟩ := shifted_lift hrc hcb (v := c') (shift := 2 ^ g.carryBits)
      (by simpa using hrange)
    have hGF : (G : F) = sumRange len (fun t => res (g.start + t) * pow32 t) + (C : F) := by
      simp only [G, Int.cast_add, intCast_sumRange, Int.cast_mul, hres, Int.cast_pow, Int.cast_ofNat, pow32]
    have hinvF : ((2 : F) ^ (32 * len)) * (g.inv : F) = 1 := by
      have : (((2 ^ (32 * len) * g.inv : ℕ)) : F) = 1 := by
        rw [← ZMod.natCast_mod, hinv, Nat.cast_one]
      simpa using this
    have hmulF : ((C' * 2 ^ (32 * len) : ℤ) : F) = (G : F) := by
      rw [Int.cast_mul, hC'F, hGF]
      push_cast
      calc (sumRange len (fun t => res (g.start + t) * pow32 t) + (C : F)) * (g.inv : F) * 2 ^ (32 * len)
          = (sumRange len (fun t => res (g.start + t) * pow32 t) + (C : F)) * ((2 : F) ^ (32 * len) * (g.inv : F)) := by ring
        _ = _ := by rw [hinvF, mul_one]
    have hGb : |G| ≤ carryIn prev + sumRange len (fun t => c.residualBound b (g.start + t) * 2 ^ (32 * t)) := by
      simp only [G]
      rw [add_comm]
      refine (abs_add _ _).trans (add_le_add hC ?_)
      rw [sumRange_eq, sumRange_eq]
      refine (Finset.abs_sum_le_sum_abs _ _).trans (Finset.sum_le_sum fun t _ => ?_)
      rw [abs_mul, abs_of_pos (by positivity : (0 : ℤ) < 2 ^ (32 * t))]
      exact mul_le_mul_of_nonneg_right (hbound _) (by positivity)
    have hC'abs : |C'| ≤ 2 ^ g.carryBits := by
      have hp : (2 : ℤ) ^ (g.carryBits + 1) = 2 * 2 ^ g.carryBits := by ring
      push_cast at hC'lo hC'hi
      rw [abs_le]; constructor <;> linarith
    have hCeq : C' * 2 ^ (32 * len) = G := by
      apply int_eq_of_cast_eq hmulF
      have h1 : |C' * 2 ^ (32 * len)| ≤ 2 ^ (32 * len + g.carryBits) := by
        rw [abs_mul, abs_of_pos (by positivity : (0 : ℤ) < 2 ^ (32 * len)), pow_add]
        rw [mul_comm]; exact mul_le_mul_of_nonneg_left hC'abs (by positivity)
      calc |C' * 2 ^ (32 * len) - G| ≤ |C' * 2 ^ (32 * len)| + |G| := abs_sub _ _
        _ < (Order : ℤ) := by linarith
    have hsum' : sumRange g.stop (fun p => Res p * 2 ^ (32 * p)) = C' * 2 ^ (32 * g.stop) := by
      have hstop : g.stop = pos + len := by omega
      rw [hstop, sumRange_split, hsum, ← hstart]
      have : sumRange len (fun t => Res (g.start + t) * 2 ^ (32 * (g.start + t))) =
          2 ^ (32 * g.start) * sumRange len (fun t => Res (g.start + t) * 2 ^ (32 * t)) := by
        rw [sumRange_mul_left]; congr 1; funext t; rw [mul_add, pow_add]; ring
      rw [this, ← hstart] at *
      have hG : sumRange len (fun t => Res (g.start + t) * 2 ^ (32 * t)) = G - C := by simp [G]
      rw [hG, ← hCeq, mul_add, pow_add]; ring
    have hC'in : |C'| ≤ carryIn (some g.carryBits) := by simpa [carryIn] using hC'abs
    exact carryChain_sound hrc hres hbound gs g.stop (some g.carryBits) final C' k hg hC'in hsum'
      (by rw [hC'F]; exact hk)

end Chain

end ZolanaVE.Field
