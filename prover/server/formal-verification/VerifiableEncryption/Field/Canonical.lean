import VerifiableEncryption.Field.Lazy
import VerifiableEncryption.Circuit.Field
import VerifiableEncryption.Circuit.Field5

/-!
`Field.AssertCanonical` (`emfield/canonical.go`) and `SplitLowBits`
(`emcurve`): a reduced element is below the modulus, and a split returns the
high and low bits of its input.

The P-256 field modulus `p` uses the limbwise lexicographic comparison against
`p - 1`; the group order `n` uses a hinted gap to `n - 1` with one carry
between the two 128-bit halves. Both statements are made directly about the
extracted definitions; the range table is the hypothesis `LookupSound`.
-/

namespace ZolanaVE.Field

def p256P : ℕ := 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff

def p256N : ℕ := 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551

/-- The integer a vector of eight limbs stands for when every limb is a canonical 32-bit value. -/
def limbNat (L : List.Vector F 8) : ℕ := ∑ i : Fin 8, (L.get i).val * 2 ^ (32 * i.val)

/-! ### Lifting native facts to `ℕ` -/

theorem natCast_inj {a b : ℕ} (ha : a < Order) (hb : b < Order) (h : (a : F) = (b : F)) : a = b := by
  have := congrArg ZMod.val h
  rwa [ZMod.val_cast_of_lt ha, ZMod.val_cast_of_lt hb] at this

theorem lt_order_of_le {a : ℕ} (h : a ≤ 2 ^ 253) : a < Order :=
  lt_of_le_of_lt h two_pow_253_lt_order

theorem val_eq_of_eq_natCast {v : F} {a : ℕ} (ha : a < Order) (h : v = (a : F)) : v.val = a := by
  rw [h, ZMod.val_cast_of_lt ha]

theorem eq_natCast_val (v : F) : v = ((v.val : ℕ) : F) := (ZMod.natCast_zmod_val v).symm

theorem val_mem_01 {v : F} (h : v * (v - 1) = 0) : v.val = 0 ∨ v.val = 1 := by
  rcases mul_eq_zero.mp h with h | h
  · left; rw [h, ZMod.val_zero]
  · right
    have : v = 1 := by linear_combination h
    rw [this]; exact ZMod.val_one Order

theorem is_zero_cases {a out : F} (h : GatesDef.is_zero a out) : (a ≠ 0 ∧ out = 0) ∨ (a = 0 ∧ out = 1) := h

/-! ### Limbwise check against `p - 1` -/

theorem assertCanonical_p_sound (L : List.Vector F 8) (hl : ∀ i, (L.get i).val < 2 ^ 32)
    (h : AssertCanonical_8_0_hc36017e9 L) : limbNat L < p256P := by
  unfold AssertCanonical_8_0_hc36017e9 at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
    GatesDef.eq, exists_eq_left] at h
  obtain ⟨g2, hz2, h6, h5, g17, hz17, g20, hz20, hfin, -⟩ := h
  have hv : ∀ i, L.get i = (((L.get i).val : ℕ) : F) := fun i => eq_natCast_val _
  have hlit : ((4294967295 : ℕ) : F) = (4294967295 : F) := by norm_num
  have hmax : ∀ i, (4294967295 : F) - L.get i = 0 ↔ (L.get i).val = 4294967295 := by
    intro i
    rw [sub_eq_zero]
    constructor
    · intro h'
      rw [← h', ← hlit]
      exact ZMod.val_cast_of_lt (lt_order_of_le (by norm_num))
    · intro h'
      have : L.get i = ((4294967295 : ℕ) : F) := by rw [← h']; exact (ZMod.natCast_zmod_val _).symm
      rw [this, hlit]
  set v0 := (L.get 0).val
  set v1 := (L.get 1).val
  set v2 := (L.get 2).val
  set v3 := (L.get 3).val
  set v4 := (L.get 4).val
  set v5 := (L.get 5).val
  set v6 := (L.get 6).val
  set v7 := (L.get 7).val
  have b0 := hl 0; have b1 := hl 1; have b2 := hl 2; have b3 := hl 3
  have b4 := hl 4; have b5 := hl 5; have b6 := hl 6; have b7 := hl 7
  have f1 : v7 = 4294967295 → g2 = 1 := by
    intro h7
    rcases is_zero_cases hz2 with ⟨ha, _⟩ | ⟨_, hg⟩
    · exact absurd (by rw [zero_add]; exact (hmax 7).mpr h7) ha
    · exact hg
  have f2 : v7 = 4294967295 → v6 = 0 ∨ v6 = 1 := by
    intro h7
    apply val_mem_01
    have := h6; rw [f1 h7] at this; simpa using this
  have f3 : v7 = 4294967295 → v6 = 1 → v5 = 0 ∧ v4 = 0 ∧ v3 = 0 := by
    intro h7 h6'
    have hL6 : L.get 6 = 1 := by rw [hv 6, show (L.get 6).val = 1 from h6']; simp
    have hs : ((v5 + v4 + v3 : ℕ) : F) = 0 := by
      have := h5; rw [f1 h7, hL6] at this
      push_cast; rw [← hv 5, ← hv 4, ← hv 3]; simpa using this
    have := natCast_inj (a := v5 + v4 + v3) (b := 0) (lt_order_of_le (by omega)) (lt_order_of_le (by norm_num))
      (by simpa using hs)
    omega
  have f4 : v7 = 4294967295 → v6 = 1 → v2 = 4294967295 → v1 = 4294967295 → v0 ≠ 4294967295 := by
    intro h7 h6' h2' h1' h0'
    have hL6 : L.get 6 = 1 := by rw [hv 6, show (L.get 6).val = 1 from h6']; simp
    have hg17 : g17 = 1 := by
      rcases is_zero_cases hz17 with ⟨ha, _⟩ | ⟨_, hg⟩
      · exact absurd (by rw [(hmax 2).mpr h2', (hmax 1).mpr h1']; simp) ha
      · exact hg
    have hg20 : g20 = 1 := by
      rcases is_zero_cases hz20 with ⟨ha, _⟩ | ⟨_, hg⟩
      · exact absurd ((hmax 0).mpr h0') ha
      · exact hg
    rw [f1 h7, hL6, hg17, hg20] at hfin
    simp at hfin
  unfold limbNat p256P
  simp only [Fin.sum_univ_eight, Fin.val_zero, Fin.val_one, Fin.val_two]
  show v0 * 2 ^ (32 * 0) + v1 * 2 ^ (32 * 1) + v2 * 2 ^ (32 * 2) + v3 * 2 ^ (32 * 3) + v4 * 2 ^ (32 * 4) +
    v5 * 2 ^ (32 * 5) + v6 * 2 ^ (32 * 6) + v7 * 2 ^ (32 * 7) < _
  norm_num
  omega

/-! ### Gap check against `n - 1` -/

theorem assertCanonical_n_sound (hl : LookupSound RangeCheck 11) (L : List.Vector F 8)
    (hlv : ∀ i, (L.get i).val < 2 ^ 32) (h : AssertCanonical_8_1_hc36017e9 L) : limbNat L < p256N := by
  unfold AssertCanonical_8_1_hc36017e9 at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
    GatesDef.eq, exists_eq_left] at h
  obtain ⟨g, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, r13, r14, r15, r16, r17, r18, r19, r20, r21, r22, r23, hc, hlo, hhi, -⟩ := h
  have hp0 : (g.get 0).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r0
  have hp1 : (g.get 1).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r1
  have hp2 : (g.get 2).val < 2 ^ 10 := hl _ _ (by norm_num) (by norm_num) r2
  have hp3 : (g.get 3).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r3
  have hp4 : (g.get 4).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r4
  have hp5 : (g.get 5).val < 2 ^ 10 := hl _ _ (by norm_num) (by norm_num) r5
  have hp6 : (g.get 6).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r6
  have hp7 : (g.get 7).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r7
  have hp8 : (g.get 8).val < 2 ^ 10 := hl _ _ (by norm_num) (by norm_num) r8
  have hp9 : (g.get 9).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r9
  have hp10 : (g.get 10).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r10
  have hp11 : (g.get 11).val < 2 ^ 10 := hl _ _ (by norm_num) (by norm_num) r11
  have hp12 : (g.get 12).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r12
  have hp13 : (g.get 13).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r13
  have hp14 : (g.get 14).val < 2 ^ 10 := hl _ _ (by norm_num) (by norm_num) r14
  have hp15 : (g.get 15).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r15
  have hp16 : (g.get 16).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r16
  have hp17 : (g.get 17).val < 2 ^ 10 := hl _ _ (by norm_num) (by norm_num) r17
  have hp18 : (g.get 18).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r18
  have hp19 : (g.get 19).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r19
  have hp20 : (g.get 20).val < 2 ^ 10 := hl _ _ (by norm_num) (by norm_num) r20
  have hp21 : (g.get 21).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r21
  have hp22 : (g.get 22).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) r22
  have hp23 : (g.get 23).val < 2 ^ 10 := hl _ _ (by norm_num) (by norm_num) r23
  have hc' : (g.get 24).val = 0 ∨ (g.get 24).val = 1 := by
    apply val_mem_01; unfold GatesDef.is_bool at hc; linear_combination -hc
  have b0 := hlv 0
  have b1 := hlv 1
  have b2 := hlv 2
  have b3 := hlv 3
  have b4 := hlv 4
  have b5 := hlv 5
  have b6 := hlv 6
  have b7 := hlv 7
  simp only [K_390, K_391, K_392, K_1233, K_1234] at hlo hhi
  set n0 := (g.get 0).val
  set n1 := (g.get 1).val
  set n2 := (g.get 2).val
  set n3 := (g.get 3).val
  set n4 := (g.get 4).val
  set n5 := (g.get 5).val
  set n6 := (g.get 6).val
  set n7 := (g.get 7).val
  set n8 := (g.get 8).val
  set n9 := (g.get 9).val
  set n10 := (g.get 10).val
  set n11 := (g.get 11).val
  set n12 := (g.get 12).val
  set n13 := (g.get 13).val
  set n14 := (g.get 14).val
  set n15 := (g.get 15).val
  set n16 := (g.get 16).val
  set n17 := (g.get 17).val
  set n18 := (g.get 18).val
  set n19 := (g.get 19).val
  set n20 := (g.get 20).val
  set n21 := (g.get 21).val
  set n22 := (g.get 22).val
  set n23 := (g.get 23).val
  set n24 := (g.get 24).val
  set v0 := (L.get 0).val
  set v1 := (L.get 1).val
  set v2 := (L.get 2).val
  set v3 := (L.get 3).val
  set v4 := (L.get 4).val
  set v5 := (L.get 5).val
  set v6 := (L.get 6).val
  set v7 := (L.get 7).val
  have hlo' : (((v0 + (n0 + 2048 * n1 + 4194304 * n2)) + (v1 + (n3 + 2048 * n4 + 4194304 * n5)) * 4294967296 + (v2 + (n6 + 2048 * n7 + 4194304 * n8)) * 18446744073709551616 + (v3 + (n9 + 2048 * n10 + 4194304 * n11)) * 79228162514264337593543950336 : ℕ) : F) = ((251094175845612772866266697226726352208 + n24 * 340282366920938463463374607431768211456 : ℕ) : F) := by
    push_cast; simp only [n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, n24, v0, v1, v2, v3, ZMod.natCast_zmod_val]
    linear_combination hlo
  have hhi' : (((v4 + (n12 + 2048 * n13 + 4194304 * n14)) + (v5 + (n15 + 2048 * n16 + 4194304 * n17)) * 4294967296 + (v6 + (n18 + 2048 * n19 + 4194304 * n20)) * 18446744073709551616 + (v7 + (n21 + 2048 * n22 + 4194304 * n23)) * 79228162514264337593543950336 + n24 : ℕ) : F) = ((340282366841710300967557013911933812735 : ℕ) : F) := by
    push_cast; simp only [n12, n13, n14, n15, n16, n17, n18, n19, n20, n21, n22, n23, n24, v4, v5, v6, v7,
      ZMod.natCast_zmod_val]
    linear_combination hhi
  have elo := natCast_inj (lt_order_of_le (by omega)) (lt_order_of_le (by omega)) hlo'
  have ehi := natCast_inj (lt_order_of_le (by omega)) (lt_order_of_le (by norm_num)) hhi'
  unfold limbNat p256N
  simp only [Fin.sum_univ_eight, Fin.val_zero, Fin.val_one, Fin.val_two]
  show v0 * 2 ^ (32 * 0) + v1 * 2 ^ (32 * 1) + v2 * 2 ^ (32 * 2) + v3 * 2 ^ (32 * 3) + v4 * 2 ^ (32 * 4) +
    v5 * 2 ^ (32 * 5) + v6 * 2 ^ (32 * 6) + v7 * 2 ^ (32 * 7) < _
  norm_num
  omega

/-! ### Low-bit splits -/

theorem splitLowBits_1_8_sound (hl : LookupSound RangeCheck 11) {V : F} {k : List.Vector F 2 → Prop}
    (h : SplitLowBits_1_8_h2c1d332a V k) :
    ∃ out : List.Vector F 2, k out ∧ V.val < 2 ^ 8 ∧ (out.get 0).val = V.val / 2 ^ 1 ∧
      (out.get 1).val = V.val % 2 ^ 1 := by
  unfold SplitLowBits_1_8_h2c1d332a at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.eq,
    exists_eq_left] at h
  obtain ⟨g, rhi, rlo, ev, hk⟩ := h
  have bhi : (g.get 0).val < 2 ^ 7 := hl _ _ (by norm_num) (by norm_num) rhi
  have blo : (g.get 1).val = 0 ∨ (g.get 1).val = 1 := by
    apply val_mem_01; unfold GatesDef.is_bool at rlo; linear_combination -rlo
  have vv : V.val = (g.get 0).val * 2 + (g.get 1).val := by
    apply val_eq_of_eq_natCast (lt_order_of_le (by omega))
    rw [ev]; push_cast; simp only [ZMod.natCast_zmod_val]
  refine ⟨g, hk, ?_, ?_, ?_⟩ <;> omega

theorem splitLowBits_1_32_sound (hl : LookupSound RangeCheck 11) {V : F} {k : List.Vector F 2 → Prop}
    (h : SplitLowBits_1_32_h2c1d332a V k) :
    ∃ out : List.Vector F 2, k out ∧ V.val < 2 ^ 32 ∧ (out.get 0).val = V.val / 2 ^ 1 ∧
      (out.get 1).val = V.val % 2 ^ 1 := by
  unfold SplitLowBits_1_32_h2c1d332a at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.eq,
    exists_eq_left] at h
  obtain ⟨g, ph, rh0, rh1, rh2, ehi, rlo, ev, hk⟩ := h
  have bh0 : (ph.get 0).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) rh0
  have bh1 : (ph.get 1).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) rh1
  have bh2 : (ph.get 2).val < 2 ^ 9 := hl _ _ (by norm_num) (by norm_num) rh2
  have blo : (g.get 1).val = 0 ∨ (g.get 1).val = 1 := by
    apply val_mem_01; unfold GatesDef.is_bool at rlo; linear_combination -rlo
  have vhi : (g.get 0).val = (ph.get 0).val * 1 + (ph.get 1).val * 2048 + (ph.get 2).val * 4194304 := by
    apply val_eq_of_eq_natCast (lt_order_of_le (by omega))
    rw [ehi]; push_cast; simp only [ZMod.natCast_zmod_val]; ring
  have vv : V.val = (g.get 0).val * 2 + (g.get 1).val := by
    apply val_eq_of_eq_natCast (lt_order_of_le (by omega))
    rw [ev]; push_cast; simp only [ZMod.natCast_zmod_val]
  refine ⟨g, hk, ?_, ?_, ?_⟩ <;> omega

theorem splitLowBits_16_32_sound (hl : LookupSound RangeCheck 11) {V : F} {k : List.Vector F 2 → Prop}
    (h : SplitLowBits_16_32_h2c1d332a V k) :
    ∃ out : List.Vector F 2, k out ∧ V.val < 2 ^ 32 ∧ (out.get 0).val = V.val / 2 ^ 16 ∧
      (out.get 1).val = V.val % 2 ^ 16 := by
  unfold SplitLowBits_16_32_h2c1d332a at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.eq,
    exists_eq_left] at h
  obtain ⟨g, ph, rh0, rh1, ehi, pl, rl0, rl1, elo, ev, hk⟩ := h
  have bh0 : (ph.get 0).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) rh0
  have bh1 : (ph.get 1).val < 2 ^ 5 := hl _ _ (by norm_num) (by norm_num) rh1
  have bl0 : (pl.get 0).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) rl0
  have bl1 : (pl.get 1).val < 2 ^ 5 := hl _ _ (by norm_num) (by norm_num) rl1
  have vhi : (g.get 0).val = (ph.get 0).val * 1 + (ph.get 1).val * 2048 := by
    apply val_eq_of_eq_natCast (lt_order_of_le (by omega))
    rw [ehi]; push_cast; simp only [ZMod.natCast_zmod_val]; ring
  have vlo : (g.get 1).val = (pl.get 0).val * 1 + (pl.get 1).val * 2048 := by
    apply val_eq_of_eq_natCast (lt_order_of_le (by omega))
    rw [elo]; push_cast; simp only [ZMod.natCast_zmod_val]; ring
  have vv : V.val = (g.get 0).val * 65536 + (g.get 1).val := by
    apply val_eq_of_eq_natCast (lt_order_of_le (by omega))
    rw [ev]; push_cast; simp only [ZMod.natCast_zmod_val]
  refine ⟨g, hk, ?_, ?_, ?_⟩ <;> omega

theorem splitLowBits_8_32_sound (hl : LookupSound RangeCheck 11) {V : F} {k : List.Vector F 2 → Prop}
    (h : SplitLowBits_8_32_h2c1d332a V k) :
    ∃ out : List.Vector F 2, k out ∧ V.val < 2 ^ 32 ∧ (out.get 0).val = V.val / 2 ^ 8 ∧
      (out.get 1).val = V.val % 2 ^ 8 := by
  unfold SplitLowBits_8_32_h2c1d332a at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.eq,
    exists_eq_left] at h
  obtain ⟨g, ph, rh0, rh1, rh2, ehi, rlo, ev, hk⟩ := h
  have bh0 : (ph.get 0).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) rh0
  have bh1 : (ph.get 1).val < 2 ^ 11 := hl _ _ (by norm_num) (by norm_num) rh1
  have bh2 : (ph.get 2).val < 2 ^ 2 := hl _ _ (by norm_num) (by norm_num) rh2
  have blo : (g.get 1).val < 2 ^ 8 := hl _ _ (by norm_num) (by norm_num) rlo
  have vhi : (g.get 0).val = (ph.get 0).val * 1 + (ph.get 1).val * 2048 + (ph.get 2).val * 4194304 := by
    apply val_eq_of_eq_natCast (lt_order_of_le (by omega))
    rw [ehi]; push_cast; simp only [ZMod.natCast_zmod_val]; ring
  have vv : V.val = (g.get 0).val * 256 + (g.get 1).val := by
    apply val_eq_of_eq_natCast (lt_order_of_le (by omega))
    rw [ev]; push_cast; simp only [ZMod.natCast_zmod_val]
  refine ⟨g, hk, ?_, ?_, ?_⟩ <;> omega

/-! ### Reduced elements -/

theorem ElemVal.reduced_limbs (e : ElemVal 8) (hred : ∀ i, e.lo.get i = 0 ∧ e.hi.get i = 2 ^ 32 - 1) :
    (∀ i, (e.limbs.get i).val < 2 ^ 32) ∧ (limbNat e.limbs : ℤ) = e.value := by
  have hval : ∀ i, ((e.limbs.get i).val : ℤ) = e.ints.get i := by
    intro i
    have h0 := (hred i).1 ▸ e.h_lo i
    have h1 := (hred i).2 ▸ e.h_hi i
    rw [e.h_cast i]
    have hn : (e.ints.get i).toNat < Order := lt_order_of_le (by omega)
    have : ((e.ints.get i : ℤ) : F) = (((e.ints.get i).toNat : ℕ) : F) := by
      rw [← Int.cast_natCast, Int.toNat_of_nonneg h0]
    rw [this, ZMod.val_cast_of_lt hn, Int.toNat_of_nonneg h0]
  refine ⟨fun i => ?_, ?_⟩
  · have h1 := (hred i).2 ▸ e.h_hi i
    have := hval i
    omega
  · unfold limbNat ElemVal.value recompose
    push_cast
    simp only [hval]
    rw [evalAt, lin_eq_sum, e.ints.toList_length, ← Fin.sum_univ_eq_sum_range]
    apply Finset.sum_congr rfl; intro i _
    rw [List.getD_eq_getElem _ _ (by simp), List.Vector.get_eq_get_toList]
    simp [limbBase, pow_mul, mul_comm]
    left; rw [← pow_mul, show (4294967296 : ℤ) = 2 ^ 32 by norm_num, ← pow_mul, mul_comm]

theorem canonical_limbwise_p_sound (e : ElemVal 8) (hred : ∀ i, e.lo.get i = 0 ∧ e.hi.get i = 2 ^ 32 - 1)
    (h : AssertCanonical_8_0_hc36017e9 e.limbs) : 0 ≤ e.value ∧ e.value < p256P := by
  obtain ⟨hl, heq⟩ := e.reduced_limbs hred
  have := assertCanonical_p_sound e.limbs hl h
  rw [← heq]; exact ⟨Int.natCast_nonneg _, by exact_mod_cast this⟩

theorem canonical_gap_n_sound (hl : LookupSound RangeCheck 11) (e : ElemVal 8)
    (hred : ∀ i, e.lo.get i = 0 ∧ e.hi.get i = 2 ^ 32 - 1)
    (h : AssertCanonical_8_1_hc36017e9 e.limbs) : 0 ≤ e.value ∧ e.value < p256N := by
  obtain ⟨hlv, heq⟩ := e.reduced_limbs hred
  have := assertCanonical_n_sound hl e.limbs hlv h
  rw [← heq]; exact ⟨Int.natCast_nonneg _, by exact_mod_cast this⟩

end ZolanaVE.Field
