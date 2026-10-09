import VerifiableEncryption.Curve.CompleteAdd

/-!
Byte decoding, bit splitting, curve membership and point compression for
the top-level key-agreement circuits.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

/-! ### Elements from native limbs -/

/-- A reduced element whose limbs are the given native values. -/
def mkElemF (L : List.Vector F 8) (hL : ∀ i, (L.get i).val < 2 ^ 32) : ElemVal 8 where
  limbs := L
  ints := List.Vector.ofFn fun i => ((L.get i).val : ℤ)
  lo := List.Vector.replicate 8 0
  hi := List.Vector.replicate 8 (2 ^ 32 - 1)
  vlo := 0
  vhi := 2 ^ 256 - 1
  h_cast := by intro i; simp [ZMod.natCast_zmod_val]
  h_lo := by intro i; simp only [List.Vector.get_replicate, List.Vector.get_ofFn]; positivity
  h_hi := by intro i; have := hL i; simp only [List.Vector.get_replicate, List.Vector.get_ofFn]; omega
  h_vlo := by
    rw [recompose_vec]
    simp only [rec8, List.Vector.get_ofFn]
    positivity
  h_vhi := by
    rw [recompose_vec]
    simp only [rec8, List.Vector.get_ofFn]
    have h0 := hL 0; have h1 := hL 1; have h2 := hL 2; have h3 := hL 3
    have h4 := hL 4; have h5 := hL 5; have h6 := hL 6; have h7 := hL 7
    omega

theorem mkElemF_bnd (L : List.Vector F 8) (hL : ∀ i, (L.get i).val < 2 ^ 32) :
    (mkElemF L hL).bnd = reducedC := rfl

theorem mkElemF_limbs (L : List.Vector F 8) (hL : ∀ i, (L.get i).val < 2 ^ 32) :
    (mkElemF L hL).limbs = L := rfl

theorem mkElemF_value (L : List.Vector F 8) (hL : ∀ i, (L.get i).val < 2 ^ 32) :
    (mkElemF L hL).value = limbNat L := by
  rw [← (reduced_vals (mkElemF_bnd L hL)).2]
  rfl

/-! ### Bytes -/

/-- The natural number a byte-range-checked native value holds. -/
def byteAt {m : ℕ} (v : List.Vector F m) (i : ℕ) : ℕ := (v.toList.getD i 0).val

/-- Big-endian bytes `v[a], …, v[a + len - 1]`. -/
def bytesBE {m : ℕ} (v : List.Vector F m) (a len : ℕ) : ℕ :=
  ∑ i ∈ Finset.range len, byteAt v (a + i) * 256 ^ (len - 1 - i)

theorem byte_lt (hl : LookupSound RangeCheck 11) {m : ℕ} {v : List.Vector F m} {i : Fin m}
    (h : RangeCheck 8 (v.get i)) : byteAt v i < 256 := by
  have := hl 8 _ (by norm_num) (by norm_num) h
  rw [byteAt, ← vget_getD]
  simpa using this

theorem byte_cast {m : ℕ} (v : List.Vector F m) (i : Fin m) : v.get i = ((byteAt v i : ℕ) : F) := by
  rw [byteAt, ← vget_getD, ZMod.natCast_zmod_val]

/-- The extracted Horner step `acc·256 + b`. -/
theorem horner_cast (acc b : ℕ) :
    Gates.add (Gates.mul ((acc : ℕ) : F) (256 : F)) ((b : ℕ) : F) = ((acc * 256 + b : ℕ) : F) := by
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
  push_cast
  ring

theorem natF_val {a : ℕ} (h : a < 2 ^ 253) : ((a : ℕ) : F).val = a :=
  ZMod.val_cast_of_lt (lt_order_of_le h.le)

theorem get_byteAt {m : ℕ} (v : List.Vector F m) (i : Fin m) : (v.get i).val = byteAt v i := by
  rw [byteAt, vget_getD]

/-- Four bytes folded big-endian by the extracted Horner gates. -/
theorem horner_limb {x0 x1 x2 x3 g1 g2 g3 g4 g5 g6 g7 g8 : F}
    (b0 : x0.val < 256) (b1 : x1.val < 256) (b2 : x2.val < 256) (b3 : x3.val < 256)
    (e1 : g1 = Gates.mul (0 : F) (256 : F)) (e2 : g2 = Gates.add g1 x0) (e3 : g3 = Gates.mul g2 (256 : F))
    (e4 : g4 = Gates.add g3 x1) (e5 : g5 = Gates.mul g4 (256 : F)) (e6 : g6 = Gates.add g5 x2)
    (e7 : g7 = Gates.mul g6 (256 : F)) (e8 : g8 = Gates.add g7 x3) :
    g8.val = x0.val * 256 ^ 3 + x1.val * 256 ^ 2 + x2.val * 256 + x3.val := by
  subst e1 e2 e3 e4 e5 e6 e7 e8
  have e : ((x0.val * 256 ^ 3 + x1.val * 256 ^ 2 + x2.val * 256 + x3.val : ℕ) : F) =
      Gates.add (Gates.mul (Gates.add (Gates.mul (Gates.add (Gates.mul (Gates.add (Gates.mul (0 : F) (256 : F))
        x0) (256 : F)) x1) (256 : F)) x2) (256 : F)) x3 := by
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
    push_cast
    rw [ZMod.natCast_zmod_val, ZMod.natCast_zmod_val, ZMod.natCast_zmod_val, ZMod.natCast_zmod_val]
    ring
  rw [← e, natF_val (by omega)]

/-- `limbNat` of limbs read from 32 big-endian bytes is the bytes' value. -/
theorem limbNat_bytes {m : ℕ} (v : List.Vector F m) (a : ℕ) {L : List.Vector F 8}
    (hv : ∀ l : Fin 8, (L.get l).val = byteAt v (a + 4 * (7 - l.val)) * 256 ^ 3 +
      byteAt v (a + 4 * (7 - l.val) + 1) * 256 ^ 2 + byteAt v (a + 4 * (7 - l.val) + 2) * 256 +
      byteAt v (a + 4 * (7 - l.val) + 3)) :
    limbNat L = bytesBE v a 32 := by
  simp only [limbNat, Fin.sum_univ_eight, hv, bytesBE, Finset.sum_range_succ, Finset.sum_range_zero]
  simp only [Fin.isValue, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero, Nat.reduceSub, Nat.reduceMul,
    Nat.reduceAdd, add_assoc, add_zero, zero_add]
  ring

theorem limbs_bytes_lt {m : ℕ} (v : List.Vector F m) (a : ℕ) {L : List.Vector F 8}
    (hb : ∀ j < 32, byteAt v (a + j) < 256)
    (hv : ∀ l : Fin 8, (L.get l).val = byteAt v (a + 4 * (7 - l.val)) * 256 ^ 3 +
      byteAt v (a + 4 * (7 - l.val) + 1) * 256 ^ 2 + byteAt v (a + 4 * (7 - l.val) + 2) * 256 +
      byteAt v (a + 4 * (7 - l.val) + 3)) :
    ∀ l, (L.get l).val < 2 ^ 32 := by
  intro l
  rw [hv l]
  have hl := l.2
  have h0 := hb (4 * (7 - l.val)) (by omega)
  have h1 := hb (4 * (7 - l.val) + 1) (by omega)
  have h2 := hb (4 * (7 - l.val) + 2) (by omega)
  have h3 := hb (4 * (7 - l.val) + 3) (by omega)
  rw [← add_assoc] at h1 h2 h3
  norm_num
  omega

theorem bytesBE_split16 {m : ℕ} (v : List.Vector F m) (a : ℕ) (h30 : byteAt v (a + 30) < 256)
    (h31 : byteAt v (a + 31) < 256) :
    bytesBE v a 32 / 2 ^ 16 = bytesBE v a 30 ∧ bytesBE v a 32 % 2 ^ 16 = bytesBE v (a + 30) 2 := by
  have e : bytesBE v a 32 = bytesBE v (a + 30) 2 + 2 ^ 16 * bytesBE v a 30 := by
    simp only [bytesBE, Finset.sum_range_succ, Finset.sum_range_zero]
    simp only [Nat.reduceSub, Nat.reduceAdd, add_assoc, add_zero, zero_add]
    ring
  have hlo : bytesBE v (a + 30) 2 < 2 ^ 16 := by
    simp only [bytesBE, Finset.sum_range_succ, Finset.sum_range_zero, add_assoc, Nat.reduceAdd, add_zero,
      zero_add, Nat.reduceSub]
    norm_num
    omega
  rw [e]
  constructor
  · rw [Nat.add_mul_div_left _ _ (by positivity), Nat.div_eq_of_lt hlo, zero_add]
  · rw [Nat.add_mul_mod_self_left, Nat.mod_eq_of_lt hlo]

theorem bytesBE_mod2 {m : ℕ} (v : List.Vector F m) (a : ℕ) : bytesBE v a 32 % 2 = byteAt v (a + 31) % 2 := by
  have e : bytesBE v a 32 = byteAt v (a + 31) + 2 * (128 * bytesBE v a 31) := by
    simp only [bytesBE, Finset.sum_range_succ, Finset.sum_range_zero]
    simp only [Nat.reduceSub, Nat.reduceAdd, add_assoc, add_zero, zero_add]
    ring
  rw [e, Nat.add_mul_mod_self_left]

theorem byteAt_lt_of {m : ℕ} {v : List.Vector F m} (hl : LookupSound RangeCheck 11)
    (h : ∀ i : Fin m, RangeCheck 8 (v.get i)) : ∀ i, byteAt v i < 256 := by
  intro i
  by_cases hi : i < m
  · exact byte_lt hl (i := ⟨i, hi⟩) (h ⟨i, hi⟩)
  · rw [byteAt, List.getD_eq_default _ _ (by simp; omega)]; simp

/-! ### Bit splitting -/

theorem rc_val (hl : LookupSound RangeCheck 11) {b : ℕ} {v : F} (h2 : 2 ≤ b) (h11 : b ≤ 11)
    (h : RangeCheck b v) : v.val < 2 ^ b :=
  hl b v h2 h11 h

/-- `hi·2^w + lo` with both parts bounded is the Euclidean split of the value. -/
theorem split_nat {V hi lo : F} {w u : ℕ} (hhi : hi.val < 2 ^ u) (hlo : lo.val < 2 ^ w) (hb : w + u ≤ 252)
    (h : V = hi * 2 ^ w + lo) : V.val = hi.val * 2 ^ w + lo.val ∧ hi.val = V.val / 2 ^ w ∧ lo.val = V.val % 2 ^ w := by
  have hlt : hi.val * 2 ^ w + lo.val < 2 ^ 253 := by
    have : hi.val * 2 ^ w + lo.val < 2 ^ (w + u) := by
      rw [pow_add]
      calc hi.val * 2 ^ w + lo.val < hi.val * 2 ^ w + 2 ^ w := by omega
        _ = (hi.val + 1) * 2 ^ w := by ring
        _ ≤ 2 ^ u * 2 ^ w := Nat.mul_le_mul_right _ hhi
        _ = 2 ^ w * 2 ^ u := by ring
    calc hi.val * 2 ^ w + lo.val < 2 ^ (w + u) := this
      _ ≤ 2 ^ 253 := Nat.pow_le_pow_right (by norm_num) (by omega)
  have hV : V = ((hi.val * 2 ^ w + lo.val : ℕ) : F) := by
    rw [h]; push_cast; rw [ZMod.natCast_zmod_val, ZMod.natCast_zmod_val]
  have hv : V.val = hi.val * 2 ^ w + lo.val := by rw [hV, natF_val hlt]
  refine ⟨hv, ?_, ?_⟩
  · rw [hv, Nat.add_comm, Nat.add_mul_div_right _ _ (by positivity), Nat.div_eq_of_lt hlo, zero_add]
  · rw [hv, Nat.add_comm, Nat.add_mul_mod_self_right, Nat.mod_eq_of_lt hlo]

/-- Three range-checked pieces `p0 + 2^11·p1 + 2^22·p2` with `p2 < 2^b2`. -/
theorem pieces3_val (hl : LookupSound RangeCheck 11) {p0 p1 p2 : F} {b2 : ℕ} (hb2 : 2 ≤ b2) (hb2' : b2 ≤ 11)
    (r0 : RangeCheck 11 p0) (r1 : RangeCheck 11 p1) (r2 : RangeCheck b2 p2) :
    (Gates.add (Gates.add (Gates.add (0 : F) (Gates.mul p0 1)) (Gates.mul p1 2048)) (Gates.mul p2 4194304)).val
      < 2 ^ (22 + b2) := by
  have h0 := rc_val hl (by norm_num) le_rfl r0
  have h1 := rc_val hl (by norm_num) le_rfl r1
  have h2 := rc_val hl hb2 hb2' r2
  have e : Gates.add (Gates.add (Gates.add (0 : F) (Gates.mul p0 1)) (Gates.mul p1 2048)) (Gates.mul p2 4194304) =
      ((p0.val + p1.val * 2048 + p2.val * 4194304 : ℕ) : F) := by
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
    push_cast
    rw [ZMod.natCast_zmod_val, ZMod.natCast_zmod_val, ZMod.natCast_zmod_val]
    ring
  have hb : 2 ^ b2 ≤ 2 ^ 11 := Nat.pow_le_pow_right (by norm_num) hb2'
  rw [e, natF_val (by
    have : p0.val + p1.val * 2048 + p2.val * 4194304 < 2 ^ 33 := by
      have : (2 : ℕ) ^ 11 = 2048 := by norm_num
      omega
    calc _ < 2 ^ 33 := this
      _ ≤ 2 ^ 253 := Nat.pow_le_pow_right (by norm_num) (by norm_num))]
  rw [pow_add]
  have : (2 : ℕ) ^ 22 = 4194304 := by norm_num
  have : (2 : ℕ) ^ 11 = 2048 := by norm_num
  nlinarith

/-- Two range-checked pieces `p0 + 2^11·p1` with `p1 < 2^5`. -/
theorem pieces2_val (hl : LookupSound RangeCheck 11) {p0 p1 : F}
    (r0 : RangeCheck 11 p0) (r1 : RangeCheck 5 p1) :
    (Gates.add (Gates.add (0 : F) (Gates.mul p0 1)) (Gates.mul p1 2048)).val < 2 ^ 16 := by
  have h0 := rc_val hl (by norm_num) le_rfl r0
  have h1 := rc_val hl (by norm_num) (by norm_num) r1
  have e : Gates.add (Gates.add (0 : F) (Gates.mul p0 1)) (Gates.mul p1 2048) =
      ((p0.val + p1.val * 2048 : ℕ) : F) := by
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
    push_cast
    rw [ZMod.natCast_zmod_val, ZMod.natCast_zmod_val]
    ring
  rw [e, natF_val (by omega)]
  omega

theorem split_1_8_sound (hl : LookupSound RangeCheck 11) {V : F} {k : List.Vector F 2 → Prop}
    (h : SplitLowBits_1_8_h2c1d332a V k) :
    ∃ w : List.Vector F 2, (w.get 1).val = V.val % 2 ∧ (w.get 0).val = V.val / 2 ∧ k w := by
  unfold SplitLowBits_1_8_h2c1d332a at h
  obtain ⟨w, r0, b1, g3, e3, g4, e4, hV, hk⟩ := h
  subst e3 e4
  have hs := split_nat (V := V) (hi := w.get 0) (lo := w.get 1) (w := 1) (u := 7)
    (rc_val hl (by norm_num) (by norm_num) r0) (is_bool_val b1) (by norm_num) (by
      simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq, GatesDef.add, GatesDef.mul] at hV
      rw [hV]; ring)
  exact ⟨w, hs.2.2, hs.2.1, hk⟩

theorem split_1_32_sound (hl : LookupSound RangeCheck 11) {V : F} {k : List.Vector F 2 → Prop}
    (h : SplitLowBits_1_32_h2c1d332a V k) :
    ∃ w : List.Vector F 2, (w.get 1).val = V.val % 2 ∧ (w.get 0).val = V.val / 2 ∧ k w := by
  unfold SplitLowBits_1_32_h2c1d332a at h
  obtain ⟨w, ps, r0, g3, e3, g4, e4, r1, g6, e6, g7, e7, r2, g9, e9, g10, e10, hhi, b1, g13, e13, g14, e14,
    hV, hk⟩ := h
  subst e3 e4 e6 e7 e9 e10 e13 e14
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq] at hhi
  have hp := pieces3_val hl (b2 := 9) (by norm_num) (by norm_num) r0 r1 r2
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] at hp
  rw [← hhi] at hp
  have hs := split_nat (V := V) (hi := w.get 0) (lo := w.get 1) (w := 1) (u := 31) hp (is_bool_val b1)
    (by norm_num) (by
      simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq, GatesDef.add, GatesDef.mul] at hV
      rw [hV]; ring)
  exact ⟨w, hs.2.2, hs.2.1, hk⟩

theorem split_8_32_sound (hl : LookupSound RangeCheck 11) {V : F} {k : List.Vector F 2 → Prop}
    (h : SplitLowBits_8_32_h2c1d332a V k) :
    ∃ w : List.Vector F 2, (w.get 1).val = V.val % 2 ^ 8 ∧ (w.get 0).val = V.val / 2 ^ 8 ∧ k w := by
  unfold SplitLowBits_8_32_h2c1d332a at h
  obtain ⟨w, ps, r0, g3, e3, g4, e4, r1, g6, e6, g7, e7, r2, g9, e9, g10, e10, hhi, r8, g13, e13, g14, e14,
    hV, hk⟩ := h
  subst e3 e4 e6 e7 e9 e10 e13 e14
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq] at hhi
  have hp := pieces3_val hl (b2 := 2) (by norm_num) (by norm_num) r0 r1 r2
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] at hp
  rw [← hhi] at hp
  have hs := split_nat (V := V) (hi := w.get 0) (lo := w.get 1) (w := 8) (u := 24) hp
    (rc_val hl (by norm_num) (by norm_num) r8) (by norm_num) (by
      simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq, GatesDef.add, GatesDef.mul] at hV
      rw [hV]; norm_num)
  exact ⟨w, hs.2.2, hs.2.1, hk⟩

theorem split_16_32_sound (hl : LookupSound RangeCheck 11) {V : F} {k : List.Vector F 2 → Prop}
    (h : SplitLowBits_16_32_h2c1d332a V k) :
    ∃ w : List.Vector F 2, (w.get 1).val = V.val % 2 ^ 16 ∧ (w.get 0).val = V.val / 2 ^ 16 ∧ k w := by
  unfold SplitLowBits_16_32_h2c1d332a at h
  obtain ⟨w, ps, r0, g3, e3, g4, e4, r1, g6, e6, g7, e7, hhi, qs, q0, g11, e11, g12, e12, q1, g14, e14, g15, e15,
    hlo, g17, e17, g18, e18, hV, hk⟩ := h
  subst e3 e4 e6 e7 e11 e12 e14 e15 e17 e18
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq] at hhi hlo
  have hp := pieces2_val hl r0 r1
  have hq := pieces2_val hl q0 q1
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] at hp
  rw [← hhi] at hp
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] at hq
  rw [← hlo] at hq
  have hs := split_nat (V := V) (hi := w.get 0) (lo := w.get 1) (w := 16) (u := 16) hp hq (by norm_num) (by
      simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq, GatesDef.add, GatesDef.mul] at hV
      rw [hV]; norm_num)
  exact ⟨w, hs.2.2, hs.2.1, hk⟩

/-! ### Point compression -/

theorem natF_eq (x : F) : x = ((x.val : ℕ) : F) := (ZMod.natCast_zmod_val x).symm

theorem limbNat_split (L : List.Vector F 8) {w : ℕ} (hw : w ≤ 32) :
    limbNat L % 2 ^ w = (L.get 0).val % 2 ^ w ∧
      limbNat L / 2 ^ w = (L.get 0).val / 2 ^ w + (L.get 1).val * 2 ^ (32 - w) + (L.get 2).val * 2 ^ (64 - w) +
        (L.get 3).val * 2 ^ (96 - w) + (L.get 4).val * 2 ^ (128 - w) + (L.get 5).val * 2 ^ (160 - w) +
        (L.get 6).val * 2 ^ (192 - w) + (L.get 7).val * 2 ^ (224 - w) := by
  have hrest : limbNat L = (L.get 0).val + 2 ^ w * ((L.get 1).val * 2 ^ (32 - w) + (L.get 2).val * 2 ^ (64 - w) +
        (L.get 3).val * 2 ^ (96 - w) + (L.get 4).val * 2 ^ (128 - w) + (L.get 5).val * 2 ^ (160 - w) +
        (L.get 6).val * 2 ^ (192 - w) + (L.get 7).val * 2 ^ (224 - w)) := by
    simp only [limbNat, Fin.sum_univ_eight, Fin.isValue, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Fin.val_zero,
      Nat.reduceMul, mul_zero, pow_zero, mul_one]
    have e : ∀ c : ℕ, w ≤ c → 2 ^ w * 2 ^ (c - w) = 2 ^ c := fun c hc => by
      rw [← pow_add, Nat.add_sub_cancel' hc]
    rw [mul_add, mul_add, mul_add, mul_add, mul_add, mul_add, mul_left_comm _ _ (2 ^ (32 - w)),
      mul_left_comm _ _ (2 ^ (64 - w)), mul_left_comm _ _ (2 ^ (96 - w)), mul_left_comm _ _ (2 ^ (128 - w)),
      mul_left_comm _ _ (2 ^ (160 - w)), mul_left_comm _ _ (2 ^ (192 - w)), mul_left_comm _ _ (2 ^ (224 - w)),
      e 32 hw, e 64 (by omega), e 96 (by omega), e 128 (by omega), e 160 (by omega), e 192 (by omega),
      e 224 (by omega)]
    ring
  rw [hrest]
  constructor
  · rw [Nat.add_mul_mod_self_left]
  · rw [Nat.add_mul_div_left _ _ (by positivity)]; ring

theorem K_pows : K_0 = ((2 ^ 240 : ℕ) : F) ∧ K_6277 = ((2 ^ 80 : ℕ) : F) ∧ K_1180 = ((2 ^ 112 : ℕ) : F) ∧
    K_6278 = ((2 ^ 144 : ℕ) : F) ∧ K_6279 = ((2 ^ 176 : ℕ) : F) ∧ K_6280 = ((2 ^ 208 : ℕ) : F) ∧
    K_1 = ((2 ^ 88 : ℕ) : F) ∧ K_2 = ((2 ^ 120 : ℕ) : F) ∧ K_3 = ((2 ^ 152 : ℕ) : F) ∧
    K_4 = ((2 ^ 184 : ℕ) : F) ∧ K_5 = ((2 ^ 216 : ℕ) : F) := by
  decide +kernel

/-- `CompressedPacking`: the SEC1 prefix `2 + (y mod 2)` above `x / 2^16`, and
the low 16 bits of `x`. -/
theorem compressedPacking_sound (hl : LookupSound RangeCheck 11) {X Y : List.Vector F 8}
    {k : List.Vector F 2 → Prop}
    (h : CompressedPacking_8_8_32_h2c1d332a X Y k) :
    k ((((2 + limbNat Y % 2) * 2 ^ 240 + limbNat X / 2 ^ 16 : ℕ) : F) ::ᵥ
      ((limbNat X % 2 ^ 16 : ℕ) : F) ::ᵥ List.Vector.nil) := by
  unfold CompressedPacking_8_8_32_h2c1d332a at h
  obtain ⟨w0, hw01, hw00, h⟩ := split_1_32_sound hl h
  obtain ⟨w1, hw11, hw10, h⟩ := split_16_32_sound hl h
  obtain ⟨g2, e2, g3, e3, g4, e4, g5, e5, g6, e6, g7, e7, g8, e8, g9, e9, g10, e10, g11, e11, g12, e12, g13, e13,
    g14, e14, g15, e15, g16, e16, g17, e17, g18, e18, hk⟩ := h
  subst e2 e3 e4 e5 e6 e7 e8 e9 e10 e11 e12 e13 e14 e15 e16 e17 e18
  obtain ⟨sy, -⟩ := limbNat_split Y (w := 1) (by norm_num)
  rw [pow_one] at sy
  obtain ⟨sx1, sx2⟩ := limbNat_split X (w := 16) (by norm_num)
  obtain ⟨k0, k6277, k1180, k6278, k6279, k6280, -⟩ := K_pows
  convert hk using 3
  · rw [natF_eq (w0.get 1), natF_eq (w1.get 0), natF_eq (X.get 1), natF_eq (X.get 2), natF_eq (X.get 3),
      natF_eq (X.get 4), natF_eq (X.get 5), natF_eq (X.get 6), natF_eq (X.get 7), hw01, hw10, k0, k6277, k1180,
      k6278, k6279, k6280, sx2, ← sy]
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
    push_cast
    norm_num
  · rw [natF_eq (w1.get 1), hw11, sx1]

/-! ### Curve membership -/

theorem assertOnCurve_sound (hl : LookupSound RangeCheck 11) (X Y : ElemVal 8) (hX : X.bnd = reducedC)
    (hY : Y.bnd = reducedC) (h : AssertOnCurve_8_8_habd58e5e X.limbs Y.limbs) :
    OnCurve (X.value : Fp) (Y.value : Fp) := by
  unfold AssertOnCurve_8_8_habd58e5e at h
  obtain ⟨X2, hX2lo, hX2hi, hX2vlo, hX2vhi, h, vX2⟩ :=
    Lazy_8_h2d947ec4_sound [⟨8, X⟩] (elemsMatch_of (by show [X.bnd] = _; rw [hX]; rfl)) _ (by limbs_tac []) h
  have hX2b := lazy_bnd hX2lo hX2hi hX2vlo hX2vhi
  obtain ⟨hoc, -⟩ := h
  have coc := CheckPolynomial_40_h29707435_sound hl
    [⟨8, X2⟩, ⟨8, X⟩, ⟨8, aElem⟩, ⟨8, constElem bLimbs⟩, ⟨8, Y⟩]
    (elemsMatch_of (by
      show [X2.bnd, X.bnd, aElem.bnd, (constElem bLimbs).bnd, Y.bnd] = _
      rw [hX2b, hX, hY]; rfl))
    _ (by limbs_tac [aElem, aLimbs, constElem, bLimbs]) hoc
  have eX2 : lazy_h2d947ec4.exprValue (values [⟨8, X⟩]) = X.value * X.value := by
    simp [PolyShape.exprValue, values, lazy_h2d947ec4]
  have eoc : cert_h29707435.exprValue (values [⟨8, X2⟩, ⟨8, X⟩, ⟨8, aElem⟩, ⟨8, constElem bLimbs⟩, ⟨8, Y⟩]) =
      X2.value * X.value + aElem.value * X.value + (constElem bLimbs).value - Y.value * Y.value := by
    simp [PolyShape.exprValue, values, cert_h29707435]; ring
  have mX2 : (lazy_h2d947ec4.m : ℤ) = p := rfl
  have moc : (cert_h29707435.m : ℤ) = p := rfl
  rw [eX2, mX2, modEq_p_iff] at vX2
  rw [eoc, moc, modEq_p_iff] at coc
  push_cast at vX2 coc
  have va : ((aElem.value : ℤ) : Fp) = -3 := by
    rw [aElem_value]; push_cast; rw [ZMod.natCast_self]; ring
  have vb : ((constElem bLimbs).value : Fp) = ((ZolanaVE.P256.b : ℕ) : Fp) := by
    rw [bConst_value]; push_cast; rfl
  rw [va, vb, vX2] at coc
  unfold OnCurve
  linear_combination -coc

theorem limbNat_eq_zero {L : List.Vector F 8} (h : limbNat L = 0) : ∀ i, L.get i = 0 := by
  intro i
  have := Finset.sum_eq_zero_iff.mp h i (Finset.mem_univ _)
  rcases mul_eq_zero.mp this with h1 | h1
  · exact (ZMod.val_eq_zero _).mp h1
  · exact absurd h1 (by positivity)

end ZolanaVE.P256
