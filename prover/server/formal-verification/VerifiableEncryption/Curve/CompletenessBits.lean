import VerifiableEncryption.Curve.CompletenessComb
import VerifiableEncryption.Curve.CompletenessAffine

/-! Explicit fixed-base parity and 256-bit recoding witnesses. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

def bitInteger : {w : ℕ} → List.Vector Bool w → ℕ
  | 0, _ => 0
  | _ + 1, bs => bs.head.toNat + 2 * bitInteger bs.tail

theorem bitInteger_lt : ∀ {w : ℕ} (bs : List.Vector Bool w), bitInteger bs < 2 ^ w
  | 0, bs => by simp [bitInteger]
  | w + 1, bs => by
    have ht := bitInteger_lt bs.tail
    simp only [Nat.add_sub_cancel] at ht
    have hb : bs.head.toNat ≤ 1 := by cases bs.head <;> decide
    simp only [bitInteger, pow_succ]
    omega

theorem bitInteger_cast {N w : ℕ} (bs : List.Vector Bool w) :
    (bitInteger bs : ZMod N) = recover_binary_zmod' (bs.map (Bool.toZMod (N := N))) := by
  induction w with
  | zero => simp [bitInteger, recover_binary_zmod']
  | succ w ih =>
    cases bs using List.Vector.casesOn with
    | cons b bs =>
      simp [bitInteger, recover_binary_zmod', Bool.toZMod, ih]

theorem bitInteger_ofBitsLE {w : ℕ} (bs : List.Vector Bool w) :
    bitInteger bs = (Fin.ofBitsLE bs).val := by
  have hc : (bitInteger bs : ZMod (2 ^ w + 1)) =
      ((Fin.ofBitsLE bs).val : ZMod (2 ^ w + 1)) := by
    rw [bitInteger_cast, recover_binary_zmod'_map_toZMod_eq_Fin_ofBitsLE]
  have hv := congrArg ZMod.val hc
  rw [ZMod.val_cast_of_lt (by have := bitInteger_lt bs; omega),
    ZMod.val_cast_of_lt (by have := (Fin.ofBitsLE bs).isLt; omega)] at hv
  exact hv

theorem bitInteger_sum {w : ℕ} (bs : List.Vector Bool w) :
    (bitInteger bs : ℤ) = ∑ j ∈ Finset.range w,
      2 ^ j * ((bs.toList.getD j false).toNat : ℤ) := by
  induction w with
  | zero => simp [bitInteger]
  | succ w ih =>
    cases bs using List.Vector.casesOn with
    | cons b bs =>
      rw [Finset.sum_range_succ']
      simp only [bitInteger, List.Vector.head_cons, List.Vector.tail_cons,
        List.Vector.toList_cons, List.getD_cons_zero, List.getD_cons_succ,
        Nat.cast_add, Nat.cast_mul, Nat.cast_ofNat, pow_zero, one_mul, pow_succ]
      rw [ih, Finset.mul_sum, add_comm]
      congr 1
      apply Finset.sum_congr rfl
      intro j hj
      ring

/-- Existing ProvenZk bit encoding gives a witness to the actual
Gates.from_binary predicate, including its bit constraints. -/
theorem fromBinary_complete {w : ℕ} (v : Fin (2 ^ w)) :
    Gates.from_binary ((Fin.toBitsLE v).map (Bool.toZMod (N := Order))) (v.val : F) := by
  change recover_binary_zmod' ((Fin.toBitsLE v).map (Bool.toZMod (N := Order))) =
      (v.val : F) ∧ is_vector_binary ((Fin.toBitsLE v).map (Bool.toZMod (N := Order)))
  constructor
  · rw [recover_binary_zmod'_map_toZMod_eq_Fin_ofBitsLE, Fin.ofBitsLE_toBitsLE_eq_self]
  · exact is_vector_binary_map_toZMod

theorem fromBinary_chunk_complete {n : ℕ} {g : List.Vector F n}
    (hb : AllBits g) {a w : ℕ} (hw : a + w ≤ n) :
    Gates.from_binary (List.Vector.ofFn (fun j : Fin w => g.get ⟨a + j, by omega⟩))
      ((chunk g a w : ℤ) : F) := by
  change recover_binary_zmod' _ = _ ∧ is_vector_binary _
  constructor
  · rw [recover_ofFn, chunk_cast hb hw]
    apply Finset.sum_congr rfl
    intro j _
    rw [vget_getD']
  · intro x hx
    obtain ⟨j, hj⟩ := (List.Vector.mem_iff_get x _).mp hx
    rw [List.Vector.get_ofFn] at hj
    rw [← hj, vget_getD']
    have hp := hb (a + j) (by omega)
    unfold GatesDef.is_bool at hp
    rcases mul_eq_zero.mp hp with h1 | h0
    · right
      linear_combination -h1
    · exact Or.inl h0

def combParity (s : ℕ) : Bool := decide ((s % n) % 2 = 1)

def combRecoded (s : ℕ) : ℕ := (s % n + 2 ^ 256 - (s % n) % 2) / 2

theorem combParity_value (s : ℕ) : (combParity s).toNat = (s % n) % 2 := by
  have hp : (s % n) % 2 = 0 ∨ (s % n) % 2 = 1 := by omega
  rcases hp with hp | hp <;> simp [combParity, hp]

theorem combRecoded_identity (s : ℕ) :
    2 * combRecoded s + (combParity s).toNat = s % n + 2 ^ 256 := by
  rw [combParity_value]
  unfold combRecoded
  norm_num
  omega

theorem combRecoded_lt (s : ℕ) : combRecoded s < 2 ^ 256 := by
  have hs := Nat.mod_lt s (by norm_num [n] : 0 < n)
  have hi := combRecoded_identity s
  have hn : n < 2 ^ 256 := by norm_num [n]
  omega

/-- The hinted vector's actual parity and all 256 recoded bits. This is
explicit mathematical witness construction, separate from Go hint correctness. -/
def combBits (s : ℕ) : List.Vector F 257 :=
  ((combParity s) ::ᵥ Fin.toBitsLE ⟨combRecoded s, combRecoded_lt s⟩).map
    (Bool.toZMod (N := Order))

theorem combBits_boolean (s : ℕ) (i : Fin 257) : GatesDef.is_bool ((combBits s).get i) := by
  have hb : is_vector_binary (combBits s) := is_vector_binary_map_toZMod
  have hi := hb _ (List.Vector.get_mem i _)
  rcases hi with hi | hi <;> simp [GatesDef.is_bool, hi]

theorem combBits_all (s : ℕ) : AllBits (combBits s) := by
  intro j hj
  rw [← vget_getD' _ j hj]
  exact combBits_boolean s ⟨j, hj⟩

theorem combBits_chunk (s : ℕ) : chunk (combBits s) 1 256 = combRecoded s := by
  let bs : List.Vector Bool 256 := Fin.toBitsLE ⟨combRecoded s, combRecoded_lt s⟩
  have hget : ∀ j, bitI (combBits s) (1 + j) = ((bs.toList.getD j false).toNat : ℤ) := by
    intro j
    unfold bitI
    rw [show 1 + j = j + 1 by omega]
    simp only [combBits, List.Vector.toList_map, List.Vector.toList_cons,
      List.map_cons, List.getD_cons_succ]
    change (((bs.toList.map (Bool.toZMod (N := Order))).getD j 0).val : ℤ) = _
    simp only [List.getD_eq_getElem?_getD, List.getElem?_map]
    cases h : bs.toList[j]? with
    | none => simp [h, Bool.toZMod]
    | some b => cases b <;> simp [h, Bool.toZMod, ZMod.val_one]
  unfold chunk
  simp only [hget]
  rw [← bitInteger_sum, bitInteger_ofBitsLE]
  simp [bs]

theorem boolRun_complete (s : ℕ) : ∀ (j m : ℕ) (R : Prop), j + m ≤ 257 → R →
    BoolRun (combBits s) j m R
  | j, 0, R, hbound, hR => hR
  | j, m + 1, R, hbound, hR => by
    have hj : j < 257 := by omega
    simp only [BoolRun, dif_pos hj]
    refine ⟨combBits_boolean s ⟨j, hj⟩, boolRun_complete s (j + 1) m R (by omega) hR⟩

/-- Scalar reduction determines the recoding quotient, so its two-bit range
is derived from the full input width rather than assumed. -/
theorem combRecoded_quotient (s : ℕ) (hs : s < 2 ^ 256) :
    ∃ q : ℤ, (q = 0 ∨ q = 1) ∧
      2 * (combRecoded s : ℤ) + (combParity s).toNat - s - rec8 twoPowLimbs = q * n := by
  refine ⟨1 - ((s / n : ℕ) : ℤ), ?_, ?_⟩
  · have hn : 2 ^ 256 < 2 * n := by norm_num [n]
    have hdiv : s / n = 0 ∨ s / n = 1 := by
      norm_num [n] at hs hn ⊢
      omega
    rcases hdiv with hdiv | hdiv <;> simp [hdiv]
  · have hi := congrArg (fun v : ℕ => (v : ℤ)) (combRecoded_identity s)
    have hsDiv := congrArg (fun v : ℕ => (v : ℤ)) (Nat.mod_add_div s n)
    have hc : rec8 twoPowLimbs = 2 ^ 256 - (n : ℤ) := by
      decide +kernel
    rw [hc]
    push_cast at hi hsDiv ⊢
    linear_combination hi + hsDiv

/-- A real fixed-base arithmetic subgadget witness for every reduced input
scalar, including noncanonical scalars at or above n. No operation-success
premise is added. The bits, recoded limbs, quotient, and carry are constructed. -/
theorem scalarRecoding_complete (hr : RangeComplete) (S : ElemVal 8)
    (hS : S.bnd = reducedC) :
    CheckPolynomial_25_hcd1dd84c
      (recodingInput (rcInts (combBits S.value.toNat)) (fun i => S.ints.get i)
        (combParity S.value.toNat).toNat) := by
  have hbS := S.fits_of_bnd hS
  have hvS : 0 ≤ S.value ∧ S.value ≤ 2 ^ 256 - 1 := by
    simpa [reducedC, uniC] using hbS.2
  have hsCast : ((S.value.toNat : ℕ) : ℤ) = S.value := Int.toNat_of_nonneg hvS.1
  have hsWidth : S.value.toNat < 2 ^ 256 := by omega
  have hbits := combBits_all S.value.toNat
  have hbR := rcInts_fits hbits (le_refl 257)
  obtain ⟨q, hq, hrec⟩ := combRecoded_quotient S.value.toNat hsWidth
  apply recodingCheck_complete hr _ _ _ q
  · have hr := hbR.2.2.1 0
    simp [reducedC, uniC] at hr
    constructor <;> omega
  · have hs := hbS.1 0
    change (0 : ℤ) ≤ S.ints.get 0 ∧ S.ints.get 0 ≤ 2 ^ 32 - 1 at hs
    constructor <;> omega
  · cases combParity S.value.toNat <;> simp
  · exact hq
  · rw [rec8_rcInts, combBits_chunk, ← S.value_eq, ← hsCast]
    exact hrec

theorem combBits_parity (s : ℕ) : bitI (combBits s) 0 = (combParity s).toNat := by
  unfold bitI combBits
  cases combParity s <;> simp [Bool.toZMod, ZMod.val_one]

theorem combBits_recoding (s : ℕ) :
    2 * chunk (combBits s) 1 256 + bitI (combBits s) 0 ≡
      (s : ℤ) + 2 ^ 256 [ZMOD n] := by
  rw [combBits_chunk, combBits_parity]
  have hi := congrArg (fun v : ℕ => (v : ℤ)) (combRecoded_identity s)
  push_cast at hi
  rw [hi]
  simpa only [Int.natCast_mod] using
    (Int.mod_modEq (s : ℤ) (n : ℤ)).add_right ((2 : ℤ) ^ 256)

theorem scalarGenerator_nonzero (s : ℕ) (hs : s % n ≠ 0) : (s : ℤ) • G ≠ 0 := by
  intro hz
  have hzNat : s • G = 0 := by simpa only [natCast_zsmul] using hz
  have hsmall : (s % n) • G = 0 := by rw [← nsmul_mod s G]; exact hzNat
  have hc : Nat.Coprime (s % n) n :=
    Nat.Coprime.symm (Nat.coprime_of_lt_prime (by omega)
      (Nat.mod_lt s (by norm_num [n])) Assumptions.p256_order_prime)
  exact mkPoint_ne_zero G_onCurve (smul_eq_zero_of_coprime hc hsmall)

/-- Every nonempty comb prefix is finite. The signed-window bounds exclude
inverse-point addition at every prefix, independently of secret validity. -/
theorem combPrefix_nonzero (s t : ℕ) (ht0 : 1 ≤ t) (ht : t ≤ 51) :
    (∑ u ∈ Finset.range t, digOf (combBits s) u * 2 ^ (5 * u)) • G ≠ 0 := by
  have hb := combBits_all s
  have hn : 257 ≤ 257 := le_refl _
  have hd := fun u => (digOf_bound hb hn u).1
  have hwindow := digOf_bound hb hn (t - 1)
  have hdistinct := Comb.chain_x_distinct (t - 1) (by omega) (digOf (combBits s)) hd
    (digOf (combBits s) (t - 1)) hwindow.2 hwindow.1
  rw [show t = (t - 1) + 1 by omega, Finset.sum_range_succ, add_zsmul]
  intro hz
  exact hdistinct.2 (eq_neg_of_add_eq_zero_left hz)

/-- Canonical mathematical coordinates for every fixed-base intermediate.
Their emulated-field CheckPolynomial encodings are a separate obligation. -/
theorem combPrefix_coordinates (s t : ℕ) (ht0 : 1 ≤ t) (ht : t ≤ 51) :
    ∃ x y : ℕ, x < p ∧ y < p ∧ ∃ h : OnCurve (x : Fp) (y : Fp),
      mkPoint h = (∑ u ∈ Finset.range t, digOf (combBits s) u * 2 ^ (5 * u)) • G := by
  obtain ⟨x, y, h, he⟩ := affine_of_nonzero _ (combPrefix_nonzero s t ht0 ht)
  have hnat : OnCurve (x.val : Fp) (y.val : Fp) := by
    rw [ZMod.natCast_zmod_val, ZMod.natCast_zmod_val]
    exact h
  refine ⟨x.val, y.val, ZMod.val_lt _, ZMod.val_lt _, hnat, ?_⟩
  rw [← he]
  apply mkPoint_inj.mpr
  exact ⟨ZMod.natCast_zmod_val _, ZMod.natCast_zmod_val _⟩

/-- The final complete-addition branch never adds inverse points for a valid
secret. This follows from the full scalar domain, not a branch-success premise. -/
theorem combFinal_noninverse (s : ℕ) (hs : s % n ≠ 0) {A T : P}
    (hA : A = (∑ u ∈ Finset.range 51, digOf (combBits s) u * 2 ^ (5 * u)) • G)
    (hT : T = ((2 * bitI (combBits s) 256 - 1) * 2 ^ 255 -
      (1 - bitI (combBits s) 0)) • G) : A ≠ -T := by
  have hsum := comb_final (combBits_recoding s) hA hT
  intro he
  have hz : (s : ℤ) • G = 0 := by rw [← hsum, he]; simp
  exact scalarGenerator_nonzero s hs hz

end ZolanaVE.P256.Completeness
