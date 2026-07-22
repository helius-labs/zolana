import FormalVerification.Circuit
import FormalVerification.Lemmas
import Mathlib
import «ProvenZk»

/-!
Semantics of the full-field strict-ordering gadget (`AssertStrictlyOrdered`).

The circuit decomposes each operand with a full-width (254-bit) `ToBinary` —
which gnark constrains to the *canonical* (< p) decomposition, modeled by
`GatesGnark12.to_binary_12` — splits the bits at 127 into two limbs, and
compares limb pairs lexicographically. The offset trick `x - y + 2^127` is
sound for limb-sized operands because the offset sum lies in (0, 2^128) ⊂ [0, p).

Main result: `AssertStrictlyOrdered_rw`:
`AssertStrictlyOrdered lo mid hi ↔ lo.val < mid.val ∧ mid.val < hi.val`.
-/

open ZolanaProver (F Order Gates)

set_option maxRecDepth 200000

lemma Order_lt_2_254 : Order < 2^254 := by decide
lemma two_pow_127_lt_Order : 2^127 < Order := by decide
lemma two_pow_128_lt_Order : 2^128 < Order := by decide

lemma F.val_lt_2_254 (v : F) : v.val < 2^254 := Nat.lt_trans v.val_lt Order_lt_2_254

/-- `Gates.select` with a constant-`0` condition selects the second input. -/
lemma select_zero_rw {a b out : F} : Gates.select (0:F) a b out ↔ out = b := by
  simp [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.select, GatesDef.is_bool]

/-- Full-width `to_binary` always succeeds and forces the canonical bits. -/
lemma to_binary_254_rw {v : F} {out : List.Vector F 254} :
    Gates.to_binary v 254 out ↔
    out = (Fin.toBitsLE ⟨v.val, F.val_lt_2_254 v⟩).map Bool.toZMod := by
  simp only [Gates, GatesGnark12, GatesDef.to_binary_12]
  apply Iff.intro
  · rintro ⟨_, rfl⟩; rfl
  · rintro rfl; exact ⟨F.val_lt_2_254 v, rfl⟩

/-- The top bit of a `(k+1)`-bit value decides `≥ 2^k`. -/
lemma Nat.testBit_top {k v : ℕ} (hv : v < 2^(k+1)) : v.testBit k = decide (2^k ≤ v) := by
  rw [Nat.testBit_to_div_mod]
  rcases Nat.lt_or_ge v (2^k) with h | h
  · simp [Nat.div_eq_of_lt h, Nat.not_le_of_lt h]
  · have hd : v / 2^k = 1 := by
      apply Nat.div_eq_of_lt_le
      · simpa using h
      · have : 2^k * 2 = 2^(k+1) := by rw [pow_succ]
        omega
    simp [hd, h]

lemma Fin.toBitsLE_succ {d : ℕ} {v : Fin (2^(d+1))} :
    Fin.toBitsLE v = (Fin.toBitsLE (Fin.lsbs v)).snoc (Fin.msb v) := by
  simp [Fin.toBitsLE, Fin.toBitsBE, List.Vector.reverse_cons]

lemma Fin.lsbs_val {d : ℕ} {v : Fin (2^(d+1))} : (Fin.lsbs v).val = v.val % 2^d := by
  have hv2 : v.val < 2^d * 2 := lt_of_lt_of_eq v.prop (pow_succ 2 d)
  show v.val - (Fin.msb v).toNat * 2^d = v.val % 2^d
  simp only [Fin.msb, ge_iff_le]
  rcases Nat.lt_or_ge v.val (2^d) with h | h
  · rw [decide_eq_false (by omega)]
    simp [Nat.mod_eq_of_lt h]
  · rw [decide_eq_true h]
    simp only [Bool.toNat_true, one_mul]
    rw [Nat.mod_eq_sub_mod h, Nat.mod_eq_of_lt (by omega)]

/-- Bits of `Fin.toBitsLE` are the `Nat.testBit`s of the value. -/
lemma Fin.getElem_toBitsLE : ∀ {d : ℕ} (v : Fin (2^d)) (i : ℕ) (hi : i < d),
    (Fin.toBitsLE v)[i] = v.val.testBit i := by
  intro d
  induction d with
  | zero => intro v i hi; omega
  | succ d ih =>
    intro v i hi
    rw [Fin.toBitsLE_succ]
    rcases Nat.lt_succ_iff_lt_or_eq.mp hi with hi' | heq
    · have hstep : ((Fin.toBitsLE (Fin.lsbs v)).snoc (Fin.msb v))[i]'(by omega) = (Fin.toBitsLE (Fin.lsbs v))[i]'hi' := by
        rw [List.Vector.getElem_def', List.Vector.getElem_def']
        rw [show (⟨i, by omega⟩ : Fin (d+1)) = Fin.castSucc ⟨i, hi'⟩ from rfl]
        exact List.Vector.snoc_get_castSucc
      rw [hstep, ih _ _ hi', Fin.lsbs_val, Nat.testBit_mod_two_pow]
      simp [hi']
    · subst heq
      have hstep : ((Fin.toBitsLE (Fin.lsbs v)).snoc (Fin.msb v))[i]'(by omega) = Fin.msb v := by
        rw [List.Vector.getElem_def']
        exact List.Vector.get_snoc_last
      rw [hstep, Nat.testBit_top v.prop]
      simp [Fin.msb, ge_iff_le]

/-- The low/high 127-bit slices, as `ofFn` — definitionally equal to the
127-entry literals the extractor emits. -/
def lowBitsF (b : List.Vector F 254) : List.Vector F 127 := List.Vector.ofFn fun i => b[i.val]
def highBitsF (b : List.Vector F 254) : List.Vector F 127 := List.Vector.ofFn fun i => b[i.val + 127]
def lowBits (b : List.Vector Bool 254) : List.Vector Bool 127 := List.Vector.ofFn fun i => b[i.val]
def highBits (b : List.Vector Bool 254) : List.Vector Bool 127 := List.Vector.ofFn fun i => b[i.val + 127]

lemma lowBitsF_map {b : List.Vector Bool 254} :
    lowBitsF (b.map Bool.toZMod) = (lowBits b).map Bool.toZMod := by
  apply List.Vector.ext
  intro m
  simp [lowBitsF, lowBits, List.Vector.get_ofFn, List.Vector.get_map, ←List.Vector.get_val_getElem]

lemma highBitsF_map {b : List.Vector Bool 254} :
    highBitsF (b.map Bool.toZMod) = (highBits b).map Bool.toZMod := by
  apply List.Vector.ext
  intro m
  simp [highBitsF, highBits, List.Vector.get_ofFn, List.Vector.get_map, ←List.Vector.get_val_getElem]

lemma List.Vector.get_eq_getElem' {v : List.Vector α n} (m : Fin n) : v.get m = v[m.val]'m.prop := rfl

lemma lowBits_toBitsLE {w : Fin (2^254)} :
    lowBits (Fin.toBitsLE w) = Fin.toBitsLE ⟨w.val % 2^127, Nat.mod_lt _ (by norm_num)⟩ := by
  apply List.Vector.ext
  intro m
  show (List.Vector.ofFn fun i => (Fin.toBitsLE w)[i.val]).get m = _
  rw [List.Vector.get_ofFn, List.Vector.get_eq_getElem']
  rw [Fin.getElem_toBitsLE _ _ (by have := m.prop; omega), Fin.getElem_toBitsLE _ _ m.prop]
  show w.val.testBit m.val = (w.val % 2^127).testBit m.val
  rw [Nat.testBit_mod_two_pow]
  simp [m.prop]

lemma highBits_toBitsLE {w : Fin (2^254)} :
    highBits (Fin.toBitsLE w) = Fin.toBitsLE ⟨w.val / 2^127, by
      have := w.prop
      apply Nat.div_lt_of_lt_mul
      omega⟩ := by
  apply List.Vector.ext
  intro m
  show (List.Vector.ofFn fun i => (Fin.toBitsLE w)[i.val + 127]).get m = _
  rw [List.Vector.get_ofFn, List.Vector.get_eq_getElem']
  rw [Fin.getElem_toBitsLE _ _ (by have := m.prop; omega), Fin.getElem_toBitsLE _ _ m.prop]
  show w.val.testBit (m.val + 127) = (w.val / 2^127).testBit m.val
  rw [Nat.testBit_div_two_pow]


/-- Literal-form slices: after delta-unfolding these are syntactically the
127-entry literals the extractor emits, so the mirror definition below is
cheaply definitionally equal to the extracted circuit. -/
def lowBitsLit (b : List.Vector F 254) : List.Vector F 127 := vec![b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23], b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31], b[32], b[33], b[34], b[35], b[36], b[37], b[38], b[39], b[40], b[41], b[42], b[43], b[44], b[45], b[46], b[47], b[48], b[49], b[50], b[51], b[52], b[53], b[54], b[55], b[56], b[57], b[58], b[59], b[60], b[61], b[62], b[63], b[64], b[65], b[66], b[67], b[68], b[69], b[70], b[71], b[72], b[73], b[74], b[75], b[76], b[77], b[78], b[79], b[80], b[81], b[82], b[83], b[84], b[85], b[86], b[87], b[88], b[89], b[90], b[91], b[92], b[93], b[94], b[95], b[96], b[97], b[98], b[99], b[100], b[101], b[102], b[103], b[104], b[105], b[106], b[107], b[108], b[109], b[110], b[111], b[112], b[113], b[114], b[115], b[116], b[117], b[118], b[119], b[120], b[121], b[122], b[123], b[124], b[125], b[126]]
def highBitsLit (b : List.Vector F 254) : List.Vector F 127 := vec![b[127], b[128], b[129], b[130], b[131], b[132], b[133], b[134], b[135], b[136], b[137], b[138], b[139], b[140], b[141], b[142], b[143], b[144], b[145], b[146], b[147], b[148], b[149], b[150], b[151], b[152], b[153], b[154], b[155], b[156], b[157], b[158], b[159], b[160], b[161], b[162], b[163], b[164], b[165], b[166], b[167], b[168], b[169], b[170], b[171], b[172], b[173], b[174], b[175], b[176], b[177], b[178], b[179], b[180], b[181], b[182], b[183], b[184], b[185], b[186], b[187], b[188], b[189], b[190], b[191], b[192], b[193], b[194], b[195], b[196], b[197], b[198], b[199], b[200], b[201], b[202], b[203], b[204], b[205], b[206], b[207], b[208], b[209], b[210], b[211], b[212], b[213], b[214], b[215], b[216], b[217], b[218], b[219], b[220], b[221], b[222], b[223], b[224], b[225], b[226], b[227], b[228], b[229], b[230], b[231], b[232], b[233], b[234], b[235], b[236], b[237], b[238], b[239], b[240], b[241], b[242], b[243], b[244], b[245], b[246], b[247], b[248], b[249], b[250], b[251], b[252], b[253]]

lemma lowBitsLit_eq {b : List.Vector F 254} : lowBitsLit b = lowBitsF b := by
  apply List.Vector.eq
  rw [show (lowBitsF b).toList = List.ofFn (fun (i : Fin 127) => b[i.val]) from List.Vector.toList_ofFn _]
  simp only [List.ofFn_succ, List.ofFn_zero, Fin.val_succ, Fin.val_zero, Fin.succ_zero_eq_one]
  rfl

lemma highBitsLit_eq {b : List.Vector F 254} : highBitsLit b = highBitsF b := by
  apply List.Vector.eq
  rw [show (highBitsF b).toList = List.ofFn (fun (i : Fin 127) => b[i.val + 127]) from List.Vector.toList_ofFn _]
  simp only [List.ofFn_succ, List.ofFn_zero, Fin.val_succ, Fin.val_zero, Fin.succ_zero_eq_one]
  rfl

/-- `from_binary` of the low slice of a canonical decomposition recovers
`val % 2^127`. -/
lemma from_binary_lowBits_rw {w : Fin (2^254)} {out : F} :
    Gates.from_binary (lowBitsF ((Fin.toBitsLE w).map Bool.toZMod)) out ↔
    out = ((w.val % 2^127 : ℕ) : F) := by
  rw [lowBitsF_map, lowBits_toBitsLE]
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.from_binary,
    recover_binary_zmod'_map_toZMod_eq_Fin_ofBitsLE, Fin.ofBitsLE_toBitsLE_eq_self,
    is_vector_binary_map_toZMod, and_true]
  exact eq_comm

/-- `from_binary` of the high slice recovers `val / 2^127`. -/
lemma from_binary_highBits_rw {w : Fin (2^254)} {out : F} :
    Gates.from_binary (highBitsF ((Fin.toBitsLE w).map Bool.toZMod)) out ↔
    out = ((w.val / 2^127 : ℕ) : F) := by
  rw [highBitsF_map, highBits_toBitsLE]
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.from_binary,
    recover_binary_zmod'_map_toZMod_eq_Fin_ofBitsLE, Fin.ofBitsLE_toBitsLE_eq_self,
    is_vector_binary_map_toZMod, and_true]
  exact eq_comm

lemma natCast_inj_of_lt {a b : ℕ} (ha : a < Order) (hb : b < Order) :
    ((a : F) = (b : F)) ↔ a = b := by
  apply Iff.intro
  · intro h
    have := congrArg ZMod.val h
    rwa [ZMod.val_cast_of_lt ha, ZMod.val_cast_of_lt hb] at this
  · rintro rfl; rfl

/-- The offset difference `x - y + 2^127` of two limb-bounded values does not
wrap, so its `val` is the exact integer `x.val + 2^127 - y.val`. -/
lemma val_sub_add_offset {x y : F} (hx : x.val < 2^127) (hy : y.val < 2^127) :
    (x - y + (170141183460469231731687303715884105728:F)).val = x.val + 2^127 - y.val := by
  have hle : y.val ≤ x.val + 2^127 := by omega
  have hlt : x.val + 2^127 - y.val < Order := by
    have := two_pow_128_lt_Order
    omega
  have hc : (170141183460469231731687303715884105728:F) = ((2^127 : ℕ) : F) := by norm_num
  have heq : x - y + (170141183460469231731687303715884105728:F) = ((x.val + 2^127 - y.val : ℕ) : F) := by
    rw [Nat.cast_sub hle, hc]
    push_cast
    rw [ZMod.natCast_rightInverse x, ZMod.natCast_rightInverse y]
    ring
  rw [heq, ZMod.val_cast_of_lt hlt]

/-! ### Mirror definitions

These name the gate patterns the extractor emits inline; each is
definitionally equal to the corresponding block of `AssertStrictlyOrdered`
(the `ofFn` slices unfold to the 127-entry literals). -/

/-- `CanonicalLimbs` (full_field_compare.go): canonical 254-bit decomposition
split into two 127-bit limbs. -/
def canonicalLimbs (v : F) (k : F → F → Prop) : Prop :=
  ∃bits, Gates.to_binary v 254 bits ∧
  ∃l, Gates.from_binary (lowBitsLit bits) l ∧
  ∃h, Gates.from_binary (highBitsLit bits) h ∧
  k l h

/-- `isLessBounded` (full_field_compare.go): the offset-sum comparator for
limb-bounded operands. -/
def isLessChunk (x y : F) (k : F → Prop) : Prop :=
  ∃d, d = Gates.sub x y ∧
  ∃dOff, dOff = Gates.add d (170141183460469231731687303715884105728:F) ∧
  ∃bits, Gates.to_binary dOff 128 bits ∧
  ∃out, out = Gates.sub (1:F) bits[127] ∧
  k out

def isZeroChunk (x y : F) (k : F → Prop) : Prop :=
  ∃d, d = Gates.sub x y ∧
  ∃out, Gates.is_zero d out ∧
  k out

/-- Mirror of the extracted `AssertStrictlyOrdered`, definitionally equal. -/
def AssertStrictlyOrdered' (Lo Mid Hi : F) : Prop :=
  canonicalLimbs Lo fun loLo loHi =>
  canonicalLimbs Mid fun midLo midHi =>
  canonicalLimbs Hi fun hiLo hiHi =>
  isLessChunk loHi midHi fun hiLess₁ =>
  isZeroChunk loHi midHi fun hiEq₁ =>
  isLessChunk loLo midLo fun loLess₁ =>
  ∃m₁, m₁ = Gates.mul hiEq₁ loLess₁ ∧
  ∃s₁, s₁ = Gates.add hiLess₁ m₁ ∧
  Gates.eq s₁ (1:F) ∧
  isLessChunk midHi hiHi fun hiLess₂ =>
  isZeroChunk midHi hiHi fun hiEq₂ =>
  isLessChunk midLo hiLo fun loLess₂ =>
  ∃m₂, m₂ = Gates.mul hiEq₂ loLess₂ ∧
  ∃s₂, s₂ = Gates.add hiLess₂ m₂ ∧
  Gates.eq s₂ (1:F) ∧
  True

lemma AssertStrictlyOrdered_mirror {lo mid hi : F} :
    ZolanaProver.AssertStrictlyOrdered lo mid hi ↔ AssertStrictlyOrdered' lo mid hi :=
  ⟨fun h => h, fun h => h⟩

lemma canonicalLimbs_rw {v : F} {k : F → F → Prop} :
    canonicalLimbs v k ↔ k ((v.val % 2^127 : ℕ) : F) ((v.val / 2^127 : ℕ) : F) := by
  unfold canonicalLimbs
  simp only [lowBitsLit_eq, highBitsLit_eq]
  simp only [to_binary_254_rw, exists_eq_left, from_binary_lowBits_rw, from_binary_highBits_rw]

lemma isLessChunk_rw {x y : F} (hx : x.val < 2^127) (hy : y.val < 2^127) {k : F → Prop} :
    isLessChunk x y k ↔ k (if x.val < y.val then 1 else 0) := by
  unfold isLessChunk
  simp only [exists_eq_left]
  have hsub : Gates.sub x y = x - y := rfl
  have hadd : ∀ (a b : F), Gates.add a b = a + b := fun _ _ => rfl
  rw [hsub, hadd]
  have key : ∀ (hp : (x - y + (170141183460469231731687303715884105728:F)).val < 2^128),
      -- NB: the index proof must be explicit — `get_elem_tactic`'s `assumption`
      -- step whnf-unifies against `hp`, forcing the big literal and overflowing.
      (1:F) - (((Fin.toBitsLE (⟨(x - y + (170141183460469231731687303715884105728:F)).val, hp⟩ : Fin (2^128))).map Bool.toZMod)[127]'(by omega)) =
      if x.val < y.val then 1 else 0 := by
    intro hp
    rw [List.Vector.getElem_map, Fin.getElem_toBitsLE _ _ (by norm_num)]
    simp only [Fin.val_mk, val_sub_add_offset hx hy]
    rw [Nat.testBit_top (by rw [val_sub_add_offset hx hy] at hp; omega)]
    rcases Nat.lt_or_ge x.val y.val with h | h
    · rw [if_pos h, decide_eq_false (by omega)]
      simp [Bool.toZMod, Bool.toNat]
    · rw [if_neg (by omega), decide_eq_true (by omega)]
      simp [Bool.toZMod, Bool.toNat]
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.to_binary_12,
    GatesDef.sub]
  apply Iff.intro
  · rintro ⟨bits, ⟨hp, rfl⟩, hk⟩
    rwa [key hp] at hk
  · intro hk
    have hp : (x - y + (170141183460469231731687303715884105728:F)).val < 2^128 := by
      rw [val_sub_add_offset hx hy]
      omega
    exact ⟨_, ⟨hp, rfl⟩, by rw [key hp]; exact hk⟩

lemma isZeroChunk_rw {x y : F} {k : F → Prop} :
    isZeroChunk x y k ↔ k (if x = y then 1 else 0) := by
  unfold isZeroChunk
  simp only [exists_eq_left]
  have hsub : Gates.sub x y = x - y := rfl
  rw [hsub]
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.is_zero]
  apply Iff.intro
  · rintro ⟨out, hout, hk⟩
    rcases hout with ⟨hne, rfl⟩ | ⟨heq, rfl⟩
    · rwa [if_neg (fun hc => hne (by rw [hc, sub_self]))]
    · rwa [if_pos (by rwa [sub_eq_zero] at heq)]
  · intro hk
    by_cases h : x = y
    · exact ⟨1, Or.inr ⟨by rw [h, sub_self], rfl⟩, by rwa [if_pos h] at hk⟩
    · exact ⟨0, Or.inl ⟨fun hc => h (by rwa [sub_eq_zero] at hc), rfl⟩, by rwa [if_neg h] at hk⟩

/-- Lexicographic combination of limb verdicts equals full-value comparison. -/
lemma lex_combine {alo ahi blo bhi : ℕ}
    (halo : alo < 2^127) (hahi : ahi < 2^127) (hblo : blo < 2^127) (hbhi : bhi < 2^127) :
    ((if ahi < bhi then (1:F) else 0) + (if ((ahi:F) = (bhi:F)) then (1:F) else 0) * (if alo < blo then (1:F) else 0) = 1)
    ↔ alo + 2^127 * ahi < blo + 2^127 * bhi := by
  have hOrder := two_pow_127_lt_Order
  have hcast : ((ahi:F) = (bhi:F)) ↔ ahi = bhi := natCast_inj_of_lt (by omega) (by omega)
  rcases Nat.lt_trichotomy ahi bhi with h | h | h
  · rw [if_pos h, if_neg (fun hc => absurd (hcast.mp hc) (Nat.ne_of_lt h))]
    simp only [zero_mul, add_zero]
    exact iff_of_true (by norm_num) (by omega)
  · rw [if_neg (by omega), if_pos (hcast.mpr h)]
    simp only [one_mul, zero_add]
    by_cases hlt : alo < blo
    · rw [if_pos hlt]
      exact iff_of_true (by norm_num) (by omega)
    · rw [if_neg hlt]
      exact iff_of_false (by norm_num) (by omega)
  · rw [if_neg (by omega), if_neg (fun hc => absurd (hcast.mp hc) (by omega))]
    simp only [zero_mul, add_zero]
    exact iff_of_false (by norm_num) (by omega)

lemma gates_eq_rw {a b : F} : Gates.eq a b ↔ a = b := by
  simp [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq]

/-- The production ordering gadget enforces exactly
`lo.val < mid.val < hi.val` over full canonical field values. -/
theorem AssertStrictlyOrdered_rw {lo mid hi : F} :
    ZolanaProver.AssertStrictlyOrdered lo mid hi ↔
    lo.val < mid.val ∧ mid.val < hi.val := by
  have hOrder := two_pow_127_lt_Order
  have hmodlt : ∀ (v : F), ((v.val % 2^127 : ℕ) : F).val = v.val % 2^127 := fun v =>
    ZMod.val_cast_of_lt (by have := Nat.mod_lt v.val (y := 2^127) (by norm_num); omega)
  have hdivlt : ∀ (v : F), ((v.val / 2^127 : ℕ) : F).val = v.val / 2^127 := fun v =>
    ZMod.val_cast_of_lt (by have h1 := F.val_lt_2_254 v; have h2 := two_pow_127_lt_Order; omega)
  have hmodb : ∀ (v : F), ((v.val % 2^127 : ℕ) : F).val < 2^127 := fun v => by
    rw [hmodlt]; exact Nat.mod_lt _ (by norm_num)
  have hdivb : ∀ (v : F), ((v.val / 2^127 : ℕ) : F).val < 2^127 := fun v => by
    rw [hdivlt]
    have := F.val_lt_2_254 v
    omega
  rw [AssertStrictlyOrdered_mirror]
  unfold AssertStrictlyOrdered'
  simp only [canonicalLimbs_rw]
  rw [isLessChunk_rw (hdivb lo) (hdivb mid),
    isZeroChunk_rw,
    isLessChunk_rw (hmodb lo) (hmodb mid),
    isLessChunk_rw (hdivb mid) (hdivb hi),
    isZeroChunk_rw,
    isLessChunk_rw (hmodb mid) (hmodb hi)]
  simp only [hmodlt, hdivlt]
  have hgmul : ∀ (a b : F), Gates.mul a b = a * b := fun _ _ => rfl
  have hgadd : ∀ (a b : F), Gates.add a b = a + b := fun _ _ => rfl
  simp only [hgmul, hgadd, exists_eq_left, gates_eq_rw, and_true]
  rw [lex_combine (Nat.mod_lt _ (by norm_num)) (by have := F.val_lt_2_254 lo; omega)
        (Nat.mod_lt _ (by norm_num)) (by have := F.val_lt_2_254 mid; omega),
      lex_combine (Nat.mod_lt _ (by norm_num)) (by have := F.val_lt_2_254 mid; omega)
        (Nat.mod_lt _ (by norm_num)) (by have := F.val_lt_2_254 hi; omega)]
  simp only [Nat.mod_add_div]
