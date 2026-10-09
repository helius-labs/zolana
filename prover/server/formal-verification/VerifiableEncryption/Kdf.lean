import FormalVerification.FullField

/-!
Semantics of the Poseidon key schedule (`poseidon_kdf.go`).

`FieldToBytesBE(v, 32)` is `bits.ToBinary(v, WithNbDigits(256))` followed by
`BitsToBytesBE`. For BN254 gnark caps the hinted digits at the field bit length
(254), recomposes them, bounds them by `MustBeLessOrEqCst(bits, p - 1)` and
appends two constant-zero digits. `ToBinary256Mirror` follows that structure;
`ToBinary256Mirror_rw` shows it forces the canonical decomposition of `v.val`.
-/

open ZolanaProver (F Order Gates)

set_option maxHeartbeats 400000

namespace VerifiableEncryption

lemma F.val_lt_2_256 (v : F) : v.val < 2^256 :=
  Nat.lt_trans (F.val_lt_2_254 v) (by norm_num)

theorem to_binary_256_rw {v : F} {out : List.Vector F 256} :
    Gates.to_binary v 256 out ↔
    out = (Fin.toBitsLE ⟨v.val, F.val_lt_2_256 v⟩).map Bool.toZMod := by
  simp only [Gates, GatesGnark12, GatesDef.to_binary_12]
  apply Iff.intro
  · rintro ⟨_, rfl⟩; rfl
  · rintro rfl; exact ⟨F.val_lt_2_256 v, rfl⟩

/-- `MustBeLessOrEqCst(aBits, bound)` from gnark v0.16.4
`frontend/cs/r1cs/api_assertions.go`, walking bit positions from the top.
`p` is the running prefix product: `p = 1` iff every bit above the current
position equals the bound's bit. A set bound bit asserts booleanity and extends
the prefix; a clear bound bit asserts `(1 - p - a) * a = 0`. -/
def leqCstChain (bound : ℕ) (a : ℕ → F) : ℕ → F → Prop
  | 0, _ => True
  | i+1, p =>
    if bound.testBit i then
      Gates.is_bool (a i) ∧ ∃p', p' = Gates.mul p (a i) ∧ leqCstChain bound a i p'
    else
      Gates.eq (Gates.mul (Gates.sub (Gates.sub (1:F) p) (a i)) (a i)) (0:F) ∧
      leqCstChain bound a i p

lemma Nat.mod_two_pow_succ' (x n : ℕ) :
    x % 2^(n+1) = x % 2^n + 2^n * (x.testBit n).toNat := by
  rw [Nat.mod_pow_succ, Nat.toNat_testBit]

lemma Bool.toZMod_mul (a b : Bool) :
    (Bool.toZMod a : F) * Bool.toZMod b = Bool.toZMod (a && b) := by
  cases a <;> cases b <;> simp

lemma neg_one_ne_zero_F : (-1 : F) ≠ 0 := by
  simp

/-- With boolean digits, the chain started at prefix `q` holds iff `q` implies
the digit value is at most the bound (both read modulo `2^n`). -/
lemma leqCstChain_bits (bound x : ℕ) :
    ∀ (n : ℕ) (q : Bool),
    leqCstChain bound (fun i => Bool.toZMod (x.testBit i)) n (Bool.toZMod q) ↔
    (q = true → x % 2^n ≤ bound % 2^n) := by
  intro n
  induction n with
  | zero => intro q; simp [leqCstChain, Nat.mod_one]
  | succ n ih =>
    intro q
    have hx := Nat.mod_lt x (show 2^n > 0 by positivity)
    have hb := Nat.mod_lt bound (show 2^n > 0 by positivity)
    rw [Nat.mod_two_pow_succ' x n, Nat.mod_two_pow_succ' bound n]
    unfold leqCstChain
    cases hc : bound.testBit n
    · simp only [Bool.false_eq_true, if_false]
      rw [ih q]
      cases q <;> cases ha : x.testBit n
      all_goals simp [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq, GatesDef.mul,
          GatesDef.sub]
      all_goals omega
    · simp only [if_true]
      have hbool : Gates.is_bool (Bool.toZMod (x.testBit n) : F) := by
        simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8]
        rw [is_bool_is_bit]
        exact Bool.toZMod_is_bit
      have hmul : Gates.mul (Bool.toZMod q : F) (Bool.toZMod (x.testBit n)) =
          Bool.toZMod (q && x.testBit n) := Bool.toZMod_mul _ _
      simp only [hbool, true_and, hmul, exists_eq_left]
      rw [ih]
      cases q <;> cases ha : x.testBit n
      all_goals simp
      all_goals omega

lemma toZMod_true_F : (Bool.toZMod true : F) = 1 := by simp

lemma Order_pos : 0 < Order := by decide

lemma Order_sub_one_mod : (Order - 1) % 2^254 = Order - 1 :=
  Nat.mod_eq_of_lt (by have := Order_lt_2_254; omega)

/-- The hinted digits of `ToBinary` beyond position 253 read as zero. -/
def digitAt (bits : List.Vector F 254) (i : ℕ) : F :=
  if h : i < 254 then bits[i] else 0

/-- Hand mirror of `bits.ToBinary(v, WithNbDigits(256))` on BN254: 254 hinted
digits, booleanity of each, recomposition equal to `v`, the `p - 1` bound
chain, and two constant-zero top digits. -/
def ToBinary256Mirror (v : F) (k : List.Vector F 256 → Prop) : Prop :=
  ∃bits : List.Vector F 254,
    (∀ a ∈ bits, Gates.is_bool a) ∧
    Gates.eq (recover_binary_zmod' bits) v ∧
    leqCstChain (Order - 1) (digitAt bits) 254 (1:F) ∧
    k (List.Vector.ofFn fun i : Fin 256 => digitAt bits i.val)

lemma digitAt_toBitsLE (x : ℕ) (hx : x < 2^254) :
    digitAt ((Fin.toBitsLE (⟨x, hx⟩ : Fin (2^254))).map Bool.toZMod) =
    fun i => Bool.toZMod (x.testBit i) := by
  funext i
  unfold digitAt
  split
  · rename_i h
    rw [List.Vector.getElem_map, Fin.getElem_toBitsLE _ _ h]
  · rename_i h
    rw [Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le hx (Nat.pow_le_pow_right (by norm_num) (by omega)))]
    simp

lemma ofFn_testBit_eq_toBitsLE {d : ℕ} (x : ℕ) (hx : x < 2^d) :
    (List.Vector.ofFn fun i : Fin d => (Bool.toZMod (x.testBit i.val) : F)) =
    (Fin.toBitsLE (⟨x, hx⟩ : Fin (2^d))).map Bool.toZMod := by
  apply List.Vector.ext
  intro m
  rw [List.Vector.get_ofFn, List.Vector.get_map, List.Vector.get_eq_getElem',
    Fin.getElem_toBitsLE _ _ m.prop]

/-- The ToBinary mirror holds exactly for the canonical 256-digit decomposition
of `v.val`. -/
theorem ToBinary256Mirror_rw {v : F} {k : List.Vector F 256 → Prop} :
    ToBinary256Mirror v k ↔
    k ((Fin.toBitsLE ⟨v.val, F.val_lt_2_256 v⟩).map Bool.toZMod) := by
  unfold ToBinary256Mirror
  apply Iff.intro
  · rintro ⟨bits, hbool, hrec, hchain, hk⟩
    have hbin : is_vector_binary bits := fun a ha => by
      have := hbool a ha
      simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] at this
      rwa [is_bool_is_bit] at this
    obtain ⟨bv, rfl⟩ := is_vector_binary_iff_exists_bool_vec.mp hbin
    set x := (Fin.ofBitsLE bv).val with hxdef
    have hx : x < 2^254 := (Fin.ofBitsLE bv).prop
    have hbv : bv = Fin.toBitsLE (⟨x, hx⟩ : Fin (2^254)) := by
      rw [← Fin.toBitsLE_ofBitsLE_eq_self (v := bv)]
    rw [hbv, digitAt_toBitsLE x hx] at hchain hk
    rw [hbv] at hrec
    have hchain' := (leqCstChain_bits (Order - 1) x 254 true).mp (by rwa [toZMod_true_F]) rfl
    rw [Order_sub_one_mod, Nat.mod_eq_of_lt hx] at hchain'
    have hxO : x < Order := by have := Order_pos; omega
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq,
      recover_binary_zmod'_map_toZMod_eq_Fin_ofBitsLE, Fin.ofBitsLE_toBitsLE_eq_self] at hrec
    have hval : v.val = x := by rw [← hrec, ZMod.val_cast_of_lt hxO]
    rw [ofFn_testBit_eq_toBitsLE x (Nat.lt_of_lt_of_le hx (by norm_num))] at hk
    have hfin : (⟨v.val, F.val_lt_2_256 v⟩ : Fin (2^256)) =
        ⟨x, Nat.lt_of_lt_of_le hx (by norm_num)⟩ := Fin.ext hval
    rw [hfin]
    exact hk
  · intro hk
    refine ⟨(Fin.toBitsLE (⟨v.val, F.val_lt_2_254 v⟩ : Fin (2^254))).map Bool.toZMod, ?_, ?_, ?_, ?_⟩
    · intro a ha
      simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8]
      rw [is_bool_is_bit]
      exact is_vector_binary_map_toZMod a ha
    · simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq,
        recover_binary_zmod'_map_toZMod_eq_Fin_ofBitsLE, Fin.ofBitsLE_toBitsLE_eq_self]
      exact ZMod.natCast_zmod_val v
    · rw [digitAt_toBitsLE]
      have := (leqCstChain_bits (Order - 1) v.val 254 true).mpr (fun _ => by
        rw [Order_sub_one_mod, Nat.mod_eq_of_lt (F.val_lt_2_254 v)]
        have := v.val_lt
        omega)
      rwa [toZMod_true_F] at this
    · rw [digitAt_toBitsLE, ofFn_testBit_eq_toBitsLE]
      exact hk

/-- The mirror agrees with proven-zk's `to_binary_12` model at 256 digits. -/
theorem ToBinary256Mirror_iff_to_binary {v : F} {k : List.Vector F 256 → Prop} :
    ToBinary256Mirror v k ↔ ∃out, Gates.to_binary v 256 out ∧ k out := by
  rw [ToBinary256Mirror_rw]
  simp only [to_binary_256_rw, exists_eq_left]

end VerifiableEncryption
