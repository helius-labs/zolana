import FormalVerification.FullField
import VerifiableEncryption.Circuit.Prelude

/-!
Semantics of the Poseidon key schedule (`poseidon_kdf.go`).

`FieldToBytesBE(v, 32)` is `bits.ToBinary(v, WithNbDigits(256))` followed by
`BitsToBytesBE`. For BN254 gnark caps the hinted digits at the field bit length
(254), recomposes them, bounds them by `MustBeLessOrEqCst(bits, p - 1)` and
appends two constant-zero digits. `ToBinary256Mirror` follows that structure;
`ToBinary256Mirror_rw` shows it forces the canonical decomposition of `v.val`.
-/

set_option maxHeartbeats 400000
set_option linter.unusedSectionVars false

namespace ZolanaVE.Kdf

open ZolanaVE

variable [Fact (Nat.Prime Order)]

lemma order_lt_two_pow_254 : Order < 2^254 := by decide

lemma F.val_lt_2_254 (v : F) : v.val < 2^254 := Nat.lt_trans v.val_lt order_lt_two_pow_254

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
  Nat.mod_eq_of_lt (by have := order_lt_two_pow_254; omega)

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

/-- Byte `i` of `BitsToBytesBE` (`circuits/gadget/bytes.go`): the little-endian
digits `8 * (31 - i) .. 8 * (31 - i) + 7`, so byte 0 is the most significant. -/
def byteBE (bits : List.Vector F 256) (i : Fin 32) : List.Vector F 8 :=
  List.Vector.ofFn fun j : Fin 8 => bits[(31 - i.val) * 8 + j.val]'(by omega)

/-- Hand mirror of `FieldToBytesBE(v, 32)` (`verifiable-encryption/bytes.go`):
the 256-digit `ToBinary` followed by one `FromBinary` per byte. -/
def FieldToBytesBEMirror (v : F) (k : (Fin 32 → F) → Prop) : Prop :=
  ToBinary256Mirror v fun bits =>
  ∃bytes : Fin 32 → F, (∀ i, Gates.from_binary (byteBE bits i) (bytes i)) ∧ k bytes

/-- Big-endian byte `i` of a 32-byte value. -/
def byteOf (x : ℕ) (i : Fin 32) : ℕ := x / 256^(31 - i.val) % 256

lemma byteOf_lt (x : ℕ) (i : Fin 32) : byteOf x i < 2^8 :=
  Nat.mod_lt _ (by norm_num)

lemma byteBE_toBitsLE (w : Fin (2^256)) (i : Fin 32) :
    byteBE ((Fin.toBitsLE w).map Bool.toZMod) i =
    (Fin.toBitsLE (⟨byteOf w.val i, byteOf_lt _ _⟩ : Fin (2^8))).map Bool.toZMod := by
  apply List.Vector.ext
  intro m
  unfold byteBE
  rw [List.Vector.get_ofFn, List.Vector.get_map, List.Vector.get_eq_getElem',
    Fin.getElem_toBitsLE _ _ m.prop, List.Vector.getElem_map,
    Fin.getElem_toBitsLE _ _ (by omega)]
  congr 1
  show w.val.testBit ((31 - i.val) * 8 + m.val) = (w.val / 256^(31 - i.val) % 2^8).testBit m.val
  rw [Nat.testBit_mod_two_pow, show (256:ℕ)^(31 - i.val) = 2^((31 - i.val) * 8) by
    rw [show (256:ℕ) = 2^8 by norm_num, ← pow_mul, mul_comm], Nat.testBit_div_two_pow]
  simp [m.prop, add_comm]

theorem fieldToBytesBE_rw {v : F} {k : (Fin 32 → F) → Prop} :
    FieldToBytesBEMirror v k ↔ k (fun i : Fin 32 => ((v.val / 256^(31 - i.val) % 256 : ℕ) : F)) := by
  unfold FieldToBytesBEMirror
  rw [ToBinary256Mirror_rw]
  simp only [byteBE_toBitsLE, Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    Gates.from_binary_iff_eq_ofBitsLE_mod_order, Fin.ofBitsLE_toBitsLE_eq_self]
  apply Iff.intro
  · rintro ⟨bytes, hbytes, hk⟩
    have : bytes = fun i => ((byteOf v.val i : ℕ) : F) := funext hbytes
    rw [this] at hk
    exact hk
  · intro hk
    exact ⟨_, fun _ => rfl, hk⟩

def domSepSilo : ℕ := 0x544d5349
def domSepKey : ℕ := 0x544d534b
def domSepKeyHi : ℕ := 0x544d534c
def domSepNonce : ℕ := 0x544d534e

/-- Consecutive 31-byte chunks; the final chunk may be shorter. -/
def chunks31 {α : Type} : List α → List (List α)
  | [] => []
  | b :: bs => (b :: bs).take 31 :: chunks31 ((b :: bs).drop 31)
termination_by l => l.length
decreasing_by simp only [List.length_drop, List.length_cons]; omega

/-- Big-endian packing of one chunk (`gadget.BytesToField`). -/
def packBE (bytes : List ℕ) : ℕ := bytes.foldl (fun acc b => acc * 256 + b) 0

/-- `gadget.PackBytesBE`: 31-byte big-endian chunks, the last one unpadded. -/
def packBE31 (info : List ℕ) : List ℕ := (chunks31 info).map packBE

/-- The key schedule of `poseidon_kdf.go` over a Poseidon hash taking the input
list (initial state zero). The key is the low 16 bytes of `keyHi` followed by
the low 16 bytes of `keyLo`; the nonce is the low 12 bytes of `nonceRaw`. -/
def kdf (poseidon : List F → F) (shared : F) (info : List ℕ) :
    (Fin 32 → ℕ) × (Fin 12 → ℕ) :=
  let siloed := poseidon ((domSepSilo : F) :: shared :: (packBE31 info).map (Nat.cast : ℕ → F))
  let keyLo := poseidon [(domSepKey : F), siloed]
  let keyHi := poseidon [(domSepKeyHi : F), siloed]
  let nonceRaw := poseidon [(domSepNonce : F), siloed]
  (fun i => if h : i.val < 16 then byteOf keyHi.val ⟨i.val + 16, by omega⟩ else byteOf keyLo.val i,
   fun j => byteOf nonceRaw.val ⟨j.val + 20, by omega⟩)

/-- `gadget.BytesToField` on circuit values: `acc * 256 + b` per byte. -/
def packGates (bytes : List F) : F :=
  bytes.foldl (fun acc b => Gates.add (Gates.mul acc (256:F)) b) (0:F)

/-- Hand mirror of `KeySchedule` in call order. `PoseidonGadget xs k` stands for
the extracted `PoseidonHash(xs)` at the arity of `xs`. -/
def KeyScheduleMirror (PoseidonGadget : List F → (F → Prop) → Prop) (info : List ℕ)
    (shared : F) (k : (Fin 32 → F) → (Fin 12 → F) → Prop) : Prop :=
  PoseidonGadget ((domSepSilo : F) :: shared ::
      (chunks31 (info.map (Nat.cast : ℕ → F))).map packGates) fun siloed =>
  PoseidonGadget [(domSepKey : F), siloed] fun keyLo =>
  PoseidonGadget [(domSepKeyHi : F), siloed] fun keyHi =>
  FieldToBytesBEMirror keyLo fun keyLoBytes =>
  FieldToBytesBEMirror keyHi fun keyHiBytes =>
  PoseidonGadget [(domSepNonce : F), siloed] fun nonceRaw =>
  FieldToBytesBEMirror nonceRaw fun nonceBytes =>
  k (fun i => if h : i.val < 16 then keyHiBytes ⟨i.val + 16, by omega⟩ else keyLoBytes i)
    (fun j => nonceBytes ⟨j.val + 20, by omega⟩)

lemma chunks31_map {α β : Type} (f : α → β) (l : List α) :
    chunks31 (l.map f) = (chunks31 l).map (List.map f) := by
  induction l using chunks31.induct with
  | case1 => simp [chunks31]
  | case2 b bs ih =>
    conv_rhs => rw [chunks31, List.map_cons, ← ih]
    conv_lhs => rw [List.map_cons, chunks31]
    simp only [List.map_take, List.map_drop, List.map_cons]

lemma packGates_foldl (l : List ℕ) (acc : ℕ) :
    (l.map (Nat.cast : ℕ → F)).foldl (fun acc b => Gates.add (Gates.mul acc (256:F)) b) (acc : F) =
    ((l.foldl (fun acc b => acc * 256 + b) acc : ℕ) : F) := by
  induction l generalizing acc with
  | nil => rfl
  | cons b bs ih =>
    rw [List.map_cons, List.foldl_cons, List.foldl_cons, ← ih]
    congr 1
    simp [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]

lemma packGates_cast (l : List ℕ) :
    packGates (l.map (Nat.cast : ℕ → F)) = ((packBE l : ℕ) : F) := by
  have := packGates_foldl l 0
  simpa [packGates, packBE] using this

theorem KeySchedule_sound (poseidon : List F → F)
    (PoseidonGadget : List F → (F → Prop) → Prop)
    (hP : ∀ xs k, PoseidonGadget xs k ↔ k (poseidon xs))
    {info : List ℕ} {shared : F} {k : (Fin 32 → F) → (Fin 12 → F) → Prop} :
    KeyScheduleMirror PoseidonGadget info shared k ↔
    k (fun i => ((kdf poseidon shared info).1 i : F))
      (fun j => ((kdf poseidon shared info).2 j : F)) := by
  unfold KeyScheduleMirror
  simp only [hP, fieldToBytesBE_rw, chunks31_map, List.map_map]
  have hpack : (packGates ∘ List.map (Nat.cast : ℕ → F)) = fun l => ((packBE l : ℕ) : F) :=
    funext packGates_cast
  rw [hpack]
  apply iff_of_eq
  congr 1
  · funext i
    simp only [kdf, packBE31, List.map_map]
    split <;> rfl
  · funext j
    simp only [kdf, packBE31, List.map_map]
    rfl

/-! ### Step lemmas for the extracted `FieldBytesBE_32`

The extracted gadget names every gate. The generated proof in
`Kdf/FieldBytes.lean` keeps each gate as a local with its defining equation and
threads three invariants through the gadget body: the running recomposition
sum `psum`, the booleanity of the hinted digits `boolsUpTo`, and a reduction of
the `MustBeLessOrEqCst` chain to its remaining lower positions. -/

/-- Hinted digit `i` of the 254-digit `ToBinary` hint. -/
def bitA (g : List.Vector F 254) (i : ℕ) : F := g.get ⟨i % 254, Nat.mod_lt _ (by norm_num)⟩

/-- Recomposition `Σ_{j<i} g[j] * 2^j` in gnark's accumulation order. -/
def psum (g : List.Vector F 254) : ℕ → F
  | 0 => 0
  | i+1 => psum g i + bitA g i * 2^i

def boolsUpTo (g : List.Vector F 254) : ℕ → Prop
  | 0 => True
  | i+1 => boolsUpTo g i ∧ Gates.is_bool (bitA g i)

theorem psum_step {g : List.Vector F 254} (i : ℕ) {acc m s c : F} (hacc : acc = psum g i)
    (hc : c = 2^i) (hm : m = Gates.mul (bitA g i) c) (hs : s = Gates.add acc m) :
    s = psum g (i+1) := by
  subst hacc hc hm hs
  rfl

theorem psum_step0 {g : List.Vector F 254} {m s c : F} (hc : c = 2^0)
    (hm : m = Gates.mul (bitA g 0) c) (hs : s = Gates.add (0:F) m) : s = psum g 1 :=
  psum_step 0 rfl hc hm hs

theorem chain_one_step {b : ℕ} {a : ℕ → F} {R : Prop} (i : ℕ) {p p' : F}
    (hbit : b.testBit i = true) (hb : Gates.is_bool (a i)) (hp : p' = Gates.mul p (a i))
    (hC : leqCstChain b a (i+1) p → R) : leqCstChain b a i p' → R := by
  intro hr
  apply hC
  unfold leqCstChain
  rw [if_pos hbit]
  exact ⟨hb, p', hp, hr⟩

theorem chain_zero_step {b : ℕ} {a : ℕ → F} {R : Prop} (i : ℕ) {p t u w : F}
    (hbit : b.testBit i = false) (ht : t = Gates.sub (1:F) p) (hu : u = Gates.sub t (a i))
    (hw : w = Gates.mul u (a i)) (heq : Gates.eq w (0:F))
    (hC : leqCstChain b a (i+1) p → R) : leqCstChain b a i p → R := by
  intro hr
  apply hC
  unfold leqCstChain
  rw [if_neg (by simp [hbit])]
  subst ht hu hw
  exact ⟨heq, hr⟩

lemma boolsUpTo_get {g : List.Vector F 254} :
    ∀ {n : ℕ}, boolsUpTo g n → ∀ i < n, Gates.is_bool (bitA g i)
  | 0, _, i, hi => absurd hi (Nat.not_lt_zero _)
  | n+1, ⟨hn, hb⟩, i, hi => by
    rcases Nat.lt_succ_iff_lt_or_eq.mp hi with h | rfl
    · exact boolsUpTo_get hn i h
    · exact hb

lemma leqCstChain_congr {b : ℕ} {a a' : ℕ → F} :
    ∀ (n : ℕ) (p : F), (∀ j < n, a j = a' j) → (leqCstChain b a n p ↔ leqCstChain b a' n p)
  | 0, _, _ => Iff.rfl
  | n+1, p, h => by
    unfold leqCstChain
    rw [h n (Nat.lt_succ_self n)]
    have ih := fun q => leqCstChain_congr (b := b) (a := a) (a' := a') n q
      (fun j hj => h j (Nat.lt_succ_of_lt hj))
    split
    · simp only [ih]
    · simp only [ih]

lemma bitA_toBitsLE (x : ℕ) (hx : x < 2^254) (i : ℕ) (hi : i < 254) :
    bitA ((Fin.toBitsLE (⟨x, hx⟩ : Fin (2^254))).map Bool.toZMod) i = Bool.toZMod (x.testBit i) := by
  unfold bitA
  rw [List.Vector.get_map, List.Vector.get_eq_getElem', Fin.getElem_toBitsLE _ _ (Nat.mod_lt _ (by norm_num)),
    Fin.val_mk, Nat.mod_eq_of_lt hi]

lemma psum_bits (x : ℕ) (hx : x < 2^254) :
    ∀ n ≤ 254, psum ((Fin.toBitsLE (⟨x, hx⟩ : Fin (2^254))).map Bool.toZMod) n = ((x % 2^n : ℕ) : F)
  | 0, _ => by simp [psum, Nat.mod_one]
  | n+1, hn => by
    rw [psum, psum_bits x hx n (by omega), bitA_toBitsLE x hx n (by omega), Nat.mod_two_pow_succ' x n]
    cases x.testBit n <;> simp [Bool.toZMod]

/-- Booleanity, recomposition to `V` and the `p - 1` chain force the hinted
digits to be the canonical bits of `V.val`. -/
theorem fieldBytes_canonical {g : List.Vector F 254} {V s : F} (hB : boolsUpTo g 254)
    (hs : s = psum g 254) (hrec : Gates.eq s V) (hC : leqCstChain (Order - 1) (bitA g) 254 1) :
    ∀ i : Fin 254, g.get i = Bool.toZMod (V.val.testBit i.val) := by
  have hbool : ∀ i : Fin 254, g.get i = Bool.toZMod (decide (g.get i = 1)) := by
    intro i
    have h := boolsUpTo_get hB i.val i.prop
    unfold bitA at h
    rw [show (⟨i.val % 254, _⟩ : Fin 254) = i from Fin.ext (Nat.mod_eq_of_lt i.prop)] at h
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] at h
    rw [is_bool_is_bit] at h
    rcases h with h | h <;> simp [h]
  obtain ⟨bv, hg⟩ : ∃ bv : List.Vector Bool 254, g = bv.map Bool.toZMod := by
    refine ⟨List.Vector.ofFn fun i => decide (g.get i = 1), ?_⟩
    apply List.Vector.ext
    intro i
    rw [List.Vector.get_map, List.Vector.get_ofFn]
    exact hbool i
  obtain ⟨x, hx, hbv⟩ : ∃ (x : ℕ) (hx : x < 2^254), bv = Fin.toBitsLE (⟨x, hx⟩ : Fin (2^254)) :=
    ⟨_, (Fin.ofBitsLE bv).prop, (Fin.toBitsLE_ofBitsLE_eq_self (v := bv)).symm⟩
  subst hbv
  subst hg
  rw [psum_bits x hx 254 le_rfl, Nat.mod_eq_of_lt hx] at hs
  subst hs
  have hchain := (leqCstChain_congr 254 1 (fun j hj => bitA_toBitsLE x hx j hj)).mp hC
  rw [← toZMod_true_F] at hchain
  have hle := (leqCstChain_bits (Order - 1) x 254 true).mp hchain rfl
  rw [Order_sub_one_mod, Nat.mod_eq_of_lt hx] at hle
  have hxO : x < Order := by have := Order_pos; omega
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq] at hrec
  have hval : V.val = x := by rw [← hrec, ZMod.val_cast_of_lt hxO]
  intro i
  rw [hval, List.Vector.get_map, List.Vector.get_eq_getElem', Fin.getElem_toBitsLE _ _ i.prop]

lemma pad_zero (V : F) (j : ℕ) (hj : 254 ≤ j) : (0:F) = Bool.toZMod (V.val.testBit j) := by
  rw [Nat.testBit_lt_two_pow (Nat.lt_of_lt_of_le (F.val_lt_2_254 V)
    (Nat.pow_le_pow_right (by norm_num) hj))]
  rfl

theorem fb_byte (x : ℕ) (j : Fin 32) {e0 e1 e2 e3 e4 e5 e6 e7 b : F}
    (h0 : e0 = Bool.toZMod (x.testBit ((31 - j.val) * 8 + 0)))
    (h1 : e1 = Bool.toZMod (x.testBit ((31 - j.val) * 8 + 1)))
    (h2 : e2 = Bool.toZMod (x.testBit ((31 - j.val) * 8 + 2)))
    (h3 : e3 = Bool.toZMod (x.testBit ((31 - j.val) * 8 + 3)))
    (h4 : e4 = Bool.toZMod (x.testBit ((31 - j.val) * 8 + 4)))
    (h5 : e5 = Bool.toZMod (x.testBit ((31 - j.val) * 8 + 5)))
    (h6 : e6 = Bool.toZMod (x.testBit ((31 - j.val) * 8 + 6)))
    (h7 : e7 = Bool.toZMod (x.testBit ((31 - j.val) * 8 + 7)))
    (h : Gates.from_binary vec![e0, e1, e2, e3, e4, e5, e6, e7] b) :
    b = ((byteOf x j : ℕ) : F) := by
  have hv : (vec![e0, e1, e2, e3, e4, e5, e6, e7] : List.Vector F 8) =
      (Fin.toBitsLE (⟨byteOf x j, byteOf_lt _ _⟩ : Fin (2^8))).map Bool.toZMod := by
    rw [← ofFn_testBit_eq_toBitsLE]
    have hbit : ∀ m : ℕ, m < 8 → (byteOf x j).testBit m = x.testBit ((31 - j.val) * 8 + m) := by
      intro m hm
      unfold byteOf
      rw [show (256:ℕ) = 2^8 by norm_num, Nat.testBit_mod_two_pow, ← pow_mul,
        Nat.testBit_div_two_pow]
      simp [hm, Nat.mul_comm 8, Nat.add_comm]
    apply List.Vector.ext
    intro m
    rw [List.Vector.get_ofFn, hbit m.val m.prop]
    fin_cases m
    · exact h0
    · exact h1
    · exact h2
    · exact h3
    · exact h4
    · exact h5
    · exact h6
    · exact h7
  rw [hv] at h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    Gates.from_binary_iff_eq_ofBitsLE_mod_order, Fin.ofBitsLE_toBitsLE_eq_self] at h
  exact h

end ZolanaVE.Kdf
