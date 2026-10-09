import FormalVerification.Lemmas
import VerifiableEncryption.Circuit.Prelude
import VerifiableEncryption.Field.Poly

/-!
Limb layout of `emfield` (`layout.go`, `field.go`, `rangecheck.go`).

An emulated element is a list of native limbs read with base `2^32`. The
circuit only ever constrains the limbs; the integers they stand for and their
compile-time bounds (`Element.lo/hi/valueMin/valueMax` in Go) are carried by
`ElemVal`, whose fields are exactly what a check consumes and produces.

Range checks are kept abstract: a check is a predicate `rc bits v`, and every
soundness statement takes `RangeSound rc` as an explicit hypothesis. For the
lookup layout `LookupCheck` spells out `RangeChecker.Check` in terms of an
opaque table predicate, and `lookupCheck_sound` derives `RangeSound` from the
idealised lookup argument.
-/

namespace ZolanaVE.Field

theorem order_eq : Order = ZolanaProver.Order := rfl

/-- The extracted circuits use their own copy of the BN254 scalar modulus; its
primality is the existing `bn254_Fr_prime` assumption. -/
instance : Fact (Nat.Prime Order) := ⟨order_eq ▸ bn254_Fr_prime⟩

def limbBase : ℤ := 2 ^ 32

/-- Integer read off a little-endian limb list with base `2^32`. -/
def recompose (l : List ℤ) : ℤ := evalAt l limbBase

theorem two_pow_253_lt_order : 2 ^ 253 < Order := by decide +kernel

theorem order_pos : 0 < Order := by decide +kernel

/-- A circuit element together with the integers its limbs stand for and the
certified bounds. Both limbwise and whole-value bounds are tracked because
`Select` keeps tighter value bounds than the limb sums. -/
structure ElemVal (w : ℕ) where
  limbs : List.Vector F w
  ints : List.Vector ℤ w
  lo : List.Vector ℤ w
  hi : List.Vector ℤ w
  vlo : ℤ
  vhi : ℤ
  h_cast : ∀ i : Fin w, limbs.get i = (ints.get i : F)
  h_lo : ∀ i : Fin w, lo.get i ≤ ints.get i
  h_hi : ∀ i : Fin w, ints.get i ≤ hi.get i
  h_vlo : vlo ≤ recompose ints.toList
  h_vhi : recompose ints.toList ≤ vhi

def ElemVal.value {w : ℕ} (e : ElemVal w) : ℤ := recompose e.ints.toList

theorem ElemVal.limbs_eq_map {w : ℕ} (e : ElemVal w) :
    e.limbs.toList = e.ints.toList.map (Int.cast : ℤ → F) := by
  apply List.ext_get
  · simp
  · intro n h1 h2
    have := e.h_cast ⟨n, by simpa using h1⟩
    simp only [List.Vector.get_eq_get_toList] at this
    simpa using this

/-! ### Range checks -/

/-- Lookup soundness, stated per call: every accepted value is below `2^bits`.
Only widths up to 253 are claimed, where the composed value cannot wrap. -/
def RangeSound (rc : ℕ → F → Prop) : Prop :=
  ∀ b v, b ≤ 253 → rc b v → v.val < 2 ^ b

/-- `RangeChecker.Compose`: piece `j` is checked to `min pieceBits (width - j * pieceBits)` bits. -/
def ComposeOk (rc : ℕ → F → Prop) (pb : ℕ) : ℕ → List F → Prop
  | w, [] => w = 0
  | w, p :: ps => 0 < w ∧ rc (min pb w) p ∧ ComposeOk rc pb (w - pb) ps

/-- The value `Compose` returns: `∑ j, pieces[j] * 2^(j * pieceBits)`. -/
def composeValue (pb : ℕ) (ps : List F) : F := evalAt ps ((2 : F) ^ pb)

theorem natCast_val_lt {N : ℕ} (h : N < Order) : ((N : F)).val = N :=
  ZMod.val_cast_of_lt h

theorem compose_sound {rc : ℕ → F → Prop} (hrc : RangeSound rc) {pb : ℕ} (hpb : 0 < pb)
    (hpb' : pb ≤ 253) :
    ∀ (w : ℕ) (ps : List F), ComposeOk rc pb w ps →
      ∃ N : ℕ, N < 2 ^ w ∧ composeValue pb ps = (N : F)
  | w, [], h => ⟨0, by simp [ComposeOk] at h; simp [h], by simp [composeValue]⟩
  | w, p :: ps, ⟨hw, hp, hrest⟩ => by
    obtain ⟨N, hN, hv⟩ := compose_sound hrc hpb hpb' (w - pb) ps hrest
    have hpv : p.val < 2 ^ (min pb w) := hrc _ _ ((min_le_left _ _).trans hpb') hp
    refine ⟨p.val + 2 ^ pb * N, ?_, ?_⟩
    · rcases le_or_lt w pb with hle | hlt
      · have : w - pb = 0 := by omega
        rw [this] at hN
        have hN0 : N = 0 := by simpa using hN
        rw [min_eq_right hle] at hpv
        simp [hN0, hpv]
      · rw [min_eq_left hlt.le] at hpv
        have h2 : 2 ^ w = 2 ^ pb * 2 ^ (w - pb) := by
          rw [← pow_add]; congr 1; omega
        have : 2 ^ pb * N + 2 ^ pb ≤ 2 ^ pb * 2 ^ (w - pb) := by
          rw [← mul_add_one]; exact Nat.mul_le_mul_left _ hN
        omega
    · simp only [composeValue, evalAt_cons] at hv ⊢
      rw [hv]
      push_cast
      rw [ZMod.natCast_zmod_val]

theorem compose_val_lt {rc : ℕ → F → Prop} (hrc : RangeSound rc) {pb : ℕ} (hpb : 0 < pb)
    (hpb' : pb ≤ 253) {w : ℕ} (hw : w ≤ 253) {ps : List F} (h : ComposeOk rc pb w ps) :
    (composeValue pb ps).val < 2 ^ w := by
  obtain ⟨N, hN, hv⟩ := compose_sound hrc hpb hpb' w ps h
  rw [hv, natCast_val_lt]
  · exact hN
  · exact lt_of_lt_of_le hN ((Nat.pow_le_pow_right (by norm_num) hw).trans two_pow_253_lt_order.le)

/-- `RangeChecker.Check` for widths at most `pieceBits`: zero, boolean, or a table lookup. -/
def SmallCheck (lookup : ℕ → F → Prop) (b : ℕ) (v : F) : Prop :=
  if b = 0 then v = 0 else if b = 1 then GatesDef.is_bool v else lookup b v

/-- `RangeChecker.Check` with the lookup layout: wide values are decomposed by a
hint into pieces that are composed back and checked one by one. -/
def LookupCheck (lookup : ℕ → F → Prop) (pb : ℕ) (b : ℕ) (v : F) : Prop :=
  if b ≤ pb then SmallCheck lookup b v
  else ∃ ps : List F, ComposeOk (SmallCheck lookup) pb b ps ∧ v = composeValue pb ps

/-- Idealised soundness of the log-derivative range table for the widths it serves. -/
def LookupSound (lookup : ℕ → F → Prop) (pb : ℕ) : Prop :=
  ∀ b v, 2 ≤ b → b ≤ pb → lookup b v → v.val < 2 ^ b

theorem is_bool_val {v : F} (h : GatesDef.is_bool v) : v.val < 2 ^ 1 := by
  unfold GatesDef.is_bool at h
  rcases mul_eq_zero.mp h with h | h
  · have : v = 1 := by linear_combination -h
    subst this; rw [ZMod.val_one]; norm_num
  · subst h; simp

theorem smallCheck_sound {lookup : ℕ → F → Prop} {pb : ℕ} (hl : LookupSound lookup pb) :
    ∀ b v, b ≤ pb → SmallCheck lookup b v → v.val < 2 ^ b := by
  intro b v hb h
  unfold SmallCheck at h
  split_ifs at h with h0 h1
  · subst h; simp
  · subst h1; exact is_bool_val h
  · exact hl b v (by omega) hb h

theorem lookupCheck_sound {lookup : ℕ → F → Prop} {pb : ℕ} (hpb : 0 < pb) (hpb' : pb ≤ 253)
    (hl : LookupSound lookup pb) : RangeSound (LookupCheck lookup pb) := by
  intro b v hb h
  unfold LookupCheck at h
  split_ifs at h with hle
  · exact smallCheck_sound hl b v hle h
  · obtain ⟨ps, hps, rfl⟩ := h
    have hs : RangeSound (fun b v => b ≤ pb ∧ SmallCheck lookup b v) := by
      intro b v _ h; exact smallCheck_sound hl b v h.1 h.2
    have hps' : ComposeOk (fun b v => b ≤ pb ∧ SmallCheck lookup b v) pb b ps := by
      clear hb hle
      induction ps generalizing b with
      | nil => exact hps
      | cons p ps ih => exact ⟨hps.1, ⟨min_le_left _ _, hps.2.1⟩, ih _ hps.2.2⟩
    exact compose_val_lt hs hpb hpb' hb hps'

/-! ### Hinted elements -/

/-- `nbPieces`: pieces needed for a limb of `w` bits. -/
def nbPieces (pb w : ℕ) : ℕ := (w + pb - 1) / pb

/-- `Field.fromPieces`: limbs composed from consecutive runs of hinted pieces. -/
def limbsOfPieces (pb : ℕ) : List ℕ → List F → List F
  | [], _ => []
  | w :: ws, ps => composeValue pb (ps.take (nbPieces pb w)) :: limbsOfPieces pb ws (ps.drop (nbPieces pb w))

/-- The range checks `Field.fromPieces` emits, together with the piece count. -/
def PiecesOk (rc : ℕ → F → Prop) (pb : ℕ) : List ℕ → List F → Prop
  | [], ps => ps = []
  | w :: ws, ps => nbPieces pb w ≤ ps.length ∧ ComposeOk rc pb w (ps.take (nbPieces pb w)) ∧
      PiecesOk rc pb ws (ps.drop (nbPieces pb w))

theorem piecesOk_limbs {rc : ℕ → F → Prop} (hrc : RangeSound rc) {pb : ℕ} (hpb : 0 < pb)
    (hpb' : pb ≤ 253) :
    ∀ (ws : List ℕ) (ps : List F), (∀ w ∈ ws, w ≤ 253) → PiecesOk rc pb ws ps →
      List.Forall₂ (fun (l : F) w => l.val < 2 ^ w) (limbsOfPieces pb ws ps) ws
  | [], _, _, _ => List.Forall₂.nil
  | w :: ws, ps, hw, ⟨_, hc, hr⟩ =>
    List.Forall₂.cons (compose_val_lt hrc hpb hpb' (hw w (by simp)) hc)
      (piecesOk_limbs hrc hpb hpb' ws _ (fun w' h => hw w' (by simp [h])) hr)

end ZolanaVE.Field
