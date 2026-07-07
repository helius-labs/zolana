import ProvenZk
import FormalVerification.Poseidon
import FormalVerification.Circuit
import FormalVerification.Lemmas

open ZolanaProver (F)

/-!
Model of the nullifier indexed Merkle tree as a vector of open ranges.

Unlike the light-protocol address tree (values truncated to 31 bytes), the
zolana nullifier tree stores full canonical field elements: the initial leaf is
`(0, p - 1)` and the insertable domain is `0 < v < p - 1`. Ranges are therefore
bounded by field elements and compared on their canonical values, matching the
full-field ordering gadget.
-/

structure Range : Type where
  lo : F
  hi : F
  valid : lo.val < hi.val

instance : Membership Nat Range where
  mem r x := r.lo.val < x ∧ x < r.hi.val

instance : Membership Nat (Option Range) where
  mem r x := match r with
    | none => false
    | some r => x ∈ r

def Range.disjoint (r₁ r₂ : Range) : Prop := r₁.hi.val ≤ r₂.lo.val ∨ r₂.hi.val ≤ r₁.lo.val

lemma isSome_of_mem {v : Nat} {r : Option Range} (h: v ∈ r): r.isSome := by
  cases r
  simp [Membership.mem] at h
  rfl

lemma mem_of_mem {v : Nat} {r : Range}: v ∈ some r → v ∈ r := by
  simp [Membership.mem]

lemma hi_ne_zero_of_mem {v : Nat} {r : Range} : v ∈ r → r.hi ≠ 0 := by
  rintro ⟨_, hlt⟩ heq
  rw [heq] at hlt
  simp [ZMod.val_zero] at hlt

structure RangeVector (l : ℕ) : Type where
  ranges : Fin l → Option Range
  rangesDisjoint : ∀ (i j : Fin l), i ≠ j → match ranges i with
    | none => True
    | some ri => match ranges j with
      | none => True
      | some rj => ri.disjoint rj

instance {l : ℕ} : Membership Nat (RangeVector l) where
  mem rv x := ∃(j : Fin l) (r : Range), x ∈ r ∧ some r = rv.ranges j

def Range.hash : Range → F := fun r => poseidon₂ vec![r.lo, r.hi]

def Range.hashOpt : Option Range → F := fun r => r.map Range.hash |>.getD 0

def poseidon₂_no_zero_preimage : Prop := ∀(a b : F), poseidon₂ vec![a, b] ≠ 0

def MerkleTree.ofFn (H : Hash α 2) (emb : β → α) (f : Fin (2^d) → β) : MerkleTree α H d := match d with
  | 0 => leaf (emb (f 0))
  | Nat.succ d' => bin (MerkleTree.ofFn H emb (fun i => f i)) (MerkleTree.ofFn H emb (fun i => f (i + 2^d')))

@[ext]
theorem MerkleTree.ext : ∀{t₁ t₂ : MerkleTree α H D}, (∀i, t₁.itemAtFin i = t₂.itemAtFin i) → t₁ = t₂ := by
  intro t₁ t₂ hp
  induction D with
  | zero =>
    cases t₁; cases t₂
    have := hp 0
    cases this
    rfl
  | succ D ih =>
    simp only [itemAtFin] at *
    cases t₁
    cases t₂
    apply congrArg₂
    · apply ih
      intro i
      have := hp i
      simp only [Fin.toBitsBE] at this
      simp only [Fin.msb, Fin.lsbs] at this
      have hlt : ¬(i : Fin (2^(D+1))).val ≥ 2^D := by
        cases i
        simp
        rw [Nat.mod_eq_of_lt]
        assumption
        apply lt_trans
        assumption
        simp [Nat.pow_succ]
      simp only [hlt, decide_false, itemAt, treeFor, List.Vector.head_cons, left, List.Vector.tail_cons, Bool.toNat, cond_false, zero_mul, Nat.sub_zero] at this
      convert this using 3 <;> {
        cases i
        simp
        rw [Nat.mod_eq_of_lt]
        apply lt_trans
        assumption
        simp [Nat.pow_succ]
      }
    · apply ih
      intro i
      have := hp ⟨2^D + i.val, by cases i; simp [Nat.pow_succ]; linarith⟩
      simp only [Fin.toBitsBE, Fin.msb, Fin.lsbs] at this
      simp [itemAt, treeFor, right] at this
      exact this

lemma Fin.lt_of_msb_zero {x : Fin (2^(d+1))} (h : Fin.msb x = false): x.val < 2^d := by
  rw [Fin.msbs_lsbs_decomposition (v:=x)]
  simp_all

lemma Fin.pow_def [NeZero k] {a : Fin k}: (a ^ d).val = (a.val ^ d) % k := by
  induction d with
  | zero => simp []
  | succ d ih =>
    simp [pow_succ, Fin.val_mul, ih]

lemma Fin.ofNat2 (h : n > 2) [NeZero n] : (2 : Fin n).val = 2 := by
  simp [OfNat.ofNat, Nat.mod_eq_of_lt h]

lemma MerkleTree.ofFn_itemAtFin {fn : Fin (2^d) → α} : (ofFn H emb fn |>.itemAtFin idx) = emb (fn idx) := by
  induction d with
  | zero =>
    fin_cases idx
    rfl
  | succ d ih =>
    simp only [itemAtFin] at *
    simp only [Fin.toBitsBE, itemAt, ofFn]
    conv => rhs; rw [Fin.msbs_lsbs_decomposition (v := idx)]
    cases h: idx.msb
    · have := Fin.lt_of_msb_zero h
      simp [treeFor, left, ih, Fin.natCast_def, Nat.mod_eq_of_lt, *]
    · simp [treeFor, right, ih, add_comm, Fin.add_def, List.Vector.head_cons]
      generalize_proofs
      congr
      cases d
      · simp
      · rename_i d _ _ _ _
        have : ((2 : Fin (2 ^ (d + 2))) ^ (d+1)).val = 2 ^ (d+1) := by
          simp [Fin.pow_def]
          rw [Fin.ofNat2]
          · rw [Nat.mod_eq_of_lt]
            simp [Nat.pow_succ]
          · simp [Nat.pow_succ];
            rw [←Nat.mul_one (n:=1)]
            apply Nat.mul_lt_mul_of_le_of_lt
            · apply Nat.one_le_pow; simp
            · simp
            · simp
        simp [this]
        rw [Nat.mod_eq_of_lt]
        congr

def rangeTree (r : RangeVector (2^d)) : MerkleTree F poseidon₂ d :=
    MerkleTree.ofFn poseidon₂ Range.hashOpt r.ranges

def RangeVector.root (r : RangeVector (2^d)) : F := rangeTree r |>.root
