import ProvenZk

/-!
Poseidon is modelled as the concrete function `poseidon₂ : F² → F`. It maps `p²`
inputs into `p` outputs, so it is not injective, and assuming it were (ProvenZk's
`CollisionResistant`) would make every theorem provable. Soundness is stated as
an extraction instead: a satisfying witness either proves the claimed statement
or exhibits a `Collision` between concrete hash inputs read off the witness and
the public trees. Finding one breaks Poseidon's collision resistance.
-/

/-- Distinct inputs with the same hash. -/
def Collision {F : Type} {n : Nat} (H : Hash F n) (a b : List.Vector F n) : Prop :=
  a ≠ b ∧ H a = H b

lemma eq_or_collision {F : Type} {n : Nat} {H : Hash F n} {a b : List.Vector F n}
    (h : H a = H b) : a = b ∨ Collision H a b := by
  by_cases hab : a = b
  · exact Or.inl hab
  · exact Or.inr ⟨hab, h⟩

namespace MerkleTree

/-- At some level of the path, the input `recover` hashes (rebuilt from `proof`
and `item`) differs from the tree's own node input, yet both hash to the node. -/
def recoverCollision {F : Type} {H : Hash F 2} :
    {d : Nat} → MerkleTree F H d → List.Vector Bool d → List.Vector F d → F → Prop
  | 0, _, _, _, _ => False
  | _ + 1, bin l r, ix, proof, item =>
    let sub := recover H ix.tail proof.tail item
    Collision H
        (match ix.head with
          | false => vec![sub, proof.head]
          | true => vec![proof.head, sub])
        vec![l.root, r.root] ∨
      recoverCollision ((bin l r).treeFor ix.head) ix.tail proof.tail item

theorem recover_eq_root {F : Type} {H : Hash F 2} {d : Nat} {tree : MerkleTree F H d}
    {ix : List.Vector Bool d} {proof : List.Vector F d} {item : F}
    (h : recover H ix proof item = tree.root) :
    (proof = tree.proof ix ∧ item = tree.itemAt ix) ∨ tree.recoverCollision ix proof item := by
  induction d with
  | zero =>
    cases tree
    cases ix using List.Vector.casesOn
    cases proof using List.Vector.casesOn
    exact Or.inl ⟨rfl, h⟩
  | succ n ih =>
    cases tree with | bin l r =>
    cases proof using List.Vector.casesOn with | cons p ps =>
    cases ix using List.Vector.casesOn with | cons b bs =>
    cases b <;> simp only [recover, root, List.Vector.head_cons, List.Vector.tail_cons] at h
    · rcases eq_or_collision h with heq | hcol
      · simp only [List.Vector.eq_cons, and_true] at heq
        rcases ih heq.1 with ⟨hps, hitem⟩ | hcol
        · left
          simp [MerkleTree.proof, itemAt, treeFor, left, right, heq.2, hps, hitem]
        · right
          exact Or.inr hcol
      · exact Or.inr (Or.inl hcol)
    · rcases eq_or_collision h with heq | hcol
      · simp only [List.Vector.eq_cons, and_true] at heq
        rcases ih heq.2 with ⟨hps, hitem⟩ | hcol
        · left
          simp [MerkleTree.proof, itemAt, treeFor, left, right, heq.1, hps, hitem]
        · right
          exact Or.inr hcol
      · exact Or.inr (Or.inl hcol)

theorem recover_proof_itemAt {F : Type} {H : Hash F 2} {d : Nat} {tree : MerkleTree F H d}
    {ix : List.Vector Bool d} :
    recover H ix (tree.proof ix) (tree.itemAt ix) = tree.root := by
  induction d with
  | zero =>
    cases tree
    rfl
  | succ n ih =>
    cases tree with | bin l r =>
    cases ix using List.Vector.casesOn with | cons b bs =>
    cases b <;> simp [recover, MerkleTree.proof, itemAt, treeFor, left, right, root, ih]

theorem recoverAtFin_eq_root {F : Type} {H : Hash F 2} {d : Nat} {tree : MerkleTree F H d}
    {ix : Fin (2^d)} {proof : List.Vector F d} {item : F}
    (h : recoverAtFin H ix proof item = tree.root) :
    (proof = tree.proofAtFin ix ∧ item = tree.itemAtFin ix) ∨
      tree.recoverCollision ix.toBitsBE proof item :=
  recover_eq_root h

theorem recoverAtFin_proofAtFin_itemAtFin {F : Type} {H : Hash F 2} {d : Nat}
    {tree : MerkleTree F H d} {ix : Fin (2^d)} :
    recoverAtFin H ix (tree.proofAtFin ix) (tree.itemAtFin ix) = tree.root :=
  recover_proof_itemAt

end MerkleTree
