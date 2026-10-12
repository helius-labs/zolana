import ProvenZk

/-!
Deterministic collision reductions. `ProvenZk.CollisionResistant` means global
injectivity, which is not a possible security assumption for a compression
function on a finite field. These statements instead return two distinct
compression inputs with the same output. The Merkle reduction locates those
inputs at a level of the supplied path; it does not appeal to an unrelated
collision elsewhere in the field.
-/

namespace HashReduction

def Collision {α : Type} (H : Hash α 2) : Prop :=
  ∃ a b : List.Vector α 2, a ≠ b ∧ H a = H b

/-- An authentic path recovers its root for every compression function. -/
theorem recover_proof {α : Type} {H : Hash α 2} {d : ℕ}
    (tree : MerkleTree α H d) (ix : List.Vector Bool d) :
    MerkleTree.recover H ix (tree.proof ix) (tree.itemAt ix) = tree.root := by
  induction d with
  | zero => cases tree; rfl
  | succ d ih =>
    cases tree
    cases ix using List.Vector.casesOn with
    | cons dir dirs =>
      cases dir <;>
        simp only [MerkleTree.recover, MerkleTree.proof, MerkleTree.itemAt,
          MerkleTree.root, MerkleTree.treeFor, MerkleTree.left, MerkleTree.right,
          List.Vector.head_cons, List.Vector.tail_cons, Bool.not_false,
          Bool.not_true, ih]

theorem recoverAtFin_proof {α : Type} {H : Hash α 2} {d : ℕ}
    (tree : MerkleTree α H d) (ix : Fin (2 ^ d)) :
    MerkleTree.recoverAtFin H ix (tree.proofAtFin ix) (tree.itemAtFin ix) = tree.root :=
  recover_proof tree ix.toBitsBE

/-- Candidate and authentic compression inputs, ordered from root to leaf. -/
def recoveryPairs {α : Type} {H : Hash α 2} {d : ℕ}
    (tree : MerkleTree α H d) (ix : List.Vector Bool d)
    (siblings : List.Vector α d) (item : α) :
    List (List.Vector α 2 × List.Vector α 2) :=
  match d, tree with
  | 0, .leaf _ => []
  | _ + 1, .bin l r =>
    let recovered := MerkleTree.recover H ix.tail siblings.tail item
    match ix.head with
    | false => (vec![recovered, siblings.head], vec![l.root, r.root]) ::
        recoveryPairs l ix.tail siblings.tail item
    | true => (vec![siblings.head, recovered], vec![l.root, r.root]) ::
        recoveryPairs r ix.tail siblings.tail item

/-- Equal roots imply a correct opening, or a collision at a supplied path level. -/
theorem recover_correct_or_collision {α : Type} {H : Hash α 2} {d : ℕ}
    {tree : MerkleTree α H d} {ix : List.Vector Bool d}
    {siblings : List.Vector α d} {item : α}
    (h : MerkleTree.recover H ix siblings item = tree.root) :
    (siblings = tree.proof ix ∧ item = tree.itemAt ix) ∨
      ∃ pair ∈ recoveryPairs tree ix siblings item,
        pair.1 ≠ pair.2 ∧ H pair.1 = H pair.2 := by
  classical
  induction d with
  | zero =>
    cases tree
    cases ix using List.Vector.casesOn
    cases siblings using List.Vector.casesOn
    exact Or.inl ⟨rfl, h⟩
  | succ d ih =>
    cases tree with
    | bin l r =>
      cases ix using List.Vector.casesOn with
      | cons dir dirs =>
        cases siblings using List.Vector.casesOn with
        | cons sibling rest =>
          cases dir
          · change H vec![MerkleTree.recover H dirs rest item, sibling] =
                H vec![l.root, r.root] at h
            by_cases he : vec![MerkleTree.recover H dirs rest item, sibling] =
                vec![l.root, r.root]
            · have hl := congrArg (fun v : List.Vector α 2 => v.get 0) he
              have hr := congrArg (fun v : List.Vector α 2 => v.get 1) he
              change MerkleTree.recover H dirs rest item = l.root at hl
              change sibling = r.root at hr
              rcases ih hl with ⟨hp, hi⟩ | ⟨pair, hm, hc⟩
              · left
                constructor
                · simpa only [MerkleTree.proof, MerkleTree.treeFor, MerkleTree.left,
                    MerkleTree.right, List.Vector.head_cons, List.Vector.tail_cons,
                    Bool.not_false] using congrArg₂ List.Vector.cons hr hp
                · exact hi
              · right
                exact ⟨pair, List.mem_cons_of_mem _ hm, hc⟩
            · right
              exact ⟨(_, _), List.mem_cons_self _ _, he, h⟩
          · change H vec![sibling, MerkleTree.recover H dirs rest item] =
                H vec![l.root, r.root] at h
            by_cases he : vec![sibling, MerkleTree.recover H dirs rest item] =
                vec![l.root, r.root]
            · have hl := congrArg (fun v : List.Vector α 2 => v.get 0) he
              have hr := congrArg (fun v : List.Vector α 2 => v.get 1) he
              change sibling = l.root at hl
              change MerkleTree.recover H dirs rest item = r.root at hr
              rcases ih hr with ⟨hp, hi⟩ | ⟨pair, hm, hc⟩
              · left
                constructor
                · simpa only [MerkleTree.proof, MerkleTree.treeFor, MerkleTree.left,
                    MerkleTree.right, List.Vector.head_cons, List.Vector.tail_cons,
                    Bool.not_true] using congrArg₂ List.Vector.cons hl hp
                · exact hi
              · right
                exact ⟨pair, List.mem_cons_of_mem _ hm, hc⟩
            · right
              exact ⟨(_, _), List.mem_cons_self _ _, he, h⟩

theorem recoverAtFin_correct_or_collision {α : Type} {H : Hash α 2} {d : ℕ}
    {tree : MerkleTree α H d} {ix : Fin (2 ^ d)}
    {siblings : List.Vector α d} {item : α}
    (h : MerkleTree.recoverAtFin H ix siblings item = tree.root) :
    (siblings = tree.proofAtFin ix ∧ item = tree.itemAtFin ix) ∨
      ∃ pair ∈ recoveryPairs tree ix.toBitsBE siblings item,
        pair.1 ≠ pair.2 ∧ H pair.1 = H pair.2 :=
  recover_correct_or_collision h

/-- The collision is drawn from the two chains' actual compression inputs. -/
def chainPairs {α : Type} (H : Hash α 2) {d : ℕ} (a b : α)
    (xs ys : List.Vector α d) : List (List.Vector α 2 × List.Vector α 2) :=
  match d with
  | 0 => []
  | _ + 1 => (vec![a, xs.head], vec![b, ys.head]) ::
      chainPairs H (H vec![a, xs.head]) (H vec![b, ys.head]) xs.tail ys.tail

theorem chain_correct_or_collision {α : Type} {H : Hash α 2} {d : ℕ}
    {a b : α} {xs ys : List.Vector α d}
    (h : xs.toList.foldl (fun z x => H vec![z, x]) a =
      ys.toList.foldl (fun z x => H vec![z, x]) b) :
    (a = b ∧ xs = ys) ∨
      ∃ pair ∈ chainPairs H a b xs ys,
        pair.1 ≠ pair.2 ∧ H pair.1 = H pair.2 := by
  classical
  induction d generalizing a b with
  | zero =>
    cases xs using List.Vector.casesOn
    cases ys using List.Vector.casesOn
    exact Or.inl ⟨h, rfl⟩
  | succ d ih =>
    cases xs using List.Vector.casesOn with
    | cons x xs =>
      cases ys using List.Vector.casesOn with
      | cons y ys =>
        rcases ih h with ⟨hh, ht⟩ | ⟨pair, hm, hc⟩
        · by_cases he : vec![a, x] = vec![b, y]
          · have ha := congrArg (fun v : List.Vector α 2 => v.get 0) he
            have hx := congrArg (fun v : List.Vector α 2 => v.get 1) he
            exact Or.inl ⟨ha, congrArg₂ List.Vector.cons hx ht⟩
          · exact Or.inr ⟨(_, _), List.mem_cons_self _ _, he, hh⟩
        · exact Or.inr ⟨pair, List.mem_cons_of_mem _ hm, hc⟩

end HashReduction
