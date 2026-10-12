import VerifiableEncryption.Circuit.Prelude

/-! The explicit completeness contract for the actual opaque row primitive.
This is separate from small-range completeness and from all curve arithmetic
witness constructors. A concrete backend must establish this contract at its
own implementation boundary; numerical challenge existence alone does not
prove it. -/

namespace ZolanaVE.P256.Completeness

def RowComplete : Prop :=
  ∀ (rows : List.Vector (List.Vector F 12) 16) (i : Fin 16)
    (k : List.Vector F 12 → Prop),
    k (rows.get i) → RowLookup_12_16 rows (i.val : F) k

theorem rowLookup_complete (hr : RowComplete)
    (rows : List.Vector (List.Vector F 12) 16) (i : Fin 16)
    (k : List.Vector F 12 → Prop) (hk : k (rows.get i)) :
    RowLookup_12_16 rows (i.val : F) k := hr rows i k hk

end ZolanaVE.P256.Completeness
