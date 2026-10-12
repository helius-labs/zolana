import VerifiableEncryption.Curve.CompletenessTripleArithmetic
import VerifiableEncryption.Field.CompletenessFlagCheck
import VerifiableEncryption.Field.CompletenessUnifiedSlope
import VerifiableEncryption.Field.CompletenessUnifiedY

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

def flagVector (b : Bool) (X : ElemVal 8) : List.Vector F 9 :=
  vec![(if b then 1 else 0), X.limbs.get 0, X.limbs.get 1, X.limbs.get 2,
    X.limbs.get 3, X.limbs.get 4, X.limbs.get 5, X.limbs.get 6, X.limbs.get 7]

theorem flagVector_inputs (b : Bool) (X : ElemVal 8) :
    limbLists [⟨1, bitElem b⟩, ⟨8, X⟩] = flagCheckInputs (flagVector b X) := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [vec8_toList X.limbs]
  rfl

def slopeVector (L X : ElemVal 8) (b : Bool) (PY PX Y : ElemVal 8) : List.Vector F 49 :=
  vec![L.limbs.get 0, L.limbs.get 1, L.limbs.get 2, L.limbs.get 3,
    L.limbs.get 4, L.limbs.get 5, L.limbs.get 6, L.limbs.get 7,
    X.limbs.get 0, X.limbs.get 1, X.limbs.get 2, X.limbs.get 3,
    X.limbs.get 4, X.limbs.get 5, X.limbs.get 6, X.limbs.get 7, (if b then 1 else 0),
    PY.limbs.get 0, PY.limbs.get 1, PY.limbs.get 2, PY.limbs.get 3,
    PY.limbs.get 4, PY.limbs.get 5, PY.limbs.get 6, PY.limbs.get 7,
    PX.limbs.get 0, PX.limbs.get 1, PX.limbs.get 2, PX.limbs.get 3,
    PX.limbs.get 4, PX.limbs.get 5, PX.limbs.get 6, PX.limbs.get 7,
    aElem.limbs.get 0, aElem.limbs.get 1, aElem.limbs.get 2, aElem.limbs.get 3,
    aElem.limbs.get 4, aElem.limbs.get 5, aElem.limbs.get 6, aElem.limbs.get 7,
    Y.limbs.get 0, Y.limbs.get 1, Y.limbs.get 2, Y.limbs.get 3,
    Y.limbs.get 4, Y.limbs.get 5, Y.limbs.get 6, Y.limbs.get 7]

theorem slopeVector_inputs (L X : ElemVal 8) (b : Bool) (PY PX Y : ElemVal 8) :
    limbLists [⟨8, L⟩, ⟨8, X⟩, ⟨1, bitElem b⟩, ⟨8, PY⟩, ⟨8, PX⟩, ⟨8, aElem⟩, ⟨8, Y⟩] =
      unifiedSlopeInputs (slopeVector L X b PY PX Y) := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [vec8_toList L.limbs, vec8_toList X.limbs, vec8_toList PY.limbs,
    vec8_toList PX.limbs, vec8_toList aElem.limbs, vec8_toList Y.limbs]
  rfl

end ZolanaVE.P256.Completeness
