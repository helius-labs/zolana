import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace HintCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order

def HintGadget (In: F) (k: List.Vector F 2 -> Prop): Prop :=
    ∃gate_0 : List.Vector F 2, -- hint github.com/reilabs/gnark-lean-extractor/v3/extractor/test_test.splitHint
    ∃gate_1, gate_1 = Gates.mul gate_0[1] (2:F) ∧
    ∃gate_2, gate_2 = Gates.add gate_0[0] gate_1 ∧
    Gates.eq gate_2 In ∧
    k gate_0

def circuit (In: F) (Out: F): Prop :=
    ∃gate_0 : List.Vector F 3, -- hint github.com/reilabs/gnark-lean-extractor/v3/extractor/test_test.splitHint
    Gates.is_bool gate_0[2] ∧
    ∃_ignored_ : List.Vector F 1, -- hint github.com/reilabs/gnark-lean-extractor/v3/extractor/test_test.splitHint
    HintGadget Out fun gate_3 =>
    Gates.eq gate_3[1] gate_0[0] ∧
    True

end HintCircuit