import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace NestedOutputCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order

def SingletonGadget (A: F) (k: List.Vector F 1 -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul A A ∧
    k vec![gate_0]

def PairGadget (A: F) (B: F) (k: List.Vector (List.Vector F 2) 2 -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.add A B ∧
    ∃gate_1, gate_1 = Gates.mul A B ∧
    k vec![vec![gate_0, gate_1], vec![gate_1, gate_0]]

def circuit (A: F) (B: F): Prop :=
    SingletonGadget A fun gate_0 =>
    Gates.eq gate_0[0] B ∧
    PairGadget A B fun gate_2 =>
    Gates.eq gate_2[0][1] gate_2[1][0] ∧
    ∃gate_4, gate_4 = Gates.add (Gates.add gate_2[0][0] gate_2[1][1]) gate_2[0][1] ∧
    Gates.eq gate_4 (0:F) ∧
    True

end NestedOutputCircuit