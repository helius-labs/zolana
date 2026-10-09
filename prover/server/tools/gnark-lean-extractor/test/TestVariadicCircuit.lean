import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace VariadicCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order



def circuit (A: F) (B: F) (C: F) (D: F): Prop :=
    ∃gate_0, gate_0 = Gates.add (Gates.add A B) C ∧
    ∃gate_1, gate_1 = Gates.add (Gates.add (Gates.add A B) C) D ∧
    Gates.eq gate_0 gate_1 ∧
    ∃gate_3, gate_3 = Gates.sub (Gates.sub A B) C ∧
    ∃gate_4, gate_4 = Gates.sub (Gates.sub (Gates.sub A B) C) D ∧
    Gates.eq gate_3 gate_4 ∧
    ∃gate_6, gate_6 = Gates.mul (Gates.mul A B) C ∧
    ∃gate_7, gate_7 = Gates.mul (Gates.mul (Gates.mul A B) C) D ∧
    Gates.eq gate_6 gate_7 ∧
    True

end VariadicCircuit