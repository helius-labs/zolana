import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace OpaqueCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order

opaque OpaqueRange (Bits: ℕ) (V: F) : Prop

opaque OpaqueRow_3_2 (Rows: List.Vector (List.Vector F 3) 2) (Index: F) (k: List.Vector F 3 -> Prop): Prop

opaque OpaqueEntry (Index: F) (k: F -> Prop): Prop

def circuit (Rows: List.Vector (List.Vector F 3) 2) (Index: F): Prop :=
    OpaqueRange 1 Index ∧
    OpaqueRange 11 Rows[0][1] ∧
    OpaqueRow_3_2 Rows Index fun gate_2 =>
    OpaqueEntry gate_2[2] fun gate_3 =>
    OpaqueEntry gate_3 fun gate_4 =>
    Gates.eq gate_4 gate_2[0] ∧
    True

end OpaqueCircuit