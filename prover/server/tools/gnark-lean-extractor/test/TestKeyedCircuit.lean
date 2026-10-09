import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace KeyedCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order

def KeyedGadget_h0000beef (In: F) (k: List.Vector F 2 -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.add In (7:F) ∧
    k vec![gate_0, (0:F)]

def circuit (In: F): Prop :=
    KeyedGadget_h0000beef In fun gate_0 =>
    Gates.eq gate_0[0] gate_0[1] ∧
    True

end KeyedCircuit