import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace NamedConstantCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order

abbrev K_0 : F := 7
abbrev K_1 : F := 0

def KeyedGadget_h0000beef (In: F) (k: List.Vector F 2 -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.add In K_0 ∧
    k vec![gate_0, K_1]

def KeyedCircuit (In: F): Prop :=
    KeyedGadget_h0000beef In fun gate_0 =>
    Gates.eq gate_0[0] gate_0[1] ∧
    True

end NamedConstantCircuit