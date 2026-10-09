import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace ScaleCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order

def ScaleGadget_4_h9d28b8ef (In: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In (3:F) ∧
    k gate_0

def ScaleGadget_4_h33a5d7fb (In: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In (5:F) ∧
    k gate_0

def ScaleGadget_4_h77598b64 (In: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In (5:F) ∧
    ∃gate_1, gate_1 = Gates.mul gate_0 gate_0 ∧
    k gate_1

def circuit (In: F): Prop :=
    ScaleGadget_4_h9d28b8ef In fun gate_0 =>
    ScaleGadget_4_h33a5d7fb gate_0 fun gate_1 =>
    ScaleGadget_4_h33a5d7fb gate_1 fun gate_2 =>
    ScaleGadget_4_h77598b64 gate_2 fun gate_3 =>
    Gates.eq gate_3 (0:F) ∧
    True

end ScaleCircuit