import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace SplitCircuit

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order

def SplitGadget_3_p2 (In: List.Vector F 3) (gate_0: List.Vector F 2) (gate_1: F) (gate_3: F) (k: List.Vector F 2 -> Prop): Prop :=
    Gates.is_bool (gate_0.get (0 : Fin 2)) ∧
    ∃gate_5, gate_5 = Gates.add (Gates.add gate_1 gate_3) (gate_0.get (0 : Fin 2)) ∧
    k vec![gate_5, gate_1]

def SplitGadget_3_p1 (In: List.Vector F 3) (gate_0: List.Vector F 2) (gate_1: F) (k: List.Vector F 2 -> Prop): Prop :=
    ∃gate_2, gate_2 = Gates.add gate_1 (In.get (2 : Fin 3)) ∧
    ∃gate_3, gate_3 = Gates.mul gate_2 (gate_0.get (1 : Fin 2)) ∧
    SplitGadget_3_p2 In gate_0 gate_1 gate_3 k

def SplitGadget_3 (In: List.Vector F 3) (k: List.Vector F 2 -> Prop): Prop :=
    ∃gate_0 : List.Vector F 2, -- hint github.com/reilabs/gnark-lean-extractor/v3/extractor/test_test.splitHint
    ∃gate_1, gate_1 = Gates.mul (In.get (0 : Fin 3)) (In.get (1 : Fin 3)) ∧
    SplitGadget_3_p1 In gate_0 gate_1 k

def SplitCircuit_3_p1 (In: List.Vector F 3) (Out: F) (gate_0: List.Vector F 2) (gate_1: F): Prop :=
    Gates.eq gate_1 Out ∧
    Gates.eq (gate_0.get (1 : Fin 2)) (In.get (0 : Fin 3)) ∧
    True

def SplitCircuit_3 (In: List.Vector F 3) (Out: F): Prop :=
    SplitGadget_3 In fun gate_0 =>
    ∃gate_1, gate_1 = Gates.mul (gate_0.get (0 : Fin 2)) (In.get (2 : Fin 3)) ∧
    SplitCircuit_3_p1 In Out gate_0 gate_1

end SplitCircuit