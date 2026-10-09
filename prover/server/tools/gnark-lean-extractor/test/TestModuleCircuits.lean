-- module Mods.Circuit
import Mods.Circuit.Prelude
import Mods.Circuit.Hints
import Mods.Circuit.Scale
import Mods.Circuit.Scale2
import Mods.Circuit.Scale3
import Mods.Circuit.Top

-- module Mods.Circuit.Hints
import Mods.Circuit.Prelude

set_option linter.unusedVariables false

namespace ModuleCircuits

variable [Fact (Nat.Prime Order)]

def HintGadget (In: F) (k: List.Vector F 2 -> Prop): Prop :=
    ∃gate_0 : List.Vector F 2, -- hint github.com/reilabs/gnark-lean-extractor/v3/extractor/test_test.splitHint
    ∃gate_1, gate_1 = Gates.mul gate_0[1] (2:F) ∧
    ∃gate_2, gate_2 = Gates.add gate_0[0] gate_1 ∧
    Gates.eq gate_2 In ∧
    k gate_0

end ModuleCircuits

-- module Mods.Circuit.Prelude
import ProvenZk.Gates
import ProvenZk.Ext.Vector

set_option linter.unusedVariables false

namespace ModuleCircuits

def Order : ℕ := 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
variable [Fact (Nat.Prime Order)]
abbrev F := ZMod Order
abbrev Gates := GatesGnark12 Order

opaque OpaqueRange (Bits: ℕ) (V: F) : Prop

opaque OpaqueRow_3_2 (Rows: List.Vector (List.Vector F 3) 2) (Index: F) (k: List.Vector F 3 -> Prop): Prop

opaque OpaqueEntry (Index: F) (k: F -> Prop): Prop

end ModuleCircuits

-- module Mods.Circuit.Scale
import Mods.Circuit.Prelude

set_option linter.unusedVariables false

namespace ModuleCircuits

variable [Fact (Nat.Prime Order)]

def ScaleGadget_4_h9d28b8ef (In: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In (3:F) ∧
    k gate_0

end ModuleCircuits

-- module Mods.Circuit.Scale2
import Mods.Circuit.Prelude

set_option linter.unusedVariables false

namespace ModuleCircuits

variable [Fact (Nat.Prime Order)]

def ScaleGadget_4_h33a5d7fb (In: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In (5:F) ∧
    k gate_0

end ModuleCircuits

-- module Mods.Circuit.Scale3
import Mods.Circuit.Prelude

set_option linter.unusedVariables false

namespace ModuleCircuits

variable [Fact (Nat.Prime Order)]

def ScaleGadget_4_h77598b64 (In: F) (k: F -> Prop): Prop :=
    ∃gate_0, gate_0 = Gates.mul In (5:F) ∧
    ∃gate_1, gate_1 = Gates.mul gate_0 gate_0 ∧
    k gate_1

end ModuleCircuits

-- module Mods.Circuit.Top
import Mods.Circuit.Prelude
import Mods.Circuit.Hints
import Mods.Circuit.Scale
import Mods.Circuit.Scale2
import Mods.Circuit.Scale3

set_option linter.unusedVariables false

namespace ModuleCircuits

variable [Fact (Nat.Prime Order)]

def HintCircuit (In: F) (Out: F): Prop :=
    ∃gate_0 : List.Vector F 3, -- hint github.com/reilabs/gnark-lean-extractor/v3/extractor/test_test.splitHint
    Gates.is_bool gate_0[2] ∧
    ∃_ignored_ : List.Vector F 1, -- hint github.com/reilabs/gnark-lean-extractor/v3/extractor/test_test.splitHint
    HintGadget Out fun gate_3 =>
    Gates.eq gate_3[1] gate_0[0] ∧
    True

def ScaleCircuit (In: F): Prop :=
    ScaleGadget_4_h9d28b8ef In fun gate_0 =>
    ScaleGadget_4_h33a5d7fb gate_0 fun gate_1 =>
    ScaleGadget_4_h33a5d7fb gate_1 fun gate_2 =>
    ScaleGadget_4_h77598b64 gate_2 fun gate_3 =>
    Gates.eq gate_3 (0:F) ∧
    True

def OpaqueCircuit_3_2 (Rows: List.Vector (List.Vector F 3) 2) (Index: F): Prop :=
    OpaqueRange 1 Index ∧
    OpaqueRange 11 Rows[0][1] ∧
    OpaqueRow_3_2 Rows Index fun gate_2 =>
    OpaqueEntry gate_2[2] fun gate_3 =>
    OpaqueEntry gate_3 fun gate_4 =>
    Gates.eq gate_4 gate_2[0] ∧
    True

end ModuleCircuits

