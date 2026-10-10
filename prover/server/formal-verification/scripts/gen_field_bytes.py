#!/usr/bin/env python3
"""Generate VerifiableEncryption/Kdf/FieldBytes.lean.

The proof walks the extracted `FieldBytesBE_32` body and its `_p<j>` parts line
by line: every gate becomes a local with its defining equation, and the step
lemmas of `VerifiableEncryption/Kdf.lean` carry the recomposition sum, the digit
booleanity and the `MustBeLessOrEqCst` chain. Each extracted part gets its own
theorem whose hypotheses are the facts still live at the part boundary; one
long tactic proof would make metavariable instantiation quadratic.

Any line the generator does not recognise aborts generation, so a change in
the extracted shape cannot produce a silently different proof.

Usage (from prover/server/formal-verification):
  scripts/gen_field_bytes.py
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "VerifiableEncryption/Circuit/Kdf.lean"
OUT = ROOT / "VerifiableEncryption/Kdf/FieldBytes.lean"

GET = r"\(gate_0\.get \((\d+) : Fin 254\)\)"
R_DEF = re.compile(r"^def (FieldBytesBE_32(?:_p\d+)?) \(V: F\)(.*)\(k: List\.Vector F 32 -> Prop\): Prop :=$")
R_PARAM = re.compile(r"\((gate_\d+): F\)")
R_HINT = re.compile(r"^∃gate_0 : List\.Vector F 254, -- hint ")
R_LET = re.compile(r"^∃(gate_\d+), \1 = (.*) ∧$")
R_MULC = re.compile(rf"^Gates\.mul {GET} (K_\d+|\(\d+:F\))$")
R_ADD = re.compile(r"^Gates\.add (gate_\d+|\(0:F\)) (gate_\d+)$")
R_MULG = re.compile(rf"^Gates\.mul (gate_\d+|\(1:F\)) {GET}$")
R_SUB1 = re.compile(r"^Gates\.sub \(1:F\) (gate_\d+)$")
R_SUB2 = re.compile(rf"^Gates\.sub (gate_\d+) {GET}$")
R_BOOL = re.compile(rf"^Gates\.is_bool {GET} ∧$")
R_EQV = re.compile(r"^Gates\.eq (gate_\d+) V ∧$")
R_EQ0 = re.compile(r"^Gates\.eq (gate_\d+) \(0:F\) ∧$")
R_FB = re.compile(r"^∃(gate_\d+), Gates\.from_binary vec!\[(.*)\] \1 ∧$")
R_FB_ENTRY = re.compile(rf"^{GET}$|^\(0:F\)$")
R_PART = re.compile(r"^(FieldBytesBE_32_p\d+) V gate_0((?: gate_\d+)*) k$")
R_K = re.compile(r"^k vec!\[(.*)\]$")
R_GATE = re.compile(r"gate_\d+")

CHAIN = "leqCstChain (Order - 1) (bitA gate_0)"
GOAL = "k (List.Vector.ofFn fun i : Fin 32 => ((byteOf V.val i : ℕ) : F))"


def fail(line):
    sys.exit(f"gen_field_bytes: unrecognised line: {line}")


def parse(text):
    defs, params, name = {}, {}, None
    for line in text.split("\n"):
        m = R_DEF.match(line)
        if m:
            name = m.group(1)
            defs[name] = []
            params[name] = R_PARAM.findall(m.group(2))
        elif line.startswith("def ") or line.startswith("end "):
            name = None
        elif name is not None and line.strip():
            defs[name].append(line.strip())
    return defs, params


def byte_args(entries):
    if len(entries) != 8:
        fail(str(entries))
    idx = []
    for e in entries:
        mm = R_FB_ENTRY.match(e)
        if not mm:
            fail(e)
        idx.append(int(mm.group(1)) if mm.group(1) else None)
    s = idx[0]
    if s is None or s % 8 != 0:
        fail(str(entries))
    args = []
    for o, ix in enumerate(idx):
        if ix is None:
            if s + o < 254:
                fail(str(entries))
            args.append(f"(pad_zero V {s + o} (by norm_num))")
        else:
            if ix != s + o:
                fail(str(entries))
            args.append(f"(hcan {ix})")
    return 31 - s // 8, args


class Gen:
    def __init__(self, defs, params):
        self.defs, self.params = defs, params
        self.facts = {}
        self.mulc, self.sub1, self.sub2, self.prod, self.mul3 = {}, {}, {}, {}, {}
        self.acc = {}
        self.bools = 0
        self.after_eq = False
        self.chain = (254, "(1:F)")
        self.rec_sum = None
        self.bytes = {}
        self.lemmas = []
        self.substituted = {}

    def set_chain(self, pos, p):
        self.chain = (pos, p)
        self.facts["hC"] = f"{CHAIN} {pos} {p} → {CHAIN} 254 1"

    def run(self, name, header):
        body = []
        emit = body.append
        for line in self.defs[name]:
            if R_HINT.match(line):
                emit("  obtain ⟨gate_0, h⟩ := h")
                emit("  have hB : boolsUpTo gate_0 0 := trivial")
                self.facts["hB"] = "boolsUpTo gate_0 0"
                emit(f"  have hC : {CHAIN} 254 1 → {CHAIN} 254 1 := id")
                self.set_chain(254, "(1:F)")
                continue
            m = R_LET.match(line)
            if m:
                g, rhs = m.group(1), m.group(2)
                emit(f"  obtain ⟨{g}, e_{g}, h⟩ := h")
                self.let(g, rhs, line, emit)
                continue
            m = R_BOOL.match(line)
            if m:
                i = int(m.group(1))
                if not self.after_eq:
                    if i != self.bools:
                        fail(line)
                    emit(f"  obtain ⟨b_{i}, h⟩ := h")
                    emit(f"  replace hB : boolsUpTo gate_0 {i + 1} := ⟨hB, b_{i}⟩")
                    self.bools += 1
                    self.facts["hB"] = f"boolsUpTo gate_0 {i + 1}"
                else:
                    p = self.prod[i]
                    emit(f"  obtain ⟨c_{i}, h⟩ := h")
                    if p in self.substituted:
                        emit(f"  replace hC := chain_one_step {i} (by decide) c_{i} rfl hC")
                        self.set_chain(i, f"({self.substituted[p]})")
                    else:
                        emit(f"  replace hC := chain_one_step {i} (by decide) c_{i} e_{p} hC")
                        self.set_chain(i, p)
                continue
            m = R_EQV.match(line)
            if m:
                self.rec_sum = m.group(1)
                if self.acc.get(self.rec_sum) != 254 or self.bools != 254:
                    fail(line)
                emit("  obtain ⟨hrec, h⟩ := h")
                self.facts["hrec"] = f"Gates.eq {self.rec_sum} V"
                self.after_eq = True
                continue
            m = R_EQ0.match(line)
            if m:
                w = m.group(1)
                u = self.mul3[w]
                t, i = self.sub2[u]
                p = self.sub1[t]
                p_txt = f"({self.substituted[p]})" if p in self.substituted else p
                if p_txt != self.chain[1]:
                    fail(line)
                emit(f"  obtain ⟨z_{w}, h⟩ := h")
                proofs = []
                for n in (t, u, w):
                    if n in self.substituted:
                        proofs.append("rfl")
                    else:
                        proofs.append(f"e_{n}")
                        del self.facts[f"e_{n}"]
                emit(f"  replace hC := chain_zero_step {i} (by decide) {' '.join(proofs)} z_{w} hC")
                self.set_chain(i, self.chain[1])
                continue
            m = R_FB.match(line)
            if m:
                g = m.group(1)
                if not self.bytes:
                    if self.chain[0] != 0:
                        fail(line)
                    srec = "rfl" if self.rec_sum in self.substituted else f"s_{self.rec_sum}"
                    emit(f"  have hcan := fieldBytes_canonical hB {srec} hrec (hC trivial)")
                    for n in ("hB", "hrec", "hC", f"s_{self.rec_sum}"):
                        self.facts.pop(n, None)
                    self.facts["hcan"] = "∀ i : Fin 254, gate_0.get i = Bool.toZMod (V.val.testBit i.val)"
                j, args = byte_args([e.strip() for e in m.group(2).split(", ")])
                emit(f"  obtain ⟨{g}, f_{g}, h⟩ := h")
                emit(f"  have y_{g} := fb_byte V.val {j} {' '.join(args)} f_{g}")
                self.bytes[g] = j
                self.facts[f"y_{g}"] = f"{g} = ((byteOf V.val {j} : ℕ) : F)"
                continue
            m = R_PART.match(line)
            if m:
                callee = m.group(1)
                args = m.group(2).split()
                if args != self.params[callee]:
                    fail(line)
                live = set(args) | {"gate_0"}
                self.eliminate(live, emit)
                facts = [(n, t) for n, t in self.facts.items() if set(R_GATE.findall(t)) <= live]
                self.facts = dict(facts)
                emit(f"  exact {lemma_name(callee)} {' '.join(n for n, _ in facts)} h")
                self.lemmas.append((name, header, body))
                self.run(callee, (args, facts))
                return
            m = R_K.match(line)
            if m:
                out = [e.strip() for e in m.group(1).split(", ")]
                if [self.bytes.get(g) for g in out] != list(range(32)):
                    sys.exit("gen_field_bytes: output order is not big-endian")
                for g in out:
                    emit(f"  subst y_{g}")
                emit("  exact h")
                self.lemmas.append((name, header, body))
                return
            fail(line)
        sys.exit(f"gen_field_bytes: {name} has no continuation")

    def eliminate(self, live, emit):
        while True:
            dead = sorted({x for t in self.facts.values() for x in R_GATE.findall(t)} - live)
            if not dead:
                return
            x = dead[0]
            defn = next((n for n in (f"e_{x}", f"s_{x}") if n in self.facts), None)
            if defn is None:
                sys.exit(f"gen_field_bytes: {x} is referenced past its part without a definition")
            rhs = self.facts.pop(defn).split(" = ", 1)[1]
            emit(f"  subst {defn}")
            self.substituted[x] = rhs
            pat = re.compile(rf"\b{x}\b")
            self.facts = {n: pat.sub(f"({rhs})", t) for n, t in self.facts.items()}
            if self.chain[1] == x:
                self.chain = (self.chain[0], f"({rhs})")

    def let(self, g, rhs, line, emit):
        if (mm := R_MULC.match(rhs)):
            self.mulc[g] = (int(mm.group(1)), mm.group(2))
            self.facts[f"e_{g}"] = f"{g} = {rhs}"
        elif (mm := R_ADD.match(rhs)):
            a, mg = mm.group(1), mm.group(2)
            i, c = self.mulc[mg]
            cproof = f"(by norm_num [{c}])" if c.startswith("K_") else "(by norm_num)"
            if a == "(0:F)":
                if i != 0:
                    fail(line)
                emit(f"  have s_{g} := psum_step0 (g := gate_0) {cproof} e_{mg} e_{g}")
            else:
                if self.acc.get(a) != i:
                    fail(line)
                emit(f"  have s_{g} := psum_step {i} s_{a} {cproof} e_{mg} e_{g}")
                del self.facts[f"s_{a}"]
            del self.facts[f"e_{mg}"]
            self.acc[g] = i + 1
            self.facts[f"s_{g}"] = f"{g} = psum gate_0 {i + 1}"
        elif (mm := R_SUB1.match(rhs)):
            self.sub1[g] = mm.group(1)
            self.facts[f"e_{g}"] = f"{g} = {rhs}"
        elif (mm := R_SUB2.match(rhs)):
            if mm.group(1) not in self.sub1:
                fail(line)
            self.sub2[g] = (mm.group(1), int(mm.group(2)))
            self.facts[f"e_{g}"] = f"{g} = {rhs}"
        elif (mm := R_MULG.match(rhs)):
            first = mm.group(1)
            if first in self.sub2:
                if self.sub2[first][1] != int(mm.group(2)):
                    fail(line)
                self.mul3[g] = first
            else:
                self.prod[int(mm.group(2))] = g
            self.facts[f"e_{g}"] = f"{g} = {rhs}"
        else:
            fail(line)


def lemma_name(part):
    return "fieldBytes_" + part.rsplit("_", 1)[1]


HEADER = """-- Code generated by scripts/gen_field_bytes.py. DO NOT EDIT.

import VerifiableEncryption.Kdf
import VerifiableEncryption.Circuit.Kdf

/-!
The extracted `FieldBytesBE_32` (`FieldToBytesBE(v, 32)`) outputs the 32
big-endian bytes of the canonical value of its input.
-/

set_option linter.unusedSectionVars false
set_option linter.unusedVariables false

namespace ZolanaVE.Kdf

open ZolanaVE

variable [Fact (Nat.Prime Order)]
"""


def render(name, header, body):
    lines = ["", "set_option maxHeartbeats 0 in"]
    if header is None:
        lines.append("theorem FieldBytesBE_32_sound {V : F} {k : List.Vector F 32 → Prop}")
        lines.append("    (h : FieldBytesBE_32 V k) :")
        lines.append(f"    {GOAL} := by")
        lines.append("  unfold FieldBytesBE_32 at h")
    else:
        args, facts = header
        lines.append(f"theorem {lemma_name(name)} {{V : F}} {{k : List.Vector F 32 → Prop}}")
        lines.append("    {gate_0 : List.Vector F 254}" + (f" {{{' '.join(args)} : F}}" if args else ""))
        for n, t in facts:
            lines.append(f"    ({n} : {t})")
        lines.append(f"    (h : {name} V gate_0 {' '.join(args)} k) :")
        lines.append(f"    {GOAL} := by")
        lines.append(f"  unfold {name} at h")
    return "\n".join(lines + body) + "\n"


def main():
    defs, params = parse(SRC.read_text())
    gen = Gen(defs, params)
    gen.run("FieldBytesBE_32", None)
    text = HEADER
    for name, header, body in reversed(gen.lemmas):
        text += render(name, header, body)
    text += "\nend ZolanaVE.Kdf\n"
    OUT.write_text(text)


if __name__ == "__main__":
    main()
