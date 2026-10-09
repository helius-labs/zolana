import sys

out_path = sys.argv[1]
upto = int(sys.argv[2]) if len(sys.argv) > 2 else 60
finish = upto == 60 and (len(sys.argv) <= 3)

W = "keyExpansion256 (keyBytes Key)"


def w(i):
    return f"({W} ⟨{i}, by norm_num⟩)"


rcon_bytes = {1: 0x01, 2: 0x02, 3: 0x04, 4: 0x08, 5: 0x10, 6: 0x20, 7: 0x40}

lines = []
emit = lines.append

emit("import VerifiableEncryption.Aes.KeySteps")
emit("")
emit("/-!")
emit("The extracted `AesKeyExpansion_32` computes FIPS-197 `keyExpansion256` of its key bytes.")
emit("-/")
emit("")
emit("namespace ZolanaVE.Aes")
emit("")
emit("open ZolanaVE")
emit("")
emit("variable [Fact (Nat.Prime Order)]")
emit("")
emit("def keyBytes (Key : List.Vector F 32) : Fin 32 → Byte := fun n => BitVec.ofNat 8 (Key.get n).val")
emit("")
emit("def rkByte (w : Fin 60 → Word) (n : Fin 240) : Byte := w ⟨n.val / 4, by omega⟩ ⟨n.val % 4, by omega⟩")
emit("")
for n, r in rcon_bytes.items():
    emit(f"theorem rcon_{n} : rcon {n} = ![{r}#8, 0, 0, 0] := by")
    emit("  funext j")
    emit("  fin_cases j <;> decide")
    emit("")
emit("set_option maxHeartbeats 0 in")
emit("theorem keyExpansion_cps (hL : AesLookupSem) {Key : List.Vector F 32}")
emit("    {k : List.Vector (List.Vector F 240) 2 → Prop} (h : AesKeyExpansion_32 Key k) :")
emit("    (∀ n, Key.get n = ((keyBytes Key n).toNat : F)) ∧")
emit(f"      ∃ v, k v ∧ (∀ n, (v.get 0).get n = (spread8 (rkByte ({W}) n) : F)) ∧")
emit(f"        ∀ n, (v.get 1).get n = ((rkByte ({W}) n).toNat : F) := by")
emit("  unfold AesKeyExpansion_32 at h")
for n in range(32):
    emit("  replace h := keyByte_step hL h")
    emit(f"  obtain ⟨hk{n}, h⟩ := h")


def earlier_proof(i, j):
    if i - 8 < 8:
        return f"(by rw [keyExpansion256_lt8 _ {i-8} (by norm_num)]; rfl)"
    return "(by rfl)"


def prev_byte_proof(i, j):
    if i - 1 < 8:
        n = 4 * (i - 1) + j
        return f"(by rw [keyExpansion256_lt8 _ {i-1} (by norm_num)]; exact hk{n})"
    return "(by simp [wordVec])"


for i in range(8, upto):
    kind = "rot" if i % 8 == 0 else ("sub" if i % 8 == 4 else "copy")
    parts = {16: 1, 27: 2, 37: 3, 48: 4, 58: 5}
    if i in parts:
        emit(f"  unfold AesKeyExpansion_32_p{parts[i]} at h")
    if kind == "rot":
        for j in [1, 2, 3, 0]:
            emit(f"  replace h := sboxLet_step hL ({w(i-1)} {j}) {prev_byte_proof(i, j)} h")
        emit("  replace h := let_step h")
        rn = i // 8
        spread_r = 6 ** (rn - 1)
        A = w(i - 8)
        B = f"(fun j => sb ({w(i-1)} (j + 1)))"
        C = f"![{rcon_bytes[rn]}#8, 0, 0, 0]"
        hx = " ".join(earlier_proof(i, j) for j in range(4))
        hy0 = f"(by rw [gate_add]; simp [show spread8 {rcon_bytes[rn]}#8 = {spread_r} by decide] <;> rfl)"
        hys = " ".join("(by simp [spread8_zero', spread8_zero] <;> rfl)" for _ in range(3))
        hR = (f"(fun j => by rw [keyWord_rot _ {i} (by norm_num) (by norm_num) (by norm_num) j, rcon_{rn}]; "
              f"fin_cases j <;> simp [BitVec.xor_assoc] <;> rfl)")
    elif kind == "sub":
        for j in range(4):
            emit(f"  replace h := sboxLet_step hL ({w(i-1)} {j}) {prev_byte_proof(i, j)} h")
        A = w(i - 8)
        B = f"(fun j => sb ({w(i-1)} j))"
        C = "(fun _ => 0)"
        hx = " ".join(earlier_proof(i, j) for j in range(4))
        hy0 = "(by simp [spread8_zero', spread8_zero])"
        hys = " ".join("(by simp [spread8_zero', spread8_zero])" for _ in range(3))
        hR = (f"(fun j => by rw [keyWord_sub _ {i} (by norm_num) (by norm_num) (by norm_num) j]; "
              f"simp <;> rfl)")
    else:
        A = w(i - 8)
        B = w(i - 1)
        C = "(fun _ => 0)"
        hx = " ".join(earlier_proof(i, j) for j in range(4))
        hy0 = "(by simp [spread8_zero', spread8_zero])"
        hys = " ".join("(by simp [spread8_zero', spread8_zero])" for _ in range(3))
        hR = (f"(fun j => by rw [keyWord_copy _ {i} (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; "
              f"simp <;> rfl)")
    emit(f"  replace h := keyWord_cps hL {A} {B} {C} {w(i)}")
    emit(f"    {hx}")
    emit(f"    {hy0} {hys}")
    emit(f"    {hR} h")

if finish:
    emit("  have hk : ∀ n, Key.get n = ((keyBytes Key n).toNat : F) := by")
    emit("    intro n")
    emit("    fin_cases n")
    for n in range(32):
        emit(f"    · exact hk{n}")
    emit("  refine ⟨hk, _, h, fun n => ?_, fun n => ?_⟩")
    emit("  · fin_cases n <;> rw [rkByte] <;> first | (rw [keyExpansion256_lt8 _ _ (by norm_num)]; rfl) | rfl")
    emit("  · fin_cases n <;> rw [rkByte] <;> first | (rw [keyExpansion256_lt8 _ _ (by norm_num)]; exact hk _) | rfl")
else:
    emit("  sorry")
emit("")
emit("end ZolanaVE.Aes")
emit("")

with open(out_path, "w") as f:
    f.write("\n".join(lines))
