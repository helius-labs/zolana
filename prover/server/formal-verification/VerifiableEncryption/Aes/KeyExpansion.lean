import VerifiableEncryption.Aes.KeySteps

/-!
The extracted `AesKeyExpansion_32` computes FIPS-197 `keyExpansion256` of its key bytes.
-/

namespace ZolanaVE.Aes

open ZolanaVE

variable [Fact (Nat.Prime Order)]

def keyBytes (Key : List.Vector F 32) : Fin 32 → Byte := fun n => BitVec.ofNat 8 (Key.get n).val

def rkByte (w : Fin 60 → Word) (n : Fin 240) : Byte := w ⟨n.val / 4, by omega⟩ ⟨n.val % 4, by omega⟩

theorem rcon_1 : rcon 1 = ![1#8, 0, 0, 0] := by
  funext j
  fin_cases j <;> decide

theorem rcon_2 : rcon 2 = ![2#8, 0, 0, 0] := by
  funext j
  fin_cases j <;> decide

theorem rcon_3 : rcon 3 = ![4#8, 0, 0, 0] := by
  funext j
  fin_cases j <;> decide

theorem rcon_4 : rcon 4 = ![8#8, 0, 0, 0] := by
  funext j
  fin_cases j <;> decide

theorem rcon_5 : rcon 5 = ![16#8, 0, 0, 0] := by
  funext j
  fin_cases j <;> decide

theorem rcon_6 : rcon 6 = ![32#8, 0, 0, 0] := by
  funext j
  fin_cases j <;> decide

theorem rcon_7 : rcon 7 = ![64#8, 0, 0, 0] := by
  funext j
  fin_cases j <;> decide

set_option maxHeartbeats 0 in
theorem keyExpansion_cps (hL : AesLookupSem) {Key : List.Vector F 32}
    {k : List.Vector (List.Vector F 240) 2 → Prop} (h : AesKeyExpansion_32 Key k) :
    (∀ n, Key.get n = ((keyBytes Key n).toNat : F)) ∧
      ∃ v, k v ∧ (∀ n, (v.get 0).get n = (spread8 (rkByte (keyExpansion256 (keyBytes Key)) n) : F)) ∧
        ∀ n, (v.get 1).get n = ((rkByte (keyExpansion256 (keyBytes Key)) n).toNat : F) := by
  unfold AesKeyExpansion_32 at h
  replace h := keyByte_step hL h
  obtain ⟨hk0, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk1, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk2, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk3, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk4, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk5, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk6, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk7, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk8, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk9, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk10, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk11, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk12, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk13, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk14, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk15, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk16, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk17, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk18, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk19, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk20, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk21, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk22, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk23, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk24, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk25, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk26, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk27, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk28, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk29, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk30, h⟩ := h
  replace h := keyByte_step hL h
  obtain ⟨hk31, h⟩ := h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨7, by norm_num⟩) 1) (by rw [keyExpansion256_lt8 _ 7 (by norm_num)]; exact hk29) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨7, by norm_num⟩) 2) (by rw [keyExpansion256_lt8 _ 7 (by norm_num)]; exact hk30) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨7, by norm_num⟩) 3) (by rw [keyExpansion256_lt8 _ 7 (by norm_num)]; exact hk31) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨7, by norm_num⟩) 0) (by rw [keyExpansion256_lt8 _ 7 (by norm_num)]; exact hk28) h
  replace h := let_step h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨0, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨7, by norm_num⟩) (j + 1))) ![1#8, 0, 0, 0] (keyExpansion256 (keyBytes Key) ⟨8, by norm_num⟩)
    (by rw [keyExpansion256_lt8 _ 0 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 0 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 0 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 0 (by norm_num)]; rfl)
    (by rw [gate_add]; simp [show spread8 1#8 = 1 by decide] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl)
    (fun j => by rw [keyWord_rot _ 8 (by norm_num) (by norm_num) (by norm_num) j, rcon_1]; fin_cases j <;> simp [BitVec.xor_assoc] <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨1, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨8, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨9, by norm_num⟩)
    (by rw [keyExpansion256_lt8 _ 1 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 1 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 1 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 1 (by norm_num)]; rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 9 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨2, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨9, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨10, by norm_num⟩)
    (by rw [keyExpansion256_lt8 _ 2 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 2 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 2 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 2 (by norm_num)]; rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 10 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨3, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨10, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨11, by norm_num⟩)
    (by rw [keyExpansion256_lt8 _ 3 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 3 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 3 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 3 (by norm_num)]; rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 11 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨11, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨11, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨11, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨11, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨4, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨11, by norm_num⟩) j)) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨12, by norm_num⟩)
    (by rw [keyExpansion256_lt8 _ 4 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 4 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 4 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 4 (by norm_num)]; rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_sub _ 12 (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨5, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨12, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨13, by norm_num⟩)
    (by rw [keyExpansion256_lt8 _ 5 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 5 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 5 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 5 (by norm_num)]; rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 13 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨6, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨13, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨14, by norm_num⟩)
    (by rw [keyExpansion256_lt8 _ 6 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 6 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 6 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 6 (by norm_num)]; rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 14 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨7, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨14, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨15, by norm_num⟩)
    (by rw [keyExpansion256_lt8 _ 7 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 7 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 7 (by norm_num)]; rfl) (by rw [keyExpansion256_lt8 _ 7 (by norm_num)]; rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 15 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  unfold AesKeyExpansion_32_p1 at h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨15, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨15, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨15, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨15, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := let_step h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨8, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨15, by norm_num⟩) (j + 1))) ![2#8, 0, 0, 0] (keyExpansion256 (keyBytes Key) ⟨16, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by rw [gate_add]; simp [show spread8 2#8 = 6 by decide] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl)
    (fun j => by rw [keyWord_rot _ 16 (by norm_num) (by norm_num) (by norm_num) j, rcon_2]; fin_cases j <;> simp [BitVec.xor_assoc] <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨9, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨16, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨17, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 17 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨10, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨17, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨18, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 18 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨11, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨18, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨19, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 19 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨19, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨19, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨19, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨19, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨12, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨19, by norm_num⟩) j)) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨20, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_sub _ 20 (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨13, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨20, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨21, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 21 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨14, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨21, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨22, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 22 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨15, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨22, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨23, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 23 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨23, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨23, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨23, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨23, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := let_step h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨16, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨23, by norm_num⟩) (j + 1))) ![4#8, 0, 0, 0] (keyExpansion256 (keyBytes Key) ⟨24, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by rw [gate_add]; simp [show spread8 4#8 = 36 by decide] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl)
    (fun j => by rw [keyWord_rot _ 24 (by norm_num) (by norm_num) (by norm_num) j, rcon_3]; fin_cases j <;> simp [BitVec.xor_assoc] <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨17, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨24, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨25, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 25 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨18, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨25, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨26, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 26 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  unfold AesKeyExpansion_32_p2 at h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨19, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨26, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨27, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 27 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨27, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨27, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨27, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨27, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨20, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨27, by norm_num⟩) j)) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨28, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_sub _ 28 (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨21, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨28, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨29, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 29 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨22, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨29, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨30, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 30 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨23, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨30, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨31, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 31 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨31, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨31, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨31, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨31, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := let_step h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨24, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨31, by norm_num⟩) (j + 1))) ![8#8, 0, 0, 0] (keyExpansion256 (keyBytes Key) ⟨32, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by rw [gate_add]; simp [show spread8 8#8 = 216 by decide] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl)
    (fun j => by rw [keyWord_rot _ 32 (by norm_num) (by norm_num) (by norm_num) j, rcon_4]; fin_cases j <;> simp [BitVec.xor_assoc] <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨25, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨32, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨33, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 33 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨26, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨33, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨34, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 34 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨27, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨34, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨35, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 35 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨35, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨35, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨35, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨35, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨28, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨35, by norm_num⟩) j)) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨36, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_sub _ 36 (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  unfold AesKeyExpansion_32_p3 at h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨29, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨36, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨37, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 37 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨30, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨37, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨38, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 38 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨31, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨38, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨39, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 39 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨39, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨39, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨39, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨39, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := let_step h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨32, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨39, by norm_num⟩) (j + 1))) ![16#8, 0, 0, 0] (keyExpansion256 (keyBytes Key) ⟨40, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by rw [gate_add]; simp [show spread8 16#8 = 1296 by decide] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl)
    (fun j => by rw [keyWord_rot _ 40 (by norm_num) (by norm_num) (by norm_num) j, rcon_5]; fin_cases j <;> simp [BitVec.xor_assoc] <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨33, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨40, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨41, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 41 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨34, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨41, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨42, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 42 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨35, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨42, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨43, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 43 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨43, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨43, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨43, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨43, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨36, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨43, by norm_num⟩) j)) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨44, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_sub _ 44 (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨37, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨44, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨45, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 45 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨38, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨45, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨46, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 46 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨39, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨46, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨47, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 47 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  unfold AesKeyExpansion_32_p4 at h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨47, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨47, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨47, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨47, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := let_step h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨40, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨47, by norm_num⟩) (j + 1))) ![32#8, 0, 0, 0] (keyExpansion256 (keyBytes Key) ⟨48, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by rw [gate_add]; simp [show spread8 32#8 = 7776 by decide] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl)
    (fun j => by rw [keyWord_rot _ 48 (by norm_num) (by norm_num) (by norm_num) j, rcon_6]; fin_cases j <;> simp [BitVec.xor_assoc] <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨41, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨48, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨49, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 49 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨42, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨49, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨50, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 50 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨43, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨50, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨51, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 51 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨51, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨51, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨51, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨51, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨44, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨51, by norm_num⟩) j)) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨52, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_sub _ 52 (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨45, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨52, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨53, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 53 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨46, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨53, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨54, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 54 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨47, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨54, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨55, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 55 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨55, by norm_num⟩) 1) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨55, by norm_num⟩) 2) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨55, by norm_num⟩) 3) (by simp [wordVec]) h
  replace h := sboxLet_step hL ((keyExpansion256 (keyBytes Key) ⟨55, by norm_num⟩) 0) (by simp [wordVec]) h
  replace h := let_step h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨48, by norm_num⟩) (fun j => sb ((keyExpansion256 (keyBytes Key) ⟨55, by norm_num⟩) (j + 1))) ![64#8, 0, 0, 0] (keyExpansion256 (keyBytes Key) ⟨56, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by rw [gate_add]; simp [show spread8 64#8 = 46656 by decide] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl) (by simp [spread8_zero', spread8_zero] <;> rfl)
    (fun j => by rw [keyWord_rot _ 56 (by norm_num) (by norm_num) (by norm_num) j, rcon_7]; fin_cases j <;> simp [BitVec.xor_assoc] <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨49, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨56, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨57, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 57 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  unfold AesKeyExpansion_32_p5 at h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨50, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨57, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨58, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 58 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  replace h := keyWord_cps hL (keyExpansion256 (keyBytes Key) ⟨51, by norm_num⟩) (keyExpansion256 (keyBytes Key) ⟨58, by norm_num⟩) (fun _ => 0) (keyExpansion256 (keyBytes Key) ⟨59, by norm_num⟩)
    (by rfl) (by rfl) (by rfl) (by rfl)
    (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero]) (by simp [spread8_zero', spread8_zero])
    (fun j => by rw [keyWord_copy _ 59 (by norm_num) (by norm_num) (by norm_num) (by norm_num) j]; simp <;> rfl) h
  -- WIP: final step (240-entry round-key read-out) still times out; see scripts/gen_aes_key_expansion.py
  sorry

end ZolanaVE.Aes
