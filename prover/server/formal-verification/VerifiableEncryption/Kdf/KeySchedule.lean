import VerifiableEncryption.Kdf.FieldBytes
import VerifiableEncryption.Kdf.Poseidon
import VerifiableEncryption.Circuit.Top

/-!
The extracted `KeySchedule_32_12` (fixed info label "TMEC", the merge KDF
label) outputs exactly `kdf poseidon shared "TMEC"`.
-/

set_option linter.unusedSectionVars false

namespace ZolanaVE.Kdf

open ZolanaVE

variable [Fact (Nat.Prime Order)]

/-- The info label "TMEC" of the extracted key schedule. -/
def tmecInfo : List ℕ := [84, 77, 69, 67]

lemma packBE31_tmec : packBE31 tmecInfo = [1414350147] := by
  simp [packBE31, tmecInfo, chunks31, packBE]

lemma poseidon_list2 (a b : F) : poseidon [a, b] = poseidon₂ vec![a, b] := rfl

lemma poseidon_list3 (a b c : F) : poseidon [a, b, c] = poseidon₃ vec![a, b, c] := rfl

/-- The extracted FieldToBytesBE meets the hand mirror. -/
theorem FieldBytesBE_32_mirror {V : F} {k : List.Vector F 32 → Prop} (h : FieldBytesBE_32 V k) :
    FieldToBytesBEMirror V (fun f => k (List.Vector.ofFn f)) := by
  rw [fieldToBytesBE_rw]
  exact FieldBytesBE_32_sound h

set_option maxHeartbeats 4000000 in
theorem KeySchedule_32_12_sound {S : F} {Key : List.Vector F 32} {Nonce : List.Vector F 12}
    (h : KeySchedule_32_12 S Key Nonce) :
    Key = List.Vector.ofFn (fun i => ((kdf poseidon S tmecInfo).1 i : F)) ∧
    Nonce = List.Vector.ofFn (fun j => ((kdf poseidon S tmecInfo).2 j : F)) := by
  unfold KeySchedule_32_12 at h
  obtain ⟨g0, e0, g1, e1, g2, e2, g3, e3, g4, e4, g5, e5, g6, e6, g7, e7, h⟩ := h
  have hpack : g7 = ((1414350147 : ℕ) : F) := by
    subst e0 e1 e2 e3 e4 e5 e6 e7
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
    norm_num
  subst hpack
  simp only [Poseidon_3_rw, Poseidon_2_rw] at h
  replace h := FieldBytesBE_32_sound h
  beta_reduce at h
  replace h := FieldBytesBE_32_sound h
  beta_reduce at h
  replace h := FieldBytesBE_32_sound h
  simp only [List.Vector.get_ofFn, Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.eq,
    Nat.cast_ofNat] at h
  obtain ⟨k0, k1, k2, k3, k4, k5, k6, k7, k8, k9, k10, k11, k12, k13, k14, k15,
    k16, k17, k18, k19, k20, k21, k22, k23, k24, k25, k26, k27, k28, k29, k30, k31,
    n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, n10, n11, -⟩ := h
  have hsilo : poseidon ((domSepSilo : F) :: S :: (packBE31 tmecInfo).map (Nat.cast : ℕ → F)) =
      poseidon₃ vec![(1414353737 : F), S, ((1414350147 : ℕ) : F)] := by
    rw [packBE31_tmec]
    simp only [domSepSilo, List.map, Nat.cast_ofNat]
    rfl
  refine ⟨?_, ?_⟩
  · apply List.Vector.ext
    intro i
    rw [List.Vector.get_ofFn]
    simp only [kdf, hsilo, poseidon_list2, domSepKey, domSepKeyHi, domSepNonce, Nat.cast_ofNat]
    fin_cases i
    · rw [dif_pos (by decide)]
      exact k0.symm
    · rw [dif_pos (by decide)]
      exact k1.symm
    · rw [dif_pos (by decide)]
      exact k2.symm
    · rw [dif_pos (by decide)]
      exact k3.symm
    · rw [dif_pos (by decide)]
      exact k4.symm
    · rw [dif_pos (by decide)]
      exact k5.symm
    · rw [dif_pos (by decide)]
      exact k6.symm
    · rw [dif_pos (by decide)]
      exact k7.symm
    · rw [dif_pos (by decide)]
      exact k8.symm
    · rw [dif_pos (by decide)]
      exact k9.symm
    · rw [dif_pos (by decide)]
      exact k10.symm
    · rw [dif_pos (by decide)]
      exact k11.symm
    · rw [dif_pos (by decide)]
      exact k12.symm
    · rw [dif_pos (by decide)]
      exact k13.symm
    · rw [dif_pos (by decide)]
      exact k14.symm
    · rw [dif_pos (by decide)]
      exact k15.symm
    · rw [dif_neg (by decide)]
      exact k16.symm
    · rw [dif_neg (by decide)]
      exact k17.symm
    · rw [dif_neg (by decide)]
      exact k18.symm
    · rw [dif_neg (by decide)]
      exact k19.symm
    · rw [dif_neg (by decide)]
      exact k20.symm
    · rw [dif_neg (by decide)]
      exact k21.symm
    · rw [dif_neg (by decide)]
      exact k22.symm
    · rw [dif_neg (by decide)]
      exact k23.symm
    · rw [dif_neg (by decide)]
      exact k24.symm
    · rw [dif_neg (by decide)]
      exact k25.symm
    · rw [dif_neg (by decide)]
      exact k26.symm
    · rw [dif_neg (by decide)]
      exact k27.symm
    · rw [dif_neg (by decide)]
      exact k28.symm
    · rw [dif_neg (by decide)]
      exact k29.symm
    · rw [dif_neg (by decide)]
      exact k30.symm
    · rw [dif_neg (by decide)]
      exact k31.symm
  · apply List.Vector.ext
    intro j
    rw [List.Vector.get_ofFn]
    simp only [kdf, hsilo, poseidon_list2, domSepKey, domSepKeyHi, domSepNonce, Nat.cast_ofNat]
    fin_cases j
    · exact n0.symm
    · exact n1.symm
    · exact n2.symm
    · exact n3.symm
    · exact n4.symm
    · exact n5.symm
    · exact n6.symm
    · exact n7.symm
    · exact n8.symm
    · exact n9.symm
    · exact n10.symm
    · exact n11.symm

end ZolanaVE.Kdf
