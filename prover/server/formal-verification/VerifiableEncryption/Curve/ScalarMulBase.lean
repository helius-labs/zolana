import VerifiableEncryption.Curve.CombBase
import VerifiableEncryption.Curve.CombConstants

/-!
Soundness of the extracted fixed-base scalar multiplication `scalarMulBase`.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks ZolanaVE.CombLimbs ZolanaVE.P256.Comb


theorem twoPow_modEq : rec8 twoPowLimbs ≡ 2 ^ 256 [ZMOD n] := by
  unfold Int.ModEq
  decide +kernel

theorem scalarMulBase_sound (hl : LookupSound RangeCheck 11) (S : ElemVal 8) (hS : S.bnd = reducedC)
    {k : List.Vector (List.Vector F 8) 2 → Prop} (h : ScalarMulBase_8_h3037b025 S.limbs k) :
    ∃ RX RY : ElemVal 8, RX.bnd = reducedC ∧ RY.bnd = reducedC ∧
      k (RX.limbs ::ᵥ RY.limbs ::ᵥ List.Vector.nil) ∧
      ∃ hR : OnCurve (RX.value : Fp) (RY.value : Fp), mkPoint hR = S.value • G := by
  unfold ScalarMulBase_8_h3037b025 at h
  obtain ⟨g, h⟩ := h
  obtain ⟨hbA, h⟩ := boolRun_split (j := 0) (m := 197) (g := g) h
  obtain ⟨hbB, h⟩ := boolRun_split (j := 197) (m := 60) (g := g) h
  have hbits : AllBits g := by
    intro j hj
    by_cases hj' : j < 197
    · exact hbA j (by omega) (by omega)
    · exact hbB j (by omega) (by omega)
  clear hbA hbB
  obtain ⟨n0, f0, n1, f1, n2, f2, n3, f3, n4, f4, n5, f5, n6, f6, n7, f7, hrec, h⟩ := h
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8] at f0 f1 f2 f3 f4 f5 f6 f7
  have fe0 := fromBinary_chunk hbits (a := 1) (w := 32) (by norm_num) rfl f0
  have fe1 := fromBinary_chunk hbits (a := 33) (w := 32) (by norm_num) rfl f1
  have fe2 := fromBinary_chunk hbits (a := 65) (w := 32) (by norm_num) rfl f2
  have fe3 := fromBinary_chunk hbits (a := 97) (w := 32) (by norm_num) rfl f3
  have fe4 := fromBinary_chunk hbits (a := 129) (w := 32) (by norm_num) rfl f4
  have fe5 := fromBinary_chunk hbits (a := 161) (w := 32) (by norm_num) rfl f5
  have fe6 := fromBinary_chunk hbits (a := 193) (w := 32) (by norm_num) rfl f6
  have fe7 := fromBinary_chunk hbits (a := 225) (w := 32) (by norm_num) rfl f7
  clear f0 f1 f2 f3 f4 f5 f6 f7
  subst fe0 fe1 fe2 fe3 fe4 fe5 fe6 fe7
  obtain ⟨π, hπ⟩ := bool_of_is_bool (bit_get hbits 0)
  set RC := mkElem _ _ (rcInts_fits hbits (le_refl 257)) with hRC
  have crec := CheckPolynomial_25_hcd1dd84c_sound hl
    [⟨8, RC⟩, ⟨1, bitElem π⟩, ⟨8, S⟩, ⟨8, constElem twoPowLimbs⟩]
    (elemsMatch_of (by show [RC.bnd, (bitElem π).bnd, S.bnd, (constElem twoPowLimbs).bnd] = _; rw [hS]; rfl))
    _ (by limbs_tac [hRC, rcInts, bitElem, ← hπ, constElem, twoPowLimbs]) hrec
  clear hrec
  obtain ⟨i0, hi0, W0X, W0Y, hW0X, hW0Y, h, hW0, pW0⟩ :=
    window_select (t := 0) (by norm_num) (bit_get hbits 1) (bit_get hbits 2) (bit_get hbits 3) (bit_get hbits 4) (bit_get hbits 5) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi0
  have pD0 := win_dig (g := g) (t := 0) (by norm_num) (sel5_chunk hbits (a := 1) (by norm_num) i0.2 hi0)
  rw [pD0] at pW0
  clear hi0 pD0
  obtain ⟨i1, hi1, W1X, W1Y, hW1X, hW1Y, h, hW1, pW1⟩ :=
    window_select (t := 1) (by norm_num) (bit_get hbits 6) (bit_get hbits 7) (bit_get hbits 8) (bit_get hbits 9) (bit_get hbits 10) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi1
  have pD1 := win_dig (g := g) (t := 1) (by norm_num) (sel5_chunk hbits (a := 6) (by norm_num) i1.2 hi1)
  rw [pD1] at pW1
  clear hi1 pD1
  obtain ⟨i2, hi2, W2X, W2Y, hW2X, hW2Y, h, hW2, pW2⟩ :=
    window_select (t := 2) (by norm_num) (bit_get hbits 11) (bit_get hbits 12) (bit_get hbits 13) (bit_get hbits 14) (bit_get hbits 15) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi2
  have pD2 := win_dig (g := g) (t := 2) (by norm_num) (sel5_chunk hbits (a := 11) (by norm_num) i2.2 hi2)
  rw [pD2] at pW2
  clear hi2 pD2
  obtain ⟨i3, hi3, W3X, W3Y, hW3X, hW3Y, h, hW3, pW3⟩ :=
    window_select (t := 3) (by norm_num) (bit_get hbits 16) (bit_get hbits 17) (bit_get hbits 18) (bit_get hbits 19) (bit_get hbits 20) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi3
  have pD3 := win_dig (g := g) (t := 3) (by norm_num) (sel5_chunk hbits (a := 16) (by norm_num) i3.2 hi3)
  rw [pD3] at pW3
  clear hi3 pD3
  obtain ⟨i4, hi4, W4X, W4Y, hW4X, hW4Y, h, hW4, pW4⟩ :=
    window_select (t := 4) (by norm_num) (bit_get hbits 21) (bit_get hbits 22) (bit_get hbits 23) (bit_get hbits 24) (bit_get hbits 25) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi4
  have pD4 := win_dig (g := g) (t := 4) (by norm_num) (sel5_chunk hbits (a := 21) (by norm_num) i4.2 hi4)
  rw [pD4] at pW4
  clear hi4 pD4
  obtain ⟨i5, hi5, W5X, W5Y, hW5X, hW5Y, h, hW5, pW5⟩ :=
    window_select (t := 5) (by norm_num) (bit_get hbits 26) (bit_get hbits 27) (bit_get hbits 28) (bit_get hbits 29) (bit_get hbits 30) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi5
  have pD5 := win_dig (g := g) (t := 5) (by norm_num) (sel5_chunk hbits (a := 26) (by norm_num) i5.2 hi5)
  rw [pD5] at pW5
  clear hi5 pD5
  obtain ⟨i6, hi6, W6X, W6Y, hW6X, hW6Y, h, hW6, pW6⟩ :=
    window_select (t := 6) (by norm_num) (bit_get hbits 31) (bit_get hbits 32) (bit_get hbits 33) (bit_get hbits 34) (bit_get hbits 35) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi6
  have pD6 := win_dig (g := g) (t := 6) (by norm_num) (sel5_chunk hbits (a := 31) (by norm_num) i6.2 hi6)
  rw [pD6] at pW6
  clear hi6 pD6
  obtain ⟨i7, hi7, W7X, W7Y, hW7X, hW7Y, h, hW7, pW7⟩ :=
    window_select (t := 7) (by norm_num) (bit_get hbits 36) (bit_get hbits 37) (bit_get hbits 38) (bit_get hbits 39) (bit_get hbits 40) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi7
  have pD7 := win_dig (g := g) (t := 7) (by norm_num) (sel5_chunk hbits (a := 36) (by norm_num) i7.2 hi7)
  rw [pD7] at pW7
  clear hi7 pD7
  obtain ⟨i8, hi8, W8X, W8Y, hW8X, hW8Y, h, hW8, pW8⟩ :=
    window_select (t := 8) (by norm_num) (bit_get hbits 41) (bit_get hbits 42) (bit_get hbits 43) (bit_get hbits 44) (bit_get hbits 45) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi8
  have pD8 := win_dig (g := g) (t := 8) (by norm_num) (sel5_chunk hbits (a := 41) (by norm_num) i8.2 hi8)
  rw [pD8] at pW8
  clear hi8 pD8
  obtain ⟨i9, hi9, W9X, W9Y, hW9X, hW9Y, h, hW9, pW9⟩ :=
    window_select (t := 9) (by norm_num) (bit_get hbits 46) (bit_get hbits 47) (bit_get hbits 48) (bit_get hbits 49) (bit_get hbits 50) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi9
  have pD9 := win_dig (g := g) (t := 9) (by norm_num) (sel5_chunk hbits (a := 46) (by norm_num) i9.2 hi9)
  rw [pD9] at pW9
  clear hi9 pD9
  obtain ⟨i10, hi10, W10X, W10Y, hW10X, hW10Y, h, hW10, pW10⟩ :=
    window_select (t := 10) (by norm_num) (bit_get hbits 51) (bit_get hbits 52) (bit_get hbits 53) (bit_get hbits 54) (bit_get hbits 55) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi10
  have pD10 := win_dig (g := g) (t := 10) (by norm_num) (sel5_chunk hbits (a := 51) (by norm_num) i10.2 hi10)
  rw [pD10] at pW10
  clear hi10 pD10
  obtain ⟨i11, hi11, W11X, W11Y, hW11X, hW11Y, h, hW11, pW11⟩ :=
    window_select (t := 11) (by norm_num) (bit_get hbits 56) (bit_get hbits 57) (bit_get hbits 58) (bit_get hbits 59) (bit_get hbits 60) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi11
  have pD11 := win_dig (g := g) (t := 11) (by norm_num) (sel5_chunk hbits (a := 56) (by norm_num) i11.2 hi11)
  rw [pD11] at pW11
  clear hi11 pD11
  obtain ⟨i12, hi12, W12X, W12Y, hW12X, hW12Y, h, hW12, pW12⟩ :=
    window_select (t := 12) (by norm_num) (bit_get hbits 61) (bit_get hbits 62) (bit_get hbits 63) (bit_get hbits 64) (bit_get hbits 65) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi12
  have pD12 := win_dig (g := g) (t := 12) (by norm_num) (sel5_chunk hbits (a := 61) (by norm_num) i12.2 hi12)
  rw [pD12] at pW12
  clear hi12 pD12
  obtain ⟨i13, hi13, W13X, W13Y, hW13X, hW13Y, h, hW13, pW13⟩ :=
    window_select (t := 13) (by norm_num) (bit_get hbits 66) (bit_get hbits 67) (bit_get hbits 68) (bit_get hbits 69) (bit_get hbits 70) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi13
  have pD13 := win_dig (g := g) (t := 13) (by norm_num) (sel5_chunk hbits (a := 66) (by norm_num) i13.2 hi13)
  rw [pD13] at pW13
  clear hi13 pD13
  obtain ⟨i14, hi14, W14X, W14Y, hW14X, hW14Y, h, hW14, pW14⟩ :=
    window_select (t := 14) (by norm_num) (bit_get hbits 71) (bit_get hbits 72) (bit_get hbits 73) (bit_get hbits 74) (bit_get hbits 75) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi14
  have pD14 := win_dig (g := g) (t := 14) (by norm_num) (sel5_chunk hbits (a := 71) (by norm_num) i14.2 hi14)
  rw [pD14] at pW14
  clear hi14 pD14
  obtain ⟨i15, hi15, W15X, W15Y, hW15X, hW15Y, h, hW15, pW15⟩ :=
    window_select (t := 15) (by norm_num) (bit_get hbits 76) (bit_get hbits 77) (bit_get hbits 78) (bit_get hbits 79) (bit_get hbits 80) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi15
  have pD15 := win_dig (g := g) (t := 15) (by norm_num) (sel5_chunk hbits (a := 76) (by norm_num) i15.2 hi15)
  rw [pD15] at pW15
  clear hi15 pD15
  obtain ⟨i16, hi16, W16X, W16Y, hW16X, hW16Y, h, hW16, pW16⟩ :=
    window_select (t := 16) (by norm_num) (bit_get hbits 81) (bit_get hbits 82) (bit_get hbits 83) (bit_get hbits 84) (bit_get hbits 85) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi16
  have pD16 := win_dig (g := g) (t := 16) (by norm_num) (sel5_chunk hbits (a := 81) (by norm_num) i16.2 hi16)
  rw [pD16] at pW16
  clear hi16 pD16
  obtain ⟨i17, hi17, W17X, W17Y, hW17X, hW17Y, h, hW17, pW17⟩ :=
    window_select (t := 17) (by norm_num) (bit_get hbits 86) (bit_get hbits 87) (bit_get hbits 88) (bit_get hbits 89) (bit_get hbits 90) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi17
  have pD17 := win_dig (g := g) (t := 17) (by norm_num) (sel5_chunk hbits (a := 86) (by norm_num) i17.2 hi17)
  rw [pD17] at pW17
  clear hi17 pD17
  obtain ⟨i18, hi18, W18X, W18Y, hW18X, hW18Y, h, hW18, pW18⟩ :=
    window_select (t := 18) (by norm_num) (bit_get hbits 91) (bit_get hbits 92) (bit_get hbits 93) (bit_get hbits 94) (bit_get hbits 95) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi18
  have pD18 := win_dig (g := g) (t := 18) (by norm_num) (sel5_chunk hbits (a := 91) (by norm_num) i18.2 hi18)
  rw [pD18] at pW18
  clear hi18 pD18
  obtain ⟨i19, hi19, W19X, W19Y, hW19X, hW19Y, h, hW19, pW19⟩ :=
    window_select (t := 19) (by norm_num) (bit_get hbits 96) (bit_get hbits 97) (bit_get hbits 98) (bit_get hbits 99) (bit_get hbits 100) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi19
  have pD19 := win_dig (g := g) (t := 19) (by norm_num) (sel5_chunk hbits (a := 96) (by norm_num) i19.2 hi19)
  rw [pD19] at pW19
  clear hi19 pD19
  obtain ⟨i20, hi20, W20X, W20Y, hW20X, hW20Y, h, hW20, pW20⟩ :=
    window_select (t := 20) (by norm_num) (bit_get hbits 101) (bit_get hbits 102) (bit_get hbits 103) (bit_get hbits 104) (bit_get hbits 105) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi20
  have pD20 := win_dig (g := g) (t := 20) (by norm_num) (sel5_chunk hbits (a := 101) (by norm_num) i20.2 hi20)
  rw [pD20] at pW20
  clear hi20 pD20
  obtain ⟨i21, hi21, W21X, W21Y, hW21X, hW21Y, h, hW21, pW21⟩ :=
    window_select (t := 21) (by norm_num) (bit_get hbits 106) (bit_get hbits 107) (bit_get hbits 108) (bit_get hbits 109) (bit_get hbits 110) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi21
  have pD21 := win_dig (g := g) (t := 21) (by norm_num) (sel5_chunk hbits (a := 106) (by norm_num) i21.2 hi21)
  rw [pD21] at pW21
  clear hi21 pD21
  obtain ⟨i22, hi22, W22X, W22Y, hW22X, hW22Y, h, hW22, pW22⟩ :=
    window_select (t := 22) (by norm_num) (bit_get hbits 111) (bit_get hbits 112) (bit_get hbits 113) (bit_get hbits 114) (bit_get hbits 115) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi22
  have pD22 := win_dig (g := g) (t := 22) (by norm_num) (sel5_chunk hbits (a := 111) (by norm_num) i22.2 hi22)
  rw [pD22] at pW22
  clear hi22 pD22
  obtain ⟨i23, hi23, W23X, W23Y, hW23X, hW23Y, h, hW23, pW23⟩ :=
    window_select (t := 23) (by norm_num) (bit_get hbits 116) (bit_get hbits 117) (bit_get hbits 118) (bit_get hbits 119) (bit_get hbits 120) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi23
  have pD23 := win_dig (g := g) (t := 23) (by norm_num) (sel5_chunk hbits (a := 116) (by norm_num) i23.2 hi23)
  rw [pD23] at pW23
  clear hi23 pD23
  obtain ⟨i24, hi24, W24X, W24Y, hW24X, hW24Y, h, hW24, pW24⟩ :=
    window_select (t := 24) (by norm_num) (bit_get hbits 121) (bit_get hbits 122) (bit_get hbits 123) (bit_get hbits 124) (bit_get hbits 125) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi24
  have pD24 := win_dig (g := g) (t := 24) (by norm_num) (sel5_chunk hbits (a := 121) (by norm_num) i24.2 hi24)
  rw [pD24] at pW24
  clear hi24 pD24
  obtain ⟨i25, hi25, W25X, W25Y, hW25X, hW25Y, h, hW25, pW25⟩ :=
    window_select (t := 25) (by norm_num) (bit_get hbits 126) (bit_get hbits 127) (bit_get hbits 128) (bit_get hbits 129) (bit_get hbits 130) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi25
  have pD25 := win_dig (g := g) (t := 25) (by norm_num) (sel5_chunk hbits (a := 126) (by norm_num) i25.2 hi25)
  rw [pD25] at pW25
  clear hi25 pD25
  obtain ⟨i26, hi26, W26X, W26Y, hW26X, hW26Y, h, hW26, pW26⟩ :=
    window_select (t := 26) (by norm_num) (bit_get hbits 131) (bit_get hbits 132) (bit_get hbits 133) (bit_get hbits 134) (bit_get hbits 135) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi26
  have pD26 := win_dig (g := g) (t := 26) (by norm_num) (sel5_chunk hbits (a := 131) (by norm_num) i26.2 hi26)
  rw [pD26] at pW26
  clear hi26 pD26
  obtain ⟨i27, hi27, W27X, W27Y, hW27X, hW27Y, h, hW27, pW27⟩ :=
    window_select (t := 27) (by norm_num) (bit_get hbits 136) (bit_get hbits 137) (bit_get hbits 138) (bit_get hbits 139) (bit_get hbits 140) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi27
  have pD27 := win_dig (g := g) (t := 27) (by norm_num) (sel5_chunk hbits (a := 136) (by norm_num) i27.2 hi27)
  rw [pD27] at pW27
  clear hi27 pD27
  obtain ⟨i28, hi28, W28X, W28Y, hW28X, hW28Y, h, hW28, pW28⟩ :=
    window_select (t := 28) (by norm_num) (bit_get hbits 141) (bit_get hbits 142) (bit_get hbits 143) (bit_get hbits 144) (bit_get hbits 145) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi28
  have pD28 := win_dig (g := g) (t := 28) (by norm_num) (sel5_chunk hbits (a := 141) (by norm_num) i28.2 hi28)
  rw [pD28] at pW28
  clear hi28 pD28
  obtain ⟨i29, hi29, W29X, W29Y, hW29X, hW29Y, h, hW29, pW29⟩ :=
    window_select (t := 29) (by norm_num) (bit_get hbits 146) (bit_get hbits 147) (bit_get hbits 148) (bit_get hbits 149) (bit_get hbits 150) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi29
  have pD29 := win_dig (g := g) (t := 29) (by norm_num) (sel5_chunk hbits (a := 146) (by norm_num) i29.2 hi29)
  rw [pD29] at pW29
  clear hi29 pD29
  obtain ⟨i30, hi30, W30X, W30Y, hW30X, hW30Y, h, hW30, pW30⟩ :=
    window_select (t := 30) (by norm_num) (bit_get hbits 151) (bit_get hbits 152) (bit_get hbits 153) (bit_get hbits 154) (bit_get hbits 155) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi30
  have pD30 := win_dig (g := g) (t := 30) (by norm_num) (sel5_chunk hbits (a := 151) (by norm_num) i30.2 hi30)
  rw [pD30] at pW30
  clear hi30 pD30
  obtain ⟨i31, hi31, W31X, W31Y, hW31X, hW31Y, h, hW31, pW31⟩ :=
    window_select (t := 31) (by norm_num) (bit_get hbits 156) (bit_get hbits 157) (bit_get hbits 158) (bit_get hbits 159) (bit_get hbits 160) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi31
  have pD31 := win_dig (g := g) (t := 31) (by norm_num) (sel5_chunk hbits (a := 156) (by norm_num) i31.2 hi31)
  rw [pD31] at pW31
  clear hi31 pD31
  obtain ⟨i32, hi32, W32X, W32Y, hW32X, hW32Y, h, hW32, pW32⟩ :=
    window_select (t := 32) (by norm_num) (bit_get hbits 161) (bit_get hbits 162) (bit_get hbits 163) (bit_get hbits 164) (bit_get hbits 165) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi32
  have pD32 := win_dig (g := g) (t := 32) (by norm_num) (sel5_chunk hbits (a := 161) (by norm_num) i32.2 hi32)
  rw [pD32] at pW32
  clear hi32 pD32
  obtain ⟨i33, hi33, W33X, W33Y, hW33X, hW33Y, h, hW33, pW33⟩ :=
    window_select (t := 33) (by norm_num) (bit_get hbits 166) (bit_get hbits 167) (bit_get hbits 168) (bit_get hbits 169) (bit_get hbits 170) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi33
  have pD33 := win_dig (g := g) (t := 33) (by norm_num) (sel5_chunk hbits (a := 166) (by norm_num) i33.2 hi33)
  rw [pD33] at pW33
  clear hi33 pD33
  obtain ⟨i34, hi34, W34X, W34Y, hW34X, hW34Y, h, hW34, pW34⟩ :=
    window_select (t := 34) (by norm_num) (bit_get hbits 171) (bit_get hbits 172) (bit_get hbits 173) (bit_get hbits 174) (bit_get hbits 175) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi34
  have pD34 := win_dig (g := g) (t := 34) (by norm_num) (sel5_chunk hbits (a := 171) (by norm_num) i34.2 hi34)
  rw [pD34] at pW34
  clear hi34 pD34
  obtain ⟨i35, hi35, W35X, W35Y, hW35X, hW35Y, h, hW35, pW35⟩ :=
    window_select (t := 35) (by norm_num) (bit_get hbits 176) (bit_get hbits 177) (bit_get hbits 178) (bit_get hbits 179) (bit_get hbits 180) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi35
  have pD35 := win_dig (g := g) (t := 35) (by norm_num) (sel5_chunk hbits (a := 176) (by norm_num) i35.2 hi35)
  rw [pD35] at pW35
  clear hi35 pD35
  obtain ⟨i36, hi36, W36X, W36Y, hW36X, hW36Y, h, hW36, pW36⟩ :=
    window_select (t := 36) (by norm_num) (bit_get hbits 181) (bit_get hbits 182) (bit_get hbits 183) (bit_get hbits 184) (bit_get hbits 185) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi36
  have pD36 := win_dig (g := g) (t := 36) (by norm_num) (sel5_chunk hbits (a := 181) (by norm_num) i36.2 hi36)
  rw [pD36] at pW36
  clear hi36 pD36
  obtain ⟨i37, hi37, W37X, W37Y, hW37X, hW37Y, h, hW37, pW37⟩ :=
    window_select (t := 37) (by norm_num) (bit_get hbits 186) (bit_get hbits 187) (bit_get hbits 188) (bit_get hbits 189) (bit_get hbits 190) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi37
  have pD37 := win_dig (g := g) (t := 37) (by norm_num) (sel5_chunk hbits (a := 186) (by norm_num) i37.2 hi37)
  rw [pD37] at pW37
  clear hi37 pD37
  obtain ⟨i38, hi38, W38X, W38Y, hW38X, hW38Y, h, hW38, pW38⟩ :=
    window_select (t := 38) (by norm_num) (bit_get hbits 191) (bit_get hbits 192) (bit_get hbits 193) (bit_get hbits 194) (bit_get hbits 195) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi38
  have pD38 := win_dig (g := g) (t := 38) (by norm_num) (sel5_chunk hbits (a := 191) (by norm_num) i38.2 hi38)
  rw [pD38] at pW38
  clear hi38 pD38
  obtain ⟨i39, hi39, W39X, W39Y, hW39X, hW39Y, h, hW39, pW39⟩ :=
    window_select (t := 39) (by norm_num) (bit_get hbits 196) (bit_get hbits 197) (bit_get hbits 198) (bit_get hbits 199) (bit_get hbits 200) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi39
  have pD39 := win_dig (g := g) (t := 39) (by norm_num) (sel5_chunk hbits (a := 196) (by norm_num) i39.2 hi39)
  rw [pD39] at pW39
  clear hi39 pD39
  obtain ⟨i40, hi40, W40X, W40Y, hW40X, hW40Y, h, hW40, pW40⟩ :=
    window_select (t := 40) (by norm_num) (bit_get hbits 201) (bit_get hbits 202) (bit_get hbits 203) (bit_get hbits 204) (bit_get hbits 205) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi40
  have pD40 := win_dig (g := g) (t := 40) (by norm_num) (sel5_chunk hbits (a := 201) (by norm_num) i40.2 hi40)
  rw [pD40] at pW40
  clear hi40 pD40
  obtain ⟨i41, hi41, W41X, W41Y, hW41X, hW41Y, h, hW41, pW41⟩ :=
    window_select (t := 41) (by norm_num) (bit_get hbits 206) (bit_get hbits 207) (bit_get hbits 208) (bit_get hbits 209) (bit_get hbits 210) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi41
  have pD41 := win_dig (g := g) (t := 41) (by norm_num) (sel5_chunk hbits (a := 206) (by norm_num) i41.2 hi41)
  rw [pD41] at pW41
  clear hi41 pD41
  obtain ⟨i42, hi42, W42X, W42Y, hW42X, hW42Y, h, hW42, pW42⟩ :=
    window_select (t := 42) (by norm_num) (bit_get hbits 211) (bit_get hbits 212) (bit_get hbits 213) (bit_get hbits 214) (bit_get hbits 215) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi42
  have pD42 := win_dig (g := g) (t := 42) (by norm_num) (sel5_chunk hbits (a := 211) (by norm_num) i42.2 hi42)
  rw [pD42] at pW42
  clear hi42 pD42
  obtain ⟨i43, hi43, W43X, W43Y, hW43X, hW43Y, h, hW43, pW43⟩ :=
    window_select (t := 43) (by norm_num) (bit_get hbits 216) (bit_get hbits 217) (bit_get hbits 218) (bit_get hbits 219) (bit_get hbits 220) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi43
  have pD43 := win_dig (g := g) (t := 43) (by norm_num) (sel5_chunk hbits (a := 216) (by norm_num) i43.2 hi43)
  rw [pD43] at pW43
  clear hi43 pD43
  obtain ⟨i44, hi44, W44X, W44Y, hW44X, hW44Y, h, hW44, pW44⟩ :=
    window_select (t := 44) (by norm_num) (bit_get hbits 221) (bit_get hbits 222) (bit_get hbits 223) (bit_get hbits 224) (bit_get hbits 225) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi44
  have pD44 := win_dig (g := g) (t := 44) (by norm_num) (sel5_chunk hbits (a := 221) (by norm_num) i44.2 hi44)
  rw [pD44] at pW44
  clear hi44 pD44
  obtain ⟨i45, hi45, W45X, W45Y, hW45X, hW45Y, h, hW45, pW45⟩ :=
    window_select (t := 45) (by norm_num) (bit_get hbits 226) (bit_get hbits 227) (bit_get hbits 228) (bit_get hbits 229) (bit_get hbits 230) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi45
  have pD45 := win_dig (g := g) (t := 45) (by norm_num) (sel5_chunk hbits (a := 226) (by norm_num) i45.2 hi45)
  rw [pD45] at pW45
  clear hi45 pD45
  obtain ⟨i46, hi46, W46X, W46Y, hW46X, hW46Y, h, hW46, pW46⟩ :=
    window_select (t := 46) (by norm_num) (bit_get hbits 231) (bit_get hbits 232) (bit_get hbits 233) (bit_get hbits 234) (bit_get hbits 235) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi46
  have pD46 := win_dig (g := g) (t := 46) (by norm_num) (sel5_chunk hbits (a := 231) (by norm_num) i46.2 hi46)
  rw [pD46] at pW46
  clear hi46 pD46
  obtain ⟨i47, hi47, W47X, W47Y, hW47X, hW47Y, h, hW47, pW47⟩ :=
    window_select (t := 47) (by norm_num) (bit_get hbits 236) (bit_get hbits 237) (bit_get hbits 238) (bit_get hbits 239) (bit_get hbits 240) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi47
  have pD47 := win_dig (g := g) (t := 47) (by norm_num) (sel5_chunk hbits (a := 236) (by norm_num) i47.2 hi47)
  rw [pD47] at pW47
  clear hi47 pD47
  obtain ⟨i48, hi48, W48X, W48Y, hW48X, hW48Y, h, hW48, pW48⟩ :=
    window_select (t := 48) (by norm_num) (bit_get hbits 241) (bit_get hbits 242) (bit_get hbits 243) (bit_get hbits 244) (bit_get hbits 245) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi48
  have pD48 := win_dig (g := g) (t := 48) (by norm_num) (sel5_chunk hbits (a := 241) (by norm_num) i48.2 hi48)
  rw [pD48] at pW48
  clear hi48 pD48
  obtain ⟨i49, hi49, W49X, W49Y, hW49X, hW49Y, h, hW49, pW49⟩ :=
    window_select (t := 49) (by norm_num) (bit_get hbits 246) (bit_get hbits 247) (bit_get hbits 248) (bit_get hbits 249) (bit_get hbits 250) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi49
  have pD49 := win_dig (g := g) (t := 49) (by norm_num) (sel5_chunk hbits (a := 246) (by norm_num) i49.2 hi49)
  rw [pD49] at pW49
  clear hi49 pD49
  obtain ⟨i50, hi50, W50X, W50Y, hW50X, hW50Y, h, hW50, pW50⟩ :=
    window_select (t := 50) (by norm_num) (bit_get hbits 251) (bit_get hbits 252) (bit_get hbits 253) (bit_get hbits 254) (bit_get hbits 255) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hi50
  have pD50 := win_dig (g := g) (t := 50) (by norm_num) (sel5_chunk hbits (a := 251) (by norm_num) i50.2 hi50)
  rw [pD50] at pW50
  clear hi50 pD50
  obtain ⟨iT, hiT, TX, TY, hTX, hTY, h, hT, pT⟩ := top_select (bit_get hbits 256) (bit_get hbits 0) h
  simp only [vget_getD, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at hiT
  rw [top_val hbits (le_refl 257) iT.2 hiT] at pT
  clear hiT
  elim_gates_shallow h
  have pA1 : mkPoint hW0 = (∑ u ∈ Finset.range 1, digOf g u * 2 ^ (5 * u)) • G := by
    rw [pW0, Finset.sum_range_one]
  obtain ⟨X1, L1, hX1, hL1, h, rel1⟩ := chain_first_sound hl W0X W1X W1Y W0Y _ _ _ hW0X hW1X hW1Y hW0Y h
  obtain ⟨hne1, hs1⟩ := comb_acc_step hbits (le_refl 257) (t := 1) (by norm_num) pA1 pW1
  obtain ⟨hA2, pA2⟩ := chain_first_group hW0 hW1 hne1 rel1
  rw [hs1] at pA2
  clear hne1 hs1 rel1
  obtain ⟨X2, L2, hX2, hL2, h, rel2⟩ := chain_hd0a2e1d5_sound hl X1 L1 W1X W1Y W2X W2Y W0Y
    hX1 hL1 hW1X hW1Y hW2X hW2Y h
  obtain ⟨hne2, hs2⟩ := comb_acc_step hbits (le_refl 257) (t := 2) (by norm_num) pA2 pW2
  obtain ⟨hA3, pA3⟩ := chain_group hA2 hW2 hne2 rel2
  rw [hs2] at pA3
  clear hne2 hs2 rel2
  obtain ⟨X3, L3, hX3, hL3, h, rel3⟩ := chain_hfeca3431_sound hl X2 L2 W2X W2Y W3X W3Y W0Y
    hX2 hL2 hW2X hW2Y hW3X hW3Y h
  obtain ⟨hne3, hs3⟩ := comb_acc_step hbits (le_refl 257) (t := 3) (by norm_num) pA3 pW3
  obtain ⟨hA4, pA4⟩ := chain_group hA3 hW3 hne3 rel3
  rw [hs3] at pA4
  clear hne3 hs3 rel3
  obtain ⟨X4, L4, hX4, hL4, h, rel4⟩ := chain_h98a10bfb_sound hl X3 L3 W3X W3Y W4X W4Y W0Y
    hX3 hL3 hW3X hW3Y hW4X hW4Y h
  obtain ⟨hne4, hs4⟩ := comb_acc_step hbits (le_refl 257) (t := 4) (by norm_num) pA4 pW4
  obtain ⟨hA5, pA5⟩ := chain_group hA4 hW4 hne4 rel4
  rw [hs4] at pA5
  clear hne4 hs4 rel4
  obtain ⟨X5, L5, hX5, hL5, h, rel5⟩ := chain_hc2445cd4_sound hl X4 L4 W4X W4Y W5X W5Y W0Y
    hX4 hL4 hW4X hW4Y hW5X hW5Y h
  obtain ⟨hne5, hs5⟩ := comb_acc_step hbits (le_refl 257) (t := 5) (by norm_num) pA5 pW5
  obtain ⟨hA6, pA6⟩ := chain_group hA5 hW5 hne5 rel5
  rw [hs5] at pA6
  clear hne5 hs5 rel5
  obtain ⟨X6, L6, hX6, hL6, h, rel6⟩ := chain_he11b64cc_sound hl X5 L5 W5X W5Y W6X W6Y W0Y
    hX5 hL5 hW5X hW5Y hW6X hW6Y h
  obtain ⟨hne6, hs6⟩ := comb_acc_step hbits (le_refl 257) (t := 6) (by norm_num) pA6 pW6
  obtain ⟨hA7, pA7⟩ := chain_group hA6 hW6 hne6 rel6
  rw [hs6] at pA7
  clear hne6 hs6 rel6
  obtain ⟨X7, L7, hX7, hL7, h, rel7⟩ := chain_ha337781a_sound hl X6 L6 W6X W6Y W7X W7Y W0Y
    hX6 hL6 hW6X hW6Y hW7X hW7Y h
  obtain ⟨hne7, hs7⟩ := comb_acc_step hbits (le_refl 257) (t := 7) (by norm_num) pA7 pW7
  obtain ⟨hA8, pA8⟩ := chain_group hA7 hW7 hne7 rel7
  rw [hs7] at pA8
  clear hne7 hs7 rel7
  obtain ⟨X8, L8, hX8, hL8, h, rel8⟩ := chain_h722a110e_sound hl X7 L7 W7X W7Y W8X W8Y W0Y
    hX7 hL7 hW7X hW7Y hW8X hW8Y h
  obtain ⟨hne8, hs8⟩ := comb_acc_step hbits (le_refl 257) (t := 8) (by norm_num) pA8 pW8
  obtain ⟨hA9, pA9⟩ := chain_group hA8 hW8 hne8 rel8
  rw [hs8] at pA9
  clear hne8 hs8 rel8
  obtain ⟨X9, L9, hX9, hL9, h, rel9⟩ := chain_h16154bb8_sound hl X8 L8 W8X W8Y W9X W9Y W0Y
    hX8 hL8 hW8X hW8Y hW9X hW9Y h
  obtain ⟨hne9, hs9⟩ := comb_acc_step hbits (le_refl 257) (t := 9) (by norm_num) pA9 pW9
  obtain ⟨hA10, pA10⟩ := chain_group hA9 hW9 hne9 rel9
  rw [hs9] at pA10
  clear hne9 hs9 rel9
  obtain ⟨X10, L10, hX10, hL10, h, rel10⟩ := chain_h0b2c7a04_sound hl X9 L9 W9X W9Y W10X W10Y W0Y
    hX9 hL9 hW9X hW9Y hW10X hW10Y h
  obtain ⟨hne10, hs10⟩ := comb_acc_step hbits (le_refl 257) (t := 10) (by norm_num) pA10 pW10
  obtain ⟨hA11, pA11⟩ := chain_group hA10 hW10 hne10 rel10
  rw [hs10] at pA11
  clear hne10 hs10 rel10
  obtain ⟨X11, L11, hX11, hL11, h, rel11⟩ := chain_h7791617c_sound hl X10 L10 W10X W10Y W11X W11Y W0Y
    hX10 hL10 hW10X hW10Y hW11X hW11Y h
  obtain ⟨hne11, hs11⟩ := comb_acc_step hbits (le_refl 257) (t := 11) (by norm_num) pA11 pW11
  obtain ⟨hA12, pA12⟩ := chain_group hA11 hW11 hne11 rel11
  rw [hs11] at pA12
  clear hne11 hs11 rel11
  obtain ⟨X12, L12, hX12, hL12, h, rel12⟩ := chain_h4279c9fa_sound hl X11 L11 W11X W11Y W12X W12Y W0Y
    hX11 hL11 hW11X hW11Y hW12X hW12Y h
  obtain ⟨hne12, hs12⟩ := comb_acc_step hbits (le_refl 257) (t := 12) (by norm_num) pA12 pW12
  obtain ⟨hA13, pA13⟩ := chain_group hA12 hW12 hne12 rel12
  rw [hs12] at pA13
  clear hne12 hs12 rel12
  obtain ⟨X13, L13, hX13, hL13, h, rel13⟩ := chain_he5aef826_sound hl X12 L12 W12X W12Y W13X W13Y W0Y
    hX12 hL12 hW12X hW12Y hW13X hW13Y h
  obtain ⟨hne13, hs13⟩ := comb_acc_step hbits (le_refl 257) (t := 13) (by norm_num) pA13 pW13
  obtain ⟨hA14, pA14⟩ := chain_group hA13 hW13 hne13 rel13
  rw [hs13] at pA14
  clear hne13 hs13 rel13
  obtain ⟨X14, L14, hX14, hL14, h, rel14⟩ := chain_h893b2021_sound hl X13 L13 W13X W13Y W14X W14Y W0Y
    hX13 hL13 hW13X hW13Y hW14X hW14Y h
  obtain ⟨hne14, hs14⟩ := comb_acc_step hbits (le_refl 257) (t := 14) (by norm_num) pA14 pW14
  obtain ⟨hA15, pA15⟩ := chain_group hA14 hW14 hne14 rel14
  rw [hs14] at pA15
  clear hne14 hs14 rel14
  obtain ⟨X15, L15, hX15, hL15, h, rel15⟩ := chain_h5c8297ae_sound hl X14 L14 W14X W14Y W15X W15Y W0Y
    hX14 hL14 hW14X hW14Y hW15X hW15Y h
  obtain ⟨hne15, hs15⟩ := comb_acc_step hbits (le_refl 257) (t := 15) (by norm_num) pA15 pW15
  obtain ⟨hA16, pA16⟩ := chain_group hA15 hW15 hne15 rel15
  rw [hs15] at pA16
  clear hne15 hs15 rel15
  obtain ⟨X16, L16, hX16, hL16, h, rel16⟩ := chain_h18d73f47_sound hl X15 L15 W15X W15Y W16X W16Y W0Y
    hX15 hL15 hW15X hW15Y hW16X hW16Y h
  obtain ⟨hne16, hs16⟩ := comb_acc_step hbits (le_refl 257) (t := 16) (by norm_num) pA16 pW16
  obtain ⟨hA17, pA17⟩ := chain_group hA16 hW16 hne16 rel16
  rw [hs16] at pA17
  clear hne16 hs16 rel16
  obtain ⟨X17, L17, hX17, hL17, h, rel17⟩ := chain_he57d21d5_sound hl X16 L16 W16X W16Y W17X W17Y W0Y
    hX16 hL16 hW16X hW16Y hW17X hW17Y h
  obtain ⟨hne17, hs17⟩ := comb_acc_step hbits (le_refl 257) (t := 17) (by norm_num) pA17 pW17
  obtain ⟨hA18, pA18⟩ := chain_group hA17 hW17 hne17 rel17
  rw [hs17] at pA18
  clear hne17 hs17 rel17
  obtain ⟨X18, L18, hX18, hL18, h, rel18⟩ := chain_hf0b5218f_sound hl X17 L17 W17X W17Y W18X W18Y W0Y
    hX17 hL17 hW17X hW17Y hW18X hW18Y h
  obtain ⟨hne18, hs18⟩ := comb_acc_step hbits (le_refl 257) (t := 18) (by norm_num) pA18 pW18
  obtain ⟨hA19, pA19⟩ := chain_group hA18 hW18 hne18 rel18
  rw [hs18] at pA19
  clear hne18 hs18 rel18
  obtain ⟨X19, L19, hX19, hL19, h, rel19⟩ := chain_hf2e5fd4b_sound hl X18 L18 W18X W18Y W19X W19Y W0Y
    hX18 hL18 hW18X hW18Y hW19X hW19Y h
  obtain ⟨hne19, hs19⟩ := comb_acc_step hbits (le_refl 257) (t := 19) (by norm_num) pA19 pW19
  obtain ⟨hA20, pA20⟩ := chain_group hA19 hW19 hne19 rel19
  rw [hs19] at pA20
  clear hne19 hs19 rel19
  obtain ⟨X20, L20, hX20, hL20, h, rel20⟩ := chain_h38305e15_sound hl X19 L19 W19X W19Y W20X W20Y W0Y
    hX19 hL19 hW19X hW19Y hW20X hW20Y h
  obtain ⟨hne20, hs20⟩ := comb_acc_step hbits (le_refl 257) (t := 20) (by norm_num) pA20 pW20
  obtain ⟨hA21, pA21⟩ := chain_group hA20 hW20 hne20 rel20
  rw [hs20] at pA21
  clear hne20 hs20 rel20
  obtain ⟨X21, L21, hX21, hL21, h, rel21⟩ := chain_hd1f04580_sound hl X20 L20 W20X W20Y W21X W21Y W0Y
    hX20 hL20 hW20X hW20Y hW21X hW21Y h
  obtain ⟨hne21, hs21⟩ := comb_acc_step hbits (le_refl 257) (t := 21) (by norm_num) pA21 pW21
  obtain ⟨hA22, pA22⟩ := chain_group hA21 hW21 hne21 rel21
  rw [hs21] at pA22
  clear hne21 hs21 rel21
  obtain ⟨X22, L22, hX22, hL22, h, rel22⟩ := chain_h2f8d1084_sound hl X21 L21 W21X W21Y W22X W22Y W0Y
    hX21 hL21 hW21X hW21Y hW22X hW22Y h
  obtain ⟨hne22, hs22⟩ := comb_acc_step hbits (le_refl 257) (t := 22) (by norm_num) pA22 pW22
  obtain ⟨hA23, pA23⟩ := chain_group hA22 hW22 hne22 rel22
  rw [hs22] at pA23
  clear hne22 hs22 rel22
  obtain ⟨X23, L23, hX23, hL23, h, rel23⟩ := chain_hbc9d292f_sound hl X22 L22 W22X W22Y W23X W23Y W0Y
    hX22 hL22 hW22X hW22Y hW23X hW23Y h
  obtain ⟨hne23, hs23⟩ := comb_acc_step hbits (le_refl 257) (t := 23) (by norm_num) pA23 pW23
  obtain ⟨hA24, pA24⟩ := chain_group hA23 hW23 hne23 rel23
  rw [hs23] at pA24
  clear hne23 hs23 rel23
  obtain ⟨X24, L24, hX24, hL24, h, rel24⟩ := chain_hd5949308_sound hl X23 L23 W23X W23Y W24X W24Y W0Y
    hX23 hL23 hW23X hW23Y hW24X hW24Y h
  obtain ⟨hne24, hs24⟩ := comb_acc_step hbits (le_refl 257) (t := 24) (by norm_num) pA24 pW24
  obtain ⟨hA25, pA25⟩ := chain_group hA24 hW24 hne24 rel24
  rw [hs24] at pA25
  clear hne24 hs24 rel24
  obtain ⟨X25, L25, hX25, hL25, h, rel25⟩ := chain_h6e26f17b_sound hl X24 L24 W24X W24Y W25X W25Y W0Y
    hX24 hL24 hW24X hW24Y hW25X hW25Y h
  obtain ⟨hne25, hs25⟩ := comb_acc_step hbits (le_refl 257) (t := 25) (by norm_num) pA25 pW25
  obtain ⟨hA26, pA26⟩ := chain_group hA25 hW25 hne25 rel25
  rw [hs25] at pA26
  clear hne25 hs25 rel25
  obtain ⟨X26, L26, hX26, hL26, h, rel26⟩ := chain_h40db0ded_sound hl X25 L25 W25X W25Y W26X W26Y W0Y
    hX25 hL25 hW25X hW25Y hW26X hW26Y h
  obtain ⟨hne26, hs26⟩ := comb_acc_step hbits (le_refl 257) (t := 26) (by norm_num) pA26 pW26
  obtain ⟨hA27, pA27⟩ := chain_group hA26 hW26 hne26 rel26
  rw [hs26] at pA27
  clear hne26 hs26 rel26
  obtain ⟨X27, L27, hX27, hL27, h, rel27⟩ := chain_h015a0c08_sound hl X26 L26 W26X W26Y W27X W27Y W0Y
    hX26 hL26 hW26X hW26Y hW27X hW27Y h
  obtain ⟨hne27, hs27⟩ := comb_acc_step hbits (le_refl 257) (t := 27) (by norm_num) pA27 pW27
  obtain ⟨hA28, pA28⟩ := chain_group hA27 hW27 hne27 rel27
  rw [hs27] at pA28
  clear hne27 hs27 rel27
  obtain ⟨X28, L28, hX28, hL28, h, rel28⟩ := chain_he6b197a7_sound hl X27 L27 W27X W27Y W28X W28Y W0Y
    hX27 hL27 hW27X hW27Y hW28X hW28Y h
  obtain ⟨hne28, hs28⟩ := comb_acc_step hbits (le_refl 257) (t := 28) (by norm_num) pA28 pW28
  obtain ⟨hA29, pA29⟩ := chain_group hA28 hW28 hne28 rel28
  rw [hs28] at pA29
  clear hne28 hs28 rel28
  obtain ⟨X29, L29, hX29, hL29, h, rel29⟩ := chain_h59272257_sound hl X28 L28 W28X W28Y W29X W29Y W0Y
    hX28 hL28 hW28X hW28Y hW29X hW29Y h
  obtain ⟨hne29, hs29⟩ := comb_acc_step hbits (le_refl 257) (t := 29) (by norm_num) pA29 pW29
  obtain ⟨hA30, pA30⟩ := chain_group hA29 hW29 hne29 rel29
  rw [hs29] at pA30
  clear hne29 hs29 rel29
  obtain ⟨X30, L30, hX30, hL30, h, rel30⟩ := chain_h18a1cf88_sound hl X29 L29 W29X W29Y W30X W30Y W0Y
    hX29 hL29 hW29X hW29Y hW30X hW30Y h
  obtain ⟨hne30, hs30⟩ := comb_acc_step hbits (le_refl 257) (t := 30) (by norm_num) pA30 pW30
  obtain ⟨hA31, pA31⟩ := chain_group hA30 hW30 hne30 rel30
  rw [hs30] at pA31
  clear hne30 hs30 rel30
  obtain ⟨X31, L31, hX31, hL31, h, rel31⟩ := chain_h84b7fff5_sound hl X30 L30 W30X W30Y W31X W31Y W0Y
    hX30 hL30 hW30X hW30Y hW31X hW31Y h
  obtain ⟨hne31, hs31⟩ := comb_acc_step hbits (le_refl 257) (t := 31) (by norm_num) pA31 pW31
  obtain ⟨hA32, pA32⟩ := chain_group hA31 hW31 hne31 rel31
  rw [hs31] at pA32
  clear hne31 hs31 rel31
  obtain ⟨X32, L32, hX32, hL32, h, rel32⟩ := chain_hfcf24f49_sound hl X31 L31 W31X W31Y W32X W32Y W0Y
    hX31 hL31 hW31X hW31Y hW32X hW32Y h
  obtain ⟨hne32, hs32⟩ := comb_acc_step hbits (le_refl 257) (t := 32) (by norm_num) pA32 pW32
  obtain ⟨hA33, pA33⟩ := chain_group hA32 hW32 hne32 rel32
  rw [hs32] at pA33
  clear hne32 hs32 rel32
  obtain ⟨X33, L33, hX33, hL33, h, rel33⟩ := chain_ha9cc5411_sound hl X32 L32 W32X W32Y W33X W33Y W0Y
    hX32 hL32 hW32X hW32Y hW33X hW33Y h
  obtain ⟨hne33, hs33⟩ := comb_acc_step hbits (le_refl 257) (t := 33) (by norm_num) pA33 pW33
  obtain ⟨hA34, pA34⟩ := chain_group hA33 hW33 hne33 rel33
  rw [hs33] at pA34
  clear hne33 hs33 rel33
  obtain ⟨X34, L34, hX34, hL34, h, rel34⟩ := chain_h63e076b3_sound hl X33 L33 W33X W33Y W34X W34Y W0Y
    hX33 hL33 hW33X hW33Y hW34X hW34Y h
  obtain ⟨hne34, hs34⟩ := comb_acc_step hbits (le_refl 257) (t := 34) (by norm_num) pA34 pW34
  obtain ⟨hA35, pA35⟩ := chain_group hA34 hW34 hne34 rel34
  rw [hs34] at pA35
  clear hne34 hs34 rel34
  obtain ⟨X35, L35, hX35, hL35, h, rel35⟩ := chain_h9ff1cd8b_sound hl X34 L34 W34X W34Y W35X W35Y W0Y
    hX34 hL34 hW34X hW34Y hW35X hW35Y h
  obtain ⟨hne35, hs35⟩ := comb_acc_step hbits (le_refl 257) (t := 35) (by norm_num) pA35 pW35
  obtain ⟨hA36, pA36⟩ := chain_group hA35 hW35 hne35 rel35
  rw [hs35] at pA36
  clear hne35 hs35 rel35
  obtain ⟨X36, L36, hX36, hL36, h, rel36⟩ := chain_h308152e6_sound hl X35 L35 W35X W35Y W36X W36Y W0Y
    hX35 hL35 hW35X hW35Y hW36X hW36Y h
  obtain ⟨hne36, hs36⟩ := comb_acc_step hbits (le_refl 257) (t := 36) (by norm_num) pA36 pW36
  obtain ⟨hA37, pA37⟩ := chain_group hA36 hW36 hne36 rel36
  rw [hs36] at pA37
  clear hne36 hs36 rel36
  obtain ⟨X37, L37, hX37, hL37, h, rel37⟩ := chain_h2ec09f94_sound hl X36 L36 W36X W36Y W37X W37Y W0Y
    hX36 hL36 hW36X hW36Y hW37X hW37Y h
  obtain ⟨hne37, hs37⟩ := comb_acc_step hbits (le_refl 257) (t := 37) (by norm_num) pA37 pW37
  obtain ⟨hA38, pA38⟩ := chain_group hA37 hW37 hne37 rel37
  rw [hs37] at pA38
  clear hne37 hs37 rel37
  obtain ⟨X38, L38, hX38, hL38, h, rel38⟩ := chain_h1d7ce17b_sound hl X37 L37 W37X W37Y W38X W38Y W0Y
    hX37 hL37 hW37X hW37Y hW38X hW38Y h
  obtain ⟨hne38, hs38⟩ := comb_acc_step hbits (le_refl 257) (t := 38) (by norm_num) pA38 pW38
  obtain ⟨hA39, pA39⟩ := chain_group hA38 hW38 hne38 rel38
  rw [hs38] at pA39
  clear hne38 hs38 rel38
  obtain ⟨X39, L39, hX39, hL39, h, rel39⟩ := chain_hc0cdb690_sound hl X38 L38 W38X W38Y W39X W39Y W0Y
    hX38 hL38 hW38X hW38Y hW39X hW39Y h
  obtain ⟨hne39, hs39⟩ := comb_acc_step hbits (le_refl 257) (t := 39) (by norm_num) pA39 pW39
  obtain ⟨hA40, pA40⟩ := chain_group hA39 hW39 hne39 rel39
  rw [hs39] at pA40
  clear hne39 hs39 rel39
  obtain ⟨X40, L40, hX40, hL40, h, rel40⟩ := chain_h27bf5feb_sound hl X39 L39 W39X W39Y W40X W40Y W0Y
    hX39 hL39 hW39X hW39Y hW40X hW40Y h
  obtain ⟨hne40, hs40⟩ := comb_acc_step hbits (le_refl 257) (t := 40) (by norm_num) pA40 pW40
  obtain ⟨hA41, pA41⟩ := chain_group hA40 hW40 hne40 rel40
  rw [hs40] at pA41
  clear hne40 hs40 rel40
  obtain ⟨X41, L41, hX41, hL41, h, rel41⟩ := chain_hcf989bc7_sound hl X40 L40 W40X W40Y W41X W41Y W0Y
    hX40 hL40 hW40X hW40Y hW41X hW41Y h
  obtain ⟨hne41, hs41⟩ := comb_acc_step hbits (le_refl 257) (t := 41) (by norm_num) pA41 pW41
  obtain ⟨hA42, pA42⟩ := chain_group hA41 hW41 hne41 rel41
  rw [hs41] at pA42
  clear hne41 hs41 rel41
  obtain ⟨X42, L42, hX42, hL42, h, rel42⟩ := chain_h87d7c1d5_sound hl X41 L41 W41X W41Y W42X W42Y W0Y
    hX41 hL41 hW41X hW41Y hW42X hW42Y h
  obtain ⟨hne42, hs42⟩ := comb_acc_step hbits (le_refl 257) (t := 42) (by norm_num) pA42 pW42
  obtain ⟨hA43, pA43⟩ := chain_group hA42 hW42 hne42 rel42
  rw [hs42] at pA43
  clear hne42 hs42 rel42
  obtain ⟨X43, L43, hX43, hL43, h, rel43⟩ := chain_hb365cd9c_sound hl X42 L42 W42X W42Y W43X W43Y W0Y
    hX42 hL42 hW42X hW42Y hW43X hW43Y h
  obtain ⟨hne43, hs43⟩ := comb_acc_step hbits (le_refl 257) (t := 43) (by norm_num) pA43 pW43
  obtain ⟨hA44, pA44⟩ := chain_group hA43 hW43 hne43 rel43
  rw [hs43] at pA44
  clear hne43 hs43 rel43
  obtain ⟨X44, L44, hX44, hL44, h, rel44⟩ := chain_hff84174b_sound hl X43 L43 W43X W43Y W44X W44Y W0Y
    hX43 hL43 hW43X hW43Y hW44X hW44Y h
  obtain ⟨hne44, hs44⟩ := comb_acc_step hbits (le_refl 257) (t := 44) (by norm_num) pA44 pW44
  obtain ⟨hA45, pA45⟩ := chain_group hA44 hW44 hne44 rel44
  rw [hs44] at pA45
  clear hne44 hs44 rel44
  obtain ⟨X45, L45, hX45, hL45, h, rel45⟩ := chain_he9395e0b_sound hl X44 L44 W44X W44Y W45X W45Y W0Y
    hX44 hL44 hW44X hW44Y hW45X hW45Y h
  obtain ⟨hne45, hs45⟩ := comb_acc_step hbits (le_refl 257) (t := 45) (by norm_num) pA45 pW45
  obtain ⟨hA46, pA46⟩ := chain_group hA45 hW45 hne45 rel45
  rw [hs45] at pA46
  clear hne45 hs45 rel45
  obtain ⟨X46, L46, hX46, hL46, h, rel46⟩ := chain_he4e1c949_sound hl X45 L45 W45X W45Y W46X W46Y W0Y
    hX45 hL45 hW45X hW45Y hW46X hW46Y h
  obtain ⟨hne46, hs46⟩ := comb_acc_step hbits (le_refl 257) (t := 46) (by norm_num) pA46 pW46
  obtain ⟨hA47, pA47⟩ := chain_group hA46 hW46 hne46 rel46
  rw [hs46] at pA47
  clear hne46 hs46 rel46
  obtain ⟨X47, L47, hX47, hL47, h, rel47⟩ := chain_h33cb1110_sound hl X46 L46 W46X W46Y W47X W47Y W0Y
    hX46 hL46 hW46X hW46Y hW47X hW47Y h
  obtain ⟨hne47, hs47⟩ := comb_acc_step hbits (le_refl 257) (t := 47) (by norm_num) pA47 pW47
  obtain ⟨hA48, pA48⟩ := chain_group hA47 hW47 hne47 rel47
  rw [hs47] at pA48
  clear hne47 hs47 rel47
  obtain ⟨X48, L48, hX48, hL48, h, rel48⟩ := chain_h2390b750_sound hl X47 L47 W47X W47Y W48X W48Y W0Y
    hX47 hL47 hW47X hW47Y hW48X hW48Y h
  obtain ⟨hne48, hs48⟩ := comb_acc_step hbits (le_refl 257) (t := 48) (by norm_num) pA48 pW48
  obtain ⟨hA49, pA49⟩ := chain_group hA48 hW48 hne48 rel48
  rw [hs48] at pA49
  clear hne48 hs48 rel48
  obtain ⟨X49, L49, hX49, hL49, h, rel49⟩ := chain_h0f057500_sound hl X48 L48 W48X W48Y W49X W49Y W0Y
    hX48 hL48 hW48X hW48Y hW49X hW49Y h
  obtain ⟨hne49, hs49⟩ := comb_acc_step hbits (le_refl 257) (t := 49) (by norm_num) pA49 pW49
  obtain ⟨hA50, pA50⟩ := chain_group hA49 hW49 hne49 rel49
  rw [hs49] at pA50
  clear hne49 hs49 rel49
  obtain ⟨X50, L50, hX50, hL50, h, rel50⟩ := chain_hb9331b93_sound hl X49 L49 W49X W49Y W50X W50Y W0Y
    hX49 hL49 hW49X hW49Y hW50X hW50Y h
  obtain ⟨hne50, hs50⟩ := comb_acc_step hbits (le_refl 257) (t := 50) (by norm_num) pA50 pW50
  obtain ⟨hA51, pA51⟩ := chain_group hA50 hW50 hne50 rel50
  rw [hs50] at pA51
  clear hne50 hs50 rel50
  obtain ⟨EX, hEXlo, hEXhi, hEXvlo, hEXvhi, h, vEX⟩ :=
    CheckPolynomial_8_h78194ae0_sound hl [⟨8, X50⟩] (elemsMatch_of (by show [X50.bnd] = _; rw [hX50]; rfl))
      _ (by limbs_tac [get2_0, get2_1]) h
  have hEXb := eval_bnd hEXlo hEXhi hEXvlo hEXvhi rfl
  clear hEXlo hEXhi hEXvlo hEXvhi
  elim_gates_shallow h
  unfold ScalarMulBase_8_h3037b025_p2 at h
  elim_gates_shallow h
  set XD := linElem [(1, W50X), (-1, EX)] with hXD
  obtain ⟨EY, hEYlo, hEYhi, hEYvlo, hEYvhi, h, vEY⟩ :=
    CheckPolynomial_24_h0845ed76_sound hl [⟨8, L50⟩, ⟨8, XD⟩, ⟨8, W50Y⟩]
      (elemsMatch_of (by
        show [L50.bnd, XD.bnd, W50Y.bnd] = _
        rw [hXD, linElem_bnd]; simp only [List.map]; rw [hW50X, hEXb, hL50, hW50Y]; rfl))
      _ (by limbs_tac [hXD, get2_0, get2_1]) h
  have hEYb := eval_bnd hEYlo hEYhi hEYvlo hEYvhi rfl
  clear hEYlo hEYhi hEYvlo hEYvhi
  have m1 : (cert_h78194ae0.m : ℤ) = p := rfl
  have m2 : (cert_h0845ed76.m : ℤ) = p := rfl
  have e1 : cert_h78194ae0.exprValue (values [⟨8, X50⟩]) = X50.value := by
    simp [PolyShape.exprValue, values, cert_h78194ae0]
  have e2 : cert_h0845ed76.exprValue (values [⟨8, L50⟩, ⟨8, XD⟩, ⟨8, W50Y⟩]) =
      L50.value * XD.value - W50Y.value := by
    simp [PolyShape.exprValue, values, cert_h0845ed76]; try ring
  have vXD : XD.value = W50X.value - EX.value := by rw [hXD, linElem_value]; simp; try ring
  rw [e1, m1, modEq_p_iff] at vEX
  rw [e2, m2, vXD, modEq_p_iff] at vEY
  push_cast at vEX vEY
  have eY : (EY.value : Fp) = ((L50.value * (W50X.value - X50.value) - W50Y.value : ℤ) : Fp) := by
    push_cast; rw [vEY, vEX]
  have hE : OnCurve (EX.value : Fp) (EY.value : Fp) := by rw [vEX, eY]; exact hA51
  have pE : mkPoint hE = mkPoint hA51 := mkPoint_inj.mpr ⟨vEX, eY⟩
  obtain ⟨RX, RY, hRX, hRY, hk, hR, pR⟩ := completeAdd_sound hl EX EY TX TY hEXb hEYb hTX hTY hE hT h
  refine ⟨RX, RY, hRX, hRY, hk, hR, ?_⟩
  rw [pR, pE, pA51, pT]
  apply comb_final _ rfl rfl
  have m0 : (cert_hcd1dd84c.m : ℤ) = n := rfl
  have e0 : cert_hcd1dd84c.exprValue (values [⟨8, RC⟩, ⟨1, bitElem π⟩, ⟨8, S⟩, ⟨8, constElem twoPowLimbs⟩]) =
      2 * RC.value + (bitElem π).value - S.value - (constElem twoPowLimbs).value := by
    simp [PolyShape.exprValue, values, cert_hcd1dd84c]; try ring
  have hπ' := bitI_eq_of_sel hbits (a := 0) (by norm_num) (b := π) (by rw [← hπ, vget_getD]; try rfl)
  rw [e0, m0, hRC, mkElem_value, rec8_rcInts, bitElem_value, ← hπ', constElem_value] at crec
  calc 2 * chunk g 1 256 + bitI g 0
        = (2 * chunk g 1 256 + bitI g 0 - S.value - rec8 twoPowLimbs) + (S.value + rec8 twoPowLimbs) := by ring
      _ ≡ 0 + (S.value + rec8 twoPowLimbs) [ZMOD n] := crec.add_right _
      _ = S.value + rec8 twoPowLimbs := by ring
      _ ≡ S.value + 2 ^ 256 [ZMOD n] := Int.ModEq.add_left _ twoPow_modEq

end ZolanaVE.P256
