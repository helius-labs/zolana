import VerifiableEncryption.Curve.CompletenessCombSelection
import VerifiableEncryption.Curve.CompletenessCombFirst
import VerifiableEncryption.Curve.CompletenessCombSecond
import VerifiableEncryption.Curve.CompletenessCombTail
import VerifiableEncryption.Curve.CompletenessGeneratedCombSteps

/-! Full fixed-base witness assembly for the actual extracted predicate.
All 256-bit scalar representatives are accepted when their residue modulo n
is nonzero. Selected points, slopes, lazy outputs, polynomial pieces, and
final coordinates are constructed. No successful-operation premise appears.
Kernel validation and remaining API/hint correspondence are recorded separately.
-/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks ZolanaVE.CombLimbs
open scoped BigOperators

theorem scalarMulBase_complete (hr : RangeComplete) (S : ElemVal 8)
    (hS : S.bnd = reducedC) (hsecret : S.value.toNat % n ≠ 0) :
    ∃ RX RY : ElemVal 8, RX.bnd = reducedC ∧ RY.bnd = reducedC ∧
      limbNat RX.limbs < p ∧ limbNat RY.limbs < p ∧
      (∃ hR : OnCurve (RX.value : Fp) (RY.value : Fp), mkPoint hR = S.value • G) ∧
      ∀ k : List.Vector (List.Vector F 8) 2 → Prop,
        k (RX.limbs ::ᵥ RY.limbs ::ᵥ List.Vector.nil) →
        ScalarMulBase_8_h3037b025 S.limbs k := by
  classical
  let s := S.value.toNat
  let g := combBits s
  have hsCast : (s : ℤ) = S.value := by
    have hv : 0 ≤ S.value ∧ S.value ≤ 2 ^ 256 - 1 := by
      simpa [reducedC, uniC] using (S.fits_of_bnd hS).2
    exact Int.toNat_of_nonneg hv.1
  have hbits : AllBits g := combBits_all s
  obtain ⟨WX, WY, hwindows⟩ := combWindows_complete s
  have hWX : ∀ t : Fin 51, (WX t).bnd = reducedC := fun t => (hwindows t).1
  have hWY : ∀ t : Fin 51, (WY t).bnd = packC := fun t => (hwindows t).2.1
  choose hOn pWindow using (fun t : Fin 51 => (hwindows t).2.2.1)
  obtain ⟨TX, TY, hTX, hTY, hcTX, hcTY, ⟨hT, pT⟩, selectTop⟩ := combTop_bits_complete s
  have pA1 : mkPoint (hOn 0) =
      (∑ u ∈ Finset.range 1, digOf g u * 2 ^ (5 * u)) • G := by
    simpa using pWindow 0
  obtain ⟨hne1, hs1⟩ := comb_acc_step hbits (le_refl 257) (t := 1) (by norm_num) pA1 (pWindow 1)
  obtain ⟨X1, L1, hX1, hL1, rel1, ⟨hA2, pA2⟩, chain1⟩ :=
    combFirst_complete hr (WX 0) (WX 1) (WY 1) (WY 0)
      (hWX 0) (hWX 1) (hWY 1) (hWY 0) (hOn 0) (hOn 1) hne1
  rw [hs1] at pA2
  obtain ⟨hne2, hs2⟩ := comb_acc_step hbits (le_refl 257) (t := 2) (by norm_num) pA2 (pWindow 2)
  obtain ⟨X2, L2, hX2, hL2, rel2, ⟨hA3, pA3⟩, chain2⟩ :=
    combSecond_complete hr X1 L1 (WX 1) (WY 1) (WX 2) (WY 2)
      hX1 hL1 (hWX 1) (hWY 1) (hWX 2) (hWY 2) hA2 (hOn 2) hne2
  rw [hs2] at pA3
  obtain ⟨hne3, hs3⟩ := comb_acc_step hbits (le_refl 257) (t := 3) (by norm_num) pA3 (pWindow 3)
  obtain ⟨X3, L3, hX3, hL3, rel3, ⟨hA4, pA4⟩, chain3⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hfeca3431_complete hr X2 L2 (WX 2) (WY 2) (WX 3) (WY 3)
      hX2 hL2 (hWX 2) (hWY 2) (hWX 3) (hWY 3) hA3 (hOn 3) hne3
  rw [hs3] at pA4
  obtain ⟨hne4, hs4⟩ := comb_acc_step hbits (le_refl 257) (t := 4) (by norm_num) pA4 (pWindow 4)
  obtain ⟨X4, L4, hX4, hL4, rel4, ⟨hA5, pA5⟩, chain4⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h98a10bfb_complete hr X3 L3 (WX 3) (WY 3) (WX 4) (WY 4)
      hX3 hL3 (hWX 3) (hWY 3) (hWX 4) (hWY 4) hA4 (hOn 4) hne4
  rw [hs4] at pA5
  obtain ⟨hne5, hs5⟩ := comb_acc_step hbits (le_refl 257) (t := 5) (by norm_num) pA5 (pWindow 5)
  obtain ⟨X5, L5, hX5, hL5, rel5, ⟨hA6, pA6⟩, chain5⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hc2445cd4_complete hr X4 L4 (WX 4) (WY 4) (WX 5) (WY 5)
      hX4 hL4 (hWX 4) (hWY 4) (hWX 5) (hWY 5) hA5 (hOn 5) hne5
  rw [hs5] at pA6
  obtain ⟨hne6, hs6⟩ := comb_acc_step hbits (le_refl 257) (t := 6) (by norm_num) pA6 (pWindow 6)
  obtain ⟨X6, L6, hX6, hL6, rel6, ⟨hA7, pA7⟩, chain6⟩ :=
    CombChainStep_8_8_8_8_8_8_8_he11b64cc_complete hr X5 L5 (WX 5) (WY 5) (WX 6) (WY 6)
      hX5 hL5 (hWX 5) (hWY 5) (hWX 6) (hWY 6) hA6 (hOn 6) hne6
  rw [hs6] at pA7
  obtain ⟨hne7, hs7⟩ := comb_acc_step hbits (le_refl 257) (t := 7) (by norm_num) pA7 (pWindow 7)
  obtain ⟨X7, L7, hX7, hL7, rel7, ⟨hA8, pA8⟩, chain7⟩ :=
    CombChainStep_8_8_8_8_8_8_8_ha337781a_complete hr X6 L6 (WX 6) (WY 6) (WX 7) (WY 7)
      hX6 hL6 (hWX 6) (hWY 6) (hWX 7) (hWY 7) hA7 (hOn 7) hne7
  rw [hs7] at pA8
  obtain ⟨hne8, hs8⟩ := comb_acc_step hbits (le_refl 257) (t := 8) (by norm_num) pA8 (pWindow 8)
  obtain ⟨X8, L8, hX8, hL8, rel8, ⟨hA9, pA9⟩, chain8⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h722a110e_complete hr X7 L7 (WX 7) (WY 7) (WX 8) (WY 8)
      hX7 hL7 (hWX 7) (hWY 7) (hWX 8) (hWY 8) hA8 (hOn 8) hne8
  rw [hs8] at pA9
  obtain ⟨hne9, hs9⟩ := comb_acc_step hbits (le_refl 257) (t := 9) (by norm_num) pA9 (pWindow 9)
  obtain ⟨X9, L9, hX9, hL9, rel9, ⟨hA10, pA10⟩, chain9⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h16154bb8_complete hr X8 L8 (WX 8) (WY 8) (WX 9) (WY 9)
      hX8 hL8 (hWX 8) (hWY 8) (hWX 9) (hWY 9) hA9 (hOn 9) hne9
  rw [hs9] at pA10
  obtain ⟨hne10, hs10⟩ := comb_acc_step hbits (le_refl 257) (t := 10) (by norm_num) pA10 (pWindow 10)
  obtain ⟨X10, L10, hX10, hL10, rel10, ⟨hA11, pA11⟩, chain10⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h0b2c7a04_complete hr X9 L9 (WX 9) (WY 9) (WX 10) (WY 10)
      hX9 hL9 (hWX 9) (hWY 9) (hWX 10) (hWY 10) hA10 (hOn 10) hne10
  rw [hs10] at pA11
  obtain ⟨hne11, hs11⟩ := comb_acc_step hbits (le_refl 257) (t := 11) (by norm_num) pA11 (pWindow 11)
  obtain ⟨X11, L11, hX11, hL11, rel11, ⟨hA12, pA12⟩, chain11⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h7791617c_complete hr X10 L10 (WX 10) (WY 10) (WX 11) (WY 11)
      hX10 hL10 (hWX 10) (hWY 10) (hWX 11) (hWY 11) hA11 (hOn 11) hne11
  rw [hs11] at pA12
  obtain ⟨hne12, hs12⟩ := comb_acc_step hbits (le_refl 257) (t := 12) (by norm_num) pA12 (pWindow 12)
  obtain ⟨X12, L12, hX12, hL12, rel12, ⟨hA13, pA13⟩, chain12⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h4279c9fa_complete hr X11 L11 (WX 11) (WY 11) (WX 12) (WY 12)
      hX11 hL11 (hWX 11) (hWY 11) (hWX 12) (hWY 12) hA12 (hOn 12) hne12
  rw [hs12] at pA13
  obtain ⟨hne13, hs13⟩ := comb_acc_step hbits (le_refl 257) (t := 13) (by norm_num) pA13 (pWindow 13)
  obtain ⟨X13, L13, hX13, hL13, rel13, ⟨hA14, pA14⟩, chain13⟩ :=
    CombChainStep_8_8_8_8_8_8_8_he5aef826_complete hr X12 L12 (WX 12) (WY 12) (WX 13) (WY 13)
      hX12 hL12 (hWX 12) (hWY 12) (hWX 13) (hWY 13) hA13 (hOn 13) hne13
  rw [hs13] at pA14
  obtain ⟨hne14, hs14⟩ := comb_acc_step hbits (le_refl 257) (t := 14) (by norm_num) pA14 (pWindow 14)
  obtain ⟨X14, L14, hX14, hL14, rel14, ⟨hA15, pA15⟩, chain14⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h893b2021_complete hr X13 L13 (WX 13) (WY 13) (WX 14) (WY 14)
      hX13 hL13 (hWX 13) (hWY 13) (hWX 14) (hWY 14) hA14 (hOn 14) hne14
  rw [hs14] at pA15
  obtain ⟨hne15, hs15⟩ := comb_acc_step hbits (le_refl 257) (t := 15) (by norm_num) pA15 (pWindow 15)
  obtain ⟨X15, L15, hX15, hL15, rel15, ⟨hA16, pA16⟩, chain15⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h5c8297ae_complete hr X14 L14 (WX 14) (WY 14) (WX 15) (WY 15)
      hX14 hL14 (hWX 14) (hWY 14) (hWX 15) (hWY 15) hA15 (hOn 15) hne15
  rw [hs15] at pA16
  obtain ⟨hne16, hs16⟩ := comb_acc_step hbits (le_refl 257) (t := 16) (by norm_num) pA16 (pWindow 16)
  obtain ⟨X16, L16, hX16, hL16, rel16, ⟨hA17, pA17⟩, chain16⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h18d73f47_complete hr X15 L15 (WX 15) (WY 15) (WX 16) (WY 16)
      hX15 hL15 (hWX 15) (hWY 15) (hWX 16) (hWY 16) hA16 (hOn 16) hne16
  rw [hs16] at pA17
  obtain ⟨hne17, hs17⟩ := comb_acc_step hbits (le_refl 257) (t := 17) (by norm_num) pA17 (pWindow 17)
  obtain ⟨X17, L17, hX17, hL17, rel17, ⟨hA18, pA18⟩, chain17⟩ :=
    CombChainStep_8_8_8_8_8_8_8_he57d21d5_complete hr X16 L16 (WX 16) (WY 16) (WX 17) (WY 17)
      hX16 hL16 (hWX 16) (hWY 16) (hWX 17) (hWY 17) hA17 (hOn 17) hne17
  rw [hs17] at pA18
  obtain ⟨hne18, hs18⟩ := comb_acc_step hbits (le_refl 257) (t := 18) (by norm_num) pA18 (pWindow 18)
  obtain ⟨X18, L18, hX18, hL18, rel18, ⟨hA19, pA19⟩, chain18⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hf0b5218f_complete hr X17 L17 (WX 17) (WY 17) (WX 18) (WY 18)
      hX17 hL17 (hWX 17) (hWY 17) (hWX 18) (hWY 18) hA18 (hOn 18) hne18
  rw [hs18] at pA19
  obtain ⟨hne19, hs19⟩ := comb_acc_step hbits (le_refl 257) (t := 19) (by norm_num) pA19 (pWindow 19)
  obtain ⟨X19, L19, hX19, hL19, rel19, ⟨hA20, pA20⟩, chain19⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hf2e5fd4b_complete hr X18 L18 (WX 18) (WY 18) (WX 19) (WY 19)
      hX18 hL18 (hWX 18) (hWY 18) (hWX 19) (hWY 19) hA19 (hOn 19) hne19
  rw [hs19] at pA20
  obtain ⟨hne20, hs20⟩ := comb_acc_step hbits (le_refl 257) (t := 20) (by norm_num) pA20 (pWindow 20)
  obtain ⟨X20, L20, hX20, hL20, rel20, ⟨hA21, pA21⟩, chain20⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h38305e15_complete hr X19 L19 (WX 19) (WY 19) (WX 20) (WY 20)
      hX19 hL19 (hWX 19) (hWY 19) (hWX 20) (hWY 20) hA20 (hOn 20) hne20
  rw [hs20] at pA21
  obtain ⟨hne21, hs21⟩ := comb_acc_step hbits (le_refl 257) (t := 21) (by norm_num) pA21 (pWindow 21)
  obtain ⟨X21, L21, hX21, hL21, rel21, ⟨hA22, pA22⟩, chain21⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hd1f04580_complete hr X20 L20 (WX 20) (WY 20) (WX 21) (WY 21)
      hX20 hL20 (hWX 20) (hWY 20) (hWX 21) (hWY 21) hA21 (hOn 21) hne21
  rw [hs21] at pA22
  obtain ⟨hne22, hs22⟩ := comb_acc_step hbits (le_refl 257) (t := 22) (by norm_num) pA22 (pWindow 22)
  obtain ⟨X22, L22, hX22, hL22, rel22, ⟨hA23, pA23⟩, chain22⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h2f8d1084_complete hr X21 L21 (WX 21) (WY 21) (WX 22) (WY 22)
      hX21 hL21 (hWX 21) (hWY 21) (hWX 22) (hWY 22) hA22 (hOn 22) hne22
  rw [hs22] at pA23
  obtain ⟨hne23, hs23⟩ := comb_acc_step hbits (le_refl 257) (t := 23) (by norm_num) pA23 (pWindow 23)
  obtain ⟨X23, L23, hX23, hL23, rel23, ⟨hA24, pA24⟩, chain23⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hbc9d292f_complete hr X22 L22 (WX 22) (WY 22) (WX 23) (WY 23)
      hX22 hL22 (hWX 22) (hWY 22) (hWX 23) (hWY 23) hA23 (hOn 23) hne23
  rw [hs23] at pA24
  obtain ⟨hne24, hs24⟩ := comb_acc_step hbits (le_refl 257) (t := 24) (by norm_num) pA24 (pWindow 24)
  obtain ⟨X24, L24, hX24, hL24, rel24, ⟨hA25, pA25⟩, chain24⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hd5949308_complete hr X23 L23 (WX 23) (WY 23) (WX 24) (WY 24)
      hX23 hL23 (hWX 23) (hWY 23) (hWX 24) (hWY 24) hA24 (hOn 24) hne24
  rw [hs24] at pA25
  obtain ⟨hne25, hs25⟩ := comb_acc_step hbits (le_refl 257) (t := 25) (by norm_num) pA25 (pWindow 25)
  obtain ⟨X25, L25, hX25, hL25, rel25, ⟨hA26, pA26⟩, chain25⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h6e26f17b_complete hr X24 L24 (WX 24) (WY 24) (WX 25) (WY 25)
      hX24 hL24 (hWX 24) (hWY 24) (hWX 25) (hWY 25) hA25 (hOn 25) hne25
  rw [hs25] at pA26
  obtain ⟨hne26, hs26⟩ := comb_acc_step hbits (le_refl 257) (t := 26) (by norm_num) pA26 (pWindow 26)
  obtain ⟨X26, L26, hX26, hL26, rel26, ⟨hA27, pA27⟩, chain26⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h40db0ded_complete hr X25 L25 (WX 25) (WY 25) (WX 26) (WY 26)
      hX25 hL25 (hWX 25) (hWY 25) (hWX 26) (hWY 26) hA26 (hOn 26) hne26
  rw [hs26] at pA27
  obtain ⟨hne27, hs27⟩ := comb_acc_step hbits (le_refl 257) (t := 27) (by norm_num) pA27 (pWindow 27)
  obtain ⟨X27, L27, hX27, hL27, rel27, ⟨hA28, pA28⟩, chain27⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h015a0c08_complete hr X26 L26 (WX 26) (WY 26) (WX 27) (WY 27)
      hX26 hL26 (hWX 26) (hWY 26) (hWX 27) (hWY 27) hA27 (hOn 27) hne27
  rw [hs27] at pA28
  obtain ⟨hne28, hs28⟩ := comb_acc_step hbits (le_refl 257) (t := 28) (by norm_num) pA28 (pWindow 28)
  obtain ⟨X28, L28, hX28, hL28, rel28, ⟨hA29, pA29⟩, chain28⟩ :=
    CombChainStep_8_8_8_8_8_8_8_he6b197a7_complete hr X27 L27 (WX 27) (WY 27) (WX 28) (WY 28)
      hX27 hL27 (hWX 27) (hWY 27) (hWX 28) (hWY 28) hA28 (hOn 28) hne28
  rw [hs28] at pA29
  obtain ⟨hne29, hs29⟩ := comb_acc_step hbits (le_refl 257) (t := 29) (by norm_num) pA29 (pWindow 29)
  obtain ⟨X29, L29, hX29, hL29, rel29, ⟨hA30, pA30⟩, chain29⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h59272257_complete hr X28 L28 (WX 28) (WY 28) (WX 29) (WY 29)
      hX28 hL28 (hWX 28) (hWY 28) (hWX 29) (hWY 29) hA29 (hOn 29) hne29
  rw [hs29] at pA30
  obtain ⟨hne30, hs30⟩ := comb_acc_step hbits (le_refl 257) (t := 30) (by norm_num) pA30 (pWindow 30)
  obtain ⟨X30, L30, hX30, hL30, rel30, ⟨hA31, pA31⟩, chain30⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h18a1cf88_complete hr X29 L29 (WX 29) (WY 29) (WX 30) (WY 30)
      hX29 hL29 (hWX 29) (hWY 29) (hWX 30) (hWY 30) hA30 (hOn 30) hne30
  rw [hs30] at pA31
  obtain ⟨hne31, hs31⟩ := comb_acc_step hbits (le_refl 257) (t := 31) (by norm_num) pA31 (pWindow 31)
  obtain ⟨X31, L31, hX31, hL31, rel31, ⟨hA32, pA32⟩, chain31⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h84b7fff5_complete hr X30 L30 (WX 30) (WY 30) (WX 31) (WY 31)
      hX30 hL30 (hWX 30) (hWY 30) (hWX 31) (hWY 31) hA31 (hOn 31) hne31
  rw [hs31] at pA32
  obtain ⟨hne32, hs32⟩ := comb_acc_step hbits (le_refl 257) (t := 32) (by norm_num) pA32 (pWindow 32)
  obtain ⟨X32, L32, hX32, hL32, rel32, ⟨hA33, pA33⟩, chain32⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hfcf24f49_complete hr X31 L31 (WX 31) (WY 31) (WX 32) (WY 32)
      hX31 hL31 (hWX 31) (hWY 31) (hWX 32) (hWY 32) hA32 (hOn 32) hne32
  rw [hs32] at pA33
  obtain ⟨hne33, hs33⟩ := comb_acc_step hbits (le_refl 257) (t := 33) (by norm_num) pA33 (pWindow 33)
  obtain ⟨X33, L33, hX33, hL33, rel33, ⟨hA34, pA34⟩, chain33⟩ :=
    CombChainStep_8_8_8_8_8_8_8_ha9cc5411_complete hr X32 L32 (WX 32) (WY 32) (WX 33) (WY 33)
      hX32 hL32 (hWX 32) (hWY 32) (hWX 33) (hWY 33) hA33 (hOn 33) hne33
  rw [hs33] at pA34
  obtain ⟨hne34, hs34⟩ := comb_acc_step hbits (le_refl 257) (t := 34) (by norm_num) pA34 (pWindow 34)
  obtain ⟨X34, L34, hX34, hL34, rel34, ⟨hA35, pA35⟩, chain34⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h63e076b3_complete hr X33 L33 (WX 33) (WY 33) (WX 34) (WY 34)
      hX33 hL33 (hWX 33) (hWY 33) (hWX 34) (hWY 34) hA34 (hOn 34) hne34
  rw [hs34] at pA35
  obtain ⟨hne35, hs35⟩ := comb_acc_step hbits (le_refl 257) (t := 35) (by norm_num) pA35 (pWindow 35)
  obtain ⟨X35, L35, hX35, hL35, rel35, ⟨hA36, pA36⟩, chain35⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h9ff1cd8b_complete hr X34 L34 (WX 34) (WY 34) (WX 35) (WY 35)
      hX34 hL34 (hWX 34) (hWY 34) (hWX 35) (hWY 35) hA35 (hOn 35) hne35
  rw [hs35] at pA36
  obtain ⟨hne36, hs36⟩ := comb_acc_step hbits (le_refl 257) (t := 36) (by norm_num) pA36 (pWindow 36)
  obtain ⟨X36, L36, hX36, hL36, rel36, ⟨hA37, pA37⟩, chain36⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h308152e6_complete hr X35 L35 (WX 35) (WY 35) (WX 36) (WY 36)
      hX35 hL35 (hWX 35) (hWY 35) (hWX 36) (hWY 36) hA36 (hOn 36) hne36
  rw [hs36] at pA37
  obtain ⟨hne37, hs37⟩ := comb_acc_step hbits (le_refl 257) (t := 37) (by norm_num) pA37 (pWindow 37)
  obtain ⟨X37, L37, hX37, hL37, rel37, ⟨hA38, pA38⟩, chain37⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h2ec09f94_complete hr X36 L36 (WX 36) (WY 36) (WX 37) (WY 37)
      hX36 hL36 (hWX 36) (hWY 36) (hWX 37) (hWY 37) hA37 (hOn 37) hne37
  rw [hs37] at pA38
  obtain ⟨hne38, hs38⟩ := comb_acc_step hbits (le_refl 257) (t := 38) (by norm_num) pA38 (pWindow 38)
  obtain ⟨X38, L38, hX38, hL38, rel38, ⟨hA39, pA39⟩, chain38⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h1d7ce17b_complete hr X37 L37 (WX 37) (WY 37) (WX 38) (WY 38)
      hX37 hL37 (hWX 37) (hWY 37) (hWX 38) (hWY 38) hA38 (hOn 38) hne38
  rw [hs38] at pA39
  obtain ⟨hne39, hs39⟩ := comb_acc_step hbits (le_refl 257) (t := 39) (by norm_num) pA39 (pWindow 39)
  obtain ⟨X39, L39, hX39, hL39, rel39, ⟨hA40, pA40⟩, chain39⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hc0cdb690_complete hr X38 L38 (WX 38) (WY 38) (WX 39) (WY 39)
      hX38 hL38 (hWX 38) (hWY 38) (hWX 39) (hWY 39) hA39 (hOn 39) hne39
  rw [hs39] at pA40
  obtain ⟨hne40, hs40⟩ := comb_acc_step hbits (le_refl 257) (t := 40) (by norm_num) pA40 (pWindow 40)
  obtain ⟨X40, L40, hX40, hL40, rel40, ⟨hA41, pA41⟩, chain40⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h27bf5feb_complete hr X39 L39 (WX 39) (WY 39) (WX 40) (WY 40)
      hX39 hL39 (hWX 39) (hWY 39) (hWX 40) (hWY 40) hA40 (hOn 40) hne40
  rw [hs40] at pA41
  obtain ⟨hne41, hs41⟩ := comb_acc_step hbits (le_refl 257) (t := 41) (by norm_num) pA41 (pWindow 41)
  obtain ⟨X41, L41, hX41, hL41, rel41, ⟨hA42, pA42⟩, chain41⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hcf989bc7_complete hr X40 L40 (WX 40) (WY 40) (WX 41) (WY 41)
      hX40 hL40 (hWX 40) (hWY 40) (hWX 41) (hWY 41) hA41 (hOn 41) hne41
  rw [hs41] at pA42
  obtain ⟨hne42, hs42⟩ := comb_acc_step hbits (le_refl 257) (t := 42) (by norm_num) pA42 (pWindow 42)
  obtain ⟨X42, L42, hX42, hL42, rel42, ⟨hA43, pA43⟩, chain42⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h87d7c1d5_complete hr X41 L41 (WX 41) (WY 41) (WX 42) (WY 42)
      hX41 hL41 (hWX 41) (hWY 41) (hWX 42) (hWY 42) hA42 (hOn 42) hne42
  rw [hs42] at pA43
  obtain ⟨hne43, hs43⟩ := comb_acc_step hbits (le_refl 257) (t := 43) (by norm_num) pA43 (pWindow 43)
  obtain ⟨X43, L43, hX43, hL43, rel43, ⟨hA44, pA44⟩, chain43⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hb365cd9c_complete hr X42 L42 (WX 42) (WY 42) (WX 43) (WY 43)
      hX42 hL42 (hWX 42) (hWY 42) (hWX 43) (hWY 43) hA43 (hOn 43) hne43
  rw [hs43] at pA44
  obtain ⟨hne44, hs44⟩ := comb_acc_step hbits (le_refl 257) (t := 44) (by norm_num) pA44 (pWindow 44)
  obtain ⟨X44, L44, hX44, hL44, rel44, ⟨hA45, pA45⟩, chain44⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hff84174b_complete hr X43 L43 (WX 43) (WY 43) (WX 44) (WY 44)
      hX43 hL43 (hWX 43) (hWY 43) (hWX 44) (hWY 44) hA44 (hOn 44) hne44
  rw [hs44] at pA45
  obtain ⟨hne45, hs45⟩ := comb_acc_step hbits (le_refl 257) (t := 45) (by norm_num) pA45 (pWindow 45)
  obtain ⟨X45, L45, hX45, hL45, rel45, ⟨hA46, pA46⟩, chain45⟩ :=
    CombChainStep_8_8_8_8_8_8_8_he9395e0b_complete hr X44 L44 (WX 44) (WY 44) (WX 45) (WY 45)
      hX44 hL44 (hWX 44) (hWY 44) (hWX 45) (hWY 45) hA45 (hOn 45) hne45
  rw [hs45] at pA46
  obtain ⟨hne46, hs46⟩ := comb_acc_step hbits (le_refl 257) (t := 46) (by norm_num) pA46 (pWindow 46)
  obtain ⟨X46, L46, hX46, hL46, rel46, ⟨hA47, pA47⟩, chain46⟩ :=
    CombChainStep_8_8_8_8_8_8_8_he4e1c949_complete hr X45 L45 (WX 45) (WY 45) (WX 46) (WY 46)
      hX45 hL45 (hWX 45) (hWY 45) (hWX 46) (hWY 46) hA46 (hOn 46) hne46
  rw [hs46] at pA47
  obtain ⟨hne47, hs47⟩ := comb_acc_step hbits (le_refl 257) (t := 47) (by norm_num) pA47 (pWindow 47)
  obtain ⟨X47, L47, hX47, hL47, rel47, ⟨hA48, pA48⟩, chain47⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h33cb1110_complete hr X46 L46 (WX 46) (WY 46) (WX 47) (WY 47)
      hX46 hL46 (hWX 46) (hWY 46) (hWX 47) (hWY 47) hA47 (hOn 47) hne47
  rw [hs47] at pA48
  obtain ⟨hne48, hs48⟩ := comb_acc_step hbits (le_refl 257) (t := 48) (by norm_num) pA48 (pWindow 48)
  obtain ⟨X48, L48, hX48, hL48, rel48, ⟨hA49, pA49⟩, chain48⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h2390b750_complete hr X47 L47 (WX 47) (WY 47) (WX 48) (WY 48)
      hX47 hL47 (hWX 47) (hWY 47) (hWX 48) (hWY 48) hA48 (hOn 48) hne48
  rw [hs48] at pA49
  obtain ⟨hne49, hs49⟩ := comb_acc_step hbits (le_refl 257) (t := 49) (by norm_num) pA49 (pWindow 49)
  obtain ⟨X49, L49, hX49, hL49, rel49, ⟨hA50, pA50⟩, chain49⟩ :=
    CombChainStep_8_8_8_8_8_8_8_h0f057500_complete hr X48 L48 (WX 48) (WY 48) (WX 49) (WY 49)
      hX48 hL48 (hWX 48) (hWY 48) (hWX 49) (hWY 49) hA49 (hOn 49) hne49
  rw [hs49] at pA50
  obtain ⟨hne50, hs50⟩ := comb_acc_step hbits (le_refl 257) (t := 50) (by norm_num) pA50 (pWindow 50)
  obtain ⟨X50, L50, hX50, hL50, rel50, ⟨hA51, pA51⟩, chain50⟩ :=
    CombChainStep_8_8_8_8_8_8_8_hb9331b93_complete hr X49 L49 (WX 49) (WY 49) (WX 50) (WY 50)
      hX49 hL49 (hWX 49) (hWY 49) (hWX 50) (hWY 50) hA50 (hOn 50) hne50
  rw [hs50] at pA51
  have hnoninverse := combFinal_noninverse s hsecret pA51 pT
  obtain ⟨RX, RY, hRX, hRY, hcRX, hcRY, ⟨hR, pR⟩, tail⟩ :=
    combTail_complete hr X50 L50 (WX 50) (WY 50) TX TY
      hX50 hL50 (hWX 50) (hWY 50) hTX hTY hcTX hA51 hT hnoninverse
  have pScalar : mkPoint hR = S.value • G := by
    calc
      mkPoint hR = mkPoint hA51 + mkPoint hT := pR.symm
      _ = (s : ℤ) • G := comb_final (combBits_recoding s) pA51 pT
      _ = S.value • G := by rw [hsCast]
  refine ⟨RX, RY, hRX, hRY, hcRX, hcRY, ⟨hR, pScalar⟩, ?_⟩
  intro k hk
  have hrec := scalarRecoding_complete hr S hS
  have parityCast : ((combParity s).toNat : F) = g.get 0 := by
    change ((combParity s).toNat : F) = Bool.toZMod (combParity s)
    cases combParity s <;> rfl
  have f0 := fromBinary_chunk_complete hbits (a := 1) (w := 32) (by norm_num)
  have f1 := fromBinary_chunk_complete hbits (a := 33) (w := 32) (by norm_num)
  have f2 := fromBinary_chunk_complete hbits (a := 65) (w := 32) (by norm_num)
  have f3 := fromBinary_chunk_complete hbits (a := 97) (w := 32) (by norm_num)
  have f4 := fromBinary_chunk_complete hbits (a := 129) (w := 32) (by norm_num)
  have f5 := fromBinary_chunk_complete hbits (a := 161) (w := 32) (by norm_num)
  have f6 := fromBinary_chunk_complete hbits (a := 193) (w := 32) (by norm_num)
  have f7 := fromBinary_chunk_complete hbits (a := 225) (w := 32) (by norm_num)
  unfold ScalarMulBase_8_h3037b025 ScalarMulBase_8_h3037b025_p1 ScalarMulBase_8_h3037b025_p2
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, GatesDef.eq, exists_eq_left,
    mul_one, zero_add, mul_neg_one, ← sub_eq_add_neg]
  refine ⟨g, ?_⟩
  repeat' first | exact combBits_boolean s _ | apply And.intro
  refine ⟨((rcInts g 0 : ℤ) : F), f0, ((rcInts g 1 : ℤ) : F), f1,
    ((rcInts g 2 : ℤ) : F), f2, ((rcInts g 3 : ℤ) : F), f3,
    ((rcInts g 4 : ℤ) : F), f4, ((rcInts g 5 : ℤ) : F), f5,
    ((rcInts g 6 : ℤ) : F), f6, ((rcInts g 7 : ℤ) : F), f7, ?_, ?_⟩
  · convert hrec using 1
    apply List.Vector.toList_injective
    simp only [recodingInput, S.limb_eq, parityCast]
    rfl
  · apply (hwindows 0).2.2.2
    apply (hwindows 1).2.2.2
    apply (hwindows 2).2.2.2
    apply (hwindows 3).2.2.2
    apply (hwindows 4).2.2.2
    apply (hwindows 5).2.2.2
    apply (hwindows 6).2.2.2
    apply (hwindows 7).2.2.2
    apply (hwindows 8).2.2.2
    apply (hwindows 9).2.2.2
    apply (hwindows 10).2.2.2
    apply (hwindows 11).2.2.2
    apply (hwindows 12).2.2.2
    apply (hwindows 13).2.2.2
    apply (hwindows 14).2.2.2
    apply (hwindows 15).2.2.2
    apply (hwindows 16).2.2.2
    apply (hwindows 17).2.2.2
    apply (hwindows 18).2.2.2
    apply (hwindows 19).2.2.2
    apply (hwindows 20).2.2.2
    apply (hwindows 21).2.2.2
    apply (hwindows 22).2.2.2
    apply (hwindows 23).2.2.2
    apply (hwindows 24).2.2.2
    apply (hwindows 25).2.2.2
    apply (hwindows 26).2.2.2
    apply (hwindows 27).2.2.2
    apply (hwindows 28).2.2.2
    apply (hwindows 29).2.2.2
    apply (hwindows 30).2.2.2
    apply (hwindows 31).2.2.2
    apply (hwindows 32).2.2.2
    apply (hwindows 33).2.2.2
    apply (hwindows 34).2.2.2
    apply (hwindows 35).2.2.2
    apply (hwindows 36).2.2.2
    apply (hwindows 37).2.2.2
    apply (hwindows 38).2.2.2
    apply (hwindows 39).2.2.2
    apply (hwindows 40).2.2.2
    apply (hwindows 41).2.2.2
    apply (hwindows 42).2.2.2
    apply (hwindows 43).2.2.2
    apply (hwindows 44).2.2.2
    apply (hwindows 45).2.2.2
    apply (hwindows 46).2.2.2
    apply (hwindows 47).2.2.2
    apply (hwindows 48).2.2.2
    apply (hwindows 49).2.2.2
    apply (hwindows 50).2.2.2
    apply selectTop
    apply chain1
    apply chain2 (WY 0).limbs
    apply chain3 (WY 0).limbs
    apply chain4 (WY 0).limbs
    apply chain5 (WY 0).limbs
    apply chain6 (WY 0).limbs
    apply chain7 (WY 0).limbs
    apply chain8 (WY 0).limbs
    apply chain9 (WY 0).limbs
    apply chain10 (WY 0).limbs
    apply chain11 (WY 0).limbs
    apply chain12 (WY 0).limbs
    apply chain13 (WY 0).limbs
    apply chain14 (WY 0).limbs
    apply chain15 (WY 0).limbs
    apply chain16 (WY 0).limbs
    apply chain17 (WY 0).limbs
    apply chain18 (WY 0).limbs
    apply chain19 (WY 0).limbs
    apply chain20 (WY 0).limbs
    apply chain21 (WY 0).limbs
    apply chain22 (WY 0).limbs
    apply chain23 (WY 0).limbs
    apply chain24 (WY 0).limbs
    apply chain25 (WY 0).limbs
    apply chain26 (WY 0).limbs
    apply chain27 (WY 0).limbs
    apply chain28 (WY 0).limbs
    apply chain29 (WY 0).limbs
    apply chain30 (WY 0).limbs
    apply chain31 (WY 0).limbs
    apply chain32 (WY 0).limbs
    apply chain33 (WY 0).limbs
    apply chain34 (WY 0).limbs
    apply chain35 (WY 0).limbs
    apply chain36 (WY 0).limbs
    apply chain37 (WY 0).limbs
    apply chain38 (WY 0).limbs
    apply chain39 (WY 0).limbs
    apply chain40 (WY 0).limbs
    apply chain41 (WY 0).limbs
    apply chain42 (WY 0).limbs
    apply chain43 (WY 0).limbs
    apply chain44 (WY 0).limbs
    apply chain45 (WY 0).limbs
    apply chain46 (WY 0).limbs
    apply chain47 (WY 0).limbs
    apply chain48 (WY 0).limbs
    apply chain49 (WY 0).limbs
    apply chain50 (WY 0).limbs
    simpa only [combTailVector] using tail k hk

end ZolanaVE.P256.Completeness
