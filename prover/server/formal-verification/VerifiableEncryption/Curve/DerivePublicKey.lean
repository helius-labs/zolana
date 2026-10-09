import VerifiableEncryption.Curve.AgreeKeyAux
import VerifiableEncryption.Circuit.Top
import VerifiableEncryption.Curve.ScalarMulBase

/-!
Soundness of the extracted `DerivePublicKey` circuit.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem derivePublicKey_sound (hl : LookupSound RangeCheck 11) {sk X : List.Vector F 32} {lo hi : F}
    (h : DerivePublicKey_32_32 sk X lo hi) :
    ∃ (xE yE : ℕ) (hE : OnCurve (xE : Fp) (yE : Fp)),
      ¬ (n : ℤ) ∣ (bytesBE sk 0 32 : ℤ) ∧ xE < p ∧ yE < p ∧
      mkPoint hE = (bytesBE sk 0 32 : ℤ) • G ∧
      bytesBE X 0 32 = xE ∧ (∀ i < 32, byteAt X i < 256) ∧
      lo = (((2 + yE % 2) * 2 ^ 240 + xE / 2 ^ 16 : ℕ) : F) ∧ hi = ((xE % 2 ^ 16 : ℕ) : F) := by
  unfold DerivePublicKey_32_32 at h
  obtain ⟨rsk_0, rsk_1, rsk_2, rsk_3, rsk_4, rsk_5, rsk_6, rsk_7, h⟩ := h
  obtain ⟨rsk_8, rsk_9, rsk_10, rsk_11, rsk_12, rsk_13, rsk_14, rsk_15, h⟩ := h
  obtain ⟨rsk_16, rsk_17, rsk_18, rsk_19, rsk_20, rsk_21, rsk_22, rsk_23, h⟩ := h
  obtain ⟨rsk_24, rsk_25, rsk_26, rsk_27, rsk_28, rsk_29, rsk_30, rsk_31, h⟩ := h
  obtain ⟨g32, e32, g33, e33, g34, e34, g35, e35, h⟩ := h
  obtain ⟨g36, e36, g37, e37, g38, e38, g39, e39, h⟩ := h
  obtain ⟨g40, e40, g41, e41, g42, e42, g43, e43, h⟩ := h
  obtain ⟨g44, e44, g45, e45, g46, e46, g47, e47, h⟩ := h
  obtain ⟨g48, e48, g49, e49, g50, e50, g51, e51, h⟩ := h
  obtain ⟨g52, e52, g53, e53, g54, e54, g55, e55, h⟩ := h
  obtain ⟨g56, e56, g57, e57, g58, e58, g59, e59, h⟩ := h
  obtain ⟨g60, e60, g61, e61, g62, e62, g63, e63, h⟩ := h
  obtain ⟨g64, e64, g65, e65, g66, e66, g67, e67, h⟩ := h
  obtain ⟨g68, e68, g69, e69, g70, e70, g71, e71, h⟩ := h
  obtain ⟨g72, e72, g73, e73, g74, e74, g75, e75, h⟩ := h
  obtain ⟨g76, e76, g77, e77, g78, e78, g79, e79, h⟩ := h
  obtain ⟨g80, e80, g81, e81, g82, e82, g83, e83, h⟩ := h
  obtain ⟨g84, e84, g85, e85, g86, e86, g87, e87, h⟩ := h
  obtain ⟨g88, e88, g89, e89, g90, e90, g91, e91, h⟩ := h
  obtain ⟨g92, e92, g93, e93, g94, e94, g95, e95, h⟩ := h
  obtain ⟨g96, rg96_0, g98, e98, g99, e99, rg96_1, g101, h⟩ := h
  obtain ⟨e101, g102, e102, rg96_2, g104, e104, g105, e105, h⟩ := h
  obtain ⟨q1, g107, rg107_0, g109, e109, g110, e110, rg107_1, h⟩ := h
  obtain ⟨g112, e112, g113, e113, rg107_2, g115, e115, g116, h⟩ := h
  obtain ⟨e116, q2, g118, rg118_0, g120, e120, g121, e121, h⟩ := h
  obtain ⟨rg118_1, g123, e123, g124, e124, rg118_2, g126, e126, h⟩ := h
  obtain ⟨g127, e127, q3, g129, rg129_0, g131, e131, g132, h⟩ := h
  obtain ⟨e132, rg129_1, g134, e134, g135, e135, rg129_2, g137, h⟩ := h
  obtain ⟨e137, g138, e138, q4, g140, rg140_0, g142, e142, h⟩ := h
  obtain ⟨g143, e143, rg140_1, g145, e145, g146, e146, rg140_2, h⟩ := h
  obtain ⟨g148, e148, g149, e149, q5, g151, rg151_0, g153, h⟩ := h
  obtain ⟨e153, g154, e154, rg151_1, g156, e156, g157, e157, h⟩ := h
  obtain ⟨rg151_2, g159, e159, g160, e160, q6, g162, rg162_0, h⟩ := h
  obtain ⟨g164, e164, g165, e165, rg162_1, g167, e167, g168, h⟩ := h
  obtain ⟨e168, rg162_2, g170, e170, g171, e171, q7, g173, h⟩ := h
  obtain ⟨rg173_0, g175, e175, g176, e176, rg173_1, g178, e178, h⟩ := h
  obtain ⟨g179, e179, rg173_2, g181, e181, g182, e182, q8, h⟩ := h
  have v39 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rsk_28) (by rw [get_byteAt]; exact byte_lt hl rsk_29) (by rw [get_byteAt]; exact byte_lt hl rsk_30) (by rw [get_byteAt]; exact byte_lt hl rsk_31) e32 e33 e34 e35 e36 e37 e38 e39
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v39
  have v47 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rsk_24) (by rw [get_byteAt]; exact byte_lt hl rsk_25) (by rw [get_byteAt]; exact byte_lt hl rsk_26) (by rw [get_byteAt]; exact byte_lt hl rsk_27) e40 e41 e42 e43 e44 e45 e46 e47
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v47
  have v55 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rsk_20) (by rw [get_byteAt]; exact byte_lt hl rsk_21) (by rw [get_byteAt]; exact byte_lt hl rsk_22) (by rw [get_byteAt]; exact byte_lt hl rsk_23) e48 e49 e50 e51 e52 e53 e54 e55
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v55
  have v63 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rsk_16) (by rw [get_byteAt]; exact byte_lt hl rsk_17) (by rw [get_byteAt]; exact byte_lt hl rsk_18) (by rw [get_byteAt]; exact byte_lt hl rsk_19) e56 e57 e58 e59 e60 e61 e62 e63
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v63
  have v71 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rsk_12) (by rw [get_byteAt]; exact byte_lt hl rsk_13) (by rw [get_byteAt]; exact byte_lt hl rsk_14) (by rw [get_byteAt]; exact byte_lt hl rsk_15) e64 e65 e66 e67 e68 e69 e70 e71
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v71
  have v79 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rsk_8) (by rw [get_byteAt]; exact byte_lt hl rsk_9) (by rw [get_byteAt]; exact byte_lt hl rsk_10) (by rw [get_byteAt]; exact byte_lt hl rsk_11) e72 e73 e74 e75 e76 e77 e78 e79
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v79
  have v87 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rsk_4) (by rw [get_byteAt]; exact byte_lt hl rsk_5) (by rw [get_byteAt]; exact byte_lt hl rsk_6) (by rw [get_byteAt]; exact byte_lt hl rsk_7) e80 e81 e82 e83 e84 e85 e86 e87
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v87
  have v95 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rsk_0) (by rw [get_byteAt]; exact byte_lt hl rsk_1) (by rw [get_byteAt]; exact byte_lt hl rsk_2) (by rw [get_byteAt]; exact byte_lt hl rsk_3) e88 e89 e90 e91 e92 e93 e94 e95
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v95
  have hvS : ∀ l : Fin 8, ((g39 ::ᵥ g47 ::ᵥ g55 ::ᵥ g63 ::ᵥ g71 ::ᵥ g79 ::ᵥ g87 ::ᵥ g95 ::ᵥ List.Vector.nil).get l).val = byteAt sk (0 + 4 * (7 - l.val)) * 256 ^ 3 +
      byteAt sk (0 + 4 * (7 - l.val) + 1) * 256 ^ 2 + byteAt sk (0 + 4 * (7 - l.val) + 2) * 256 +
      byteAt sk (0 + 4 * (7 - l.val) + 3) := by
    intro l; fin_cases l
    exacts [v39, v47, v55, v63, v71, v79, v87, v95]
  have hbS : ∀ j < 32, byteAt sk (0 + j) < 256 := by
    intro j hj; interval_cases j
    exacts [byte_lt hl rsk_0, byte_lt hl rsk_1, byte_lt hl rsk_2, byte_lt hl rsk_3, byte_lt hl rsk_4, byte_lt hl rsk_5, byte_lt hl rsk_6, byte_lt hl rsk_7, byte_lt hl rsk_8, byte_lt hl rsk_9, byte_lt hl rsk_10, byte_lt hl rsk_11, byte_lt hl rsk_12, byte_lt hl rsk_13, byte_lt hl rsk_14, byte_lt hl rsk_15, byte_lt hl rsk_16, byte_lt hl rsk_17, byte_lt hl rsk_18, byte_lt hl rsk_19, byte_lt hl rsk_20, byte_lt hl rsk_21, byte_lt hl rsk_22, byte_lt hl rsk_23, byte_lt hl rsk_24, byte_lt hl rsk_25, byte_lt hl rsk_26, byte_lt hl rsk_27, byte_lt hl rsk_28, byte_lt hl rsk_29, byte_lt hl rsk_30, byte_lt hl rsk_31]
  have hLS := limbs_bytes_lt sk 0 hbS hvS
  have hNS := limbNat_bytes sk 0 hvS
  set SC := mkElemF (g39 ::ᵥ g47 ::ᵥ g55 ::ᵥ g63 ::ᵥ g71 ::ᵥ g79 ::ᵥ g87 ::ᵥ g95 ::ᵥ List.Vector.nil) hLS with hSC
  obtain ⟨S0, hS0lo, hS0hi, hS0vlo, hS0vhi, h, vS0⟩ :=
    CheckPolynomial_8_h57d6a69c_sound hl [⟨8, SC⟩] (elemsMatch_of (by show [SC.bnd] = _; rfl)) _ (by limbs_tac [hSC, mkElemF_limbs]) h
  have hS0b := eval_bnd hS0lo hS0hi hS0vlo hS0vhi rfl
  clear hS0lo hS0hi hS0vlo hS0vhi
  obtain ⟨c9, g186, e186, hne, h⟩ := h
  have hS0can := canonical_gap_n_sound hl S0 (reduced_lohi hS0b) c9
  rw [p256N_eq] at hS0can
  have hS0ne : S0.value ≠ 0 := by
    intro h0
    obtain ⟨-, heq⟩ := reduced_vals hS0b
    have hz : limbNat S0.limbs = 0 := by exact_mod_cast heq.trans h0
    have hl0 := limbNat_eq_zero hz
    apply hne
    rw [e186, hl0 0, hl0 1, hl0 2, hl0 3, hl0 4, hl0 5, hl0 6, hl0 7]
    simp [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add]
  have m0 : (cert_h57d6a69c.m : ℤ) = n := rfl
  have e0 : cert_h57d6a69c.exprValue (values [⟨8, SC⟩]) = SC.value := by
    simp [PolyShape.exprValue, values, cert_h57d6a69c]
  rw [e0, m0] at vS0
  have vSC : SC.value = (bytesBE sk 0 32 : ℤ) := by rw [hSC, mkElemF_value, hNS]
  have hndvd : ¬ (n : ℤ) ∣ (bytesBE sk 0 32 : ℤ) := by
    intro hd
    apply hS0ne
    unfold Int.ModEq at vS0
    rw [vSC, Int.emod_eq_zero_of_dvd hd, Int.emod_eq_of_lt hS0can.1 hS0can.2] at vS0
    exact vS0
  obtain ⟨EX, EY, hEX, hEY, h, hE, pE⟩ := scalarMulBase_sound hl SC rfl h
  obtain ⟨c10, c11, c12, g192, rg192_0, rg192_1, rg192_2, rg192_3, h⟩ := h
  obtain ⟨g197, e197, g198, e198, g199, e199, h⟩ := h
  unfold DerivePublicKey_32_32_p1 at h
  obtain ⟨g200, e200, g201, e201, g202, e202, g203, e203, h⟩ := h
  obtain ⟨g204, e204, q13, g206, rg206_0, rg206_1, rg206_2, rg206_3, h⟩ := h
  obtain ⟨g211, e211, g212, e212, g213, e213, g214, e214, h⟩ := h
  obtain ⟨g215, e215, g216, e216, g217, e217, g218, e218, h⟩ := h
  obtain ⟨q14, g220, rg220_0, rg220_1, rg220_2, rg220_3, g225, e225, h⟩ := h
  obtain ⟨g226, e226, g227, e227, g228, e228, g229, e229, h⟩ := h
  obtain ⟨g230, e230, g231, e231, g232, e232, q15, g234, h⟩ := h
  obtain ⟨rg234_0, rg234_1, rg234_2, rg234_3, g239, e239, g240, e240, h⟩ := h
  obtain ⟨g241, e241, g242, e242, g243, e243, g244, e244, h⟩ := h
  obtain ⟨g245, e245, g246, e246, q16, g248, rg248_0, rg248_1, h⟩ := h
  obtain ⟨rg248_2, rg248_3, g253, e253, g254, e254, g255, e255, h⟩ := h
  obtain ⟨g256, e256, g257, e257, g258, e258, g259, e259, h⟩ := h
  obtain ⟨g260, e260, q17, g262, rg262_0, rg262_1, rg262_2, rg262_3, h⟩ := h
  obtain ⟨g267, e267, g268, e268, g269, e269, g270, e270, h⟩ := h
  obtain ⟨g271, e271, g272, e272, g273, e273, g274, e274, h⟩ := h
  obtain ⟨q18, g276, rg276_0, rg276_1, rg276_2, rg276_3, g281, e281, h⟩ := h
  obtain ⟨g282, e282, g283, e283, g284, e284, g285, e285, h⟩ := h
  obtain ⟨g286, e286, g287, e287, g288, e288, q19, g290, h⟩ := h
  obtain ⟨rg290_0, rg290_1, rg290_2, rg290_3, g295, e295, g296, e296, h⟩ := h
  obtain ⟨g297, e297, g298, e298, g299, e299, g300, e300, h⟩ := h
  obtain ⟨g301, e301, g302, e302, q20, h⟩ := h
  have h := compressedPacking_sound hl h
  obtain ⟨q21, q22, h⟩ := h
  obtain ⟨w307, -, -, h⟩ := split_1_32_sound hl h
  obtain ⟨-, -, q23, q24, q25, q26, q27, q28, q29, q30, q31, q32, q33, q34, q35, q36, q37, q38, q39, q40, q41, q42, q43, q44, q45, q46, q47, q48, q49, q50, q51, q52, q53, q54, -⟩ := h
  simp only [get2_0, get2_1] at c10 c11 c12 q13 q14 q15 q16 q17 q18 q19 q20 q21 q22
  have u204 := horner_limb (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg192_0) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg192_1) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg192_2) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg192_3) (by norm_num)) e197 e198 e199 e200 e201 e202 e203 e204
  rw [q23, q24, q25, q26, get_byteAt, get_byteAt, get_byteAt, get_byteAt] at u204
  simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at u204
  have u218 := horner_limb (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg206_0) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg206_1) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg206_2) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg206_3) (by norm_num)) e211 e212 e213 e214 e215 e216 e217 e218
  rw [q27, q28, q29, q30, get_byteAt, get_byteAt, get_byteAt, get_byteAt] at u218
  simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at u218
  have u232 := horner_limb (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg220_0) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg220_1) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg220_2) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg220_3) (by norm_num)) e225 e226 e227 e228 e229 e230 e231 e232
  rw [q31, q32, q33, q34, get_byteAt, get_byteAt, get_byteAt, get_byteAt] at u232
  simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at u232
  have u246 := horner_limb (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg234_0) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg234_1) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg234_2) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg234_3) (by norm_num)) e239 e240 e241 e242 e243 e244 e245 e246
  rw [q35, q36, q37, q38, get_byteAt, get_byteAt, get_byteAt, get_byteAt] at u246
  simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at u246
  have u260 := horner_limb (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg248_0) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg248_1) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg248_2) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg248_3) (by norm_num)) e253 e254 e255 e256 e257 e258 e259 e260
  rw [q39, q40, q41, q42, get_byteAt, get_byteAt, get_byteAt, get_byteAt] at u260
  simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at u260
  have u274 := horner_limb (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg262_0) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg262_1) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg262_2) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg262_3) (by norm_num)) e267 e268 e269 e270 e271 e272 e273 e274
  rw [q43, q44, q45, q46, get_byteAt, get_byteAt, get_byteAt, get_byteAt] at u274
  simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at u274
  have u288 := horner_limb (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg276_0) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg276_1) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg276_2) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg276_3) (by norm_num)) e281 e282 e283 e284 e285 e286 e287 e288
  rw [q47, q48, q49, q50, get_byteAt, get_byteAt, get_byteAt, get_byteAt] at u288
  simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at u288
  have u302 := horner_limb (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg290_0) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg290_1) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg290_2) (by norm_num)) (lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg290_3) (by norm_num)) e295 e296 e297 e298 e299 e300 e301 e302
  rw [q51, q52, q53, q54, get_byteAt, get_byteAt, get_byteAt, get_byteAt] at u302
  simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at u302
  have wl0 : (EX.limbs.get 0).val = byteAt X 28 * 256 ^ 3 + byteAt X 29 * 256 ^ 2 + byteAt X 30 * 256 + byteAt X 31 := by rw [q20]; exact u302
  have wl1 : (EX.limbs.get 1).val = byteAt X 24 * 256 ^ 3 + byteAt X 25 * 256 ^ 2 + byteAt X 26 * 256 + byteAt X 27 := by rw [q19]; exact u288
  have wl2 : (EX.limbs.get 2).val = byteAt X 20 * 256 ^ 3 + byteAt X 21 * 256 ^ 2 + byteAt X 22 * 256 + byteAt X 23 := by rw [q18]; exact u274
  have wl3 : (EX.limbs.get 3).val = byteAt X 16 * 256 ^ 3 + byteAt X 17 * 256 ^ 2 + byteAt X 18 * 256 + byteAt X 19 := by rw [q17]; exact u260
  have wl4 : (EX.limbs.get 4).val = byteAt X 12 * 256 ^ 3 + byteAt X 13 * 256 ^ 2 + byteAt X 14 * 256 + byteAt X 15 := by rw [q16]; exact u246
  have wl5 : (EX.limbs.get 5).val = byteAt X 8 * 256 ^ 3 + byteAt X 9 * 256 ^ 2 + byteAt X 10 * 256 + byteAt X 11 := by rw [q15]; exact u232
  have wl6 : (EX.limbs.get 6).val = byteAt X 4 * 256 ^ 3 + byteAt X 5 * 256 ^ 2 + byteAt X 6 * 256 + byteAt X 7 := by rw [q14]; exact u218
  have wl7 : (EX.limbs.get 7).val = byteAt X 0 * 256 ^ 3 + byteAt X 1 * 256 ^ 2 + byteAt X 2 * 256 + byteAt X 3 := by rw [q13]; exact u204
  have hvE : ∀ l : Fin 8, (EX.limbs.get l).val = byteAt X (0 + 4 * (7 - l.val)) * 256 ^ 3 +
      byteAt X (0 + 4 * (7 - l.val) + 1) * 256 ^ 2 + byteAt X (0 + 4 * (7 - l.val) + 2) * 256 +
      byteAt X (0 + 4 * (7 - l.val) + 3) := by
    intro l; fin_cases l
    exacts [wl0, wl1, wl2, wl3, wl4, wl5, wl6, wl7]
  have bx0 : byteAt X 0 < 256 := by
    have e := get_byteAt X 0
    rw [← q23] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg192_0) (by norm_num)
  have bx1 : byteAt X 1 < 256 := by
    have e := get_byteAt X 1
    rw [← q24] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg192_1) (by norm_num)
  have bx2 : byteAt X 2 < 256 := by
    have e := get_byteAt X 2
    rw [← q25] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg192_2) (by norm_num)
  have bx3 : byteAt X 3 < 256 := by
    have e := get_byteAt X 3
    rw [← q26] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg192_3) (by norm_num)
  have bx4 : byteAt X 4 < 256 := by
    have e := get_byteAt X 4
    rw [← q27] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg206_0) (by norm_num)
  have bx5 : byteAt X 5 < 256 := by
    have e := get_byteAt X 5
    rw [← q28] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg206_1) (by norm_num)
  have bx6 : byteAt X 6 < 256 := by
    have e := get_byteAt X 6
    rw [← q29] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg206_2) (by norm_num)
  have bx7 : byteAt X 7 < 256 := by
    have e := get_byteAt X 7
    rw [← q30] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg206_3) (by norm_num)
  have bx8 : byteAt X 8 < 256 := by
    have e := get_byteAt X 8
    rw [← q31] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg220_0) (by norm_num)
  have bx9 : byteAt X 9 < 256 := by
    have e := get_byteAt X 9
    rw [← q32] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg220_1) (by norm_num)
  have bx10 : byteAt X 10 < 256 := by
    have e := get_byteAt X 10
    rw [← q33] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg220_2) (by norm_num)
  have bx11 : byteAt X 11 < 256 := by
    have e := get_byteAt X 11
    rw [← q34] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg220_3) (by norm_num)
  have bx12 : byteAt X 12 < 256 := by
    have e := get_byteAt X 12
    rw [← q35] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg234_0) (by norm_num)
  have bx13 : byteAt X 13 < 256 := by
    have e := get_byteAt X 13
    rw [← q36] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg234_1) (by norm_num)
  have bx14 : byteAt X 14 < 256 := by
    have e := get_byteAt X 14
    rw [← q37] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg234_2) (by norm_num)
  have bx15 : byteAt X 15 < 256 := by
    have e := get_byteAt X 15
    rw [← q38] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg234_3) (by norm_num)
  have bx16 : byteAt X 16 < 256 := by
    have e := get_byteAt X 16
    rw [← q39] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg248_0) (by norm_num)
  have bx17 : byteAt X 17 < 256 := by
    have e := get_byteAt X 17
    rw [← q40] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg248_1) (by norm_num)
  have bx18 : byteAt X 18 < 256 := by
    have e := get_byteAt X 18
    rw [← q41] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg248_2) (by norm_num)
  have bx19 : byteAt X 19 < 256 := by
    have e := get_byteAt X 19
    rw [← q42] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg248_3) (by norm_num)
  have bx20 : byteAt X 20 < 256 := by
    have e := get_byteAt X 20
    rw [← q43] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg262_0) (by norm_num)
  have bx21 : byteAt X 21 < 256 := by
    have e := get_byteAt X 21
    rw [← q44] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg262_1) (by norm_num)
  have bx22 : byteAt X 22 < 256 := by
    have e := get_byteAt X 22
    rw [← q45] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg262_2) (by norm_num)
  have bx23 : byteAt X 23 < 256 := by
    have e := get_byteAt X 23
    rw [← q46] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg262_3) (by norm_num)
  have bx24 : byteAt X 24 < 256 := by
    have e := get_byteAt X 24
    rw [← q47] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg276_0) (by norm_num)
  have bx25 : byteAt X 25 < 256 := by
    have e := get_byteAt X 25
    rw [← q48] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg276_1) (by norm_num)
  have bx26 : byteAt X 26 < 256 := by
    have e := get_byteAt X 26
    rw [← q49] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg276_2) (by norm_num)
  have bx27 : byteAt X 27 < 256 := by
    have e := get_byteAt X 27
    rw [← q50] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg276_3) (by norm_num)
  have bx28 : byteAt X 28 < 256 := by
    have e := get_byteAt X 28
    rw [← q51] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg290_0) (by norm_num)
  have bx29 : byteAt X 29 < 256 := by
    have e := get_byteAt X 29
    rw [← q52] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg290_1) (by norm_num)
  have bx30 : byteAt X 30 < 256 := by
    have e := get_byteAt X 30
    rw [← q53] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg290_2) (by norm_num)
  have bx31 : byteAt X 31 < 256 := by
    have e := get_byteAt X 31
    rw [← q54] at e
    simp only [Fin.coe_ofNat_eq_mod, Nat.reduceMod] at e
    rw [← e]; exact lt_of_lt_of_eq (rc_val hl (by norm_num) (by norm_num) rg290_3) (by norm_num)
  have hbX : ∀ i < 32, byteAt X i < 256 := by
    intro i hi; interval_cases i
    exacts [bx0, bx1, bx2, bx3, bx4, bx5, bx6, bx7, bx8, bx9, bx10, bx11, bx12, bx13, bx14, bx15, bx16, bx17, bx18, bx19, bx20, bx21, bx22, bx23, bx24, bx25, bx26, bx27, bx28, bx29, bx30, bx31]
  have hNE := limbNat_bytes X 0 hvE
  have lEX := assertCanonical_p_sound _ (reduced_vals hEX).1 c10
  have lEY := assertCanonical_p_sound _ (reduced_vals hEY).1 c11
  rw [p256P_eq] at lEX lEY
  have cEXv : ((limbNat EX.limbs : ℕ) : Fp) = ((EX.value : ℤ) : Fp) := by
    rw [← (reduced_vals hEX).2]; push_cast; rfl
  have cEYv : ((limbNat EY.limbs : ℕ) : Fp) = ((EY.value : ℤ) : Fp) := by
    rw [← (reduced_vals hEY).2]; push_cast; rfl
  have hE' : OnCurve ((limbNat EX.limbs : ℕ) : Fp) ((limbNat EY.limbs : ℕ) : Fp) := by
    rw [cEXv, cEYv]; exact hE
  refine ⟨limbNat EX.limbs, limbNat EY.limbs, hE', hndvd, lEX, lEY, ?_, hNE.symm, hbX, q21.symm, q22.symm⟩
  rw [mkPoint_inj.mpr ⟨cEXv, cEYv⟩, pE, vSC]

end ZolanaVE.P256
