import VerifiableEncryption.Curve.AgreeKeyAux
import VerifiableEncryption.Envelope.Bodies
import VerifiableEncryption.Curve.ScalarMul
import VerifiableEncryption.Curve.ScalarMulBase

/-!
Soundness of the key-agreement constraints that open both extracted
envelopes (`AgreeKeyBody`), with the continuation abstracted. The proof walks
the same gates as `agreeKey_sound`; only the final read-out differs.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem agreeKey_core (hl : LookupSound RangeCheck 11) (hr : RowLookupSound)
    {sk : List.Vector F 32} {pk : List.Vector F 65}
    {Q : F → F → List.Vector F 2 → List.Vector F 2 → F → Prop}
    (h : AgreeKeyBody sk pk Q) :
    ∃ hQ : OnCurve ((bytesBE pk 1 32 : ℕ) : Fp) ((bytesBE pk 33 32 : ℕ) : Fp),
      pk.get 0 = 4 ∧ bytesBE pk 1 32 < p ∧ bytesBE pk 33 32 < p ∧
      ∃ (xS yS xE yE : ℕ) (hS : OnCurve (xS : Fp) (yS : Fp)) (hE : OnCurve (xE : Fp) (yE : Fp)),
        xS < p ∧ xE < p ∧ yE < p ∧
        mkPoint hS = (bytesBE sk 0 32 : ℤ) • mkPoint hQ ∧ mkPoint hE = (bytesBE sk 0 32 : ℤ) • G ∧
        ∃ (a b : F) (c d : List.Vector F 2) (e : F),
          a = (((2 + bytesBE pk 33 32 % 2) * 2 ^ 240 + bytesBE pk 1 32 / 2 ^ 16 : ℕ) : F) ∧
          b = ((bytesBE pk 1 32 % 2 ^ 16 : ℕ) : F) ∧
          c.get 0 = (((2 + yE % 2) * 2 ^ 240 + xE / 2 ^ 16 : ℕ) : F) ∧
          c.get 1 = ((xE % 2 ^ 16 : ℕ) : F) ∧
          e = ((xS / 2 ^ 8 : ℕ) : F) ∧
          d.get 1 = ((xS % 2 ^ 8 : ℕ) : F) ∧
          Q a b c d e := by
  unfold AgreeKeyBody at h
  obtain ⟨q0, rp1, rp2, rp3, rp4, rp5, rp6, rp7, h⟩ := h
  obtain ⟨rp8, rp9, rp10, rp11, rp12, rp13, rp14, rp15, h⟩ := h
  obtain ⟨rp16, rp17, rp18, rp19, rp20, rp21, rp22, rp23, h⟩ := h
  obtain ⟨rp24, rp25, rp26, rp27, rp28, rp29, rp30, rp31, h⟩ := h
  obtain ⟨rp32, rp33, rp34, rp35, rp36, rp37, rp38, rp39, h⟩ := h
  obtain ⟨rp40, rp41, rp42, rp43, rp44, rp45, rp46, rp47, h⟩ := h
  obtain ⟨rp48, rp49, rp50, rp51, rp52, rp53, rp54, rp55, h⟩ := h
  obtain ⟨rp56, rp57, rp58, rp59, rp60, rp61, rp62, rp63, h⟩ := h
  obtain ⟨rp64, g65, e65, g66, e66, g67, e67, g68, h⟩ := h
  obtain ⟨e68, g69, e69, g70, e70, g71, e71, g72, h⟩ := h
  obtain ⟨e72, g73, e73, g74, e74, g75, e75, g76, h⟩ := h
  obtain ⟨e76, g77, e77, g78, e78, g79, e79, g80, h⟩ := h
  obtain ⟨e80, g81, e81, g82, e82, g83, e83, g84, h⟩ := h
  obtain ⟨e84, g85, e85, g86, e86, g87, e87, g88, h⟩ := h
  obtain ⟨e88, g89, e89, g90, e90, g91, e91, g92, h⟩ := h
  obtain ⟨e92, g93, e93, g94, e94, g95, e95, g96, h⟩ := h
  obtain ⟨e96, g97, e97, g98, e98, g99, e99, g100, h⟩ := h
  obtain ⟨e100, g101, e101, g102, e102, g103, e103, g104, h⟩ := h
  obtain ⟨e104, g105, e105, g106, e106, g107, e107, g108, h⟩ := h
  obtain ⟨e108, g109, e109, g110, e110, g111, e111, g112, h⟩ := h
  obtain ⟨e112, g113, e113, g114, e114, g115, e115, g116, h⟩ := h
  obtain ⟨e116, g117, e117, g118, e118, g119, e119, g120, h⟩ := h
  obtain ⟨e120, g121, e121, g122, e122, g123, e123, g124, h⟩ := h
  obtain ⟨e124, g125, e125, g126, e126, g127, e127, g128, h⟩ := h
  obtain ⟨e128, g129, e129, g130, e130, g131, e131, g132, h⟩ := h
  obtain ⟨e132, g133, e133, g134, e134, g135, e135, g136, h⟩ := h
  obtain ⟨e136, g137, e137, g138, e138, g139, e139, g140, h⟩ := h
  obtain ⟨e140, g141, e141, g142, e142, g143, e143, g144, h⟩ := h
  obtain ⟨e144, g145, e145, g146, e146, g147, e147, g148, h⟩ := h
  obtain ⟨e148, g149, e149, g150, e150, g151, e151, g152, h⟩ := h
  obtain ⟨e152, g153, e153, g154, e154, g155, e155, g156, h⟩ := h
  obtain ⟨e156, g157, e157, g158, e158, g159, e159, g160, h⟩ := h
  obtain ⟨e160, g161, e161, g162, e162, g163, e163, g164, h⟩ := h
  obtain ⟨e164, g165, e165, g166, e166, g167, e167, g168, h⟩ := h
  obtain ⟨e168, g169, e169, g170, e170, g171, e171, g172, h⟩ := h
  obtain ⟨e172, g173, e173, g174, e174, g175, e175, g176, h⟩ := h
  obtain ⟨e176, g177, e177, g178, e178, g179, e179, g180, h⟩ := h
  obtain ⟨e180, g181, e181, g182, e182, g183, e183, g184, h⟩ := h
  obtain ⟨e184, g185, e185, g186, e186, g187, e187, g188, h⟩ := h
  obtain ⟨e188, g189, e189, g190, e190, g191, e191, g192, h⟩ := h
  obtain ⟨e192, cX, cY, onc, h⟩ := h
  have v72 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp29) (by rw [get_byteAt]; exact byte_lt hl rp30) (by rw [get_byteAt]; exact byte_lt hl rp31) (by rw [get_byteAt]; exact byte_lt hl rp32) e65 e66 e67 e68 e69 e70 e71 e72
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v72
  have v80 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp25) (by rw [get_byteAt]; exact byte_lt hl rp26) (by rw [get_byteAt]; exact byte_lt hl rp27) (by rw [get_byteAt]; exact byte_lt hl rp28) e73 e74 e75 e76 e77 e78 e79 e80
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v80
  have v88 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp21) (by rw [get_byteAt]; exact byte_lt hl rp22) (by rw [get_byteAt]; exact byte_lt hl rp23) (by rw [get_byteAt]; exact byte_lt hl rp24) e81 e82 e83 e84 e85 e86 e87 e88
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v88
  have v96 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp17) (by rw [get_byteAt]; exact byte_lt hl rp18) (by rw [get_byteAt]; exact byte_lt hl rp19) (by rw [get_byteAt]; exact byte_lt hl rp20) e89 e90 e91 e92 e93 e94 e95 e96
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v96
  have v104 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp13) (by rw [get_byteAt]; exact byte_lt hl rp14) (by rw [get_byteAt]; exact byte_lt hl rp15) (by rw [get_byteAt]; exact byte_lt hl rp16) e97 e98 e99 e100 e101 e102 e103 e104
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v104
  have v112 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp9) (by rw [get_byteAt]; exact byte_lt hl rp10) (by rw [get_byteAt]; exact byte_lt hl rp11) (by rw [get_byteAt]; exact byte_lt hl rp12) e105 e106 e107 e108 e109 e110 e111 e112
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v112
  have v120 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp5) (by rw [get_byteAt]; exact byte_lt hl rp6) (by rw [get_byteAt]; exact byte_lt hl rp7) (by rw [get_byteAt]; exact byte_lt hl rp8) e113 e114 e115 e116 e117 e118 e119 e120
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v120
  have v128 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp1) (by rw [get_byteAt]; exact byte_lt hl rp2) (by rw [get_byteAt]; exact byte_lt hl rp3) (by rw [get_byteAt]; exact byte_lt hl rp4) e121 e122 e123 e124 e125 e126 e127 e128
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v128
  have hvX : ∀ l : Fin 8, ((g72 ::ᵥ g80 ::ᵥ g88 ::ᵥ g96 ::ᵥ g104 ::ᵥ g112 ::ᵥ g120 ::ᵥ g128 ::ᵥ List.Vector.nil).get l).val = byteAt pk (1 + 4 * (7 - l.val)) * 256 ^ 3 +
      byteAt pk (1 + 4 * (7 - l.val) + 1) * 256 ^ 2 + byteAt pk (1 + 4 * (7 - l.val) + 2) * 256 +
      byteAt pk (1 + 4 * (7 - l.val) + 3) := by
    intro l; fin_cases l
    exacts [v72, v80, v88, v96, v104, v112, v120, v128]
  have hbX : ∀ j < 32, byteAt pk (1 + j) < 256 := by
    intro j hj; interval_cases j
    exacts [byte_lt hl rp1, byte_lt hl rp2, byte_lt hl rp3, byte_lt hl rp4, byte_lt hl rp5, byte_lt hl rp6, byte_lt hl rp7, byte_lt hl rp8, byte_lt hl rp9, byte_lt hl rp10, byte_lt hl rp11, byte_lt hl rp12, byte_lt hl rp13, byte_lt hl rp14, byte_lt hl rp15, byte_lt hl rp16, byte_lt hl rp17, byte_lt hl rp18, byte_lt hl rp19, byte_lt hl rp20, byte_lt hl rp21, byte_lt hl rp22, byte_lt hl rp23, byte_lt hl rp24, byte_lt hl rp25, byte_lt hl rp26, byte_lt hl rp27, byte_lt hl rp28, byte_lt hl rp29, byte_lt hl rp30, byte_lt hl rp31, byte_lt hl rp32]
  have hLX := limbs_bytes_lt pk 1 hbX hvX
  have hNX := limbNat_bytes pk 1 hvX
  have v136 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp61) (by rw [get_byteAt]; exact byte_lt hl rp62) (by rw [get_byteAt]; exact byte_lt hl rp63) (by rw [get_byteAt]; exact byte_lt hl rp64) e129 e130 e131 e132 e133 e134 e135 e136
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v136
  have v144 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp57) (by rw [get_byteAt]; exact byte_lt hl rp58) (by rw [get_byteAt]; exact byte_lt hl rp59) (by rw [get_byteAt]; exact byte_lt hl rp60) e137 e138 e139 e140 e141 e142 e143 e144
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v144
  have v152 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp53) (by rw [get_byteAt]; exact byte_lt hl rp54) (by rw [get_byteAt]; exact byte_lt hl rp55) (by rw [get_byteAt]; exact byte_lt hl rp56) e145 e146 e147 e148 e149 e150 e151 e152
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v152
  have v160 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp49) (by rw [get_byteAt]; exact byte_lt hl rp50) (by rw [get_byteAt]; exact byte_lt hl rp51) (by rw [get_byteAt]; exact byte_lt hl rp52) e153 e154 e155 e156 e157 e158 e159 e160
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v160
  have v168 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp45) (by rw [get_byteAt]; exact byte_lt hl rp46) (by rw [get_byteAt]; exact byte_lt hl rp47) (by rw [get_byteAt]; exact byte_lt hl rp48) e161 e162 e163 e164 e165 e166 e167 e168
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v168
  have v176 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp41) (by rw [get_byteAt]; exact byte_lt hl rp42) (by rw [get_byteAt]; exact byte_lt hl rp43) (by rw [get_byteAt]; exact byte_lt hl rp44) e169 e170 e171 e172 e173 e174 e175 e176
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v176
  have v184 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp37) (by rw [get_byteAt]; exact byte_lt hl rp38) (by rw [get_byteAt]; exact byte_lt hl rp39) (by rw [get_byteAt]; exact byte_lt hl rp40) e177 e178 e179 e180 e181 e182 e183 e184
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v184
  have v192 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rp33) (by rw [get_byteAt]; exact byte_lt hl rp34) (by rw [get_byteAt]; exact byte_lt hl rp35) (by rw [get_byteAt]; exact byte_lt hl rp36) e185 e186 e187 e188 e189 e190 e191 e192
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v192
  have hvY : ∀ l : Fin 8, ((g136 ::ᵥ g144 ::ᵥ g152 ::ᵥ g160 ::ᵥ g168 ::ᵥ g176 ::ᵥ g184 ::ᵥ g192 ::ᵥ List.Vector.nil).get l).val = byteAt pk (33 + 4 * (7 - l.val)) * 256 ^ 3 +
      byteAt pk (33 + 4 * (7 - l.val) + 1) * 256 ^ 2 + byteAt pk (33 + 4 * (7 - l.val) + 2) * 256 +
      byteAt pk (33 + 4 * (7 - l.val) + 3) := by
    intro l; fin_cases l
    exacts [v136, v144, v152, v160, v168, v176, v184, v192]
  have hbY : ∀ j < 32, byteAt pk (33 + j) < 256 := by
    intro j hj; interval_cases j
    exacts [byte_lt hl rp33, byte_lt hl rp34, byte_lt hl rp35, byte_lt hl rp36, byte_lt hl rp37, byte_lt hl rp38, byte_lt hl rp39, byte_lt hl rp40, byte_lt hl rp41, byte_lt hl rp42, byte_lt hl rp43, byte_lt hl rp44, byte_lt hl rp45, byte_lt hl rp46, byte_lt hl rp47, byte_lt hl rp48, byte_lt hl rp49, byte_lt hl rp50, byte_lt hl rp51, byte_lt hl rp52, byte_lt hl rp53, byte_lt hl rp54, byte_lt hl rp55, byte_lt hl rp56, byte_lt hl rp57, byte_lt hl rp58, byte_lt hl rp59, byte_lt hl rp60, byte_lt hl rp61, byte_lt hl rp62, byte_lt hl rp63, byte_lt hl rp64]
  have hLY := limbs_bytes_lt pk 33 hbY hvY
  have hNY := limbNat_bytes pk 33 hvY
  set PX := mkElemF (g72 ::ᵥ g80 ::ᵥ g88 ::ᵥ g96 ::ᵥ g104 ::ᵥ g112 ::ᵥ g120 ::ᵥ g128 ::ᵥ List.Vector.nil) hLX with hPX
  set PY := mkElemF (g136 ::ᵥ g144 ::ᵥ g152 ::ᵥ g160 ::ᵥ g168 ::ᵥ g176 ::ᵥ g184 ::ᵥ g192 ::ᵥ List.Vector.nil) hLY with hPY
  have lX := assertCanonical_p_sound _ hLX cX
  have lY := assertCanonical_p_sound _ hLY cY
  have hQ := assertOnCurve_sound hl PX PY rfl rfl onc
  obtain ⟨w196, hw1, hw0, h⟩ := split_1_8_sound hl h
  obtain ⟨g197, e197, g198, e198, g199, e199, h⟩ := h
  obtain ⟨g200, e200, g201, e201, g202, e202, g203, e203, h⟩ := h
  obtain ⟨g204, e204, g205, e205, g206, e206, g207, e207, h⟩ := h
  obtain ⟨g208, e208, g209, e209, g210, e210, g211, e211, h⟩ := h
  obtain ⟨g212, e212, g213, e213, g214, e214, g215, e215, h⟩ := h
  obtain ⟨g216, e216, g217, e217, g218, e218, g219, e219, h⟩ := h
  obtain ⟨g220, e220, g221, e221, g222, e222, g223, e223, h⟩ := h
  obtain ⟨g224, e224, g225, e225, g226, e226, g227, e227, h⟩ := h
  obtain ⟨g228, e228, g229, e229, g230, e230, g231, e231, h⟩ := h
  obtain ⟨g232, e232, g233, e233, g234, e234, g235, e235, h⟩ := h
  obtain ⟨g236, e236, g237, e237, g238, e238, g239, e239, h⟩ := h
  obtain ⟨g240, e240, g241, e241, g242, e242, g243, e243, h⟩ := h
  obtain ⟨g244, e244, g245, e245, g246, e246, g247, e247, h⟩ := h
  obtain ⟨g248, e248, g249, e249, g250, e250, g251, e251, h⟩ := h
  obtain ⟨g252, e252, g253, e253, g254, e254, g255, e255, h⟩ := h
  obtain ⟨g256, e256, g257, e257, g258, e258, g259, e259, h⟩ := h
  obtain ⟨g260, e260, g261, e261, g262, e262, g263, e263, h⟩ := h
  obtain ⟨rs0, rs1, rs2, rs3, rs4, rs5, rs6, rs7, h⟩ := h
  obtain ⟨rs8, rs9, rs10, rs11, rs12, rs13, rs14, rs15, h⟩ := h
  obtain ⟨rs16, rs17, rs18, rs19, rs20, rs21, rs22, rs23, h⟩ := h
  obtain ⟨rs24, rs25, rs26, rs27, rs28, rs29, rs30, rs31, h⟩ := h
  obtain ⟨g296, e296, g297, e297, g298, e298, g299, e299, h⟩ := h
  obtain ⟨g300, e300, g301, e301, g302, e302, g303, e303, h⟩ := h
  obtain ⟨g304, e304, g305, e305, g306, e306, g307, e307, h⟩ := h
  obtain ⟨g308, e308, g309, e309, g310, e310, g311, e311, h⟩ := h
  obtain ⟨g312, e312, g313, e313, g314, e314, g315, e315, h⟩ := h
  obtain ⟨g316, e316, g317, e317, g318, e318, g319, e319, h⟩ := h
  obtain ⟨g320, e320, g321, e321, g322, e322, g323, e323, h⟩ := h
  obtain ⟨g324, e324, g325, e325, g326, e326, g327, e327, h⟩ := h
  obtain ⟨g328, e328, g329, e329, g330, e330, g331, e331, h⟩ := h
  obtain ⟨g332, e332, g333, e333, g334, e334, g335, e335, h⟩ := h
  obtain ⟨g336, e336, g337, e337, g338, e338, g339, e339, h⟩ := h
  obtain ⟨g340, e340, g341, e341, g342, e342, g343, e343, h⟩ := h
  obtain ⟨g344, e344, g345, e345, g346, e346, g347, e347, h⟩ := h
  obtain ⟨g348, e348, g349, e349, g350, e350, g351, e351, h⟩ := h
  obtain ⟨g352, e352, g353, e353, g354, e354, g355, e355, h⟩ := h
  obtain ⟨g356, e356, g357, e357, g358, e358, g359, e359, h⟩ := h
  have v303 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rs28) (by rw [get_byteAt]; exact byte_lt hl rs29) (by rw [get_byteAt]; exact byte_lt hl rs30) (by rw [get_byteAt]; exact byte_lt hl rs31) e296 e297 e298 e299 e300 e301 e302 e303
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v303
  have v311 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rs24) (by rw [get_byteAt]; exact byte_lt hl rs25) (by rw [get_byteAt]; exact byte_lt hl rs26) (by rw [get_byteAt]; exact byte_lt hl rs27) e304 e305 e306 e307 e308 e309 e310 e311
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v311
  have v319 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rs20) (by rw [get_byteAt]; exact byte_lt hl rs21) (by rw [get_byteAt]; exact byte_lt hl rs22) (by rw [get_byteAt]; exact byte_lt hl rs23) e312 e313 e314 e315 e316 e317 e318 e319
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v319
  have v327 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rs16) (by rw [get_byteAt]; exact byte_lt hl rs17) (by rw [get_byteAt]; exact byte_lt hl rs18) (by rw [get_byteAt]; exact byte_lt hl rs19) e320 e321 e322 e323 e324 e325 e326 e327
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v327
  have v335 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rs12) (by rw [get_byteAt]; exact byte_lt hl rs13) (by rw [get_byteAt]; exact byte_lt hl rs14) (by rw [get_byteAt]; exact byte_lt hl rs15) e328 e329 e330 e331 e332 e333 e334 e335
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v335
  have v343 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rs8) (by rw [get_byteAt]; exact byte_lt hl rs9) (by rw [get_byteAt]; exact byte_lt hl rs10) (by rw [get_byteAt]; exact byte_lt hl rs11) e336 e337 e338 e339 e340 e341 e342 e343
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v343
  have v351 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rs4) (by rw [get_byteAt]; exact byte_lt hl rs5) (by rw [get_byteAt]; exact byte_lt hl rs6) (by rw [get_byteAt]; exact byte_lt hl rs7) e344 e345 e346 e347 e348 e349 e350 e351
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v351
  have v359 := horner_limb (by rw [get_byteAt]; exact byte_lt hl rs0) (by rw [get_byteAt]; exact byte_lt hl rs1) (by rw [get_byteAt]; exact byte_lt hl rs2) (by rw [get_byteAt]; exact byte_lt hl rs3) e352 e353 e354 e355 e356 e357 e358 e359
  simp only [get_byteAt, Fin.coe_ofNat_eq_mod, Nat.reduceMod] at v359
  have hvS : ∀ l : Fin 8, ((g303 ::ᵥ g311 ::ᵥ g319 ::ᵥ g327 ::ᵥ g335 ::ᵥ g343 ::ᵥ g351 ::ᵥ g359 ::ᵥ List.Vector.nil).get l).val = byteAt sk (0 + 4 * (7 - l.val)) * 256 ^ 3 +
      byteAt sk (0 + 4 * (7 - l.val) + 1) * 256 ^ 2 + byteAt sk (0 + 4 * (7 - l.val) + 2) * 256 +
      byteAt sk (0 + 4 * (7 - l.val) + 3) := by
    intro l; fin_cases l
    exacts [v303, v311, v319, v327, v335, v343, v351, v359]
  have hbS : ∀ j < 32, byteAt sk (0 + j) < 256 := by
    intro j hj; interval_cases j
    exacts [byte_lt hl rs0, byte_lt hl rs1, byte_lt hl rs2, byte_lt hl rs3, byte_lt hl rs4, byte_lt hl rs5, byte_lt hl rs6, byte_lt hl rs7, byte_lt hl rs8, byte_lt hl rs9, byte_lt hl rs10, byte_lt hl rs11, byte_lt hl rs12, byte_lt hl rs13, byte_lt hl rs14, byte_lt hl rs15, byte_lt hl rs16, byte_lt hl rs17, byte_lt hl rs18, byte_lt hl rs19, byte_lt hl rs20, byte_lt hl rs21, byte_lt hl rs22, byte_lt hl rs23, byte_lt hl rs24, byte_lt hl rs25, byte_lt hl rs26, byte_lt hl rs27, byte_lt hl rs28, byte_lt hl rs29, byte_lt hl rs30, byte_lt hl rs31]
  have hLS := limbs_bytes_lt sk 0 hbS hvS
  have hNS := limbNat_bytes sk 0 hvS
  set SC := mkElemF (g303 ::ᵥ g311 ::ᵥ g319 ::ᵥ g327 ::ᵥ g335 ::ᵥ g343 ::ᵥ g351 ::ᵥ g359 ::ᵥ List.Vector.nil) hLS with hSC
  have hg258 : g258 = ((bytesBE pk 1 30 : ℕ) : F) := by
    rw [e258, e257, e256, e255, e254, e253, e252, e251, e250, e249, e248, e247, e246, e245, e244, e243, e242, e241, e240, e239, e238, e237, e236, e235, e234, e233, e232, e231, e230, e229, e228, e227, e226, e225, e224, e223, e222, e221, e220, e219, e218, e217, e216, e215, e214, e213, e212, e211, e210, e209, e208, e207, e206, e205, e204, e203, e202, e201, e200, e199]
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, byte_cast pk,
      bytesBE, Finset.sum_range_succ, Finset.sum_range_zero, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Nat.reduceAdd,
      Nat.reduceSub]
    push_cast
    ring
  have hg263 : g263 = ((bytesBE pk 31 2 : ℕ) : F) := by
    rw [e263, e262, e261, e260]
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, byte_cast pk,
      bytesBE, Finset.sum_range_succ, Finset.sum_range_zero, Fin.coe_ofNat_eq_mod, Nat.reduceMod, Nat.reduceAdd,
      Nat.reduceSub]
    push_cast
    ring
  obtain ⟨RX, RY, hRX, hRY, h, hS, pS⟩ := scalarMulChecked_sound hl hr PX PY SC rfl rfl rfl hQ h
  obtain ⟨EX, EY, hEX, hEY, h, hE, pE⟩ := scalarMulBase_sound hl SC rfl h
  obtain ⟨cEX, cEY, h⟩ := h
  have h := compressedPacking_sound hl h
  obtain ⟨cSX, h⟩ := h
  obtain ⟨w366, hw366a, hw366b, h⟩ := split_8_32_sound hl h
  obtain ⟨g367, e367, g368, e368, g369, e369, g370, e370, g371, e371, g372, e372, g373, e373, g374, e374,
    g375, e375, g376, e376, g377, e377, g378, e378, g379, e379, g380, e380, h⟩ := h
  simp only [get2_0, get2_1] at cEX cEY cSX hw366a hw366b e367 e369 e371 e373 e375 e377 e379
  have lEX := assertCanonical_p_sound _ (reduced_vals hEX).1 cEX
  have lEY := assertCanonical_p_sound _ (reduced_vals hEY).1 cEY
  have lSX := assertCanonical_p_sound _ (reduced_vals hRX).1 cSX
  rw [p256P_eq] at lX lY lEX lEY lSX
  rw [hNX] at lX
  rw [hNY] at lY
  have vPX : PX.value = (bytesBE pk 1 32 : ℤ) := by rw [hPX, mkElemF_value, hNX]
  have vPY : PY.value = (bytesBE pk 33 32 : ℤ) := by rw [hPY, mkElemF_value, hNY]
  have vSC : SC.value = (bytesBE sk 0 32 : ℤ) := by rw [hSC, mkElemF_value, hNS]
  have cPX : ((PX.value : ℤ) : Fp) = ((bytesBE pk 1 32 : ℕ) : Fp) := by rw [vPX]; push_cast; rfl
  have cPY : ((PY.value : ℤ) : Fp) = ((bytesBE pk 33 32 : ℕ) : Fp) := by rw [vPY]; push_cast; rfl
  have hQ' : OnCurve ((bytesBE pk 1 32 : ℕ) : Fp) ((bytesBE pk 33 32 : ℕ) : Fp) := by
    rw [← cPX, ← cPY]; exact hQ
  have pQ : mkPoint hQ' = mkPoint hQ := mkPoint_inj.mpr ⟨cPX.symm, cPY.symm⟩
  have cRX : ((limbNat RX.limbs : ℕ) : Fp) = ((RX.value : ℤ) : Fp) := by
    rw [← (reduced_vals hRX).2]; push_cast; rfl
  have cRY : ((limbNat RY.limbs : ℕ) : Fp) = ((RY.value : ℤ) : Fp) := by
    rw [← (reduced_vals hRY).2]; push_cast; rfl
  have cEXv : ((limbNat EX.limbs : ℕ) : Fp) = ((EX.value : ℤ) : Fp) := by
    rw [← (reduced_vals hEX).2]; push_cast; rfl
  have cEYv : ((limbNat EY.limbs : ℕ) : Fp) = ((EY.value : ℤ) : Fp) := by
    rw [← (reduced_vals hEY).2]; push_cast; rfl
  have hS' : OnCurve ((limbNat RX.limbs : ℕ) : Fp) ((limbNat RY.limbs : ℕ) : Fp) := by
    rw [cRX, cRY]; exact hS
  have hE' : OnCurve ((limbNat EX.limbs : ℕ) : Fp) ((limbNat EY.limbs : ℕ) : Fp) := by
    rw [cEXv, cEYv]; exact hE
  have h30 : byteAt pk (1 + 30) < 256 := hbX 30 (by norm_num)
  have h31 : byteAt pk (1 + 31) < 256 := hbX 31 (by norm_num)
  obtain ⟨sdiv, smod⟩ := bytesBE_split16 pk 1 h30 h31
  obtain ⟨sx8m, sx8d⟩ := limbNat_split RX.limbs (w := 8) (by norm_num)
  obtain ⟨k0, -, -, -, -, -, k1, k2, k3, k4, k5⟩ := K_pows
  refine ⟨hQ', q0, lX, lY, limbNat RX.limbs, limbNat RY.limbs, limbNat EX.limbs, limbNat EY.limbs, hS', hE',
    lSX, lEX, lEY, ?_, ?_, _, _, _, _, _, ?_, ?_, rfl, rfl, ?_, ?_, h⟩
  · have e1 : mkPoint hS' = mkPoint hS := mkPoint_inj.mpr ⟨cRX, cRY⟩
    calc mkPoint hS' = mkPoint hS := e1
      _ = SC.value • mkPoint hQ := pS
      _ = (bytesBE sk 0 32 : ℤ) • mkPoint hQ := congrArg (fun P => P • mkPoint hQ) vSC
      _ = (bytesBE sk 0 32 : ℤ) • mkPoint hQ' := congrArg (fun P => (bytesBE sk 0 32 : ℤ) • P) pQ.symm
  · have e1 : mkPoint hE' = mkPoint hE := mkPoint_inj.mpr ⟨cEXv, cEYv⟩
    calc mkPoint hE' = mkPoint hE := e1
      _ = SC.value • G := pE
      _ = (bytesBE sk 0 32 : ℤ) • G := congrArg (fun P => P • G) vSC
  · rw [e259, e198, e197, hg258, natF_eq (w196.get 1), hw1, k0, bytesBE_mod2, sdiv, get_byteAt]
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, Fin.coe_ofNat_eq_mod,
      Nat.reduceMod, Nat.reduceAdd]
    push_cast
    ring
  · rw [hg263, smod]
  · rw [e380, e379, e378, e377, e376, e375, e374, e373, e372, e371, e370, e369, e368, e367,
      natF_eq (w366.get 0), natF_eq (RX.limbs.get 1), natF_eq (RX.limbs.get 2), natF_eq (RX.limbs.get 3),
      natF_eq (RX.limbs.get 4), natF_eq (RX.limbs.get 5), natF_eq (RX.limbs.get 6), natF_eq (RX.limbs.get 7),
      hw366b, k1, k2, k3, k4, k5, sx8d]
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul]
    push_cast
    norm_num
  · rw [natF_eq (w366.get 1), hw366a, sx8m]

end ZolanaVE.P256
