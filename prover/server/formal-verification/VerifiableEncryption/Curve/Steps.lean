import VerifiableEncryption.Curve.Guards
import VerifiableEncryption.Field.Canonical
import VerifiableEncryption.Circuit.Curve

/-!
Soundness of the extracted curve step gadgets, from the field layer's
instance theorems and the group law.
-/

namespace ZolanaVE.P256

open ZolanaVE.Field

theorem p256P_eq : p256P = p := rfl
theorem p256N_eq : p256N = n := rfl

theorem limbNat_eq_limbValue (L : List.Vector F 8) : limbNat L = limbValue (fun i => L.get i) := rfl

theorem assertDistinctX_parts {P Q : List.Vector F 8} (h : AssertDistinctX_8_8_h689cdb88 P Q) :
    AssertCanonical_8_0_hcc2f8a19 P ∧ AssertCanonical_8_0_hcc2f8a19 Q ∧
      ∑ i : Fin 8, (P.get i - Q.get i) ^ 2 ≠ 0 := by
  unfold AssertDistinctX_8_8_h689cdb88 at h
  unfold AssertCanonical_8_0_hcc2f8a19
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, GatesDef.sub,
    GatesDef.eq, GatesDef.ne, exists_eq_left] at h ⊢
  obtain ⟨g2, hz2, h6, h5, g17, hz17, g20, hz20, hfin, q2, qz2, q6, q5, q17, qz17, q20, qz20, qfin,
    hne, -⟩ := h
  refine ⟨⟨g2, hz2, h6, h5, g17, hz17, g20, hz20, hfin, trivial⟩,
    ⟨q2, qz2, q6, q5, q17, qz17, q20, qz20, qfin, trivial⟩, ?_⟩
  intro h0
  apply hne
  rw [Fin.sum_univ_eight] at h0
  linear_combination h0

/-- `AssertDistinctX`: both inputs canonical, and their P-256 values distinct. -/
theorem assertDistinctX_sound {P Q : List.Vector F 8} (hP : ∀ i, (P.get i).val < 2 ^ 32)
    (hQ : ∀ i, (Q.get i).val < 2 ^ 32) (h : AssertDistinctX_8_8_h689cdb88 P Q) :
    limbNat P < p ∧ limbNat Q < p ∧ ((limbNat P : ℕ) : Fp) ≠ ((limbNat Q : ℕ) : Fp) := by
  obtain ⟨cP, cQ, hs⟩ := assertDistinctX_parts h
  have lP := assertCanonical_p_sound P hP cP
  have lQ := assertCanonical_p_sound Q hQ cQ
  exact ⟨lP, lQ, distinctX_guard (a := fun i => P.get i) (c := fun i => Q.get i) hP hQ lP lQ hs⟩

end ZolanaVE.P256
