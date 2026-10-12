import VerifiableEncryption.Curve.CompletenessAddLayout

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field
open scoped BigOperators

theorem completeAdd_native (PX PY QX QY L RX RY : ElemVal 8) (b : Bool) (inverse : F)
    (raw pieces : List.Vector F 24)
    (hbool : GatesDef.is_bool (if b then (1 : F) else 0))
    (hguard : (∑ i : Fin 8, (PX.limbs.get i - QX.limbs.get i) ^ 2) * inverse =
      1 - (if b then 1 else 0))
    (cp : AssertCanonical_8_0_hc36017e9 PX.limbs) (cq : AssertCanonical_8_0_hc36017e9 QX.limbs)
    (hr : ∀ i : Fin 8, RangeCheck 11 (pieces.get ⟨3 * i.val, by omega⟩) ∧
      RangeCheck 11 (pieces.get ⟨3 * i.val + 1, by omega⟩) ∧
      RangeCheck 10 (pieces.get ⟨3 * i.val + 2, by omega⟩))
    (hL : ∀ i : Fin 8, L.limbs.get i = pieces.get ⟨3 * i.val, by omega⟩ +
      pieces.get ⟨3 * i.val + 1, by omega⟩ * 2048 +
      pieces.get ⟨3 * i.val + 2, by omega⟩ * 4194304 - 2147483648)
    (cx : CheckPolynomial_9_hd299af1e (flagVector b (linElem [(1, QX), (-1, PX)])))
    (cy : CheckPolynomial_9_hd299af1e (flagVector b (linElem [(1, QY), (-1, PY)])))
    (cl : CheckPolynomial_49_h8f49f727
      (slopeVector L (linElem [(1, QX), (-1, PX)]) b PY PX (linElem [(1, QY), (-1, PY)])))
    (cxOutput : ∀ k : List.Vector F 8 → Prop, k RX.limbs → CheckPolynomial_24_h42186a27 (vec3 L PX QX) k)
    (cyOutput : ∀ k : List.Vector F 8 → Prop, k RY.limbs →
      CheckPolynomial_24_h2629e496 (vec3 L (linElem [(1, PX), (-1, RX)]) PY) k)
    (k : List.Vector (List.Vector F 8) 2 → Prop) (hk : k (RX.limbs ::ᵥ RY.limbs ::ᵥ List.Vector.nil)) :
    CompleteAdd_8_8_8_8_hd2848b17 PX.limbs PY.limbs QX.limbs QY.limbs k := by
  have h0 := hL (0 : Fin 8)
  change L.limbs.get 0 = pieces.get 0 + pieces.get 1 * 2048 + pieces.get 2 * 4194304 - 2147483648 at h0
  have h1 := hL (1 : Fin 8)
  change L.limbs.get 1 = pieces.get 3 + pieces.get 4 * 2048 + pieces.get 5 * 4194304 - 2147483648 at h1
  have h2 := hL (2 : Fin 8)
  change L.limbs.get 2 = pieces.get 6 + pieces.get 7 * 2048 + pieces.get 8 * 4194304 - 2147483648 at h2
  have h3 := hL (3 : Fin 8)
  change L.limbs.get 3 = pieces.get 9 + pieces.get 10 * 2048 + pieces.get 11 * 4194304 - 2147483648 at h3
  have h4 := hL (4 : Fin 8)
  change L.limbs.get 4 = pieces.get 12 + pieces.get 13 * 2048 + pieces.get 14 * 4194304 - 2147483648 at h4
  have h5 := hL (5 : Fin 8)
  change L.limbs.get 5 = pieces.get 15 + pieces.get 16 * 2048 + pieces.get 17 * 4194304 - 2147483648 at h5
  have h6 := hL (6 : Fin 8)
  change L.limbs.get 6 = pieces.get 18 + pieces.get 19 * 2048 + pieces.get 20 * 4194304 - 2147483648 at h6
  have h7 := hL (7 : Fin 8)
  change L.limbs.get 7 = pieces.get 21 + pieces.get 22 * 2048 + pieces.get 23 * 4194304 - 2147483648 at h7
  unfold AssertCanonical_8_0_hc36017e9 at cp cq
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, GatesDef.eq, exists_eq_left] at cp cq
  obtain ⟨p2, pz2, p6, p5, p17, pz17, p20, pz20, pfin, -⟩ := cp
  obtain ⟨q2, qz2, q6, q5, q17, qz17, q20, qz20, qfin, -⟩ := cq
  unfold CompleteAdd_8_8_8_8_hd2848b17 CompleteAdd_8_8_8_8_hd2848b17_p1
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, GatesDef.eq, exists_eq_left]
  refine ⟨vec![(if b then 1 else 0), inverse], hbool,
    p2, pz2, p6, p5, p17, pz17, p20, pz20, pfin,
    q2, qz2, q6, q5, q17, qz17, q20, qz20, qfin, ?_, ?_, ?_,
    raw, pieces,
    (hr 0).1, (hr 0).2.1, (hr 0).2.2,
    (hr 1).1, (hr 1).2.1, (hr 1).2.2,
    (hr 2).1, (hr 2).2.1, (hr 2).2.2,
    (hr 3).1, (hr 3).2.1, (hr 3).2.2,
    (hr 4).1, (hr 4).2.1, (hr 4).2.2,
    (hr 5).1, (hr 5).2.1, (hr 5).2.2,
    (hr 6).1, (hr 6).2.1, (hr 6).2.2,
    (hr 7).1, (hr 7).2.1, (hr 7).2.2, ?_, ?_⟩
  · simpa only [Fin.sum_univ_eight, pow_two, zero_add] using hguard
  · convert cx using 1
    apply List.Vector.toList_injective
    simp only [flagVector, linDiff_limb, List.Vector.toList_cons, List.Vector.toList_nil,
      sub_eq_add_neg, mul_neg_one, zero_add, mul_one, List.Vector.get_cons_zero]
  · convert cy using 1
    apply List.Vector.toList_injective
    simp only [flagVector, linDiff_limb, List.Vector.toList_cons, List.Vector.toList_nil,
      sub_eq_add_neg, mul_neg_one, zero_add, mul_one, List.Vector.get_cons_zero]
  · simp only [mul_one, zero_add]
    rw [← h0, ← h1, ← h2,
      ← h3, ← h4, ← h5,
      ← h6, ← h7]
    convert cl using 1
    apply List.Vector.toList_injective
    simp only [slopeVector]
    rw [triple_aElem_native]
    simp only [slopeVector, linDiff_limb, quadCompositionA, List.Vector.toList_cons,
      List.Vector.toList_nil, sub_eq_add_neg, mul_neg_one, zero_add, mul_one,
      List.Vector.get_cons_zero, List.Vector.get_cons_succ,
      Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod]
    rfl
  · simp only [mul_one, zero_add]
    rw [← h0, ← h1, ← h2,
      ← h3, ← h4, ← h5,
      ← h6, ← h7]
    apply cxOutput
    simp only [mul_one, zero_add, mul_neg_one, ← sub_eq_add_neg]
    rw [← linDiff_limb PX RX 0, ← linDiff_limb PX RX 1, ← linDiff_limb PX RX 2,
      ← linDiff_limb PX RX 3, ← linDiff_limb PX RX 4, ← linDiff_limb PX RX 5,
      ← linDiff_limb PX RX 6, ← linDiff_limb PX RX 7]
    change CheckPolynomial_24_h2629e496 (vec3 L (linElem [(1, PX), (-1, RX)]) PY) _
    simpa only [vec8_eta] using cyOutput (fun out => k (RX.limbs ::ᵥ out ::ᵥ List.Vector.nil)) hk

end ZolanaVE.P256.Completeness
