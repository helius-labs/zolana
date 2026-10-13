import VerifiableEncryption.Curve.CompletenessHalfTangentArithmetic

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

theorem halfTangent_native (X Y L S : ElemVal 8) (raw pieces : List.Vector F 24)
    (hr : ∀ i : Fin 8, RangeCheck 11 (pieces.get ⟨3 * i.val, by omega⟩) ∧
      RangeCheck 11 (pieces.get ⟨3 * i.val + 1, by omega⟩) ∧
      RangeCheck 10 (pieces.get ⟨3 * i.val + 2, by omega⟩))
    (hL : ∀ i : Fin 8, L.limbs.get i = pieces.get ⟨3 * i.val, by omega⟩ +
      pieces.get ⟨3 * i.val + 1, by omega⟩ * 2048 +
      pieces.get ⟨3 * i.val + 2, by omega⟩ * 4194304 - 2147483648)
    (hsquare : ∀ k : List.Vector F 8 → Prop, k S.limbs → Lazy_8_h158c056f L.limbs k)
    (hc : CheckPolynomial_40_h0930c075 (vec5 S X L Y aElem))
    (k : List.Vector F 8 → Prop) (hk : k L.limbs) :
    HalfTangentSlope_8_8_h2c0228bb X.limbs Y.limbs k := by
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
  unfold HalfTangentSlope_8_8_h2c0228bb
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left]
  refine ⟨raw, pieces,
    (hr 0).1, (hr 0).2.1, (hr 0).2.2,
    (hr 1).1, (hr 1).2.1, (hr 1).2.2,
    (hr 2).1, (hr 2).2.1, (hr 2).2.2,
    (hr 3).1, (hr 3).2.1, (hr 3).2.2,
    (hr 4).1, (hr 4).2.1, (hr 4).2.2,
    (hr 5).1, (hr 5).2.1, (hr 5).2.2,
    (hr 6).1, (hr 6).2.1, (hr 6).2.2,
    (hr 7).1, (hr 7).2.1, (hr 7).2.2, ?_⟩
  simp only [mul_one, zero_add]
  rw [← h0, ← h1, ← h2,
    ← h3, ← h4, ← h5,
    ← h6, ← h7]
  simp only [vec8_eta]
  apply hsquare
  refine ⟨?_, ?_⟩
  · simpa only [vec5, triple_aElem_native, quadCompositionA] using hc
  · simpa only [vec8_eta] using hk

end ZolanaVE.P256.Completeness
