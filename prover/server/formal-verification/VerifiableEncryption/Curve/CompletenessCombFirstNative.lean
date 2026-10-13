import VerifiableEncryption.Curve.CompletenessGeneratedChainComposition
import VerifiableEncryption.Curve.CompletenessCoordinates

/-! The first comb step has a four-element slope assertion, unlike the
six-element assertions of later steps. This bridge follows that actual body
and keeps both arithmetic primitive premises explicit. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

def combFirstSlopeInput (L D WY FY : List.Vector F 8) : List.Vector F 32 :=
  vec![L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7, D.get 0, D.get 1, D.get 2, D.get 3, D.get 4, D.get 5, D.get 6, D.get 7, WY.get 0, WY.get 1, WY.get 2, WY.get 3, WY.get 4, WY.get 5, WY.get 6, WY.get 7, FY.get 0, FY.get 1, FY.get 2, FY.get 3, FY.get 4, FY.get 5, FY.get 6, FY.get 7]

def combFirstDifference (WX X : List.Vector F 8) : List.Vector F 8 :=
  List.Vector.ofFn (fun i => WX.get i - X.get i)

theorem combFirstDifference_get (WX X : List.Vector F 8) (i : Fin 8) :
    (combFirstDifference WX X).get i = WX.get i - X.get i := by
  simp only [combFirstDifference, List.Vector.get_ofFn]

theorem combFirst_native
    (X PS PX PY WX WY FY L : List.Vector F 8) (raw pieces : List.Vector F 24)
    (hr : ∀ i : Fin 8, RangeCheck 11 (pieces.get ⟨3 * i.val, by omega⟩) ∧
      RangeCheck 11 (pieces.get ⟨3 * i.val + 1, by omega⟩) ∧
      RangeCheck 10 (pieces.get ⟨3 * i.val + 2, by omega⟩))
    (hL : ∀ i : Fin 8, L.get i =
      pieces.get ⟨3 * i.val, by omega⟩ + pieces.get ⟨3 * i.val + 1, by omega⟩ * 2048 +
      pieces.get ⟨3 * i.val + 2, by omega⟩ * 4194304 - 2147483648)
    (k : List.Vector (List.Vector F 8) 2 → Prop)
    (hs : CheckPolynomial_32_hb838cae4
      (combFirstSlopeInput L (combFirstDifference WX X) WY FY))
    (hn : Lazy_24_h4ef94fb8 (chainCompositionLazyInput L X WX)
      (fun out => k (out ::ᵥ L ::ᵥ List.Vector.nil))) :
    CombChainStep_8_8_8_8_8_8_8_h14296507 X PS PX PY WX WY FY k := by
  have h0 := hL (0 : Fin 8)
  have h1 := hL (1 : Fin 8)
  have h2 := hL (2 : Fin 8)
  have h3 := hL (3 : Fin 8)
  have h4 := hL (4 : Fin 8)
  have h5 := hL (5 : Fin 8)
  have h6 := hL (6 : Fin 8)
  have h7 := hL (7 : Fin 8)
  change L.get 0 = pieces.get 0 + pieces.get 1 * 2048 + pieces.get 2 * 4194304 - 2147483648 at h0
  change L.get 1 = pieces.get 3 + pieces.get 4 * 2048 + pieces.get 5 * 4194304 - 2147483648 at h1
  change L.get 2 = pieces.get 6 + pieces.get 7 * 2048 + pieces.get 8 * 4194304 - 2147483648 at h2
  change L.get 3 = pieces.get 9 + pieces.get 10 * 2048 + pieces.get 11 * 4194304 - 2147483648 at h3
  change L.get 4 = pieces.get 12 + pieces.get 13 * 2048 + pieces.get 14 * 4194304 - 2147483648 at h4
  change L.get 5 = pieces.get 15 + pieces.get 16 * 2048 + pieces.get 17 * 4194304 - 2147483648 at h5
  change L.get 6 = pieces.get 18 + pieces.get 19 * 2048 + pieces.get 20 * 4194304 - 2147483648 at h6
  change L.get 7 = pieces.get 21 + pieces.get 22 * 2048 + pieces.get 23 * 4194304 - 2147483648 at h7
  unfold CombChainStep_8_8_8_8_8_8_8_h14296507
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left]
  refine ⟨raw, pieces, (hr 0).1, (hr 0).2.1, (hr 0).2.2,
    (hr 1).1, (hr 1).2.1, (hr 1).2.2, (hr 2).1, (hr 2).2.1, (hr 2).2.2,
    (hr 3).1, (hr 3).2.1, (hr 3).2.2, (hr 4).1, (hr 4).2.1, (hr 4).2.2,
    (hr 5).1, (hr 5).2.1, (hr 5).2.2, (hr 6).1, (hr 6).2.1, (hr 6).2.2,
    (hr 7).1, (hr 7).2.1, (hr 7).2.2, ?_, ?_⟩
  · simp only [mul_one, zero_add]
    rw [← h0, ← h1, ← h2, ← h3, ← h4, ← h5, ← h6, ← h7]
    simpa only [combFirstSlopeInput, combFirstDifference_get, sub_eq_add_neg,
      mul_neg_one] using hs
  · simp only [mul_one, zero_add]
    rw [← h0, ← h1, ← h2, ← h3, ← h4, ← h5, ← h6, ← h7]
    simpa only [chainCompositionLazyInput, vec8_eta] using hn

end ZolanaVE.P256.Completeness
