import VerifiableEncryption.Curve.CompletenessGeneratedChainComposition
import VerifiableEncryption.Curve.CompletenessCoordinates

/-! Native second-step composition with the actual six-element assertion and
Lazy output. The outer constructor supplies both arithmetic primitives. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field

theorem combSecond_native
    (X PreviousSlope PreviousWindowX PreviousWindowY WindowX WindowY FirstWindowY Lambda : List.Vector F 8)
    (raw pieces : List.Vector F 24)
    (hr : ∀ i : Fin 8, RangeCheck 11 (pieces.get ⟨3 * i.val, by omega⟩) ∧
      RangeCheck 11 (pieces.get ⟨3 * i.val + 1, by omega⟩) ∧
      RangeCheck 10 (pieces.get ⟨3 * i.val + 2, by omega⟩))
    (hLambda : ∀ i : Fin 8, Lambda.get i =
      pieces.get ⟨3 * i.val, by omega⟩ + pieces.get ⟨3 * i.val + 1, by omega⟩ * 2048 +
      pieces.get ⟨3 * i.val + 2, by omega⟩ * 4194304 - 2147483648)
    (k : List.Vector (List.Vector F 8) 2 → Prop)
    (hs : CheckPolynomial_48_hd6f972c2 (chainCompositionSlopeInput Lambda X PreviousSlope PreviousWindowX WindowX WindowY PreviousWindowY))
    (hn : Lazy_24_h33616364 (chainCompositionLazyInput Lambda X WindowX)
      (fun out => k (out ::ᵥ Lambda ::ᵥ List.Vector.nil))) :
    CombChainStep_8_8_8_8_8_8_8_hd0a2e1d5 X PreviousSlope PreviousWindowX PreviousWindowY WindowX WindowY FirstWindowY k := by
  have h0 := hLambda (0 : Fin 8)
  have h1 := hLambda (1 : Fin 8)
  have h2 := hLambda (2 : Fin 8)
  have h3 := hLambda (3 : Fin 8)
  have h4 := hLambda (4 : Fin 8)
  have h5 := hLambda (5 : Fin 8)
  have h6 := hLambda (6 : Fin 8)
  have h7 := hLambda (7 : Fin 8)
  change Lambda.get 0 = pieces.get 0 + pieces.get 1 * 2048 + pieces.get 2 * 4194304 - 2147483648 at h0
  change Lambda.get 1 = pieces.get 3 + pieces.get 4 * 2048 + pieces.get 5 * 4194304 - 2147483648 at h1
  change Lambda.get 2 = pieces.get 6 + pieces.get 7 * 2048 + pieces.get 8 * 4194304 - 2147483648 at h2
  change Lambda.get 3 = pieces.get 9 + pieces.get 10 * 2048 + pieces.get 11 * 4194304 - 2147483648 at h3
  change Lambda.get 4 = pieces.get 12 + pieces.get 13 * 2048 + pieces.get 14 * 4194304 - 2147483648 at h4
  change Lambda.get 5 = pieces.get 15 + pieces.get 16 * 2048 + pieces.get 17 * 4194304 - 2147483648 at h5
  change Lambda.get 6 = pieces.get 18 + pieces.get 19 * 2048 + pieces.get 20 * 4194304 - 2147483648 at h6
  change Lambda.get 7 = pieces.get 21 + pieces.get 22 * 2048 + pieces.get 23 * 4194304 - 2147483648 at h7
  unfold CombChainStep_8_8_8_8_8_8_8_hd0a2e1d5
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.sub, exists_eq_left]
  refine ⟨raw, pieces, (hr 0).1, (hr 0).2.1, (hr 0).2.2, (hr 1).1, (hr 1).2.1, (hr 1).2.2, (hr 2).1, (hr 2).2.1, (hr 2).2.2, (hr 3).1, (hr 3).2.1, (hr 3).2.2, (hr 4).1, (hr 4).2.1, (hr 4).2.2, (hr 5).1, (hr 5).2.1, (hr 5).2.2, (hr 6).1, (hr 6).2.1, (hr 6).2.2, (hr 7).1, (hr 7).2.1, (hr 7).2.2, ?_, ?_⟩
  · simp only [mul_one, zero_add]
    rw [← h0, ← h1, ← h2, ← h3, ← h4, ← h5, ← h6, ← h7]
    simpa only [chainCompositionSlopeInput, sub_eq_add_neg, mul_neg_one] using hs
  · simp only [mul_one, zero_add]
    rw [← h0, ← h1, ← h2, ← h3, ← h4, ← h5, ← h6, ← h7]
    simpa only [chainCompositionLazyInput, vec8_eta] using hn

end ZolanaVE.P256.Completeness
