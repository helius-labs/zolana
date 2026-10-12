import VerifiableEncryption.Curve.CompletenessCoordinates
import VerifiableEncryption.Curve.CompletenessGeneratedChainComposition
import VerifiableEncryption.Field.CompletenessBridgeChain
import VerifiableEncryption.Field.CompletenessLazy

/-! Shared comb layouts and Lazy arithmetic, proved before substituting
constructed slope elements. Actual per-hash bounds and predicates stay explicit. -/

namespace ZolanaVE.P256.Completeness

open ZolanaVE.Field ZolanaVE.EmcurveChecks

theorem combSecondSlope_layout (L X L0 PWX PWY WX WY : ElemVal 8) :
    limbLists [⟨8, L⟩, ⟨8, linElem [(1, WX), (-1, X)]⟩, ⟨8, L0⟩,
      ⟨8, linElem [(1, PWX), (-1, X)]⟩, ⟨8, WY⟩, ⟨8, PWY⟩] =
      chainCheckInputs48 (chainCompositionSlopeInput L.limbs X.limbs L0.limbs
        PWX.limbs WX.limbs WY.limbs PWY.limbs) := by
  simp only [limbLists, List.map_cons, List.map_nil]
  rw [vec8_toList L.limbs, vec8_toList (linElem [(1, WX), (-1, X)]).limbs,
    vec8_toList L0.limbs, vec8_toList (linElem [(1, PWX), (-1, X)]).limbs,
    vec8_toList WY.limbs, vec8_toList PWY.limbs]
  simp only [chainCheckInputs48, chainCompositionSlopeInput, linDiff_limb,
    List.Vector.get_cons_zero, List.Vector.get_cons_succ,
    Fin.instOfNat, Fin.ofNat', Fin.coe_ofNat_eq_mod]
  rfl

theorem combLazy_layout (L X WX : ElemVal 8) :
    limbLists [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩] =
      outputCheckInputs (chainCompositionLazyInput L.limbs X.limbs WX.limbs) := by
  simp only [limbLists, List.map_cons, List.map_nil, outputCheckInputs]
  rw [vec8_toList L.limbs, vec8_toList X.limbs, vec8_toList WX.limbs]
  rfl

theorem combLazy_expr (c : LazyParams)
    (hterms : c.terms = [⟨1, [0, 0]⟩, ⟨-1, [1]⟩, ⟨-1, [2]⟩]) (L X WX : ElemVal 8) :
    c.exprValue (values [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]) =
      L.value * L.value - X.value - WX.value := by
  simp [PolyShape.exprValue, values, hterms]
  ring

theorem combLazy_arithmetic (c : LazyParams)
    (hterms : c.terms = [⟨1, [0, 0]⟩, ⟨-1, [1]⟩, ⟨-1, [2]⟩]) (hm : c.m = p)
    (L X WX : ElemVal 8)
    (P : List.Vector F 24 → (List.Vector F 8 → Prop) → Prop)
    (hNative : ∀ k, P (chainCompositionLazyInput L.limbs X.limbs WX.limbs) k =
      Lazy_24_h4ef94fb8 (chainCompositionLazyInput L.limbs X.limbs WX.limbs) k)
    (hSound : ∀ k, P (chainCompositionLazyInput L.limbs X.limbs WX.limbs) k →
      LazySound c [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩] k) :
    ∃ NX : ElemVal 8, NX.bnd = ⟨c.outLo, c.outHi, c.outVlo, c.outVhi⟩ ∧
      NX.value ≡ L.value * L.value - X.value - WX.value [ZMOD p] ∧
      ∀ k : List.Vector F 8 → Prop, k NX.limbs →
        P (chainCompositionLazyInput L.limbs X.limbs WX.limbs) k := by
  obtain ⟨NX, hNX, hv, ha⟩ := combLazy_complete c [⟨8, L⟩, ⟨8, X⟩, ⟨8, WX⟩]
    P (chainCompositionLazyInput L.limbs X.limbs WX.limbs) hNative hSound
  rw [combLazy_expr c hterms L X WX, hm] at hv
  exact ⟨NX, hNX, hv, ha⟩

end ZolanaVE.P256.Completeness
