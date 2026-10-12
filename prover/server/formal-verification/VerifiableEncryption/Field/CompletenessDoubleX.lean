import VerifiableEncryption.Field.CompletenessReducedHints
import VerifiableEncryption.Field.CompletenessUnifiedX
import VerifiableEncryption.Field.AllInstances

namespace ZolanaVE.Field

open ZolanaVE.EmcurveChecks

def reducedInput16 (L : List.Vector F 16) : List (List F) :=
  [[L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7],
   [L.get 8, L.get 9, L.get 10, L.get 11, L.get 12, L.get 13, L.get 14, L.get 15]]

theorem doubleX_check_of_model (L : List.Vector F 16) (k : List.Vector F 8 → Prop)
    (h : CheckPolynomial.circuit basis cert_h0c8d6bae (reducedInput16 L)
      (LookupCheck RangeCheck 11) (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) :
    CheckPolynomial_16_h0c8d6bae L k := by
  obtain ⟨w⟩ := reducedHintVectors_of_model cert_h0c8d6bae (reducedInput16 L)
    3 4 36 (by decide) (by decide) rfl rfl rfl rfl rfl rfl rfl k h
  let pr := w.pr
  let pq := w.pq
  let pc := w.pc
  let env : ℕ → F := fun i =>
    [L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7,
     L.get 8, L.get 9, L.get 10, L.get 11, L.get 12, L.get 13, L.get 14, L.get 15,
     pr.get 0, pr.get 1, pr.get 2, pr.get 3, pr.get 4, pr.get 5, pr.get 6, pr.get 7,
     pr.get 8, pr.get 9, pr.get 10, pr.get 11, pr.get 12, pr.get 13, pr.get 14, pr.get 15,
     pr.get 16, pr.get 17, pr.get 18, pr.get 19, pr.get 20, pr.get 21, pr.get 22, pr.get 23].getD i 0
  let pxs : List (List Ex) :=
    ([[0, 1, 2, 3, 4, 5, 6, 7], [8, 9, 10, 11, 12, 13, 14, 15]] : List (List ℕ)).map
      (fun is => is.map Ex.atom)
  let prp := ([16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39] : List ℕ).map Ex.atom
  let prr := eLimbsOfPieces 11 widths8 prp
  have hxs : evalLE pxs env = reducedInput16 L := rfl
  have hprp : evalE env prp = pr.toList := by
    rw [evalE_atoms]
    obtain ⟨ps, hl⟩ := pr
    match ps, hl with
    | [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11,
        a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23], _ => rfl
  have hprr : evalE env prr = limbsOfPieces 11 widths8 pr.toList := by
    rw [evalE_eLimbsOfPieces, hprp]
  let eq := eFoldQuotient basis cert_h0c8d6bae pxs prr
  let er := eResidual basis cert_h0c8d6bae pxs prr [] eq
  let ec := eCarry er ⟨0, 2, 36,
    16662651760482593750343275155358532940078388361286693648211298903031153094221⟩ .zero
  have hQref : (Ex.add eq (.lit 31138512913)).eval env = composeValue 11 pq.toList := by
    rw [Ex.eval]
    change (eFoldQuotient basis cert_h0c8d6bae pxs prr).eval env + 31138512913 = _
    rw [eval_eFoldQuotient, hxs, hprr]
    exact w.quotientValue
  have hCref : (Ex.add ec (.lit (2 ^ 36))).eval env = composeValue 11 pc.toList := by
    have he : ec.eval env = reducedCarry cert_h0c8d6bae (reducedInput16 L) pr := by
      simp only [ec, eCarry, Ex.eval, eval_eSumRange, eval_ePow32,
        er, eval_eResidual, eq, eval_eFoldQuotient, hxs, hprr, evalE, List.map_nil]
      rfl
    rw [Ex.eval, he]
    exact w.carryValue
  unfold CheckPolynomial_16_h0c8d6bae CheckPolynomial_16_h0c8d6bae_p1
    CheckPolynomial_16_h0c8d6bae_p2 CheckPolynomial_16_h0c8d6bae_p3 CheckPolynomial_16_h0c8d6bae_p4
  simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8,
    GatesDef.add, GatesDef.mul, GatesDef.eq, exists_eq_left]
  have hr := w.remainderRanges
  have hq := w.quotientRanges
  have hc := w.carryRanges
  refine ⟨pr, (hr 0).1, (hr 0).2.1, (hr 0).2.2,
    (hr 1).1, (hr 1).2.1, (hr 1).2.2,
    (hr 2).1, (hr 2).2.1, (hr 2).2.2,
    (hr 3).1, (hr 3).2.1, (hr 3).2.2,
    (hr 4).1, (hr 4).2.1, (hr 4).2.2,
    (hr 5).1, (hr 5).2.1, (hr 5).2.2,
    (hr 6).1, (hr 6).2.1, (hr 6).2.2,
    (hr 7).1, (hr 7).2.1, (hr 7).2.2,
    pq, hq.1, hq.2.1, hq.2.2.1, hq.2.2.2, ?_,
    pc, hc.1, hc.2.1, hc.2.2.1, hc.2.2.2, ?_, ?_⟩
  · convert hQref using 1
    · symm; ex_refl
    · obtain ⟨ps, hl⟩ := pq
      match ps, hl with | [a, b, c, d], _ => norm_num [composeValue, evalAt] <;> ring
  · convert hCref using 1
    · symm; ex_refl
    · obtain ⟨ps, hl⟩ := pc
      match ps, hl with | [a, b, c, d], _ => norm_num [composeValue, evalAt] <;> ring
  · simpa [remainder24_output] using w.continuation

theorem doubleX_quotient_lower :
    foldedMagnitude basis cert_h0c8d6bae + (cert_h0c8d6bae.m : ℤ) - 1 ≤
      (cert_h0c8d6bae.offset : ℤ) * cert_h0c8d6bae.m := by decide +kernel

theorem doubleX_quotient_upper :
    foldedMagnitude basis cert_h0c8d6bae <
      ((2 : ℤ) ^ cert_h0c8d6bae.quotientBits - cert_h0c8d6bae.offset) * cert_h0c8d6bae.m := by
  decide +kernel

theorem doubleX_carry_capacity :
    CarryCapacity (cert_h0c8d6bae.residualBound basis) cert_h0c8d6bae.positions
      cert_h0c8d6bae.carryPositions cert_h0c8d6bae.groups 0 none := by
  change CarryCapacity (cert_h0c8d6bae.residualBound basis) 8 2
    [⟨0, 2, 36, 16662651760482593750343275155358532940078388361286693648211298903031153094221⟩] 0 none
  apply CarryCapacity.cons
  · rfl
  · norm_num
  · norm_num
  · norm_num
  · reduce_mod_char; norm_num
  · decide +kernel
  · exact CarryCapacity.nil _

theorem doubleX_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es cert_h0c8d6bae.elems) (L : List.Vector F 16)
    (hxs : limbLists es = reducedInput16 L)
    (hl : ∀ bits value : ℕ, 2 ≤ bits → bits ≤ 11 → value < 2 ^ bits → RangeCheck bits (value : F))
    (k : List.Vector F 8 → Prop)
    (hk : k (natLimbVector8 ((foldedValue basis cert_h0c8d6bae es % (cert_h0c8d6bae.m : ℤ)).toNat))) :
    CheckPolynomial_16_h0c8d6bae L k := by
  apply doubleX_check_of_model L k
  rw [← hxs]
  apply foldedEval_complete basis cert_h0c8d6bae basis_sound cert_h0c8d6bae_sound
    rfl rfl rfl rfl (by norm_num [cert_h0c8d6bae]) doubleX_quotient_lower
    doubleX_quotient_upper doubleX_carry_capacity hl es hb
  refine ⟨natLimbVector8 _, ?_, hk⟩
  rw [natLimbVector8_list]

end ZolanaVE.Field
