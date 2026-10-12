import VerifiableEncryption.Field.CompletenessBridgeOutput

/-! Extract the concrete remainder/quotient/carry hint vectors from a folded
single-group reduced-output model. This is a reverse-bridge helper; complete
callers construct the model independently from integer arithmetic. -/

namespace ZolanaVE.Field

private def reducedInverse64 : ℕ :=
  16662651760482593750343275155358532940078388361286693648211298903031153094221

def reducedCarry (c : PlainCheckParams) (xs : List (List F)) (pr : List.Vector F 24) : F :=
  let r := limbsOfPieces 11 widths8 pr.toList
  let q := CheckPolynomial.foldQuotient ZolanaVE.EmcurveChecks.basis c xs r
  let res := CheckPolynomial.residual ZolanaVE.EmcurveChecks.basis c xs r [] q
  (sumRange 2 (fun j => res j * pow32 j) + 0) * (reducedInverse64 : F)

structure ReducedHintVectors (c : PlainCheckParams) (xs : List (List F))
    (lastQ lastC carryBits : ℕ) (k : List.Vector F 8 → Prop) where
  pr : List.Vector F 24
  pq pc : List.Vector F 4
  remainderRanges : ∀ i : Fin 8,
    RangeCheck 11 (pr.get ⟨3 * i.val, by omega⟩) ∧
    RangeCheck 11 (pr.get ⟨3 * i.val + 1, by omega⟩) ∧
    RangeCheck 10 (pr.get ⟨3 * i.val + 2, by omega⟩)
  quotientRanges : RangeCheck 11 (pq.get 0) ∧ RangeCheck 11 (pq.get 1) ∧
    RangeCheck 11 (pq.get 2) ∧ RangeCheck lastQ (pq.get 3)
  carryRanges : RangeCheck 11 (pc.get 0) ∧ RangeCheck 11 (pc.get 1) ∧
    RangeCheck 11 (pc.get 2) ∧ RangeCheck lastC (pc.get 3)
  quotientValue : CheckPolynomial.foldQuotient ZolanaVE.EmcurveChecks.basis c xs
    (limbsOfPieces 11 widths8 pr.toList) + (c.offset : F) = composeValue 11 pq.toList
  carryValue : reducedCarry c xs pr + (2 : F) ^ carryBits = composeValue 11 pc.toList
  continuation : k (remainder24_output pr)

theorem reducedHintVectors_of_model (c : PlainCheckParams) (xs : List (List F))
    (lastQ lastC carryBits : ℕ) (hQ : 2 ≤ lastQ ∧ lastQ ≤ 11) (hC : 2 ≤ lastC ∧ lastC ≤ 11)
    (hfold : c.fold = true) (hwith : c.withResult = true) (hpb : c.pieceBits = 11)
    (hwidths : c.resultWidths = widths8) (hqbits : c.quotientBits = 33 + lastQ)
    (hcbits : carryBits + 1 = 33 + lastC)
    (hgroups : c.groups = [⟨0, 2, carryBits, reducedInverse64⟩])
    (k : List.Vector F 8 → Prop)
    (h : CheckPolynomial.circuit ZolanaVE.EmcurveChecks.basis c xs
      (LookupCheck RangeCheck 11) (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) :
    Nonempty (ReducedHintVectors c xs lastQ lastC carryBits k) := by
  unfold CheckPolynomial.circuit at h
  obtain ⟨rp, qp, hrp, hqp, h⟩ := h
  have hqpNil : qp = [] := by simpa only [hfold, if_true] using hqp
  subst qp
  have hrp' : PiecesOk (LookupCheck RangeCheck 11) 11 widths8 rp := by
    simpa only [hwith, if_true, hpb, hwidths] using hrp
  obtain ⟨pr, hpr, hrange⟩ := remainder24_pieces rp hrp'
  rw [← hpr] at h
  simp only [hwith, hfold, if_true, hpb, hwidths] at h
  let r := limbsOfPieces 11 widths8 pr.toList
  let q := CheckPolynomial.foldQuotient ZolanaVE.EmcurveChecks.basis c xs r
  let res := CheckPolynomial.residual ZolanaVE.EmcurveChecks.basis c xs r [] q
  let carry := (sumRange 2 (fun j => res j * pow32 j) + 0) * (reducedInverse64 : F)
  have hQR : LookupCheck RangeCheck 11 (33 + lastQ) (q + (c.offset : F)) := by
    simpa only [hqbits] using h.1 rfl
  have hrest := h.2.2
  rw [hgroups] at hrest
  change LookupCheck RangeCheck 11 (carryBits + 1) (carry + (2 : F) ^ carryBits) ∧
    (c.checkTop = true → _) ∧ (∃ v : List.Vector F 8, some r = some v.toList ∧ k v) at hrest
  have hCR : LookupCheck RangeCheck 11 (33 + lastC) (carry + (2 : F) ^ carryBits) := by
    simpa only [hcbits] using hrest.1
  obtain ⟨v, hv, hkv⟩ := hrest.2.2
  have hvOut : v = remainder24_output pr := by
    apply List.Vector.toList_injective
    rw [← Option.some.inj hv]
    exact remainder24_output_list pr
  rw [hvOut] at hkv
  obtain ⟨pq, hq0, hq1, hq2, hq3, hqValue⟩ := lookupCheck_four_pieces lastQ hQ _ hQR
  obtain ⟨pc, hc0, hc1, hc2, hc3, hcValue⟩ := lookupCheck_four_pieces lastC hC _ hCR
  exact ⟨⟨pr, pq, pc, hrange, ⟨hq0, hq1, hq2, hq3⟩,
    ⟨hc0, hc1, hc2, hc3⟩, hqValue, hcValue, hkv⟩⟩

end ZolanaVE.Field
