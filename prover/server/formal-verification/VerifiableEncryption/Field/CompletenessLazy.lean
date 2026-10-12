import VerifiableEncryption.Field.AllInstances
import VerifiableEncryption.Field.CompletenessGeneratedLazy_20
import VerifiableEncryption.Circuit.Field3
import VerifiableEncryption.Circuit.Field4
import VerifiableEncryption.Circuit.Field5

/-!
Constructive existence for the actual first fixed-base lazy x-update.
All emitted native gates are functional, so their displayed arithmetic values
give an output before any soundness result is used. Existing bound/congruence
soundness can then attach integer limbs to that concrete output.
-/

namespace ZolanaVE.Field

open ZolanaVE.EmcurveChecks

theorem lazyFirst_witness (L : List.Vector F 24) :
    ∃ output : List.Vector F 8, Lazy_24_h4ef94fb8 L (fun o => o = output) :=
  Lazy_24_h4ef94fb8_witness L

theorem lazyFirst_mono (L : List.Vector F 24) {k j : List.Vector F 8 → Prop}
    (h : Lazy_24_h4ef94fb8 L k) (hm : ∀ o, k o → j o) : Lazy_24_h4ef94fb8 L j :=
  Lazy_24_h4ef94fb8_mono L hm h

/-! The fifty fixed-base lazy x-updates have distinct bound certificate
hashes but identical native bodies. These are definitional equalities between
the actual extracted predicates, not replacement predicates. Read-only source
comparison checked all four native fragments per hash; no circuit ran. -/

theorem lazy_h33616364_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h33616364 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h5d959345_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h5d959345 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h8bca4322_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h8bca4322 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hda13b782_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hda13b782 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h4c46916d_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h4c46916d L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h70433ddf_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h70433ddf L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h8fbed755_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h8fbed755 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_heb19166d_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_heb19166d L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hd5ac7c2a_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hd5ac7c2a L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hdc687f01_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hdc687f01 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h183e6a3f_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h183e6a3f L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hde720dec_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hde720dec L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hca4d82bd_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hca4d82bd L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hb31eb938_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hb31eb938 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h0b39a3e2_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h0b39a3e2 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h81cfec0e_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h81cfec0e L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h77f7514c_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h77f7514c L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hd23c1321_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hd23c1321 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h289d8769_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h289d8769 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hfd15ca5e_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hfd15ca5e L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h6bcb0ecf_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h6bcb0ecf L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h70762eb9_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h70762eb9 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h38e8ac31_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h38e8ac31 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hb9b2a022_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hb9b2a022 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h40955e83_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h40955e83 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hf09a21c7_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hf09a21c7 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h4972f626_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h4972f626 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h677e8427_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h677e8427 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hae8dc535_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hae8dc535 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h0f279e18_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h0f279e18 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h19f9c19c_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h19f9c19c L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h311d38f1_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h311d38f1 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hc65e35fe_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hc65e35fe L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h6ef8b49c_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h6ef8b49c L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hc3ec5671_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hc3ec5671 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hfc273997_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hfc273997 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h96360ee1_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h96360ee1 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h83a415b9_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h83a415b9 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h3ed7df0f_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h3ed7df0f L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h26631a60_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h26631a60 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h8e929349_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h8e929349 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h2fd0ed5d_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h2fd0ed5d L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h6f54b8b1_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h6f54b8b1 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_he088c588_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_he088c588 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_hcc322c7b_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_hcc322c7b L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h4e5489d2_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h4e5489d2 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_he1cc16ce_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_he1cc16ce L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h636a42b5_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h636a42b5 L k = Lazy_24_h4ef94fb8 L k := rfl
theorem lazy_h7e1bb4d8_eq (L : List.Vector F 24) (k : List.Vector F 8 → Prop) : Lazy_24_h7e1bb4d8 L k = Lazy_24_h4ef94fb8 L k := rfl

/-- A bounded integer element and continuation-preserving actual lazy gadget
are constructed. No lazy circuit or desired output existence is assumed. -/
theorem lazyFirst_complete (es : List (Σ w, ElemVal w))
    (hb : ElemsMatch es lazy_h4ef94fb8.elems) (L : List.Vector F 24)
    (hxs : limbLists es =
      [[L.get 0, L.get 1, L.get 2, L.get 3, L.get 4, L.get 5, L.get 6, L.get 7],
       [L.get 8, L.get 9, L.get 10, L.get 11, L.get 12, L.get 13, L.get 14, L.get 15],
       [L.get 16, L.get 17, L.get 18, L.get 19, L.get 20, L.get 21, L.get 22, L.get 23]]) :
    ∃ e : ElemVal 8,
      e.lo.toList = lazy_h4ef94fb8.outLo ∧ e.hi.toList = lazy_h4ef94fb8.outHi ∧
      e.vlo = lazy_h4ef94fb8.outVlo ∧ e.vhi = lazy_h4ef94fb8.outVhi ∧
      (∀ k : List.Vector F 8 → Prop, k e.limbs → Lazy_24_h4ef94fb8 L k) ∧
      e.value ≡ lazy_h4ef94fb8.exprValue (values es) [ZMOD lazy_h4ef94fb8.m] := by
  obtain ⟨output, hactual⟩ := lazyFirst_witness L
  obtain ⟨e, hlo, hhi, hvlo, hvhi, he, hvalue⟩ :=
    Lazy_24_h4ef94fb8_sound es hb L hxs hactual
  refine ⟨e, hlo, hhi, hvlo, hvhi, ?_, hvalue⟩
  intro k hk
  apply lazyFirst_mono L hactual
  intro o ho
  rw [ho, ← he]
  exact hk

/-- Construct a bounded witness for a concrete comb Lazy predicate whose
native body agrees with the first update. The equality is checked separately
for each actual hash; the bound/congruence premise is its existing soundness
theorem, rather than a desired satisfying-witness premise. -/
theorem combLazy_complete (c : LazyParams) (es : List (Σ w, ElemVal w))
    (P : List.Vector F 24 → (List.Vector F 8 → Prop) → Prop)
    (L : List.Vector F 24)
    (hNative : ∀ k, P L k = Lazy_24_h4ef94fb8 L k)
    (hSound : ∀ k, P L k → LazySound c es k) :
    ∃ e : ElemVal 8, e.bnd = ⟨c.outLo, c.outHi, c.outVlo, c.outVhi⟩ ∧
      e.value ≡ c.exprValue (values es) [ZMOD (c.m : ℤ)] ∧
      ∀ k : List.Vector F 8 → Prop, k e.limbs → P L k := by
  obtain ⟨output, hactual⟩ := lazyFirst_witness L
  have hp : P L (fun o => o = output) :=
    (hNative (fun o => o = output)).mpr hactual
  obtain ⟨e, hlo, hhi, hvlo, hvhi, he, hv⟩ := hSound _ hp
  refine ⟨e, ?_, hv, ?_⟩
  · change (⟨e.lo.toList, e.hi.toList, e.vlo, e.vhi⟩ : ElemC) = _
    rw [hlo, hhi, hvlo, hvhi]
  · intro k hk
    rw [hNative k]
    apply lazyFirst_mono L hactual
    intro o ho
    rw [ho, ← he]
    exact hk

end ZolanaVE.Field
