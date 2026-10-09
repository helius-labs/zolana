import VerifiableEncryption.Field.Lazy
import VerifiableEncryption.Field.ExMirror
import VerifiableEncryption.Field.ReflectTactic

/-!
Glue between the extracted check definitions and the generic theorems.

An extracted `CheckPolynomial_<n>_h<key>` or `Lazy_<n>_h<key>` is first shown to
imply the generic constraint system for its certificate (`<name>_mirror` in
`Instances*.lean`); the lemmas here then turn a mirror into the soundness
statement about the extracted definition.
-/

namespace ZolanaVE.Field

theorem lookupCheck_big_of {lookup : ℕ → F → Prop} {pb b : ℕ} (hb : pb < b) {v w x : F} (ps : List F)
    (hc : ComposeOk (SmallCheck lookup) pb b ps) (hvw : v = w) (hwx : w = x) (hx : x = composeValue pb ps) :
    LookupCheck lookup pb b v := by
  unfold LookupCheck; rw [if_neg (by omega)]; exact ⟨ps, hc, hvw.trans (hwx.trans hx)⟩

theorem lookupCheck_small_of {lookup : ℕ → F → Prop} {pb b : ℕ} (hb : 2 ≤ b ∧ b ≤ pb) {v w : F}
    (hvw : v = w) (h : lookup b w) : LookupCheck lookup pb b v := by
  unfold LookupCheck SmallCheck
  rw [if_pos hb.2, if_neg (by omega), if_neg (by omega), hvw]; exact h

theorem lookupCheck_bool_of {lookup : ℕ → F → Prop} {pb : ℕ} (hpb : 1 ≤ pb) {v w : F}
    (hvw : v = w) (h : GatesDef.is_bool w) : LookupCheck lookup pb 1 v := by
  unfold LookupCheck SmallCheck
  rw [if_pos hpb, if_neg (by omega), if_pos rfl, hvw]; exact h

theorem eq_zero_of {v w : F} (hvw : v = w) (h : w = 0) : v = 0 := hvw.trans h

theorem rangeSound_lookup (hl : LookupSound RangeCheck 11) : RangeSound (LookupCheck RangeCheck 11) :=
  lookupCheck_sound (by norm_num) (by norm_num) hl

/-- What an extracted `CheckPolynomial` with a result establishes: a reduced
element with the field's limb bounds, passed to the continuation, congruent to
the expression. -/
def EvalSound (c : PlainCheckParams) (es : List (Σ w, ElemVal w)) (k : List.Vector F 8 → Prop) : Prop :=
  ∃ r : ElemVal limbCount,
    r.lo.toList = List.replicate limbCount 0 ∧
    r.hi.toList = c.resultWidths.map (fun w => (2 : ℤ) ^ w - 1) ∧
    r.vlo = 0 ∧ r.vhi = recompose (c.resultWidths.map fun w => (2 : ℤ) ^ w - 1) ∧
    k r.limbs ∧
    r.value ≡ c.exprValue (values es) [ZMOD c.m]

/-- What an extracted `Lazy` establishes: an element with the certified bounds,
passed to the continuation, congruent to the expression. -/
def LazySound (c : LazyParams) (es : List (Σ w, ElemVal w)) (k : List.Vector F 8 → Prop) : Prop :=
  ∃ e : ElemVal limbCount,
    e.lo.toList = c.outLo ∧ e.hi.toList = c.outHi ∧ e.vlo = c.outVlo ∧ e.vhi = c.outVhi ∧
    k e.limbs ∧
    e.value ≡ c.exprValue (values es) [ZMOD c.m]

theorem eval_instance_sound (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true) (hres : c.withResult = true)
    (hl : LookupSound RangeCheck 11) (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {xs : List (List F)} (hxs : limbLists es = xs) {k : List.Vector F 8 → Prop}
    (hm : CheckPolynomial.circuit b c xs (LookupCheck RangeCheck 11)
      (fun o => ∃ v : List.Vector F 8, o = some v.toList ∧ k v)) :
    EvalSound c es k := by
  rw [← hxs] at hm
  obtain ⟨r, h1, h2, h3, h4, ⟨v, hv, hk⟩, h6⟩ :=
    checkPolynomial_eval_sound b c hbs hc hres (rangeSound_lookup hl) es hb hm
  have : r.limbs = v := List.Vector.toList_injective (Option.some.inj hv)
  exact ⟨r, h1, h2, h3, h4, this ▸ hk, h6⟩

theorem assertZero_instance_sound (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true) (hres : c.withResult = false)
    (hl : LookupSound RangeCheck 11) (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {xs : List (List F)} (hxs : limbLists es = xs)
    (hm : CheckPolynomial.circuit b c xs (LookupCheck RangeCheck 11) (fun _ => True)) :
    c.exprValue (values es) ≡ 0 [ZMOD c.m] := by
  rw [← hxs] at hm
  exact (checkPolynomial_assertZero_sound b c hbs hc hres (rangeSound_lookup hl) es hb hm).2

theorem lazy_instance_sound (b : BasisParams) (c : LazyParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {xs : List (List F)} (hxs : limbLists es = xs) {k : List.Vector F 8 → Prop}
    (hm : Lazy.circuit b c xs (fun o => ∃ v : List.Vector F 8, o = v.toList ∧ k v)) :
    LazySound c es k := by
  rw [← hxs] at hm
  obtain ⟨e, h1, h2, h3, h4, ⟨v, hv, hk⟩, h6⟩ := lazy_sound b c hbs hc es hb hm
  have : e.limbs = v := List.Vector.toList_injective hv
  exact ⟨e, h1, h2, h3, h4, this ▸ hk, h6⟩

end ZolanaVE.Field
