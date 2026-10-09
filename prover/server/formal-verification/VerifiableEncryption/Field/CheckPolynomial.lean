import VerifiableEncryption.Field.Layout
import VerifiableEncryption.Field.Interval

/-!
Generic model of `Field.checkPolynomial` and `Field.Lazy`
(`emfield/arithmetic.go`).

A check is described by certificate parameters that `ExtractEmcurveChecks`
records at compile time (`PlainCheckParams`, `LazyParams`), plus the matrices
shared by every check over the BN254 scalar field (`BasisParams`).
`CheckPolynomial.circuit` restates the constraints the Go code emits for one
check over the native values of its input limbs, and `sound` recomputes the
compile-time bounds the soundness argument relies on. The statements of
`checkPolynomial_eval_sound`, `checkPolynomial_assertZero_sound` and
`lazy_sound` are the contract the curve layer builds on.

Layout decisions mirrored from Go:
* limbs have 32 bits, `limbCount = 8` limbs per reduced element;
* evaluation point `k` is `0, 1, -1, 2, -2, …` (`evalPoint`);
* a product of two full-width elements over a folding modulus goes through
  the CRT basis when one exists, every other product of two or more
  factors through the inverse Vandermonde matrix of its degree;
* the folded path derives the quotient from the native equation and range
  checks it as one value; the general path hints quotient limbs.
-/

namespace ZolanaVE.Field

open ZolanaProver (F Order)

def limbCount : ℕ := 8

structure TermC where
  coef : ℤ
  factors : List ℕ
deriving Inhabited, Repr

structure ElemC where
  lo : List ℤ
  hi : List ℤ
  vlo : ℤ
  vhi : ℤ
deriving Inhabited, Repr

structure CarryGroup where
  start : ℕ
  stop : ℕ
  carryBits : ℕ
deriving Inhabited, Repr

/-- Matrices shared by every check over the native field. `foldRows[i]` are
the eight balanced digits of `2^(32 i) mod foldModulus`; `vinv` maps a degree
`d` to the `(d+1)×(d+1)` inverse Vandermonde matrix over `ℤ/Order` for the
points `evalPoint 0..d`; `crtForms`/`crtCombine` are the CRT evaluation forms
and recombination rows of `crt.go` (empty when no basis exists). -/
structure BasisParams where
  foldModulus : ℕ
  foldRows : List (List ℤ)
  vinv : List (ℕ × List (List ℕ))
  crtForms : List (List ℕ)
  crtCombine : List (List ℕ)
deriving Inhabited, Repr

/-- The polynomial expression a check or a lazy element is built from. -/
structure PolyShape where
  elems : List ElemC
  terms : List TermC
  degree : ℕ
  fold : Bool
  useCrt : Bool
deriving Inhabited, Repr

structure PlainCheckParams extends PolyShape where
  m : ℕ
  modulusLimbs : List ℕ
  pieceBits : ℕ
  withResult : Bool
  resultWidths : List ℕ
  positions : ℕ
  quotientBits : ℕ
  quotientWidths : List ℕ
  offset : ℕ
  offsetLimbs : List ℕ
  remainderMax : ℕ
  carryPositions : ℕ
  groups : List CarryGroup
  checkTop : Bool
deriving Inhabited, Repr

structure LazyParams extends PolyShape where
  m : ℕ
  outLo : List ℤ
  outHi : List ℤ
  outVlo : ℤ
  outVhi : ℤ
deriving Inhabited, Repr

/-! ### Shared definitions -/

def evalPoint (k : ℕ) : ℤ :=
  if k = 0 then 0 else if k % 2 = 1 then (((k + 1) / 2 : ℕ) : ℤ) else -(((k / 2 : ℕ)) : ℤ)

def PolyShape.elem (s : PolyShape) (f : ℕ) : ElemC := s.elems.getD f default

def PolyShape.nLimbs (s : PolyShape) (f : ℕ) : ℕ := (s.elem f).lo.length

def PolyShape.termDegree (s : PolyShape) (t : TermC) : ℕ :=
  (t.factors.map fun f => s.nLimbs f - 1).sum

/-- `foldedForms` sends a term through the CRT basis exactly when this holds. -/
def PolyShape.isCrtTerm (s : PolyShape) (t : TermC) : Bool :=
  s.fold && s.useCrt && t.factors.length == 2 && t.factors.all (fun f => s.nLimbs f == limbCount)

def BasisParams.vinvAt (b : BasisParams) (d i k : ℕ) : ℕ :=
  (((b.vinv.lookup d).getD []).getD i []).getD k 0

def BasisParams.foldAt (b : BasisParams) (i j : ℕ) : ℤ := (b.foldRows.getD i []).getD j 0

def BasisParams.formAt (b : BasisParams) (k i : ℕ) : ℕ := (b.crtForms.getD k []).getD i 0

def BasisParams.combineAt (b : BasisParams) (j k : ℕ) : ℕ := (b.crtCombine.getD j []).getD k 0

def sumRange {α : Type*} [AddCommMonoid α] (n : ℕ) (f : ℕ → α) : α :=
  ((List.range n).map f).sum

/-! ### Native values of the linear forms (`foldedForms`) -/

section Native

variable (b : BasisParams) (s : PolyShape) (xs : List (List F))

def limbsOf (f : ℕ) : List F := xs.getD f []

/-- Contribution of one term to `coefForms[i]`. -/
def termCoefVal (t : TermC) (i : ℕ) : F :=
  match t.factors with
  | [] => if i = 0 then (t.coef : F) else 0
  | [f] => (t.coef : F) * (limbsOf xs f).getD i 0
  | _ =>
    if s.isCrtTerm t then 0
    else
      let d := s.termDegree t
      if i ≤ d then
        sumRange (d + 1) fun k =>
          (t.coef : F) * (b.vinvAt d i k : F) *
            (t.factors.map fun f => evalAt (limbsOf xs f) ((evalPoint k : ℤ) : F)).prod
      else 0

def coefVal (i : ℕ) : F := (s.terms.map fun t => termCoefVal b s xs t i).sum

def crtVal (j : ℕ) : F :=
  (s.terms.map fun t =>
    if s.isCrtTerm t then
      let x := limbsOf xs (t.factors.getD 0 0)
      let y := limbsOf xs (t.factors.getD 1 0)
      sumRange b.crtForms.length fun k =>
        (t.coef : F) * (b.combineAt j k : F) *
          (lin (fun i => (b.formAt k i : F)) x * lin (fun i => (b.formAt k i : F)) y)
    else 0).sum

/-- Native value of `expressionForm(j)`. -/
def exprVal (j : ℕ) : F :=
  if s.fold then
    sumRange (s.degree + 1) (fun i => (b.foldAt i j : F) * coefVal b s xs i) + crtVal b s xs j
  else if j ≤ s.degree then coefVal b s xs j
  else 0

end Native

/-! ### `checkPolynomial` constraints -/

def pow32 (j : ℕ) : F := (2 : F) ^ (32 * j)

/-- The carry loop of step 7, in continuation-passing style like the extracted
gadgets: each group divides its weighted residual sum plus the incoming carry
by `2^(32·len)` and range checks the shifted carry. -/
def carryChain (res : ℕ → F) (rc : ℕ → F → Prop) : List CarryGroup → F → (F → Prop) → Prop
  | [], carry, k => k carry
  | g :: gs, carry, k =>
    let c' := (sumRange (g.stop - g.start) (fun t => res (g.start + t) * pow32 t) + carry) *
      (pow32 (g.stop - g.start))⁻¹
    rc (g.carryBits + 1) (c' + (2 : F) ^ g.carryBits) ∧ carryChain res rc gs c' k

namespace CheckPolynomial

variable (b : BasisParams) (c : PlainCheckParams) (xs : List (List F))

def modLimb (j : ℕ) : F := (c.modulusLimbs.getD j 0 : F)

/-- Quotient read from the native equation on the folded path. -/
def foldQuotient (r : List F) : F :=
  (sumRange limbCount (fun j => exprVal b c.toPolyShape xs j * pow32 j) -
    sumRange limbCount (fun j => r.getD j 0 * pow32 j)) * (c.m : F)⁻¹

/-- Native value of `residualForm(pos)`. -/
def residual (r ql : List F) (kq : F) (pos : ℕ) : F :=
  exprVal b c.toPolyShape xs pos - r.getD pos 0 -
    (if c.fold then (if pos < limbCount then kq * modLimb c pos else 0)
     else sumRange ql.length (fun a =>
       if a ≤ pos ∧ pos - a < limbCount then
         (ql.getD a 0 - (c.offsetLimbs.getD a 0 : F)) * modLimb c (pos - a)
       else 0))

/-- The constraints `checkPolynomial` emits, over the native values of the
input limbs `xs` (one list per distinct element, in first-use order). Hinted
remainder and quotient pieces are existential; `rc` is `RangeChecker.Check`. -/
def circuit (rc : ℕ → F → Prop) (k : Option (List F) → Prop) : Prop :=
  ∃ rp qp : List F,
    (if c.withResult then PiecesOk rc c.pieceBits c.resultWidths rp else rp = []) ∧
    (if c.fold then qp = [] else PiecesOk rc c.pieceBits c.quotientWidths qp) ∧
    let r := if c.withResult then limbsOfPieces c.pieceBits c.resultWidths rp else []
    let ql := if c.fold then [] else limbsOfPieces c.pieceBits c.quotientWidths qp
    let kq := foldQuotient b c xs r
    let res := residual b c xs r ql kq
    (c.fold = true → rc c.quotientBits (kq + (c.offset : F))) ∧
    (c.fold = false ∧ c.checkTop = false →
      sumRange c.positions (fun pos => res pos * pow32 pos) = 0) ∧
    carryChain res rc c.groups 0 (fun carry =>
      (c.checkTop = true → res c.carryPositions + carry = 0) ∧
      k (if c.withResult then some r else none))

end CheckPolynomial

/-- `Field.Lazy`: no constraints, the limbs are the folded expression forms. -/
def Lazy.circuit (b : BasisParams) (c : LazyParams) (xs : List (List F)) (k : List F → Prop) : Prop :=
  k ((List.range limbCount).map (exprVal b c.toPolyShape xs))

/-! ### Certificate checks -/

def ElemC.absLimbs (e : ElemC) : List ℤ := List.zipWith (fun l h => max |l| |h|) e.lo e.hi

def BasisParams.sound (b : BasisParams) : Bool :=
  decide (0 < b.foldModulus) &&
  b.foldRows.length.fold (fun i _ acc => acc &&
    ((b.foldRows.getD i []).length == limbCount) &&
    ((recompose (b.foldRows.getD i []) - 2 ^ (32 * i)) % (b.foldModulus : ℤ) == 0)) true &&
  b.vinv.all (fun ⟨d, v⟩ =>
    v.length == d + 1 && v.all (fun row => row.length == d + 1) &&
    (List.range (d + 1)).all fun i => (List.range (d + 1)).all fun i' =>
      (sumRange (d + 1) (fun k => ((b.vinvAt d i k : ℤ) * (evalPoint k ^ i' % (Order : ℤ))))) %
        (Order : ℤ) == if i = i' then 1 else 0) &&
  (b.crtForms.isEmpty ||
    (b.crtForms.all (fun row => row.length == limbCount) &&
     b.crtCombine.length == limbCount &&
     b.crtCombine.all (fun row => row.length == b.crtForms.length) &&
     decide (2 * limbCount - 2 < b.foldRows.length) &&
     (List.range limbCount).all fun j => (List.range limbCount).all fun a =>
       (List.range limbCount).all fun a' =>
         (sumRange b.crtForms.length (fun k =>
           (b.combineAt j k : ℤ) * b.formAt k a * b.formAt k a') - b.foldAt (a + a') j) %
           (Order : ℤ) == 0))

namespace PolyShape

variable (s : PolyShape)

/-- `coefficientBounds`: `∑ |coef| ∏ limbAbs` coefficientwise. -/
def coefBounds : List ℤ :=
  polySum (s.terms.map fun t => termPoly |t.coef| (t.factors.map fun f => (s.elem f).absLimbs))

/-- `foldedBounds[j]` (`degree + 1` fold rows). -/
def foldedBound (b : BasisParams) (j : ℕ) : ℤ :=
  sumRange (s.degree + 1) fun i => |b.foldAt i j| * (s.coefBounds).getD i 0

/-- Structural conditions shared by checks and lazy elements. -/
def shapeSound (b : BasisParams) (m : ℕ) : Bool :=
  s.elems.all (fun e => e.lo.length == e.hi.length && !e.lo.isEmpty) &&
  s.terms.all (fun t => t.factors.all (· < s.elems.length) && decide (s.termDegree t ≤ s.degree)) &&
  (!s.fold || (m == b.foldModulus && decide (s.degree < b.foldRows.length))) &&
  (!s.useCrt || !b.crtForms.isEmpty) &&
  s.terms.all (fun t => t.factors.length < 2 || s.isCrtTerm t ||
    (b.vinv.lookup (s.termDegree t)).isSome)

end PolyShape

namespace PlainCheckParams

variable (c : PlainCheckParams)

/-- `max(offset, 2^bits - 1 - offset)`: bound on a shifted quotient. -/
def shiftedBound (offset bits : ℕ) : ℤ := max (offset : ℤ) (2 ^ bits - 1 - offset)

def quotientMagnitude : ℤ := shiftedBound c.offset c.quotientBits

/-- Bound on `|quotient limb a|` multiplying `modulusLimbs` in the residual. -/
def quotientLimbBound (a : ℕ) : ℤ :=
  if c.fold then c.quotientMagnitude
  else shiftedBound (c.offsetLimbs.getD a 0) (c.quotientWidths.getD a 0)

def quotientLimbCount : ℕ := if c.fold then 1 else c.quotientWidths.length

/-- `residualBounds[pos]`. -/
def residualBound (b : BasisParams) (pos : ℕ) : ℤ :=
  (if c.fold then c.toPolyShape.foldedBound b pos else (c.coefBounds).getD pos 0) +
  (if c.withResult then 2 ^ (c.resultWidths.getD pos 0) - 1 else 0) +
  sumRange c.quotientLimbCount (fun a =>
    if a ≤ pos ∧ pos - a < limbCount then c.quotientLimbBound a * c.modulusLimbs.getD (pos - a) 0
    else 0)

/-- Integer bound on the whole residual `∑ residual_j 2^(32 j)`. -/
def residualMagnitude (b : BasisParams) : ℤ :=
  (if c.fold then sumRange limbCount (fun j => c.toPolyShape.foldedBound b j * 2 ^ (32 * j))
   else
     let bounds := fun f => ((c.elem f).vlo, (c.elem f).vhi)
     let lo := (c.terms.map fun t => (termRange bounds t.coef t.factors).1).sum
     let hi := (c.terms.map fun t => (termRange bounds t.coef t.factors).2).sum
     max |lo| |hi|) +
  (if c.withResult then (c.remainderMax : ℤ) else 0) +
  c.quotientMagnitude * c.m

/-- Carry-group walk: the groups tile `[0, carryPositions)`, and every group
lifts, i.e. its bound plus the carry range stays below the native modulus. The
result is the carry width entering the top position (`none` before any group). -/
def groupsSound (b : BasisParams) : List CarryGroup → ℕ → Option ℕ → Option (Option ℕ)
  | [], pos, prev => if pos = c.carryPositions then some prev else none
  | g :: gs, pos, prev =>
    let carryIn : ℤ := match prev with | none => 0 | some cb => 2 ^ cb
    let len := g.stop - g.start
    let bound := carryIn + sumRange len (fun t => c.residualBound b (g.start + t) * 2 ^ (32 * t))
    if g.start = pos ∧ g.start < g.stop ∧ g.carryBits + 1 ≤ 253 ∧
        bound + 2 ^ (32 * len + g.carryBits) < (Order : ℤ) then
      groupsSound b gs g.stop (some g.carryBits)
    else none

def sound (b : BasisParams) : Bool :=
  c.toPolyShape.shapeSound b c.m &&
  decide (0 < c.m) && c.m % Order != 0 &&
  c.modulusLimbs.length == limbCount &&
  recompose (c.modulusLimbs.map (fun l => (l : ℤ))) == c.m &&
  decide (0 < c.pieceBits) && decide (c.pieceBits ≤ 253) &&
  c.resultWidths.length == limbCount &&
  c.resultWidths.all (· ≤ 32) &&
  (!c.withResult || decide (recompose (c.resultWidths.map fun w => (2 : ℤ) ^ w - 1) ≤ c.remainderMax)) &&
  (if c.fold then
    c.positions == limbCount && decide (c.quotientBits ≤ 253)
   else
    c.quotientWidths.all (· ≤ 32) &&
    c.offsetLimbs.length == c.quotientWidths.length &&
    recompose (c.offsetLimbs.map (fun l => (l : ℤ))) == c.offset &&
    decide (recompose (c.quotientWidths.map fun w => (2 : ℤ) ^ w - 1) ≤ 2 ^ c.quotientBits - 1) &&
    decide (c.degree < c.positions) && decide (limbCount ≤ c.positions) &&
    decide (c.quotientWidths.length + limbCount ≤ c.positions + 1)) &&
  decide (c.carryPositions < c.positions) &&
  (match c.groupsSound b c.groups 0 none with
   | none => false
   | some prev =>
     if c.checkTop then
       c.carryPositions + 1 == c.positions &&
       decide (c.residualBound b c.carryPositions +
         (match prev with | none => 0 | some cb => 2 ^ cb) < (Order : ℤ))
     else
       decide (c.residualMagnitude b < (Order : ℤ) * 2 ^ (32 * c.carryPositions)))

end PlainCheckParams

namespace LazyParams

variable (c : LazyParams) (b : BasisParams)

/-- Coefficient intervals of the lazy expression (`coefficientMin/Max`). -/
def coefInterval : List ℤ × List ℤ :=
  c.terms.foldl (fun acc t =>
    let p := t.factors.foldl (fun p f => polyMulIv p.1 p.2 (c.elem f).lo (c.elem f).hi)
      ([t.coef], [t.coef])
    (polyAdd acc.1 p.1, polyAdd acc.2 p.2)) ([], [])

/-- Limb interval `j` of the folded lazy element (sign-split fold). -/
def limbInterval (j : ℕ) : ℤ × ℤ :=
  let ci := c.coefInterval
  (sumRange ci.1.length (fun i =>
      let f := b.foldAt i j
      if 0 ≤ f then f * ci.1.getD i 0 else f * ci.2.getD i 0),
   sumRange ci.1.length (fun i =>
      let f := b.foldAt i j
      if 0 ≤ f then f * ci.2.getD i 0 else f * ci.1.getD i 0))

def sound : Bool :=
  c.toPolyShape.shapeSound b c.m && c.fold &&
  c.coefInterval.1.length == c.degree + 1 &&
  c.outLo.length == limbCount && c.outHi.length == limbCount &&
  (List.range limbCount).all (fun j =>
    c.outLo.getD j 0 == (c.limbInterval b j).1 && c.outHi.getD j 0 == (c.limbInterval b j).2) &&
  c.outVlo == recompose c.outLo && c.outVhi == recompose c.outHi

end LazyParams

/-! ### Statements -/

/-- Inputs carry exactly the bounds the certificate was computed from. -/
def ElemsMatch (es : List (Σ w, ElemVal w)) (cs : List ElemC) : Prop :=
  List.Forall₂ (fun e c => e.2.lo.toList = c.lo ∧ e.2.hi.toList = c.hi ∧ e.2.vlo = c.vlo ∧
    e.2.vhi = c.vhi) es cs

/-- `∑ terms coef * ∏ factors value`. -/
def PolyShape.exprValue (s : PolyShape) (vals : List ℤ) : ℤ :=
  (s.terms.map fun t => t.coef * (t.factors.map fun f => vals.getD f 0).prod).sum

def values (es : List (Σ w, ElemVal w)) : List ℤ := es.map fun e => e.2.value

def limbLists (es : List (Σ w, ElemVal w)) : List (List F) := es.map fun e => e.2.limbs.toList

theorem checkPolynomial_eval_sound (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true) (hres : c.withResult = true)
    {rc : ℕ → F → Prop} (hrc : RangeSound rc)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {k : Option (List F) → Prop} (h : CheckPolynomial.circuit b c (limbLists es) rc k) :
    ∃ r : ElemVal limbCount,
      r.lo.toList = List.replicate limbCount 0 ∧
      r.hi.toList = c.resultWidths.map (fun w => (2 : ℤ) ^ w - 1) ∧
      r.vlo = 0 ∧ r.vhi = recompose (c.resultWidths.map fun w => (2 : ℤ) ^ w - 1) ∧
      k (some r.limbs.toList) ∧
      r.value ≡ c.exprValue (values es) [ZMOD c.m] := by
  sorry

theorem checkPolynomial_assertZero_sound (b : BasisParams) (c : PlainCheckParams)
    (hbs : b.sound = true) (hc : c.sound b = true) (hres : c.withResult = false)
    {rc : ℕ → F → Prop} (hrc : RangeSound rc)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {k : Option (List F) → Prop} (h : CheckPolynomial.circuit b c (limbLists es) rc k) :
    k none ∧ c.exprValue (values es) ≡ 0 [ZMOD c.m] := by
  sorry

theorem lazy_sound (b : BasisParams) (c : LazyParams)
    (hbs : b.sound = true) (hc : c.sound b = true)
    (es : List (Σ w, ElemVal w)) (hb : ElemsMatch es c.elems)
    {k : List F → Prop} (h : Lazy.circuit b c (limbLists es) k) :
    ∃ e : ElemVal limbCount,
      e.lo.toList = c.outLo ∧ e.hi.toList = c.outHi ∧ e.vlo = c.outVlo ∧ e.vhi = c.outVhi ∧
      k e.limbs.toList ∧
      e.value ≡ c.exprValue (values es) [ZMOD c.m] := by
  sorry

end ZolanaVE.Field
