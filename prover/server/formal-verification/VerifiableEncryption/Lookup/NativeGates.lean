import VerifiableEncryption.Lookup.Realization

/-!
Ordinary semantics of the frontend's native field gate program. Arithmetic
outputs are explicitly constrained; unchecked division and inverse have their
different equations. Hints are untrusted existential values. `commit` marks
the exact ordered input list and the point at which its challenge is returned;
the native gates alone impose no cryptographic distribution or binding claim.

This is a source-level frontend API interpretation, not a claim that the
opaque extraction predicates contain the deferred program or that every
backend serialized constraint has already been mechanically refined.
-/

namespace ZolanaVE.Lookup

open scoped Polynomial BigOperators

variable {K : Type*} [Field K]

inductive NativeProgram (K : Type*) where
  | finish
  | add (a b : K) (next : K → NativeProgram K)
  | mul (a b : K) (next : K → NativeProgram K)
  | divUnchecked (numerator denominator : K) (next : K → NativeProgram K)
  | inverse (denominator : K) (next : K → NativeProgram K)
  | batchInverse (size : ℕ) (denominators : Fin size → K)
      (next : (Fin size → K) → NativeProgram K)
  | assertEqual (a b : K) (next : NativeProgram K)
  | hint (size : ℕ) (inputs : List K) (next : (Fin size → K) → NativeProgram K)
  | commit (inputs : List K) (next : K → NativeProgram K)

def NativeProgram.Satisfies : NativeProgram K → Prop
  | .finish => True
  | .add a b next => ∃ out, out = a + b ∧ (next out).Satisfies
  | .mul a b next => ∃ out, out = a * b ∧ (next out).Satisfies
  | .divUnchecked a b next => ∃ out, out * b = a ∧ (next out).Satisfies
  | .inverse b next => ∃ out, out * b = 1 ∧ (next out).Satisfies
  | .batchInverse _ denominators next =>
      ∃ out, (∀ j, out j * denominators j = 1) ∧ (next out).Satisfies
  | .assertEqual a b next => a = b ∧ next.Satisfies
  | .hint _ _ next => ∃ out, (next out).Satisfies
  | .commit _ next => ∃ challenge, (next challenge).Satisfies

@[simp] theorem NativeProgram.satisfies_add (a b : K) (next : K → NativeProgram K) :
    (NativeProgram.add a b next).Satisfies ↔ (next (a + b)).Satisfies := by
  constructor
  · rintro ⟨out, rfl, h⟩; exact h
  · exact fun h => ⟨a + b, rfl, h⟩

@[simp] theorem NativeProgram.satisfies_mul (a b : K) (next : K → NativeProgram K) :
    (NativeProgram.mul a b next).Satisfies ↔ (next (a * b)).Satisfies := by
  constructor
  · rintro ⟨out, rfl, h⟩; exact h
  · exact fun h => ⟨a * b, rfl, h⟩

inductive NativeExpression (K : Type*) where
  | input (value : K)
  | add (a b : NativeExpression K)
  | sub (a b : NativeExpression K)
  | mul (a b : NativeExpression K)

def NativeExpression.value : NativeExpression K → K
  | .input x => x
  | .add a b => a.value + b.value
  | .sub a b => a.value - b.value
  | .mul a b => a.value * b.value

def NativeExpression.emit : NativeExpression K → (K → NativeProgram K) → NativeProgram K
  | .input x, next => next x
  | .add a b, next => a.emit (fun x => b.emit (fun y => .add x y next))
  | .sub a b, next => a.emit (fun x => b.emit (fun y => .add x (-y) next))
  | .mul a b, next => a.emit (fun x => b.emit (fun y => .mul x y next))

theorem NativeExpression.emit_satisfies (e : NativeExpression K) (next : K → NativeProgram K) :
    (e.emit next).Satisfies ↔ (next e.value).Satisfies := by
  induction e generalizing next with
  | input x => rfl
  | add a b ha hb => simp [NativeExpression.emit, NativeExpression.value, ha, hb]
  | sub a b ha hb => simp [NativeExpression.emit, NativeExpression.value, ha, hb, sub_eq_add_neg]
  | mul a b ha hb => simp [NativeExpression.emit, NativeExpression.value, ha, hb]

def emitArray : {n : ℕ} → (Fin n → NativeExpression K) → ((Fin n → K) → NativeProgram K) → NativeProgram K
  | 0, _, next => next Fin.elim0
  | n + 1, es, next => (es 0).emit (fun value =>
      emitArray (fun i : Fin n => es i.succ) (fun tail => next (Fin.cases value tail)))

theorem emitArray_satisfies {n : ℕ} (es : Fin n → NativeExpression K)
    (next : (Fin n → K) → NativeProgram K) :
    (emitArray es next).Satisfies ↔ (next (fun i => (es i).value)).Satisfies := by
  induction n with
  | zero =>
    have hf : (Fin.elim0 : Fin 0 → K) = (fun i => (es i).value) := by
      funext i
      exact Fin.elim0 i
    simp only [emitArray, hf]
  | succ n ih =>
    simp only [emitArray, NativeExpression.emit_satisfies, ih]
    have hf : Fin.cases (es 0).value (fun i : Fin n => (es i.succ).value) =
        (fun i => (es i).value) := by
      funext i
      exact Fin.cases rfl (fun _ => rfl) i
    rw [hf]

def tableDivisions : {n : ℕ} → (Fin n → K) → (Fin n → K) →
    ((Fin n → K) → NativeProgram K) → NativeProgram K
  | 0, _, _, next => next Fin.elim0
  | n + 1, numerators, denominators, next =>
      .divUnchecked (numerators 0) (denominators 0) (fun quotient =>
        tableDivisions (fun i : Fin n => numerators i.succ)
          (fun i => denominators i.succ) (fun tail => next (Fin.cases quotient tail)))

theorem tableDivisions_satisfies {n : ℕ} (numerators denominators : Fin n → K)
    (next : (Fin n → K) → NativeProgram K) :
    (tableDivisions numerators denominators next).Satisfies ↔
      ∃ quotient, (∀ i, quotient i * denominators i = numerators i) ∧ (next quotient).Satisfies := by
  induction n with
  | zero =>
    constructor
    · intro h
      exact ⟨Fin.elim0, (fun i => Fin.elim0 i), h⟩
    · rintro ⟨quotient, _, h⟩
      have he : quotient = Fin.elim0 := by funext i; exact Fin.elim0 i
      simpa only [tableDivisions, he] using h
  | succ n ih =>
    simp only [tableDivisions, NativeProgram.Satisfies, ih]
    constructor
    · rintro ⟨head, hh, tail, ht, hn⟩
      refine ⟨Fin.cases head tail, ?_, hn⟩
      intro i
      exact Fin.cases hh (fun j => ht j) i
    · rintro ⟨quotient, hq, hn⟩
      have he : Fin.cases (quotient 0) (fun i : Fin n => quotient i.succ) = quotient := by
        funext i
        exact Fin.cases rfl (fun _ => rfl) i
      exact ⟨quotient 0, hq 0, (fun i => quotient i.succ), (fun i => hq i.succ), he.symm ▸ hn⟩

def queryInverses : {m : ℕ} → (Fin m → K) → ((Fin m → K) → NativeProgram K) → NativeProgram K
  | 0, _, next => next Fin.elim0
  | m + 1, denominators, next => .inverse (denominators 0) (fun inverse =>
      queryInverses (fun j : Fin m => denominators j.succ)
        (fun tail => next (Fin.cases inverse tail)))

theorem queryInverses_satisfies {m : ℕ} (denominators : Fin m → K)
    (next : (Fin m → K) → NativeProgram K) :
    (queryInverses denominators next).Satisfies ↔
      ∃ inverse, (∀ j, inverse j * denominators j = 1) ∧ (next inverse).Satisfies := by
  induction m with
  | zero =>
    constructor
    · intro h
      exact ⟨Fin.elim0, (fun j => Fin.elim0 j), h⟩
    · rintro ⟨inverse, _, h⟩
      have he : inverse = Fin.elim0 := by funext j; exact Fin.elim0 j
      simpa only [queryInverses, he] using h
  | succ m ih =>
    simp only [queryInverses, NativeProgram.Satisfies, ih]
    constructor
    · rintro ⟨head, hh, tail, ht, hn⟩
      refine ⟨Fin.cases head tail, ?_, hn⟩
      intro j
      exact Fin.cases hh (fun i => ht i) j
    · rintro ⟨inverse, hi, hn⟩
      have he : Fin.cases (inverse 0) (fun j : Fin m => inverse j.succ) = inverse := by
        funext j
        exact Fin.cases rfl (fun _ => rfl) j
      exact ⟨inverse 0, hi 0, (fun j => inverse j.succ), (fun j => hi j.succ), he.symm ▸ hn⟩

/-- Both pinned r1cs/scs batch-inverter builders emit the same per-output
inverse verification equation. Their blueprint/hint optimizes computation,
not the satisfying assignments. This semantic normalization does not trust
any batch-inverse hint output or ignore zero denominators.
-/
theorem batchInverse_iff_queryInverses {m : ℕ} (denominators : Fin m → K)
    (next : (Fin m → K) → NativeProgram K) :
    (NativeProgram.batchInverse m denominators next).Satisfies ↔
      (queryInverses denominators next).Satisfies :=
  (queryInverses_satisfies denominators next).symm

def sumNative : {n : ℕ} → (Fin n → K) → K → (K → NativeProgram K) → NativeProgram K
  | 0, _, accumulator, next => next accumulator
  | n + 1, values, accumulator, next => .add accumulator (values 0) (fun sum =>
      sumNative (fun i : Fin n => values i.succ) sum next)

theorem sumNative_satisfies {n : ℕ} (values : Fin n → K) (accumulator : K)
    (next : K → NativeProgram K) :
    (sumNative values accumulator next).Satisfies ↔
      (next (accumulator + ∑ i, values i)).Satisfies := by
  induction n generalizing accumulator with
  | zero => simp [sumNative]
  | succ n ih =>
    simp only [sumNative, NativeProgram.satisfies_add, ih, Fin.sum_univ_succ]
    rw [add_assoc]

/-- Source table-divide / query-inverse / sum / equality phase, including all
arithmetic used to construct denominator expressions. -/
def nativeLookupCallback {n m : ℕ} (counts : Fin n → K)
    (table : Fin n → NativeExpression K)
    (queries : Fin m → NativeExpression K) : NativeProgram K :=
  emitArray table (fun tableDenominators => emitArray queries (fun queryDenominators =>
    tableDivisions counts tableDenominators (fun tableQuotients =>
      queryInverses queryDenominators (fun inverses =>
        sumNative tableQuotients 0 (fun tableSum =>
          sumNative inverses 0 (fun querySum => .assertEqual tableSum querySum .finish))))))

theorem nativeLookupCallback_certificate {n m : ℕ} (b : Batch K n m) (x : K)
    (table : Fin n → NativeExpression K) (queries : Fin m → NativeExpression K)
    (ht : ∀ i, (table i).value = (b.table i).eval x)
    (hq : ∀ j, (queries j).value = (b.query j).eval x)
    (h : (nativeLookupCallback b.multiplicity table queries).Satisfies) :
    Nonempty (RawGateTrace b x) := by
  simp only [nativeLookupCallback, emitArray_satisfies, tableDivisions_satisfies,
    queryInverses_satisfies, sumNative_satisfies, zero_add, NativeProgram.Satisfies] at h
  obtain ⟨quotient, hquotient, inverse, hinverse, hsum, _⟩ := h
  refine ⟨⟨quotient, inverse, ?_, ?_, hsum⟩⟩
  · intro i
    simpa only [ht i] using hquotient i
  · intro j
    simpa only [hq j] using hinverse j

theorem nativeLookupCallback_of_certificate {n m : ℕ} (b : Batch K n m) (x : K)
    (table : Fin n → NativeExpression K) (queries : Fin m → NativeExpression K)
    (ht : ∀ i, (table i).value = (b.table i).eval x)
    (hq : ∀ j, (queries j).value = (b.query j).eval x)
    (trace : RawGateTrace b x) :
    (nativeLookupCallback b.multiplicity table queries).Satisfies := by
  simp only [nativeLookupCallback, emitArray_satisfies, tableDivisions_satisfies,
    queryInverses_satisfies, sumNative_satisfies, zero_add, NativeProgram.Satisfies]
  refine ⟨trace.tableQuotient, ?_, trace.queryInverse, ?_, trace.sumEquation, trivial⟩
  · intro i
    simpa only [ht i] using trace.tableEquation i
  · intro j
    simpa only [hq j] using trace.queryEquation j

end ZolanaVE.Lookup
