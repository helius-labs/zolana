import Mathlib

/-!
List polynomials (lowest coefficient first) and the interval arithmetic of
`emfield/bounds.go` and `emfield/arithmetic.go`.

`lin f P = ∑ i, f i * P[i]` is the one functional every argument in the field
layer reduces to: evaluation at a point (`f i = x^i`), folding a coefficient
vector into eight limbs (`f i = fold[i][j]`), interpolation from evaluations
(`f i = ∑ k, vinv[r][k] * x_k^i`) and the CRT product forms.

All definitions are structural on lists so that the kernel evaluates them in
`decide +kernel` certificates.
-/

namespace ZolanaVE.Field

def sumRange {α : Type*} [AddCommMonoid α] (n : ℕ) (f : ℕ → α) : α :=
  ((List.range n).map f).sum

section Generic

variable {R : Type*} [CommRing R]

def polyAdd : List R → List R → List R
  | [], b => b
  | a :: as, [] => a :: as
  | a :: as, b :: bs => (a + b) :: polyAdd as bs

def polyScale (k : R) (a : List R) : List R := a.map (k * ·)

def polyMul : List R → List R → List R
  | [], _ => []
  | a :: as, b => polyAdd (polyScale a b) (0 :: polyMul as b)

def polySum (ps : List (List R)) : List R := ps.foldr polyAdd []

/-- `coef * ∏ ps`, multiplied left to right as `polyMulAbs` does in `checkPolynomial`. -/
def termPoly (coef : R) (ps : List (List R)) : List R := ps.foldl polyMul [coef]

def lin (f : ℕ → R) : List R → R
  | [] => 0
  | p :: ps => f 0 * p + lin (fun i => f (i + 1)) ps

def evalAt (P : List R) (x : R) : R := lin (fun i => x ^ i) P

@[simp] theorem lin_nil (f : ℕ → R) : lin f [] = 0 := rfl

@[simp] theorem lin_cons (f : ℕ → R) (p : R) (ps : List R) :
    lin f (p :: ps) = f 0 * p + lin (fun i => f (i + 1)) ps := rfl

theorem lin_polyAdd (f : ℕ → R) (a b : List R) :
    lin f (polyAdd a b) = lin f a + lin f b := by
  induction a generalizing f b with
  | nil => simp [polyAdd]
  | cons a as ih =>
    cases b with
    | nil => simp [polyAdd]
    | cons b bs => simp [polyAdd, ih]; ring

theorem lin_polyScale (f : ℕ → R) (k : R) (a : List R) :
    lin f (polyScale k a) = k * lin f a := by
  induction a generalizing f with
  | nil => simp [polyScale]
  | cons a as ih =>
    have := ih (fun i => f (i + 1))
    simp only [polyScale, List.map_cons, lin_cons] at this ⊢
    rw [this]; ring

theorem lin_add_fun (f g : ℕ → R) (a : List R) :
    lin (fun i => f i + g i) a = lin f a + lin g a := by
  induction a generalizing f g with
  | nil => simp
  | cons a as ih => simp only [lin_cons, ih (fun i => f (i + 1)) (fun i => g (i + 1))]; ring

theorem lin_mul_fun (f : ℕ → R) (c : R) (a : List R) :
    lin (fun i => f i * c) a = c * lin f a := by
  induction a generalizing f with
  | nil => simp
  | cons a as ih => simp only [lin_cons, ih (fun i => f (i + 1))]; ring

theorem lin_zero_fun (a : List R) : lin (fun _ => (0 : R)) a = 0 := by
  induction a with
  | nil => simp
  | cons a as ih => simp [ih]

theorem lin_sum_fun {ι : Type*} (s : Finset ι) (f : ι → ℕ → R) (a : List R) :
    lin (fun i => ∑ k ∈ s, f k i) a = ∑ k ∈ s, lin (f k) a := by
  classical
  induction s using Finset.induction_on with
  | empty => simp [lin_zero_fun]
  | insert hk ih =>
    simp only [Finset.sum_insert hk]
    rw [lin_add_fun, ih]

theorem lin_congr {f g : ℕ → R} {a : List R} (h : ∀ i < a.length, f i = g i) :
    lin f a = lin g a := by
  induction a generalizing f g with
  | nil => simp
  | cons a as ih =>
    simp only [lin_cons]
    rw [h 0 (by simp), ih (fun i hi => h (i + 1) (by simp; omega))]

theorem lin_delta (a : List R) (j : ℕ) :
    lin (fun i => if i = j then (1 : R) else 0) a = a.getD j 0 := by
  induction a generalizing j with
  | nil => simp
  | cons a as ih =>
    simp only [lin_cons]
    cases j with
    | zero =>
      simp only [if_true, one_mul, List.getD_cons_zero]
      have : (fun i : ℕ => if i + 1 = 0 then (1 : R) else 0) = fun _ => 0 := by
        funext i; simp
      rw [this, lin_zero_fun, add_zero]
    | succ j =>
      have h1 : (fun i : ℕ => if i + 1 = j + 1 then (1 : R) else 0) =
          fun i => if i = j then 1 else 0 := by funext i; simp
      simp [h1, ih]

theorem lin_polyMul (f : ℕ → R) (x y : List R) :
    lin f (polyMul x y) = lin (fun a => lin (fun b => f (a + b)) y) x := by
  induction x generalizing f with
  | nil => simp [polyMul]
  | cons a as ih =>
    simp only [polyMul, lin_polyAdd, lin_polyScale, lin_cons, zero_add, mul_zero, ih]
    have : (fun i => lin (fun b => f (i + 1 + b)) y) =
        (fun a => lin (fun b => f (a + b + 1)) y) := by
      funext i; congr 1; funext b; congr 1; omega
    rw [this]; ring

@[simp] theorem evalAt_nil (x : R) : evalAt [] x = 0 := rfl

theorem evalAt_cons (a : R) (as : List R) (x : R) :
    evalAt (a :: as) x = a + x * evalAt as x := by
  simp only [evalAt, lin_cons, pow_zero, one_mul]
  have : (fun i => x ^ (i + 1)) = fun i => x ^ i * x := by funext i; ring
  rw [this, lin_mul_fun]

theorem evalAt_polyAdd (a b : List R) (x : R) :
    evalAt (polyAdd a b) x = evalAt a x + evalAt b x := lin_polyAdd _ a b

theorem evalAt_polyScale (k : R) (a : List R) (x : R) :
    evalAt (polyScale k a) x = k * evalAt a x := lin_polyScale _ k a

theorem evalAt_polyMul (a b : List R) (x : R) :
    evalAt (polyMul a b) x = evalAt a x * evalAt b x := by
  unfold evalAt
  rw [lin_polyMul]
  have : (fun i => lin (fun j => x ^ (i + j)) b) = fun i => x ^ i * lin (fun j => x ^ j) b := by
    funext i
    have : (fun j => x ^ (i + j)) = fun j => x ^ j * x ^ i := by funext j; ring
    rw [this, lin_mul_fun]
  rw [this, lin_mul_fun]; ring

theorem evalAt_polySum (ps : List (List R)) (x : R) :
    evalAt (polySum ps) x = (ps.map (evalAt · x)).sum := by
  induction ps with
  | nil => rfl
  | cons p ps ih => simp [polySum, evalAt_polyAdd, ← ih]

theorem lin_polySum (f : ℕ → R) (ps : List (List R)) :
    lin f (polySum ps) = (ps.map (lin f)).sum := by
  induction ps with
  | nil => rfl
  | cons p ps ih => simp [polySum, lin_polyAdd, ← ih]

theorem evalAt_foldl_polyMul (ps : List (List R)) (p0 : List R) (x : R) :
    evalAt (ps.foldl polyMul p0) x = evalAt p0 x * (ps.map (evalAt · x)).prod := by
  induction ps generalizing p0 with
  | nil => simp
  | cons p ps ih => simp [ih, evalAt_polyMul, mul_assoc]

theorem evalAt_termPoly (coef : R) (ps : List (List R)) (x : R) :
    evalAt (termPoly coef ps) x = coef * (ps.map (evalAt · x)).prod := by
  simp [termPoly, evalAt_foldl_polyMul, evalAt_cons]

theorem length_polyAdd (a b : List R) :
    (polyAdd a b).length = max a.length b.length := by
  induction a generalizing b with
  | nil => simp [polyAdd]
  | cons a as ih => cases b <;> simp [polyAdd, ih, Nat.succ_max_succ]

theorem length_polyMul_cons (a : R) (as b : List R) (hb : b ≠ []) :
    (polyMul (a :: as) b).length = as.length + b.length := by
  have hb' : 0 < b.length := List.length_pos.mpr hb
  induction as generalizing a with
  | nil => simp [polyMul, length_polyAdd, polyScale]; omega
  | cons c cs ih =>
    have h := ih c
    simp only [polyMul, length_polyAdd, polyScale, List.length_map, List.length_cons] at h ⊢
    omega

theorem length_polyMul (a b : List R) (ha : a ≠ []) (hb : b ≠ []) :
    (polyMul a b).length = a.length + b.length - 1 := by
  cases a with
  | nil => exact absurd rfl ha
  | cons a as => rw [length_polyMul_cons a as b hb]; simp

theorem length_foldl_polyMul (ps : List (List R)) (p0 : List R) (h0 : p0 ≠ [])
    (hps : ∀ p ∈ ps, p ≠ []) :
    (ps.foldl polyMul p0).length = p0.length + (ps.map (fun p => p.length - 1)).sum := by
  induction ps generalizing p0 with
  | nil => simp
  | cons p ps ih =>
    simp only [List.foldl_cons, List.map_cons, List.sum_cons]
    have hp : p ≠ [] := hps p (by simp)
    have hpl : 0 < p.length := List.length_pos.mpr hp
    have h0l : 0 < p0.length := List.length_pos.mpr h0
    have hlen := length_polyMul p0 p h0 hp
    have hne : polyMul p0 p ≠ [] := by
      intro hc
      rw [hc] at hlen
      simp only [List.length_nil] at hlen
      omega
    rw [ih _ hne (fun q hq => hps q (by simp [hq])), hlen]
    omega

theorem length_polySum_le (ps : List (List R)) (N : ℕ) (h : ∀ p ∈ ps, p.length ≤ N) :
    (polySum ps).length ≤ N := by
  induction ps with
  | nil => simp [polySum]
  | cons p ps ih =>
    simp only [polySum, List.foldr_cons] at ih ⊢
    rw [length_polyAdd]
    exact max_le (h p (by simp)) (ih (fun q hq => h q (by simp [hq])))

/-- Ring homomorphisms commute with the list polynomial operations. -/
theorem map_polyAdd {S : Type*} [CommRing S] (φ : R →+* S) (a b : List R) :
    (polyAdd a b).map φ = polyAdd (a.map φ) (b.map φ) := by
  induction a generalizing b with
  | nil => simp [polyAdd]
  | cons a as ih => cases b <;> simp [polyAdd, ih]

theorem map_polyMul {S : Type*} [CommRing S] (φ : R →+* S) (a b : List R) :
    (polyMul a b).map φ = polyMul (a.map φ) (b.map φ) := by
  induction a with
  | nil => simp [polyMul]
  | cons a as ih => simp [polyMul, map_polyAdd, polyScale, ih, Function.comp_def]

theorem map_lin {S : Type*} [CommRing S] (φ : R →+* S) (f : ℕ → R) (a : List R) :
    φ (lin f a) = lin (fun i => φ (f i)) (a.map φ) := by
  induction a generalizing f with
  | nil => simp
  | cons a as ih => simp [ih]

theorem map_evalAt {S : Type*} [CommRing S] (φ : R →+* S) (a : List R) (x : R) :
    φ (evalAt a x) = evalAt (a.map φ) (φ x) := by
  simp [evalAt, map_lin]

end Generic

/-! ### Integer bounds -/

/-- `AbsLe a A`: the coefficients of `a` are bounded in absolute value by `A`, position by position. -/
def AbsLe (a A : List ℤ) : Prop := List.Forall₂ (fun x X => |x| ≤ X) a A

theorem AbsLe.polyAdd {a A b B : List ℤ} (ha : AbsLe a A) (hb : AbsLe b B) :
    AbsLe (polyAdd a b) (polyAdd A B) := by
  induction ha generalizing b B with
  | nil => simpa [ZolanaVE.Field.polyAdd] using hb
  | cons hxX _ ih =>
    cases hb with
    | nil => exact List.Forall₂.cons hxX (by assumption)
    | cons hyY hr =>
      exact List.Forall₂.cons ((abs_add _ _).trans (add_le_add hxX hyY)) (ih hr)

theorem AbsLe.polyScale {k K : ℤ} {a A : List ℤ} (hk : |k| ≤ K) (ha : AbsLe a A) :
    AbsLe (polyScale k a) (polyScale K A) := by
  induction ha with
  | nil => exact List.Forall₂.nil
  | cons hxX _ ih =>
    refine List.Forall₂.cons ?_ ih
    rw [abs_mul]
    exact mul_le_mul hk hxX (abs_nonneg _) ((abs_nonneg k).trans hk)

theorem AbsLe.polyMul {a A b B : List ℤ} (ha : AbsLe a A) (hb : AbsLe b B) :
    AbsLe (polyMul a b) (polyMul A B) := by
  induction ha with
  | nil => exact List.Forall₂.nil
  | cons hxX _ ih =>
    exact AbsLe.polyAdd (AbsLe.polyScale hxX hb) (List.Forall₂.cons (by simp) ih)

end ZolanaVE.Field
