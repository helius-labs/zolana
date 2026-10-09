import VerifiableEncryption.Field.Poly

/-!
Algebra of `lin` and finite sums used by the check soundness proofs.
-/

namespace ZolanaVE.Field

section Generic

variable {R : Type*} [CommRing R]

theorem lin_eq_sum (f : ℕ → R) (P : List R) :
    lin f P = ∑ i ∈ Finset.range P.length, f i * P.getD i 0 := by
  induction P generalizing f with
  | nil => simp
  | cons p ps ih =>
    rw [lin_cons, ih, List.length_cons, Finset.sum_range_succ']
    simp only [List.getD_cons_succ, List.getD_cons_zero]
    ring

theorem getD_eq_zero_of_le {P : List R} {i : ℕ} (h : P.length ≤ i) : P.getD i 0 = 0 := by
  rw [List.getD_eq_getElem?_getD, List.getElem?_eq_none h]; rfl

theorem lin_eq_sum_of_le (f : ℕ → R) (P : List R) {N : ℕ} (hN : P.length ≤ N) :
    lin f P = ∑ i ∈ Finset.range N, f i * P.getD i 0 := by
  rw [lin_eq_sum]
  obtain ⟨d, rfl⟩ := Nat.exists_eq_add_of_le hN
  rw [Finset.sum_range_add]
  have : ∑ x ∈ Finset.range d, f (P.length + x) * P.getD (P.length + x) 0 = 0 := by
    apply Finset.sum_eq_zero; intro x _
    rw [getD_eq_zero_of_le (by omega), mul_zero]
  rw [this, add_zero]

theorem sumRange_eq {α : Type*} [AddCommMonoid α] (n : ℕ) (f : ℕ → α) :
    sumRange n f = ∑ i ∈ Finset.range n, f i := by
  induction n with
  | zero => rfl
  | succ n ih =>
    simp only [sumRange, List.range_succ, List.map_append, List.sum_append, List.map_cons,
      List.map_nil, List.sum_cons, List.sum_nil, add_zero, Finset.sum_range_succ] at ih ⊢
    rw [ih]

theorem lin_mul_fun_left (f : ℕ → R) (c : R) (a : List R) :
    lin (fun i => c * f i) a = c * lin f a := by
  rw [← lin_mul_fun]; congr 1; funext i; ring

theorem lin_mul_lin (g h : ℕ → R) (X Y : List R) :
    lin g X * lin h Y = lin (fun a => lin (fun b => g a * h b) Y) X := by
  have : (fun a => lin (fun b => g a * h b) Y) = fun a => g a * lin h Y := by
    funext a; exact lin_mul_fun_left h (g a) Y
  rw [this, lin_mul_fun]; ring

theorem lin_modEq {f g : ℕ → ℤ} {m : ℤ} {P : List ℤ} (h : ∀ i < P.length, f i ≡ g i [ZMOD m]) :
    lin f P ≡ lin g P [ZMOD m] := by
  induction P generalizing f g with
  | nil => rfl
  | cons p ps ih =>
    simp only [lin_cons]
    exact Int.ModEq.add (Int.ModEq.mul_right _ (h 0 (by simp)))
      (ih (fun i hi => h (i + 1) (by simp; omega)))

theorem lin_abs_le {P B : List ℤ} (h : AbsLe P B) (f : ℕ → ℤ) :
    |lin f P| ≤ lin (fun i => |f i|) B := by
  induction h generalizing f with
  | nil => simp
  | cons hxX _ ih =>
    simp only [lin_cons]
    refine (abs_add _ _).trans (add_le_add ?_ (ih _))
    rw [abs_mul]
    exact mul_le_mul_of_nonneg_left hxX (abs_nonneg _)

theorem AbsLe.length_eq {P B : List ℤ} (h : AbsLe P B) : P.length = B.length :=
  List.Forall₂.length_eq h

theorem AbsLe.polySum {Ps Bs : List (List ℤ)} (h : List.Forall₂ AbsLe Ps Bs) :
    AbsLe (ZolanaVE.Field.polySum Ps) (ZolanaVE.Field.polySum Bs) := by
  induction h with
  | nil => exact List.Forall₂.nil
  | cons hab _ ih => exact AbsLe.polyAdd hab ih

theorem AbsLe.foldl_polyMul {Ps Bs : List (List ℤ)} (h : List.Forall₂ AbsLe Ps Bs) :
    ∀ {p B : List ℤ}, AbsLe p B → AbsLe (Ps.foldl ZolanaVE.Field.polyMul p) (Bs.foldl ZolanaVE.Field.polyMul B) := by
  induction h with
  | nil => intro p B hp; exact hp
  | cons hab _ ih => intro p B hp; exact ih (AbsLe.polyMul hp hab)

theorem AbsLe.nonneg {P B : List ℤ} (h : AbsLe P B) : ∀ i, 0 ≤ B.getD i 0 := by
  induction h with
  | nil => intro i; simp
  | cons hxX _ ih =>
    intro i; cases i with
    | zero => simpa using (abs_nonneg _).trans hxX
    | succ i => simpa using ih i

/-- Two polynomials related by `lin g P = c * lin g Q` for every functional stay
related after multiplying both on the right by the same polynomial. -/
theorem lin_polyMul_scaled {P Q : List R} {c : R} (h : ∀ g, lin g P = c * lin g Q) (b : List R) (f : ℕ → R) :
    lin f (polyMul P b) = c * lin f (polyMul Q b) := by
  rw [lin_polyMul, lin_polyMul, h]

theorem lin_foldl_polyMul_scaled (ps : List (List R)) :
    ∀ {P Q : List R} {c : R}, (∀ g, lin g P = c * lin g Q) →
      ∀ f, lin f (ps.foldl polyMul P) = c * lin f (ps.foldl polyMul Q) := by
  induction ps with
  | nil => intro P Q c h f; exact h f
  | cons p ps ih => intro P Q c h f; exact ih (lin_polyMul_scaled h p) f

theorem lin_termPoly (coef : R) (ps : List (List R)) (f : ℕ → R) :
    lin f (termPoly coef ps) = coef * lin f (termPoly 1 ps) := by
  apply lin_foldl_polyMul_scaled
  intro g; simp [mul_comm]

theorem getD_eq_lin_delta (P : List R) (j : ℕ) :
    P.getD j 0 = lin (fun i => if i = j then (1 : R) else 0) P := (lin_delta P j).symm

theorem sumRange_mul_left (n : ℕ) (f : ℕ → R) (c : R) :
    c * sumRange n f = sumRange n (fun i => c * f i) := by
  rw [sumRange_eq, sumRange_eq, Finset.mul_sum]

theorem lin_sumRange_fun (n : ℕ) (f : ℕ → ℕ → R) (a : List R) :
    lin (fun i => sumRange n (fun k => f k i)) a = sumRange n (fun k => lin (f k) a) := by
  simp only [sumRange_eq]
  exact lin_sum_fun (Finset.range n) f a

theorem map_sumRange {S : Type*} [CommRing S] (φ : R →+* S) (n : ℕ) (f : ℕ → R) :
    φ (sumRange n f) = sumRange n (fun i => φ (f i)) := by
  simp only [sumRange_eq, map_sum]

theorem map_getD {S : Type*} [CommRing S] (φ : R →+* S) (P : List R) (i : ℕ) :
    (P.map φ).getD i 0 = φ (P.getD i 0) := by
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases P[i]? <;> simp

theorem intCast_sumRange (n : ℕ) (f : ℕ → ℤ) :
    ((sumRange n f : ℤ) : R) = sumRange n (fun i => (f i : R)) :=
  map_sumRange (Int.castRingHom R) n f

theorem intCast_lin (f : ℕ → ℤ) (P : List ℤ) :
    ((lin f P : ℤ) : R) = lin (fun i => (f i : R)) (P.map (Int.cast : ℤ → R)) :=
  map_lin (Int.castRingHom R) f P

theorem intCast_evalAt (P : List ℤ) (x : ℤ) :
    ((evalAt P x : ℤ) : R) = evalAt (P.map (Int.cast : ℤ → R)) (x : R) :=
  map_evalAt (Int.castRingHom R) P x

theorem intCast_getD (P : List ℤ) (i : ℕ) :
    (P.map (Int.cast : ℤ → R)).getD i 0 = ((P.getD i 0 : ℤ) : R) := by
  rw [List.getD_eq_getElem?_getD, List.getD_eq_getElem?_getD, List.getElem?_map]
  cases P[i]? <;> simp

theorem intCast_list_prod (l : List ℤ) : ((l.prod : ℤ) : R) = (l.map (Int.cast : ℤ → R)).prod := by
  induction l with
  | nil => simp
  | cons a l ih => simp [ih]

theorem intCast_list_sum (l : List ℤ) : ((l.sum : ℤ) : R) = (l.map (Int.cast : ℤ → R)).sum := by
  induction l with
  | nil => simp
  | cons a l ih => simp [ih]

theorem sumRange_congr' {α : Type*} [AddCommMonoid α] {n : ℕ} {f g : ℕ → α} (h : ∀ i, f i = g i) :
    sumRange n f = sumRange n g := by rw [funext h]

theorem sumRange_add (n : ℕ) (f g : ℕ → R) :
    sumRange n (fun i => f i + g i) = sumRange n f + sumRange n g := by
  simp only [sumRange_eq, Finset.sum_add_distrib]

theorem sumRange_list_sum {ι : Type*} (n : ℕ) (l : List ι) (g : ι → ℕ → R) :
    sumRange n (fun i => (l.map (fun t => g t i)).sum) = (l.map fun t => sumRange n (g t)).sum := by
  induction l with
  | nil => simp [sumRange_eq]
  | cons t l ih => simp only [List.map_cons, List.sum_cons, sumRange_add, ih]

theorem lin_single_polyMul (g : ℕ → R) (c : R) (x : List R) :
    lin g (polyMul [c] x) = c * lin g x := by
  rw [lin_polyMul]; simp only [lin_cons, lin_nil, add_zero, zero_add]; ring

theorem list_sum_congr {ι : Type*} {l : List ι} {f g : ι → R} (h : ∀ t ∈ l, f t = g t) :
    (l.map f).sum = (l.map g).sum := by
  rw [List.map_congr_left h]

end Generic

end ZolanaVE.Field
