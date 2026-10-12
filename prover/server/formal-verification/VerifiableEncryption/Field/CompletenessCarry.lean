import VerifiableEncryption.Field.PlainCheck

/-!
Constructive carry witnesses for the actual generic CheckPolynomial carry
chain. Capacity is an input-independent numerical certificate property. It
does not assert that hints or constraints succeed. The integer carries are
defined by prefix division, and every emitted native range check is proved
from residual bounds and capacity.
-/

namespace ZolanaVE.Field

open scoped BigOperators

def RangeComplete253 (rc : ℕ → F → Prop) : Prop :=
  ∀ bits value : ℕ, bits ≤ 253 → value < 2 ^ bits → rc bits (value : F)

def carryRadix (pos : ℕ) : ℤ := 2 ^ (32 * pos)

theorem carryRadix_pos (pos : ℕ) : 0 < carryRadix pos := by
  unfold carryRadix
  positivity

def weightedPrefix (res : ℕ → ℤ) (pos : ℕ) : ℤ :=
  sumRange pos (fun i => res i * carryRadix i)

theorem weightedPrefix_split (res : ℕ → ℤ) (pos len : ℕ) :
    weightedPrefix res (pos + len) = weightedPrefix res pos +
      carryRadix pos * sumRange len (fun i => res (pos + i) * carryRadix i) := by
  unfold weightedPrefix
  rw [sumRange_split]
  congr 1
  rw [sumRange_eq, sumRange_eq, Finset.mul_sum]
  apply Finset.sum_congr rfl
  intro i hi
  simp only [carryRadix, Nat.mul_add, pow_add]
  ring

theorem weightedPrefix_dvd {res : ℕ → ℤ} {positions pos : ℕ}
    (hzero : weightedPrefix res positions = 0) (hpos : pos ≤ positions) :
    carryRadix pos ∣ weightedPrefix res pos := by
  rw [show positions = pos + (positions - pos) by omega,
    weightedPrefix_split] at hzero
  refine ⟨-sumRange (positions - pos) (fun i => res (pos + i) * carryRadix i), ?_⟩
  linear_combination hzero

/-- Additional numerical completeness property of a carry layout. Existing
groupsSound proves lifting bounds; this capacity inequality proves that the
chosen carry width also accommodates every bounded integer residual. -/
inductive CarryCapacity (bound : ℕ → ℤ) (positions finish : ℕ) :
    List CarryGroup → ℕ → Option ℕ → Prop
  | nil (prev : Option ℕ) : CarryCapacity bound positions finish [] finish prev
  | cons (g : CarryGroup) (gs : List CarryGroup) (pos : ℕ) (prev : Option ℕ)
      (hstart : g.start = pos) (hstop : pos < g.stop) (hpositions : g.stop ≤ positions)
      (hbits : g.carryBits + 1 ≤ 253)
      (hinv : ((2 : F) ^ (32 * (g.stop - g.start))) * (g.inv : F) = 1)
      (hcapacity : PlainCheckParams.carryIn prev +
        sumRange (g.stop - g.start) (fun i => bound (g.start + i) * carryRadix i) <
          carryRadix (g.stop - g.start) * 2 ^ g.carryBits)
      (htail : CarryCapacity bound positions finish gs g.stop (some g.carryBits)) :
      CarryCapacity bound positions finish (g :: gs) pos prev

/-- Construct the emitted carry chain from a zero integer residual. Every
carry is the exact weighted-prefix quotient. The continuation is evaluated
at that explicit final quotient, not supplied satisfying constraints. -/
theorem carryChain_complete {res : ℕ → F} {Res bound : ℕ → ℤ}
    {rc : ℕ → F → Prop} (hrc : RangeComplete253 rc)
    (hres : ∀ i, (Res i : F) = res i) (hbound : ∀ i, |Res i| ≤ bound i)
    {positions finish : ℕ} (hzero : weightedPrefix Res positions = 0)
    (hfinish : finish ≤ positions) :
    ∀ (gs : List CarryGroup) (pos : ℕ) (prev : Option ℕ) (C : ℤ) (k : F → Prop),
      CarryCapacity bound positions finish gs pos prev →
      |C| ≤ PlainCheckParams.carryIn prev →
      weightedPrefix Res pos = C * carryRadix pos →
      k ((weightedPrefix Res finish / carryRadix finish : ℤ) : F) →
      carryChain res rc gs (C : F) k
  | [], pos, prev, C, k, hcap, hC, hprefix, hk => by
    cases hcap
    simp only [carryChain]
    rw [hprefix, Int.mul_ediv_cancel _ (ne_of_gt (carryRadix_pos finish))] at hk
    exact hk
  | g :: gs, pos, prev, C, k, hcap, hC, hprefix, hk => by
    cases hcap with
    | cons _ _ _ _ hstart hstop hpositions hbits hinv hcapacity htail =>
      let len := g.stop - g.start
      let G : ℤ := sumRange len (fun i => Res (g.start + i) * carryRadix i) + C
      let nextCarry : ℤ := weightedPrefix Res g.stop / carryRadix g.stop
      have hnPrefix : nextCarry * carryRadix g.stop = weightedPrefix Res g.stop :=
        Int.ediv_mul_cancel (weightedPrefix_dvd hzero hpositions)
      have hradix : carryRadix g.stop = carryRadix pos * carryRadix len := by
        unfold carryRadix
        rw [← pow_add]
        congr 1
        dsimp [len]
        omega
      have hG : nextCarry * carryRadix len = G := by
        apply mul_right_cancel₀ (ne_of_gt (carryRadix_pos pos))
        calc
          nextCarry * carryRadix len * carryRadix pos = nextCarry * carryRadix g.stop := by
            rw [hradix]; ring
          _ = weightedPrefix Res g.stop := hnPrefix
          _ = G * carryRadix pos := by
            rw [show g.stop = pos + len by dsimp [len]; omega,
              weightedPrefix_split, hprefix]
            dsimp [G]
            rw [hstart]
            ring
      have hGb : |G| ≤ PlainCheckParams.carryIn prev +
          sumRange len (fun i => bound (g.start + i) * carryRadix i) := by
        dsimp [G]
        refine (abs_add _ _).trans ?_
        rw [add_comm]
        apply add_le_add hC
        refine (abs_sumRange_le _ _).trans ?_
        apply sumRange_le_sumRange
        intro i hi
        rw [abs_mul, abs_of_pos (carryRadix_pos i)]
        exact mul_le_mul_of_nonneg_right (hbound _) (carryRadix_pos i).le
      have hnBound : |nextCarry| < (2 : ℤ) ^ g.carryBits := by
        have hproduct : |nextCarry| * carryRadix len <
            2 ^ g.carryBits * carryRadix len := by
          calc
            |nextCarry| * carryRadix len = |nextCarry * carryRadix len| := by
              rw [abs_mul, abs_of_pos (carryRadix_pos len)]
            _ = |G| := by rw [hG]
            _ < 2 ^ g.carryBits * carryRadix len := by
              simpa [len, mul_comm] using lt_of_le_of_lt hGb hcapacity
        exact (mul_lt_mul_right (carryRadix_pos len)).mp hproduct
      have hnRange : rc (g.carryBits + 1)
          ((nextCarry : F) + (2 : F) ^ g.carryBits) := by
        have hshift : 0 ≤ nextCarry + 2 ^ g.carryBits := by
          rw [abs_lt] at hnBound
          omega
        have hlt : (nextCarry + 2 ^ g.carryBits).toNat < 2 ^ (g.carryBits + 1) := by
          have hp : (2 : ℤ) ^ (g.carryBits + 1) = 2 * 2 ^ g.carryBits := by ring
          rw [abs_lt] at hnBound
          have hi : (((nextCarry + 2 ^ g.carryBits).toNat : ℕ) : ℤ) <
              (2 : ℤ) ^ (g.carryBits + 1) := by
            rw [Int.toNat_of_nonneg hshift, hp]
            omega
          exact_mod_cast hi
        have hc := hrc _ _ hbits hlt
        have he : (((nextCarry + 2 ^ g.carryBits).toNat : ℕ) : F) =
            (nextCarry : F) + (2 : F) ^ g.carryBits := by
          rw [← Int.cast_natCast, Int.toNat_of_nonneg hshift]
          push_cast
          rfl
        rwa [he] at hc
      have hGF : (G : F) = sumRange len (fun i => res (g.start + i) * pow32 i) + (C : F) := by
        simp only [G, Int.cast_add, intCast_sumRange, Int.cast_mul, hres,
          carryRadix, Int.cast_pow, Int.cast_ofNat, pow32]
      have hnF : (G : F) * (g.inv : F) = (nextCarry : F) := by
        rw [← hG, Int.cast_mul]
        simp only [carryRadix, Int.cast_pow, Int.cast_ofNat]
        rw [mul_assoc, hinv, mul_one]
      simp only [carryChain]
      rw [← hGF, hnF]
      refine ⟨hnRange, carryChain_complete hrc hres hbound hzero hfinish gs g.stop
        (some g.carryBits) nextCarry k htail ?_ hnPrefix.symm hk⟩
      exact hnBound.le

end ZolanaVE.Field
