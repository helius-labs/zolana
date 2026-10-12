import VerifiableEncryption.Field.Layout

/-! The fixed-base recoding limbs, independent of the extracted comb tables. -/

namespace ZolanaVE.P256

/-- Limbs of `2^256 mod n`, the recoding constant. -/
def twoPowLimbs (i : Fin 8) : ℤ :=
  [60611247, 205927741, 1491624315, 1125713234, 0, 0, 4294967295, 0].getD i 0

end ZolanaVE.P256
