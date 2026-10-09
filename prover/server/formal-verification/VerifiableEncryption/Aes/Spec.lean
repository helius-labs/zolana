/-
AES-256 (FIPS-197) and counter mode (SP 800-38A section 6.5, SP 800-38D inc32).

Layout decisions:
* A state and a block are `Fin 16 → Byte` in FIPS-197 input order, which is column-major:
  state entry `s[r,c]` is index `r + 4 * c`.
* A word is `Fin 4 → Byte` with byte 0 the most significant (FIPS-197 `a0 a1 a2 a3`).
* `ctrGeneric` increments the counter block with `inc32` (the low 32 bits big-endian, mod 2^32).
  SP 800-38A leaves the increment function open; `inc32` is the one SP 800-38D fixes and the
  one the circuit uses.
-/
namespace ZolanaVE.Aes

abbrev Byte := BitVec 8
abbrev Word := Fin 4 → Byte
abbrev State := Fin 16 → Byte
abbrev Block := Fin 16 → Byte

def sbox : List Byte := [
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]

def sb (x : Byte) : Byte := sbox[x.toNat]!

def xtime (x : Byte) : Byte := (x <<< 1) ^^^ (if x.msb then 0x1b else 0)

def mul3 (x : Byte) : Byte := xtime x ^^^ x

/-- Carry-less product of two bytes as polynomials over GF(2) (FIPS-197 section 4.2). -/
def clmul (a b : Nat) : Nat :=
  (List.range 8).foldl (fun acc i => if b.testBit i then acc ^^^ (a <<< i) else acc) 0

/-- Reduction of a polynomial of degree at most 14 modulo `m(x) = x^8 + x^4 + x^3 + x + 1`. -/
def polyReduce (p : Nat) : Nat :=
  (List.range 7).reverse.foldl
    (fun acc i => if acc.testBit (i + 8) then acc ^^^ (0x11b <<< i) else acc) p

def gmul (a b : Byte) : Byte := BitVec.ofNat 8 (polyReduce (clmul a.toNat b.toNat))

/-- Multiplicative inverse in GF(2^8) as `x^254`, with `0 ↦ 0` (FIPS-197 section 5.1.1). -/
def ginv (x : Byte) : Byte :=
  let x2 := gmul x x
  let x4 := gmul x2 x2
  let x8 := gmul x4 x4
  let x16 := gmul x8 x8
  let x32 := gmul x16 x16
  let x64 := gmul x32 x32
  let x128 := gmul x64 x64
  gmul x2 (gmul x4 (gmul x8 (gmul x16 (gmul x32 (gmul x64 x128)))))

/-- The S-box affine transformation of FIPS-197 equation (5.1). -/
def affine (b : Byte) : Byte :=
  b ^^^ b.rotateLeft 1 ^^^ b.rotateLeft 2 ^^^ b.rotateLeft 3 ^^^ b.rotateLeft 4 ^^^ 0x63

def idx (r c : Fin 4) : Fin 16 := ⟨r.val + 4 * c.val, by omega⟩

def row (i : Fin 16) : Fin 4 := ⟨i.val % 4, by omega⟩

def col (i : Fin 16) : Fin 4 := ⟨i.val / 4, by omega⟩

def column (s : State) (c : Fin 4) : Fin 4 → Byte := fun r => s (idx r c)

def subBytes (s : State) : State := fun i => sb (s i)

def shiftRows (s : State) : State := fun i => s (idx (row i) (col i + row i))

def mixColumn (a : Fin 4 → Byte) : Fin 4 → Byte :=
  fun r => xtime (a r) ^^^ mul3 (a (r + 1)) ^^^ a (r + 2) ^^^ a (r + 3)

def mixColumns (s : State) : State := fun i => mixColumn (column s (col i)) (row i)

def addRoundKey (s : State) (k : State) : State := fun i => s i ^^^ k i

def rotWord (w : Word) : Word := fun j => w (j + 1)

def subWord (w : Word) : Word := fun j => sb (w j)

def zeroWord : Word := fun _ => 0

def xorWord (a b : Word) : Word := fun j => a j ^^^ b j

/-- `Rcon[i] = [x^(i-1), 0, 0, 0]` for `i ≥ 1`. -/
def rcon (i : Nat) : Word :=
  fun j => if j.val = 0 then (List.range (i - 1)).foldl (fun acc _ => xtime acc) 1 else 0

def keyWord (key : Fin 32 → Byte) (i : Fin 8) : Word := fun j => key ⟨4 * i.val + j.val, by omega⟩

/-- Word `w[n]` of the AES-256 key schedule (FIPS-197 section 5.2, `Nk = 8`) given `ws = w[0..n)`. -/
def nextKeyWord (key : Fin 32 → Byte) (ws : List Word) (n : Nat) : Word :=
  if h : n < 8 then keyWord key ⟨n, h⟩
  else
    let temp := ws.getD (n - 1) zeroWord
    let temp :=
      if n % 8 = 0 then xorWord (subWord (rotWord temp)) (rcon (n / 8))
      else if n % 8 = 4 then subWord temp
      else temp
    xorWord (ws.getD (n - 8) zeroWord) temp

/-- Words `w[0..n)` of the AES-256 key schedule, in order. -/
def keyWords (key : Fin 32 → Byte) : Nat → List Word
  | 0 => []
  | n + 1 => keyWords key n ++ [nextKeyWord key (keyWords key n) n]

def keyExpansion256 (key : Fin 32 → Byte) : Fin 60 → Word :=
  fun i => (keyWords key 60).getD i.val zeroWord

def roundKey (w : Fin 60 → Word) (round : Fin 15) : State :=
  fun i => w ⟨4 * round.val + (col i).val, by omega⟩ (row i)

def cipherRound (w : Fin 60 → Word) (round : Fin 15) (s : State) : State :=
  addRoundKey (mixColumns (shiftRows (subBytes s))) (roundKey w round)

def finalRound (w : Fin 60 → Word) (s : State) : State :=
  addRoundKey (shiftRows (subBytes s)) (roundKey w 14)

/-- The state after the initial `AddRoundKey` and `n` full rounds (`n ≤ 13`). -/
def roundsFrom (w : Fin 60 → Word) (blk : Block) : Nat → State
  | 0 => addRoundKey blk (roundKey w 0)
  | n + 1 => cipherRound w ⟨min (n + 1) 14, by omega⟩ (roundsFrom w blk n)

def encryptWith (w : Fin 60 → Word) (blk : Block) : Block := finalRound w (roundsFrom w blk 13)

def encryptBlock (key : Fin 32 → Byte) (blk : Block) : Block :=
  encryptWith (keyExpansion256 key) blk

def be32 (n : Nat) : Fin 4 → Byte := fun j => BitVec.ofNat 8 (n / 256 ^ (3 - j.val))

def counterBlock (nonce : Fin 12 → Byte) (ctr : Nat) : Block :=
  fun i => if h : i.val < 12 then nonce ⟨i.val, h⟩ else be32 ctr ⟨i.val - 12, by omega⟩

def low32 (cb : Block) : Nat :=
  (cb 12).toNat * 2 ^ 24 + (cb 13).toNat * 2 ^ 16 + (cb 14).toNat * 2 ^ 8 + (cb 15).toNat

def inc32 (cb : Block) : Block :=
  fun i => if i.val < 12 then cb i else be32 (low32 cb + 1) ⟨i.val - 12, by omega⟩

/-- `n` blocks of counter mode over the block cipher `enc` starting at counter block `cb`;
the last block may be partial. -/
def ctrBlocks (enc : Block → Block) : Block → Nat → List Byte → List Byte
  | _, 0, _ => []
  | cb, n + 1, pt =>
    List.zipWith (· ^^^ ·) (pt.take 16) (List.ofFn (enc cb)) ++
      ctrBlocks enc (inc32 cb) n (pt.drop 16)

def ctrGeneric (key : Fin 32 → Byte) (cb : Block) (pt : List Byte) : List Byte :=
  ctrBlocks (encryptBlock key) cb ((pt.length + 15) / 16) pt

/-- AES-256-CTR with `nonce ‖ BE32(counter)` blocks, the first one at counter 2 (GCM `inc32(J0)`). -/
def ctrEncrypt (key : Fin 32 → Byte) (nonce : Fin 12 → Byte) (pt : List Byte) : List Byte :=
  ctrGeneric key (counterBlock nonce 2) pt

theorem forall_byte {p : Byte → Prop} (h : ∀ n : Fin 256, p (BitVec.ofFin n)) (x : Byte) : p x := by
  cases x with
  | ofFin f => exact h f

theorem sbox_length : sbox.length = 256 := by decide

theorem sbox_spec_fin : ∀ n : Fin 256, sb (BitVec.ofFin n) = affine (ginv (BitVec.ofFin n)) := by
  decide +kernel

/-- The literal S-box is the FIPS-197 section 5.1.1 construction: inversion in GF(2^8),
then the affine transformation. -/
theorem sbox_spec (x : Byte) : sb x = affine (ginv x) :=
  forall_byte (p := fun x => sb x = affine (ginv x)) sbox_spec_fin x

theorem xtime_eq_gmul_fin : ∀ n : Fin 256, xtime (BitVec.ofFin n) = gmul 2 (BitVec.ofFin n) := by
  decide +kernel

theorem mul3_eq_gmul_fin : ∀ n : Fin 256, mul3 (BitVec.ofFin n) = gmul 3 (BitVec.ofFin n) := by
  decide +kernel

theorem xtime_eq_gmul (x : Byte) : xtime x = gmul 2 x :=
  forall_byte (p := fun x => xtime x = gmul 2 x) xtime_eq_gmul_fin x

theorem mul3_eq_gmul (x : Byte) : mul3 x = gmul 3 x :=
  forall_byte (p := fun x => mul3 x = gmul 3 x) mul3_eq_gmul_fin x

theorem row_idx (r c : Fin 4) : row (idx r c) = r := by
  simp only [row, idx]; ext; simp only; omega

theorem col_idx (r c : Fin 4) : col (idx r c) = c := by
  simp only [col, idx]; ext; simp only; omega

theorem idx_row_col (i : Fin 16) : idx (row i) (col i) = i := by
  simp only [row, col, idx]; ext; simp only; omega

theorem mixColumn_zero (a : Fin 4 → Byte) :
    mixColumn a 0 = xtime (a 0) ^^^ mul3 (a 1) ^^^ a 2 ^^^ a 3 := rfl

theorem mixColumn_one (a : Fin 4 → Byte) :
    mixColumn a 1 = xtime (a 1) ^^^ mul3 (a 2) ^^^ a 3 ^^^ a 0 := rfl

theorem mixColumn_two (a : Fin 4 → Byte) :
    mixColumn a 2 = xtime (a 2) ^^^ mul3 (a 3) ^^^ a 0 ^^^ a 1 := rfl

theorem mixColumn_three (a : Fin 4 → Byte) :
    mixColumn a 3 = xtime (a 3) ^^^ mul3 (a 0) ^^^ a 1 ^^^ a 2 := rfl

/-- FIPS-197 equation (5.6): row `r` of the column is `{02}·a_r ⊕ {03}·a_{r+1} ⊕ a_{r+2} ⊕ a_{r+3}`. -/
theorem mixColumn_gmul (a : Fin 4 → Byte) (r : Fin 4) :
    mixColumn a r = gmul 2 (a r) ^^^ gmul 3 (a (r + 1)) ^^^ a (r + 2) ^^^ a (r + 3) := by
  simp only [mixColumn, xtime_eq_gmul, mul3_eq_gmul]

theorem column_mixColumns (s : State) (c : Fin 4) :
    column (mixColumns s) c = mixColumn (column s c) := by
  funext r
  simp only [column, mixColumns, row_idx, col_idx]

theorem mixColumns_idx (s : State) (r c : Fin 4) :
    mixColumns s (idx r c) = mixColumn (column s c) r := by
  simp only [mixColumns, row_idx, col_idx]

theorem column_shiftRows (s : State) (c r : Fin 4) :
    column (shiftRows s) c r = s (idx r (c + r)) := by
  simp only [column, shiftRows, row_idx, col_idx]

theorem column_subBytes (s : State) (c r : Fin 4) : column (subBytes s) c r = sb (column s c r) :=
  rfl

theorem column_addRoundKey (s k : State) (c r : Fin 4) :
    column (addRoundKey s k) c r = column s c r ^^^ column k c r := rfl

theorem column_roundKey (w : Fin 60 → Word) (round : Fin 15) (c : Fin 4) :
    column (roundKey w round) c = w ⟨4 * round.val + c.val, by omega⟩ := by
  funext r
  simp only [column, roundKey, row_idx, col_idx]

end ZolanaVE.Aes
