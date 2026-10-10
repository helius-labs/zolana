import VerifiableEncryption.Envelope.AgreeCore
import VerifiableEncryption.Envelope.KdfHead
import VerifiableEncryption.LookupAssumptions

/-!
Soundness of the two extracted ECIES envelopes.

If the constraints of `Envelope_32_65_16_16` (16-byte plaintext) or
`EnvelopeMerge_32_65_40_4` (40-byte merge plaintext with a context and packed
ciphertext elements) hold, then the recipient key is the canonical on-curve
point `Q` given by the 65 input bytes, the ephemeral secret is the big-endian
scalar `s` of the 32 secret bytes, the published ephemeral key is the
compressed encoding of `s • G`, the shared secret is the Poseidon hash of the
tag, the split x-coordinate of `s • Q` and both compressed packings (and the
context for merge), and the ciphertext is AES-256-CTR under
`kdf poseidon sharedSecret "TMEC"`.
-/

set_option linter.unusedSectionVars false

namespace ZolanaVE.Envelope

open ZolanaVE ZolanaVE.Kdf ZolanaVE.Aes ZolanaVE.P256 ZolanaVE.Field

variable [Fact (Nat.Prime Order)]

/-- Compressed recipient key, high field: prefix byte and the top 30 x bytes. -/
def recipientLo (pk : List.Vector F 65) : F :=
  (((2 + bytesBE pk 33 32 % 2) * 2 ^ 240 + bytesBE pk 1 32 / 2 ^ 16 : ℕ) : F)

/-- Compressed recipient key, low field: the last two x bytes. -/
def recipientHi (pk : List.Vector F 65) : F := ((bytesBE pk 1 32 % 2 ^ 16 : ℕ) : F)

/-- Compressed ephemeral key, high field. -/
def ephemeralLo (xE yE : ℕ) : F := (((2 + yE % 2) * 2 ^ 240 + xE / 2 ^ 16 : ℕ) : F)

/-- Compressed ephemeral key, low field. -/
def ephemeralHi (xE : ℕ) : F := ((xE % 2 ^ 16 : ℕ) : F)

/-- The domain tag "TMES" of the shared-secret hash. -/
def sharedTag : F := 1414350163

/-- Shared-secret Poseidon inputs: tag, x-coordinate of `s • Q` split at its last
byte, the ephemeral and the recipient packings. -/
def sharedInputs (xS xE yE : ℕ) (pk : List.Vector F 65) : List F :=
  [sharedTag, ((xS / 2 ^ 8 : ℕ) : F), ((xS % 2 ^ 8 : ℕ) : F), ephemeralLo xE yE, ephemeralHi xE,
    recipientLo pk, recipientHi pk]

/-- Big-endian packing of ciphertext bytes (`gadget.BytesToField`). -/
def packBytes (l : List Byte) : ℕ := packBE (l.map BitVec.toNat)

lemma poseidon_list7 (a b c d e f g : F) :
    poseidon [a, b, c, d, e, f, g] = poseidon₇ vec![a, b, c, d, e, f, g] := rfl

lemma poseidon_list8 (a b c d e f g x : F) :
    poseidon [a, b, c, d, e, f, g, x] = poseidon₈ vec![a, b, c, d, e, f, g, x] := rfl

theorem envelope16_sound (hA : LookupAssumptions) {Esk : List.Vector F 32} {Rpk : List.Vector F 65}
    {Pt Ct : List.Vector F 16} {RLo RHi ELo EHi : F}
    (h : Envelope_32_65_16_16 Esk Rpk Pt RLo RHi ELo EHi Ct) :
    ∃ hQ : OnCurve ((bytesBE Rpk 1 32 : ℕ) : Fp) ((bytesBE Rpk 33 32 : ℕ) : Fp),
      Rpk.get 0 = 4 ∧ bytesBE Rpk 1 32 < p ∧ bytesBE Rpk 33 32 < p ∧
      ∃ (xS yS xE yE : ℕ) (hS : OnCurve (xS : Fp) (yS : Fp)) (hE : OnCurve (xE : Fp) (yE : Fp)),
        xS < p ∧ xE < p ∧ yE < p ∧
        mkPoint hS = (bytesBE Esk 0 32 : ℤ) • mkPoint hQ ∧ mkPoint hE = (bytesBE Esk 0 32 : ℤ) • G ∧
        RLo = recipientLo Rpk ∧ RHi = recipientHi Rpk ∧ ELo = ephemeralLo xE yE ∧ EHi = ephemeralHi xE ∧
        (∀ n, Pt.get n = ((bytesOf Pt n).toNat : F)) ∧ (∀ n, Ct.get n = ((bytesOf Ct n).toNat : F)) ∧
        List.ofFn (bytesOf Ct) =
          ctrEncrypt (kdfKey (poseidon (sharedInputs xS xE yE Rpk)))
            (kdfNonce (poseidon (sharedInputs xS xE yE Rpk))) (List.ofFn (bytesOf Pt)) := by
  obtain ⟨hQ, h0, hX, hY, xS, yS, xE, yE, hS, hE, lS, lE, lEy, pS, pE, a, b, c, d, e,
    ha, hb, hc0, hc1, he, hd1, h⟩ := agreeKey_core hA.range hA.rows (envelope16_body h)
  have h := envelope16Tail_head h
  simp only [Poseidon_7_rw] at h
  obtain ⟨Key, Nb, hK, hN, h⟩ := kdfAesHead_sound h
  obtain ⟨-, -, hPt, h259, h263, h364a, h364b, hCt, hct⟩ := envelope16_aes hA.aes h
  have hss : poseidon₇ vec![(1414350163 : F), e, d.get 1, c.get 0, c.get 1, a, b] =
      poseidon (sharedInputs xS xE yE Rpk) := by
    rw [ha, hb, he, hc0, hc1, hd1]
    rfl
  rw [hss] at hK hN
  refine ⟨hQ, h0, hX, hY, xS, yS, xE, yE, hS, hE, lS, lE, lEy, pS, pE, ?_, ?_, ?_, ?_, hPt, hCt, ?_⟩
  · rw [← h259, ha]; rfl
  · rw [← h263, hb]; rfl
  · rw [← h364a, hc0]; rfl
  · rw [← h364b, hc1]; rfl
  · rw [hct, hK, hN]

theorem envelopeMerge_sound (hA : LookupAssumptions) {Esk : List.Vector F 32} {Rpk : List.Vector F 65}
    {Pt : List.Vector F 40} {Ctx Bl : F} {El : List.Vector F 4}
    (h : EnvelopeMerge_32_65_40_4 Esk Rpk Pt Ctx El Bl) :
    ∃ hQ : OnCurve ((bytesBE Rpk 1 32 : ℕ) : Fp) ((bytesBE Rpk 33 32 : ℕ) : Fp),
      Rpk.get 0 = 4 ∧ bytesBE Rpk 1 32 < p ∧ bytesBE Rpk 33 32 < p ∧
      ∃ (xS yS xE yE : ℕ) (hS : OnCurve (xS : Fp) (yS : Fp)) (hE : OnCurve (xE : Fp) (yE : Fp)),
        xS < p ∧ xE < p ∧ yE < p ∧
        mkPoint hS = (bytesBE Esk 0 32 : ℤ) • mkPoint hQ ∧ mkPoint hE = (bytesBE Esk 0 32 : ℤ) • G ∧
        (∀ n, Pt.get n = ((bytesOf Pt n).toNat : F)) ∧
        let ss := poseidon (sharedInputs xS xE yE Rpk ++ [Ctx])
        let ct := ctrEncrypt (kdfKey ss) (kdfNonce ss) (List.ofFn (bytesOf Pt))
        El.get 0 = recipientLo Rpk ∧ El.get 1 = ephemeralLo xE yE ∧
        El.get 2 = ((bytesBE Rpk 1 32 % 2 ^ 16 * 2 ^ 232 + xE % 2 ^ 16 * 2 ^ 216 + packBytes (ct.take 27) : ℕ) : F) ∧
        El.get 3 = ((packBytes (ct.drop 27) : ℕ) : F) ∧
        Bl = poseidon [1414350146, ss] := by
  obtain ⟨hQ, h0, hX, hY, xS, yS, xE, yE, hS, hE, lS, lE, lEy, pS, pE, a, b, c, d, e,
    ha, hb, hc0, hc1, he, hd1, h⟩ := agreeKey_core hA.range hA.rows (envelopeMerge_body h)
  have h := envelopeMergeKdf_head h
  simp only [Poseidon_8_rw] at h
  obtain ⟨Key, Nb, hK, hN, h⟩ := kdfAesHead_sound h
  obtain ⟨-, -, hPt, c1, c2, c3, hct, h⟩ := envelopeMerge_aes hA.aes h
  have hss : poseidon₈ vec![(1414350163 : F), e, d.get 1, c.get 0, c.get 1, a, b, Ctx] =
      poseidon (sharedInputs xS xE yE Rpk ++ [Ctx]) := by
    rw [ha, hb, he, hc0, hc1, hd1]
    rfl
  rw [hss] at hK hN h
  rw [hK, hN] at hct
  unfold EnvelopeMergeTail at h
  obtain ⟨g671, e671, g672, e672, g673, e673, g674, e674, g675, e675, g676, e676, g677, e677, g678, e678,
    g679, e679, g680, e680, g681, e681, g682, e682, g683, e683, g684, e684, g685, e685, g686, e686,
    g687, e687, g688, e688, g689, e689, g690, e690, g691, e691, g692, e692, g693, e693, g694, e694,
    g695, e695, g696, e696, g697, e697, g698, e698, g699, e699, g700, e700, g701, e701, g702, e702,
    g703, e703, g704, e704, g705, e705, g706, e706, g707, e707, g708, e708, g709, e709, g710, e710,
    g711, e711, g712, e712, g713, e713, g714, e714, g715, e715, g716, e716, g717, e717, g718, e718,
    g719, e719, g720, e720, g721, e721, g722, e722, g723, e723, g724, e724, g725, e725, g726, e726,
    g727, e727, g728, e728, g729, e729, g730, e730, g731, e731, g732, e732, g733, e733, g734, e734,
    g735, e735, g736, e736, g737, e737, g738, e738, g739, e739, g740, e740, g741, e741, g742, e742,
    g743, e743, g744, e744, g745, e745, g746, e746, g747, e747, g748, e748, g749, e749, g750, e750,
    g751, e751, g752, e752, g753, e753, q0, q1, q2, q3, h⟩ := h
  simp only [Poseidon_2_rw] at h
  obtain ⟨qb, -⟩ := h
  refine ⟨hQ, h0, hX, hY, xS, yS, xE, yE, hS, hE, lS, lE, lEy, pS, pE, hPt, ?_, ?_, ?_, ?_, ?_⟩
  · rw [← q0, ha]; rfl
  · rw [← q1, hc0]; rfl
  · rw [← q2, ← hct]
    have h726 : g726 = packGates ((((List.ofFn c1 ++ List.ofFn c2 ++ List.ofFn c3).take 27).map
        BitVec.toNat).map (Nat.cast : ℕ → F)) := by
      subst e726 e725 e724 e723 e722 e721 e720 e719 e718 e717 e716 e715 e714 e713 e712 e711 e710 e709 e708 e707 e706 e705 e704 e703 e702 e701 e700 e699 e698 e697 e696 e695 e694 e693 e692 e691 e690 e689 e688 e687 e686 e685 e684 e683 e682 e681 e680 e679 e678 e677 e676 e675 e674 e673
      rfl
    have k232 : K_7180 = ((2 ^ 232 : ℕ) : F) := by norm_num [K_7180]
    have k216 : K_5 = ((2 ^ 216 : ℕ) : F) := by norm_num [K_5]
    rw [e727, e671, e672, h726, packGates_cast, hb, hc1, k232, k216]
    simp only [Gates, GatesGnark12, GatesGnark9, GatesGnark8, GatesDef.add, GatesDef.mul, packBytes]
    push_cast
    ring
  · rw [← q3, ← hct]
    have h753 : g753 = packGates ((((List.ofFn c1 ++ List.ofFn c2 ++ List.ofFn c3).drop 27).map
        BitVec.toNat).map (Nat.cast : ℕ → F)) := by
      subst e753 e752 e751 e750 e749 e748 e747 e746 e745 e744 e743 e742 e741 e740 e739 e738 e737 e736 e735 e734 e733 e732 e731 e730 e729 e728
      rfl
    rw [h753, packGates_cast]
    rfl
  · rw [← qb]
    rfl

end ZolanaVE.Envelope
