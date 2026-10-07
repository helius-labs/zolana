package hintattack

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/consensys/gnark/constraint/solver"
)

const (
	ScalarMulHint       = "/sw_emulated.scalarMulHint"
	RationalReconstruct = "/sw_emulated.rationalReconstruct"
	UnifiedSlopeHint    = "/sw_emulated.unifiedSlopeHint"
	TangentHintA        = "/sw_emulated.tangentHintA"
	RatioHint           = "/sw_emulated.ratioHint"
	CombChainLambdaHint = "/sw_emulated.combChainLambdaHint"
	CombRecodeHint      = "/sw_emulated.combRecodeHint"
	NBits               = "/math/bits.nBits"
	DecomposeHint       = "/rangecheck.DecomposeHint"
	CountHint           = "/logderivarg.countHint"
	InvZeroHint         = "/constraint/solver.InvZeroHint"
	LaneChunksHint      = "/verifiable-encryption/aes.laneChunksHint"
	LowBytesHint        = "/verifiable-encryption.LowBytesHint"
	PolyMvHint          = "/math/emulated.polyMvHint"
	MulHint             = "/math/emulated.mulHint"
)

const (
	laneChunkRadix = 1296
	byteRadix      = 256
)

type Forge func(mod *big.Int, inputs, outputs []*big.Int) error

type HintAttack struct {
	Name  string
	Hint  string
	Forge Forge
}

func HintAttacks() []HintAttack {
	attacks := []HintAttack{
		{"scalar mul result zero", ScalarMulHint, forgeScalarMul(func(p, x, y, px, py *big.Int) (*big.Int, *big.Int) {
			return new(big.Int), new(big.Int)
		})},
		{"scalar mul result mirrored", ScalarMulHint, forgeScalarMul(func(p, x, y, px, py *big.Int) (*big.Int, *big.Int) {
			return x, negate(p, y)
		})},
		{"scalar mul result equals input point", ScalarMulHint, forgeScalarMul(func(p, x, y, px, py *big.Int) (*big.Int, *big.Int) {
			return px, py
		})},
		{"scalar mul result equals negated input point", ScalarMulHint, forgeScalarMul(func(p, x, y, px, py *big.Int) (*big.Int, *big.Int) {
			return px, negate(p, py)
		})},
		{"scalar mul result off curve", ScalarMulHint, forgeScalarMul(func(p, x, y, px, py *big.Int) (*big.Int, *big.Int) {
			return new(big.Int).Add(x, big.NewInt(1)), y
		})},
		{"scalar mul result x plus modulus", ScalarMulHint, forgeScalarMul(func(p, x, y, px, py *big.Int) (*big.Int, *big.Int) {
			return new(big.Int).Add(x, p), y
		})},
		{"rational reconstruction halves zero", RationalReconstruct, forgeReconstruction(func(n *big.Int, sign *big.Int, s1, s2 []*big.Int, bits uint) {
			setLimbs(s1, bits, new(big.Int))
			setLimbs(s2, bits, new(big.Int))
		})},
		{"rational reconstruction sign flipped", RationalReconstruct, forgeReconstruction(func(n *big.Int, sign *big.Int, s1, s2 []*big.Int, bits uint) {
			sign.Sub(big.NewInt(1), sign)
		})},
		{"rational reconstruction s2 low limb plus one", RationalReconstruct, forgeReconstruction(func(n *big.Int, sign *big.Int, s1, s2 []*big.Int, bits uint) {
			s2[0].Add(s2[0], big.NewInt(1))
		})},
	}
	for _, slope := range []struct{ name, hint string }{
		{"unified slope", UnifiedSlopeHint},
		{"tangent slope", TangentHintA},
		{"ratio", RatioHint},
		{"comb chain slope", CombChainLambdaHint},
	} {
		attacks = append(attacks,
			HintAttack{slope.name + " plus one", slope.hint, forgeSlope(func(v *big.Int) *big.Int { return v.Add(v, big.NewInt(1)) })},
			HintAttack{slope.name + " zero", slope.hint, forgeSlope(func(v *big.Int) *big.Int { return v.SetUint64(0) })},
		)
	}
	return append(attacks,
		HintAttack{"comb recoding first output plus one", CombRecodeHint, forgeFirstOutputPlusOne},
		HintAttack{"bits of value plus field modulus", NBits, forgeNonCanonicalBits},
		HintAttack{"range check first digit plus one", DecomposeHint, forgeFirstOutputPlusOne},
		HintAttack{"range check digit borrows from its upper neighbour", DecomposeHint, forgeDigitBorrow},
		HintAttack{"lookup first multiplicity plus one", CountHint, forgeFirstOutputPlusOne},
		HintAttack{"lookup multiplicity moved to the next entry", CountHint, forgeMovedMultiplicity},
		HintAttack{"inverse of a nonzero value zero", InvZeroHint, forgeInverse(0)},
		HintAttack{"lane chunk borrowed from its upper neighbour", LaneChunksHint, forgeLaneChunks(laneChunkRadix, -1)},
		HintAttack{"lane chunk shifted by one", LaneChunksHint, forgeLaneChunks(1, 0)},
		HintAttack{"lane chunk wrapped below zero", LaneChunksHint, forgeLaneChunks(-laneChunkRadix, 1)},
		HintAttack{"first byte plus one", LowBytesHint, forgeFirstOutputPlusOne},
		HintAttack{"low byte borrows from its upper neighbour", LowBytesHint, forgeByteBorrow},
	)
}

func RunHintAttacks(t *testing.T, solve func(opts ...solver.Option) error) {
	t.Helper()
	if err := solve(); err != nil {
		t.Fatalf("the honest witness is rejected: %v", err)
	}
	start := time.Now()
	attacks := HintAttacks()
	for _, attack := range attacks {
		t.Run(attack.Name, func(t *testing.T) {
			runHintAttack(t, attack, solve)
		})
	}
	t.Logf("%d hint attacks in %s", len(attacks), time.Since(start).Round(time.Millisecond))
}

func runHintAttack(t *testing.T, attack HintAttack, solve func(opts ...solver.Option) error) {
	t.Helper()
	honest, err := registeredHint(attack.Hint)
	if err != nil {
		t.Fatal(err)
	}
	if honest == nil {
		t.Skipf("not applicable: no registered hint ends in %s", attack.Hint)
	}
	forged := &forgedHint{honest: honest, forge: attack.Forge}
	opts := append(append(LenientZeroChecks(), LenientLookupCounts()...), solver.OverrideHint(solver.GetHintID(honest), forged.solve))
	err = solve(opts...)
	calls, forgedCall, forgeErr := forged.report()
	switch {
	case forgeErr != nil:
		t.Fatalf("forging %s: %v", attack.Hint, forgeErr)
	case calls == 0:
		t.Skipf("not applicable: the circuit never calls %s", attack.Hint)
	case forgedCall == 0:
		t.Skipf("not applicable: none of the %d calls to %s qualifies", calls, attack.Hint)
	case err == nil:
		t.Fatalf("accepted: call %d of %d to %s forged", forgedCall, calls, attack.Hint)
	case !strings.Contains(err.Error(), "constraint"):
		t.Fatalf("stopped by a hint, not a constraint: %v", err)
	case strings.Contains(err.Error(), "lookup query too large"):
		t.Logf("call %d of %d forged, refused by the lookup solver before the log-derivative constraint: %v", forgedCall, calls, err)
	default:
		t.Logf("call %d of %d forged, rejected: %v", forgedCall, calls, err)
	}
}

func LenientZeroChecks() []solver.Option {
	return lenientHints(PolyMvHint, MulHint)
}

func LenientLookupCounts() []solver.Option {
	return lenientHints(CountHint)
}

func lenientHints(suffixes ...string) []solver.Option {
	var opts []solver.Option
	for _, suffix := range suffixes {
		honest, err := registeredHint(suffix)
		if err != nil {
			panic(err)
		}
		if honest == nil {
			continue
		}
		opts = append(opts, solver.OverrideHint(solver.GetHintID(honest), lenient(honest)))
	}
	return opts
}

func lenient(honest solver.Hint) solver.Hint {
	return func(mod *big.Int, inputs, outputs []*big.Int) error {
		if err := honest(mod, inputs, outputs); err != nil {
			zero(outputs)
		}
		return nil
	}
}

func registeredHint(suffix string) (solver.Hint, error) {
	var found []solver.Hint
	for _, h := range solver.GetRegisteredHints() {
		if strings.HasSuffix(solver.GetHintName(h), suffix) {
			found = append(found, h)
		}
	}
	switch len(found) {
	case 0:
		return nil, nil
	case 1:
		return found[0], nil
	default:
		names := make([]string, len(found))
		for i, h := range found {
			names[i] = solver.GetHintName(h)
		}
		return nil, fmt.Errorf("hint suffix %s is ambiguous: %v", suffix, names)
	}
}

type forgedHint struct {
	honest solver.Hint
	forge  Forge
	mu     sync.Mutex
	calls  int
	forged int
	err    error
}

func (f *forgedHint) solve(mod *big.Int, inputs, outputs []*big.Int) error {
	honestErr := f.honest(mod, inputs, outputs)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if honestErr != nil {
		if f.forged == 0 {
			return honestErr
		}
		zero(outputs)
		return nil
	}
	if f.forged != 0 {
		return nil
	}
	before := make([]*big.Int, len(outputs))
	for i, o := range outputs {
		before[i] = new(big.Int).Set(o)
	}
	if err := f.forge(mod, inputs, outputs); err != nil {
		f.err = err
		return err
	}
	for i, o := range outputs {
		diff := new(big.Int).Sub(o, before[i])
		if diff.Mod(diff, mod).Sign() != 0 {
			f.forged = f.calls
			break
		}
	}
	return nil
}

func (f *forgedHint) report() (calls, forged int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.forged, f.err
}

func zero(values []*big.Int) {
	for _, v := range values {
		v.SetUint64(0)
	}
}

func negate(p, v *big.Int) *big.Int {
	out := new(big.Int).Neg(v)
	return out.Mod(out, p)
}

func forgeFirstOutputPlusOne(_ *big.Int, _, outputs []*big.Int) error {
	if len(outputs) == 0 {
		return errors.New("no outputs")
	}
	outputs[0].Add(outputs[0], big.NewInt(1))
	return nil
}

func forgeScalarMul(result func(p, x, y, px, py *big.Int) (*big.Int, *big.Int)) Forge {
	return func(_ *big.Int, inputs, outputs []*big.Int) error {
		call, err := unpackEmulated(inputs, outputs)
		if err != nil {
			return err
		}
		if len(call.fields) == 0 {
			return errors.New("scalar mul: no base field")
		}
		base := call.fields[0]
		if len(base.inputs) != 2 || len(base.outputs) != 2 {
			return fmt.Errorf("scalar mul: want a point in and out, got %d inputs and %d outputs", len(base.inputs), len(base.outputs))
		}
		x, y := recompose(base.outputs[0], base.bits), recompose(base.outputs[1], base.bits)
		rx, ry := result(base.modulus, x, y, base.inputs[0], base.inputs[1])
		setLimbs(base.outputs[0], base.bits, rx)
		setLimbs(base.outputs[1], base.bits, ry)
		return nil
	}
}

func forgeReconstruction(forge func(n *big.Int, sign *big.Int, s1, s2 []*big.Int, bits uint)) Forge {
	return func(_ *big.Int, inputs, outputs []*big.Int) error {
		call, err := unpackEmulated(inputs, outputs)
		if err != nil {
			return err
		}
		if len(call.native) != 1 || len(call.fields) == 0 || len(call.fields[0].outputs) != 2 {
			return errors.New("rational reconstruction: want a sign and two half scalars")
		}
		scalar := call.fields[0]
		forge(scalar.modulus, call.native[0], scalar.outputs[0], scalar.outputs[1], scalar.bits)
		return nil
	}
}

func forgeSlope(forge func(v *big.Int) *big.Int) Forge {
	return func(_ *big.Int, inputs, outputs []*big.Int) error {
		call, err := unpackEmulated(inputs, outputs)
		if err != nil {
			return err
		}
		if len(call.native) != 0 || len(call.fields) == 0 || len(call.fields[0].outputs) != 1 {
			return errors.New("slope: want a single emulated output")
		}
		field := call.fields[0]
		setLimbs(field.outputs[0], field.bits, forge(recompose(field.outputs[0], field.bits)))
		return nil
	}
}

func forgeNonCanonicalBits(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 1 {
		return fmt.Errorf("bits: want one input, got %d", len(inputs))
	}
	shifted := new(big.Int).Add(inputs[0], mod)
	if shifted.BitLen() > len(outputs) {
		return nil
	}
	for i, o := range outputs {
		o.SetUint64(uint64(shifted.Bit(i)))
	}
	return nil
}

func forgeDigitBorrow(mod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 || !inputs[1].IsUint64() {
		return errors.New("range check: want the bit length, the digit width and the value")
	}
	if len(outputs) < 2 || outputs[1].Sign() == 0 {
		return nil
	}
	base := new(big.Int).Lsh(big.NewInt(1), uint(inputs[1].Uint64()))
	outputs[0].Add(outputs[0], base)
	outputs[1].Sub(outputs[1], big.NewInt(1))
	return nil
}

func forgeMovedMultiplicity(_ *big.Int, _, outputs []*big.Int) error {
	if len(outputs) < 2 {
		return nil
	}
	for i, o := range outputs {
		if o.Sign() > 0 {
			next := outputs[(i+1)%len(outputs)]
			o.Sub(o, big.NewInt(1))
			next.Add(next, big.NewInt(1))
			return nil
		}
	}
	return nil
}

func forgeInverse(value uint64) Forge {
	return func(mod *big.Int, inputs, outputs []*big.Int) error {
		if len(inputs) != 1 || len(outputs) != 1 {
			return errors.New("inverse: want one input and one output")
		}
		if new(big.Int).Mod(inputs[0], mod).Sign() == 0 {
			return nil
		}
		outputs[0].SetUint64(value)
		return nil
	}
}

func forgeLaneChunks(low, high int64) Forge {
	return func(mod *big.Int, _, outputs []*big.Int) error {
		if len(outputs) < 2 {
			return nil
		}
		outputs[0].Add(outputs[0], big.NewInt(low)).Mod(outputs[0], mod)
		outputs[1].Add(outputs[1], big.NewInt(high)).Mod(outputs[1], mod)
		return nil
	}
}

func forgeByteBorrow(_ *big.Int, _, outputs []*big.Int) error {
	n := len(outputs)
	if n < 2 || outputs[n-2].Sign() == 0 {
		return nil
	}
	outputs[n-1].Add(outputs[n-1], big.NewInt(byteRadix))
	outputs[n-2].Sub(outputs[n-2], big.NewInt(1))
	return nil
}

type emulatedField struct {
	modulus *big.Int
	bits    uint
	inputs  []*big.Int
	outputs [][]*big.Int
}

type emulatedCall struct {
	native []*big.Int
	fields []emulatedField
}

type cursor struct {
	values []*big.Int
	pos    int
}

func (c *cursor) next() (int, error) {
	if c.pos >= len(c.values) || !c.values[c.pos].IsInt64() {
		return 0, fmt.Errorf("emulated hint: no small integer at %d", c.pos)
	}
	v := int(c.values[c.pos].Int64())
	c.pos++
	return v, nil
}

func (c *cursor) take(n int) ([]*big.Int, error) {
	if n < 0 || c.pos+n > len(c.values) {
		return nil, fmt.Errorf("emulated hint: %d values at %d overrun %d", n, c.pos, len(c.values))
	}
	v := c.values[c.pos : c.pos+n]
	c.pos += n
	return v, nil
}

func unpackEmulated(inputs, outputs []*big.Int) (emulatedCall, error) {
	in := &cursor{values: inputs}
	out := &cursor{values: outputs}
	var header [6]int
	for i := range header {
		v, err := in.next()
		if err != nil {
			return emulatedCall{}, err
		}
		header[i] = v
	}
	if _, err := in.take(header[0]); err != nil {
		return emulatedCall{}, err
	}
	native, err := out.take(header[1])
	if err != nil {
		return emulatedCall{}, err
	}
	call := emulatedCall{native: native}
	for _, counts := range [][2]int{{header[2], header[3]}, {header[4], header[5]}} {
		if in.pos+2 > len(inputs) {
			break
		}
		field, err := unpackEmulatedField(in, out, counts[0], counts[1])
		if err != nil {
			return emulatedCall{}, err
		}
		call.fields = append(call.fields, field)
	}
	if in.pos != len(inputs) || out.pos != len(outputs) {
		return emulatedCall{}, fmt.Errorf("emulated hint: read %d of %d inputs and %d of %d outputs", in.pos, len(inputs), out.pos, len(outputs))
	}
	return call, nil
}

func unpackEmulatedField(in, out *cursor, nbInputs, nbOutputs int) (emulatedField, error) {
	nbLimbs, err := in.next()
	if err != nil {
		return emulatedField{}, err
	}
	nbBits, err := in.next()
	if err != nil {
		return emulatedField{}, err
	}
	modulus, err := in.take(nbLimbs)
	if err != nil {
		return emulatedField{}, err
	}
	field := emulatedField{modulus: recompose(modulus, uint(nbBits)), bits: uint(nbBits)}
	for range nbInputs {
		n, err := in.next()
		if err != nil {
			return emulatedField{}, err
		}
		limbs, err := in.take(n)
		if err != nil {
			return emulatedField{}, err
		}
		field.inputs = append(field.inputs, recompose(limbs, field.bits))
	}
	for range nbOutputs {
		limbs, err := out.take(nbLimbs)
		if err != nil {
			return emulatedField{}, err
		}
		field.outputs = append(field.outputs, limbs)
	}
	return field, nil
}

func recompose(limbs []*big.Int, bits uint) *big.Int {
	v := new(big.Int)
	for i := len(limbs) - 1; i >= 0; i-- {
		v.Lsh(v, bits).Add(v, limbs[i])
	}
	return v
}

func setLimbs(limbs []*big.Int, bits uint, v *big.Int) {
	rest := new(big.Int).Set(v)
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), bits), big.NewInt(1))
	for i, limb := range limbs {
		if i == len(limbs)-1 {
			limb.Set(rest)
			return
		}
		limb.And(rest, mask)
		rest.Rsh(rest, bits)
	}
}
