package gadget

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkrapi"
	"github.com/consensys/gnark/std/gkrapi/gkr"
)

type GKRCompressor struct {
	circuit *gkrapi.Circuit
	inputs  [3]gkr.Variable
	output  gkr.Variable
}

func NewGKRCompressor(api frontend.API) (*GKRCompressor, error) {
	return NewGKRCompressorWithTranscript(api, "POSEIDON2")
}

func NewGKRCompressorWithTranscript(api frontend.API, transcript string) (*GKRCompressor, error) {
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		return nil, fmt.Errorf("legacy Poseidon GKR requires BN254")
	}
	g, err := gkrapi.New(api)
	if err != nil {
		return nil, err
	}
	inputs := [3]gkr.Variable{g.NewInput(), g.NewInput(), g.NewInput()}
	state := inputs
	constants := elemsToBigInt(iden3C.c[1])
	sparse := elemsToBigInt(iden3C.s[1])
	matrix := elems2DToBigInt(iden3C.m[1])
	transition := elems2DToBigInt(iden3C.p[1])
	partial := nRoundsP[1]
	for i := range state {
		state[i] = g.Gate(addConstant(constants[i]), state[i])
	}
	fullRound := func(ark []*big.Int, m [][]*big.Int, outputs int) {
		previous := state
		for i := 0; i < outputs; i++ {
			state[i] = g.Gate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
				result := frontend.Variable(0)
				for j := range in {
					power := powerFive(api, in[j])
					if ark != nil {
						power = api.Add(power, ark[j])
					}
					result = api.Add(result, api.Mul(m[j][i], power))
				}
				return result
			}, previous[:]...)
		}
	}
	for i := 0; i < nRoundsF/2-1; i++ {
		fullRound(constants[(i+1)*3:(i+2)*3], matrix, 3)
	}
	fullRound(constants[(nRoundsF/2)*3:(nRoundsF/2+1)*3], transition, 3)
	state = scalarPartialRounds(g, state, sparse, constants[(nRoundsF/2+1)*3:(nRoundsF/2+1)*3+partial])
	for i := 0; i < nRoundsF/2-1; i++ {
		start := (nRoundsF/2+1)*3 + partial + i*3
		fullRound(constants[start:start+3], matrix, 3)
	}
	fullRound(nil, matrix, 1)
	circuit, err := g.Compile(transcript)
	if err != nil {
		return nil, err
	}
	return &GKRCompressor{circuit: circuit, inputs: inputs, output: state[0]}, nil
}

func (c *GKRCompressor) Compress(left, right frontend.Variable) frontend.Variable {
	outputs, err := c.circuit.AddInstance(map[gkr.Variable]frontend.Variable{c.inputs[0]: 0, c.inputs[1]: left, c.inputs[2]: right})
	if err != nil {
		panic(err)
	}
	return outputs[c.output]
}

func powerFive(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
	square := api.Mul(input[0], input[0])
	return api.Mul(square, square, input[0])
}

func addConstant(constant *big.Int) gkr.GateFunction {
	return func(api gkr.GateAPI, input ...frontend.Variable) frontend.Variable {
		return api.Add(input[0], constant)
	}
}

// Consecutive sparse rows eliminate the two linear lanes, leaving a three-step scalar recurrence.
func scalarPartialRounds(g *gkrapi.API, state [3]gkr.Variable, sparse, ark []*big.Int) [3]gkr.Variable {
	modulus := ecc.BN254.ScalarField()
	add := func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), modulus) }
	mul := func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), modulus) }
	sub := func(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), modulus) }
	row := func(r int) []*big.Int { return sparse[5*r : 5*r+5] }
	dot := func(a, b []*big.Int) *big.Int { return add(mul(a[1], b[3]), mul(a[2], b[4])) }
	coefficients := func(a, b []*big.Int, left, right *big.Int) (*big.Int, *big.Int) {
		determinant := sub(mul(a[1], b[2]), mul(a[2], b[1]))
		inverse := new(big.Int).ModInverse(determinant, modulus)
		if inverse == nil {
			panic("Poseidon partial rows are linearly dependent")
		}
		return mul(sub(mul(left, b[2]), mul(right, b[1])), inverse),
			mul(sub(mul(right, a[1]), mul(left, a[2])), inverse)
	}
	f := func(api gkr.GateAPI, value frontend.Variable, r int) frontend.Variable {
		return api.Add(powerFive(api, value), ark[r])
	}
	x := []gkr.Variable{state[0]}
	x = append(x, g.Gate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		a := row(0)
		return api.Add(api.Mul(a[0], f(api, in[0], 0)), api.Mul(a[1], in[1]), api.Mul(a[2], in[2]))
	}, state[:]...))
	x = append(x, g.Gate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
		a, b := row(1), row(0)
		return api.Add(api.Mul(a[0], f(api, in[0], 1)), api.Mul(dot(a, b), f(api, in[1], 0)), api.Mul(a[1], in[2]), api.Mul(a[2], in[3]))
	}, x[1], x[0], state[1], state[2]))
	for r := 2; r < len(ark); r++ {
		a, b, c := row(r), row(r-1), row(r-2)
		alpha, beta := coefficients(b, c, a[1], a[2])
		previous := add(mul(alpha, sub(dot(b, b), b[0])), mul(beta, dot(c, b)))
		older := mul(beta, sub(dot(c, c), c[0]))
		x = append(x, g.Gate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			return api.Add(api.Mul(a[0], f(api, in[0], r)), api.Mul(alpha, in[0]), api.Mul(beta, in[1]),
				api.Mul(previous, f(api, in[1], r-1)), api.Mul(older, f(api, in[2], r-2)))
		}, x[r], x[r-1], x[r-2]))
	}
	r := len(ark)
	state[0] = x[r]
	for i := 1; i < 3; i++ {
		left, right := big.NewInt(0), big.NewInt(0)
		if i == 1 {
			left.SetInt64(1)
		} else {
			right.SetInt64(1)
		}
		a, b := row(r-1), row(r-2)
		alpha, beta := coefficients(a, b, left, right)
		previous := add(mul(alpha, sub(dot(a, a), a[0])), mul(beta, dot(b, a)))
		older := mul(beta, sub(dot(b, b), b[0]))
		state[i] = g.Gate(func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			return api.Add(api.Mul(alpha, in[0]), api.Mul(beta, in[1]),
				api.Mul(previous, f(api, in[1], r-1)), api.Mul(older, f(api, in[2], r-2)))
		}, x[r], x[r-1], x[r-2])
	}
	return state
}
