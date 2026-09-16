package transcript

import (
	"errors"
	"fmt"
	"hash"
	"math"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativeposeidon "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	cryptohash "github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	fieldhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// Experimental transcript adapter; its composition has not been audited.
const Name = "ZOLANA-GKR-P2-W16-R14-C2-V1"

const defaultWidth, capacity = 16, 2

var widths = [...]int{4, 8, 12, 16}

var registerOnce sync.Once

func Register() {
	registerOnce.Do(func() {
		for _, width := range widths {
			name := NameForWidth(width)
			fieldhash.RegisterCustomHash(name, func(api frontend.API) (fieldhash.FieldHasher, error) {
				return NewWithWidth(api, width)
			})
			cryptohash.RegisterCustomHash(name+"_BN254", func() hash.Hash {
				return NewNativeWithWidth(width)
			})
		}
	})
}

func partialRounds(width int) int {
	switch width {
	case 4:
		return 56
	case 8, 12, 16:
		return 57
	default:
		panic("unsupported wide transcript width")
	}
}

func NameForWidth(width int) string {
	partialRounds(width)
	return fmt.Sprintf("ZOLANA-GKR-P2-W%d-R%d-C2-V1", width, width-capacity)
}

type sponge[T any] struct {
	state   [defaultWidth]T
	width   int
	rate    int
	domain  T
	zero    T
	add     func(T, T) T
	integer func(uint64) T
	permute func([]T)
	used    int
	count   uint64
}

func (s *sponge[T]) reset() {
	for i := range s.state {
		s.state[i] = s.zero
	}
	s.state[s.rate] = s.domain
	s.used, s.count = 0, 0
}

func (s *sponge[T]) absorb(value T) {
	s.state[s.used] = s.add(s.state[s.used], value)
	s.used++
	if s.used == s.rate {
		s.permute(s.state[:s.width])
		s.used = 0
	}
}

func (s *sponge[T]) write(values []T) error {
	if uint64(len(values)) > math.MaxUint64-s.count {
		return errors.New("transcript field count overflow")
	}
	for _, value := range values {
		s.absorb(value)
	}
	s.count += uint64(len(values))
	return nil
}

func (s *sponge[T]) sum() T {
	final := *s
	final.absorb(final.integer(1))
	for final.used != final.rate-1 {
		final.absorb(final.zero)
	}
	final.absorb(final.integer(s.count))
	return final.state[0]
}

type circuitHasher struct {
	sponge[frontend.Variable]
}

func New(api frontend.API) (fieldhash.FieldHasher, error) {
	return NewWithWidth(api, defaultWidth)
}

func NewWithWidth(api frontend.API, width int) (fieldhash.FieldHasher, error) {
	if api.Compiler().Field().Cmp(ecc.BN254.ScalarField()) != 0 {
		return nil, errors.New("wide transcript requires BN254")
	}
	p, err := poseidon2.NewPoseidon2FromParameters(api, width, 8, partialRounds(width))
	if err != nil {
		return nil, err
	}
	h := &circuitHasher{sponge[frontend.Variable]{
		width:   width,
		rate:    width - capacity,
		domain:  new(big.Int).SetBytes([]byte(NameForWidth(width))),
		zero:    0,
		add:     func(a, b frontend.Variable) frontend.Variable { return api.Add(a, b) },
		integer: func(value uint64) frontend.Variable { return value },
		permute: func(state []frontend.Variable) {
			if err := p.Permutation(state); err != nil {
				panic(err)
			}
		},
	}}
	h.Reset()
	return h, nil
}

func (h *circuitHasher) Write(values ...frontend.Variable) {
	if err := h.write(values); err != nil {
		panic(err)
	}
}

func (h *circuitHasher) Sum() frontend.Variable { return h.sum() }
func (h *circuitHasher) Reset()                 { h.reset() }

type nativeHasher struct {
	sponge[fr.Element]
}

func NewNative() hash.Hash {
	return NewNativeWithWidth(defaultWidth)
}

func NewNativeWithWidth(width int) hash.Hash {
	p := nativeposeidon.NewPermutation(width, 8, partialRounds(width))
	var domain fr.Element
	domain.SetBigInt(new(big.Int).SetBytes([]byte(NameForWidth(width))))
	h := &nativeHasher{sponge[fr.Element]{
		width:  width,
		rate:   width - capacity,
		domain: domain,
		add: func(a, b fr.Element) fr.Element {
			a.Add(&a, &b)
			return a
		},
		integer: func(value uint64) fr.Element {
			var result fr.Element
			result.SetUint64(value)
			return result
		},
		permute: func(state []fr.Element) {
			if err := p.Permutation(state); err != nil {
				panic(err)
			}
		},
	}}
	h.Reset()
	return h
}

// Write accepts canonical field records and GKR's single-byte zero separator.
func (h *nativeHasher) Write(data []byte) (int, error) {
	if len(data) == 1 && data[0] == 0 {
		if err := h.write([]fr.Element{{}}); err != nil {
			return 0, err
		}
		return 1, nil
	}
	if len(data)%fr.Bytes != 0 {
		return 0, errors.New("transcript requires complete field records")
	}
	values := make([]fr.Element, len(data)/fr.Bytes)
	for i := range values {
		if err := values[i].SetBytesCanonical(data[i*fr.Bytes : (i+1)*fr.Bytes]); err != nil {
			return 0, err
		}
	}
	if err := h.write(values); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (h *nativeHasher) Sum(prefix []byte) []byte {
	result := h.sum()
	encoded := result.Bytes()
	return append(prefix, encoded[:]...)
}

func (h *nativeHasher) Reset()         { h.reset() }
func (h *nativeHasher) Size() int      { return fr.Bytes }
func (h *nativeHasher) BlockSize() int { return fr.Bytes }
