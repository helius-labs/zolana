package hosttest

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"fmt"
	"math/big"
)

const maxSearchSteps = 1 << 16

type NamedScalar struct {
	Name   string
	Scalar *big.Int
}

type NamedKeys struct {
	Name string
	Keys Keys
}

func NewKeys(recipientScalar, ephemeralScalar *big.Int) Keys {
	return Keys{RecipientSecret: reducedKey(recipientScalar), EphemeralSecret: reducedKey(ephemeralScalar)}
}

func EdgeCaseScalars() []NamedScalar {
	n := groupOrder()
	one := big.NewInt(1)
	power := func(e uint) *big.Int { return new(big.Int).Lsh(one, e) }
	ratio := func(num, den int64) *big.Int {
		r := new(big.Int).ModInverse(big.NewInt(den), n)
		return r.Mul(r, big.NewInt(num)).Mod(r, n)
	}
	return []NamedScalar{
		{"one", big.NewInt(1)},
		{"two", big.NewInt(2)},
		{"three", big.NewInt(3)},
		{"order minus one", new(big.Int).Sub(n, one)},
		{"order minus two", new(big.Int).Sub(n, big.NewInt(2))},
		{"order minus three", new(big.Int).Sub(n, big.NewInt(3))},
		{"half", new(big.Int).Rsh(new(big.Int).Add(n, one), 1)},
		{"one third", ratio(1, 3)},
		{"three fifths", ratio(3, 5)},
		{"2^128 minus one", new(big.Int).Sub(power(128), one)},
		{"2^128", power(128)},
		{"2^129 plus one", new(big.Int).Add(power(129), one)},
		{"2^255 mod order", new(big.Int).Mod(power(255), n)},
	}
}

// LadderExceptionalScalars are the ephemeral residues the P-256 variable-base
// ladder refuses for every recipient: R = [s]Q collides with its distinct-x
// guards (R vs Q, R vs 3Q, 3R vs Q) exactly when s is +-1, +-3 or +-1/3.
func LadderExceptionalScalars() []*big.Int {
	n := groupOrder()
	third := new(big.Int).ModInverse(big.NewInt(3), n)
	var out []*big.Int
	for _, s := range []*big.Int{big.NewInt(1), big.NewInt(3), third} {
		out = append(out, s, new(big.Int).Sub(n, s))
	}
	return out
}

func IsLadderExceptional(scalar *big.Int) bool {
	reduced := new(big.Int).Mod(scalar, groupOrder())
	for _, e := range LadderExceptionalScalars() {
		if reduced.Cmp(e) == 0 {
			return true
		}
	}
	return false
}

func EdgeCaseKeys() []NamedKeys {
	n := groupOrder()
	defaults := DefaultKeys()
	recipient := new(big.Int).SetBytes(defaults.RecipientSecret.Bytes())
	ephemeral := new(big.Int).SetBytes(defaults.EphemeralSecret.Bytes())
	recipientPublic := defaults.RecipientSecret.PublicKey()
	searchStart := new(big.Int).Add(ephemeral, big.NewInt(1))

	var cases []NamedKeys
	for _, s := range EdgeCaseScalars() {
		cases = append(cases, NamedKeys{"ephemeral " + s.Name, NewKeys(recipient, s.Scalar)})
	}

	recipients := []NamedScalar{
		{"generator", big.NewInt(1)},
		{"negated generator", new(big.Int).Sub(n, big.NewInt(1))},
		{"doubled generator", big.NewInt(2)},
		{"x with leading zero byte", searchScalar(big.NewInt(1), func(k *ecdh.PrivateKey) bool {
			return k.PublicKey().Bytes()[1] == 0
		})},
		{"y with leading zero byte", searchScalar(big.NewInt(1), func(k *ecdh.PrivateKey) bool {
			return k.PublicKey().Bytes()[33] == 0
		})},
		{"even y", searchScalar(big.NewInt(4), func(k *ecdh.PrivateKey) bool {
			return k.PublicKey().Bytes()[64]&1 == 0
		})},
		{"odd y", searchScalar(big.NewInt(4), func(k *ecdh.PrivateKey) bool {
			return k.PublicKey().Bytes()[64]&1 == 1
		})},
		{"equal to ephemeral public key", ephemeral},
	}
	for _, r := range recipients {
		cases = append(cases, NamedKeys{"recipient " + r.Name, NewKeys(r.Scalar, ephemeral)})
	}

	sharedByte := func(index int, value byte) func(*ecdh.PrivateKey) bool {
		return func(k *ecdh.PrivateKey) bool {
			shared, err := k.ECDH(recipientPublic)
			if err != nil {
				panic(err)
			}
			return shared[index] == value
		}
	}
	pairs := []NamedKeys{
		{"shared x with leading zero byte", NewKeys(recipient, searchScalar(searchStart, sharedByte(0, 0)))},
		{"shared x with trailing zero byte", NewKeys(recipient, searchScalar(searchStart, sharedByte(31, 0)))},
		{"ephemeral x with leading zero byte", NewKeys(recipient, searchScalar(searchStart, func(k *ecdh.PrivateKey) bool {
			return k.PublicKey().Bytes()[1] == 0
		}))},
		{"ephemeral one to generator", NewKeys(big.NewInt(1), big.NewInt(1))},
		{"ephemeral order minus one to generator", NewKeys(big.NewInt(1), new(big.Int).Sub(n, big.NewInt(1)))},
	}
	return append(cases, pairs...)
}

func groupOrder() *big.Int {
	return elliptic.P256().Params().N
}

func reducedKey(scalar *big.Int) *ecdh.PrivateKey {
	reduced := new(big.Int).Mod(scalar, groupOrder())
	if reduced.Sign() == 0 {
		panic(fmt.Sprintf("hosttest: scalar %x reduces to zero modulo the group order", scalar))
	}
	var bytes [32]byte
	reduced.FillBytes(bytes[:])
	return mustKey(bytes)
}

func searchScalar(start *big.Int, accept func(*ecdh.PrivateKey) bool) *big.Int {
	s := new(big.Int).Set(start)
	for range maxSearchSteps {
		if accept(reducedKey(s)) {
			return s
		}
		s.Add(s, big.NewInt(1))
	}
	panic(fmt.Sprintf("hosttest: no scalar from %x within %d steps", start, maxSearchSteps))
}
