package gadget

import "github.com/consensys/gnark/frontend"

// DisclosurePad is Poseidon(seed, j) for field j over seed = Poseidon(domain, key0, key1, salt), a salt reused under one key repeats the pad.
func DisclosurePad(api frontend.API, domain uint64, key [2]frontend.Variable, salt frontend.Variable, n int) []frontend.Variable {
	seed := PoseidonHash(api, []frontend.Variable{domain, key[0], key[1], salt})
	pad := make([]frontend.Variable, n)
	for i := range pad {
		pad[i] = PoseidonHash(api, []frontend.Variable{seed, i})
	}
	return pad
}
