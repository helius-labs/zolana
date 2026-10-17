package gadget

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// PoseidonCtr is counter mode over the scalar field: element i of a plaintext
// is added to the pad Poseidon(Domain, Key, Nonce, i). It is the second CTR
// variant of Rotaru, Smart and Stam (ToSC 2017, Section 4.1) with Poseidon as
// the PRF and the counter inside the PRF input, so no index needs to be
// non-zero. The recipient recomputes the pad from Key and the published Nonce.
//
// The gadget has no MAC. A caller places the ciphertext in its public-input
// hash, and the recipient checks the decrypted plaintext against a commitment. Nonce must
// be a public input and fresh per attempt: two ciphertexts under one (Key,
// Nonce) publish the difference of their plaintexts.
type PoseidonCtr struct {
	// 4-byte ASCII tag, one per use of the gadget.
	Domain uint32
	Key    frontend.Variable
	Nonce  frontend.Variable
}

// Encrypt returns ciphertext[i] = plaintext[i] + Poseidon(Domain, Key, Nonce, i).
func (c PoseidonCtr) Encrypt(api frontend.API, plaintext []frontend.Variable) []frontend.Variable {
	if len(plaintext) == 0 {
		return nil
	}
	return abstractor.Call1(api, PoseidonCtrGadget{
		Domain:    uint64(c.Domain),
		Key:       c.Key,
		Nonce:     c.Nonce,
		Plaintext: plaintext,
	})
}

// PoseidonCtrGadget is Encrypt as an abstractor gadget, so Lean extraction
// names one def per plaintext length; abstractor.Call1 is a passthrough on a
// real builder.
type PoseidonCtrGadget struct {
	Domain    frontend.Variable
	Key       frontend.Variable
	Nonce     frontend.Variable
	Plaintext []frontend.Variable
}

func (g PoseidonCtrGadget) DefineGadget(api frontend.API) interface{} {
	ciphertext := make([]frontend.Variable, len(g.Plaintext))
	for i, element := range g.Plaintext {
		pad := PoseidonHash(api, []frontend.Variable{g.Domain, g.Key, g.Nonce, i})
		ciphertext[i] = api.Add(element, pad)
	}
	return ciphertext
}
