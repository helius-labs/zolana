package aes

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/prover/prover-test/hintattack"
)

type reusableCipherCircuit struct {
	Key        [32]frontend.Variable
	Nonce      [2][12]frontend.Variable
	Plaintext  [2][16]frontend.Variable
	Ciphertext [2][16]frontend.Variable `gnark:",public"`
	reuse      bool
}

func (c *reusableCipherCircuit) Define(api frontend.API) error {
	var cipher *Cipher
	if c.reuse {
		cipher = NewCipher(api, c.Key)
	}
	for stream := range c.Nonce {
		var ciphertext []frontend.Variable
		if c.reuse {
			ciphertext = cipher.CTREncrypt(c.Nonce[stream], c.Plaintext[stream][:])
		} else {
			ciphertext = NewCipher(api, c.Key).CTREncrypt(c.Nonce[stream], c.Plaintext[stream][:])
		}
		for i, b := range ciphertext {
			api.AssertIsEqual(b, c.Ciphertext[stream][i])
		}
	}
	return nil
}

func TestCipherReusesKeyExpansionAcrossStreams(t *testing.T) {
	key := ctrPattern(32, 0xa5)
	w := &reusableCipherCircuit{}
	copy(w.Key[:], toVariables(key))
	for i := range w.Nonce {
		nonce, plain := ctrPattern(12, byte(i)), ctrPattern(16, byte(i+1))
		copy(w.Nonce[i][:], toVariables(nonce))
		copy(w.Plaintext[i][:], toVariables(plain))
		copy(w.Ciphertext[i][:], toVariables(hostCtr(t, key, nonce, plain)))
	}
	var counts [2]int
	for i, reuse := range []bool{false, true} {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &reusableCipherCircuit{reuse: reuse})
		if err != nil {
			t.Fatal(err)
		}
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); err != nil {
			t.Fatal(err)
		}
		counts[i] = cs.GetNbConstraints()
		for stream := range w.Ciphertext {
			honest := w.Ciphertext[stream][15]
			w.Ciphertext[stream][15] = honest.(byte) ^ 1
			witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			hintattack.RequireConstraintRejection(t, cs.IsSolved(witness))
			w.Ciphertext[stream][15] = honest
		}
	}
	if counts[1] >= counts[0] {
		t.Fatalf("key expansion reuse did not save constraints: separate %d, reused %d", counts[0], counts[1])
	}
	t.Logf("two streams: separate %d constraints, reused %d, saved %d", counts[0], counts[1], counts[0]-counts[1])
}
