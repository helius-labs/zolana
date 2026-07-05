package keyencryption

import (
	kecircuit "zolana/prover/circuits/squads/key_encryption"

	"github.com/consensys/gnark/std/math/emulated"
)

// CreateWitness assigns the pre-computed parameters onto the squads key
// encryption circuit. It performs no hashing/encryption — every signal is taken
// verbatim from the client-supplied params.
func (p *KeyEncryptionParameters) CreateWitness() (*kecircuit.Circuit, error) {
	circuit := kecircuit.NewKeyEncryptionCircuit(int(p.NumKeys))

	circuit.OldStateHash = p.OldStateHash
	circuit.ViewingSecretKey = emulated.ValueOf[emulated.P256Fr](p.ViewingSecretKey)
	circuit.EphemeralSecretKey = emulated.ValueOf[emulated.P256Fr](p.EphemeralSecretKey)
	circuit.NullifierSecret = p.NullifierSecret
	circuit.PublicInputHash = p.PublicInputHash

	for i := range p.RecipientKeys {
		for j := 0; j < 65; j++ {
			circuit.RecipientKeys[i].Pubkey[j] = p.RecipientKeys[i].Pubkey[j]
		}
	}

	return circuit, nil
}
