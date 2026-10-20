package custom_ring

import (
	"crypto/ecdh"
	"fmt"
)

// The base circuit binds ciphertext plaintext to one X25519 key encoding.
// Reject aliases here before constructing an expensive witness.
func validateX25519ViewingSecret(secret []byte, name string) error {
	if len(secret) != 32 || secret[0]&7 != 0 || secret[31]&0xc0 != 0x40 {
		return fmt.Errorf("custom-ring: %s is not a canonical X25519 viewing secret", name)
	}
	return nil
}

// Reject encoding aliases and noncontributory keys before building a witness.
// The circuit independently enforces these requirements.
func validateX25519Point(key []byte, name string) error {
	if len(key) != 32 || key[31] > 127 {
		return fmt.Errorf("custom-ring: invalid %s", name)
	}
	canonical := false
	for i := 31; i >= 0; i-- {
		bound := byte(255)
		if i == 31 {
			bound = 127
		}
		if i == 0 {
			bound = 237
		}
		if key[i] < bound {
			canonical = true
			break
		}
		if key[i] > bound {
			break
		}
	}
	if !canonical {
		return fmt.Errorf("custom-ring: noncanonical %s", name)
	}
	pub, err := ecdh.X25519().NewPublicKey(key)
	if err != nil {
		return err
	}
	secret, _ := ecdh.X25519().NewPrivateKey(make([]byte, 32))
	if _, err := secret.ECDH(pub); err != nil {
		return fmt.Errorf("custom-ring: noncontributory %s", name)
	}
	return nil
}
