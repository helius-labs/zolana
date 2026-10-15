package custom_ring

import (
	"crypto/ecdh"
	"fmt"
)

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
