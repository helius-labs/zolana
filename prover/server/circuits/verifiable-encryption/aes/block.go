// Package aes implements AES-256 block cipher circuit for gnark.
package aes

import (
	"github.com/consensys/gnark/frontend"
)

// AES256Block encrypts a 16-byte plaintext block with a 32-byte key.
// Creates a standalone AESGadget internally. For multiple AES calls in the
// same circuit, use NewAESGadget + AES256BlockWithGadget to share tables.
func AES256Block(api frontend.API, plaintext [16]frontend.Variable, key [32]frontend.Variable) [16]frontend.Variable {
	g := NewAESGadget(api)
	return g.Encrypt(key[:], plaintext)
}

// AES256BlockWithGadget encrypts a 16-byte plaintext block using a shared
// AESGadget. This avoids allocating duplicate lookup tables when multiple
// AES calls share the same circuit.
func AES256BlockWithGadget(g *AESGadget, plaintext [16]frontend.Variable, key []frontend.Variable) [16]frontend.Variable {
	return g.Encrypt(key, plaintext)
}
