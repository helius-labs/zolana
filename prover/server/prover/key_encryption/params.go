package keyencryption

import "math/big"

// RecipientKeyParams is one recovery or auditor recipient: the 65-byte
// uncompressed P-256 point (0x04 || x || y) the shared secret is encrypted to.
type RecipientKeyParams struct {
	Pubkey [65]*big.Int
}

// KeyEncryptionParameters is the flat, pre-computed witness for the squads key
// encryption circuit. The prover does no hashing/encryption: the client
// computes the public-input hash, ciphertexts, and commitments and sends the
// secrets/keys here. NumKeys is the recovery + auditor recipient count.
type KeyEncryptionParameters struct {
	NumKeys uint32

	OldStateHash *big.Int
	// ViewingSecretKey is the shared viewing scalar (P-256 Fr).
	ViewingSecretKey *big.Int
	// EphemeralSecretKey is the single ephemeral scalar (full-range P-256 Fr).
	EphemeralSecretKey *big.Int
	NullifierSecret    *big.Int

	RecipientKeys []RecipientKeyParams

	PublicInputHash *big.Int
}
