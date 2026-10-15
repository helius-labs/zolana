package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/x25519"
	"math/big"
)

// AgreeAuditKey binds the same clamped secret to its public key and DH result.
// Application keys have one canonical encoding, although the RFC gadget itself
// accepts aliases. Tagged keys retain the existing 33-byte transcript packing.
// The raw shared secret retains its 31-byte/remainder packing.
// Input bytes, canonical recipient coordinates and nonzero DH are constrained.
// The caller must authenticate the recipient and bind these outputs into its KDF
// and public statement. This relation cannot prove randomness or nonce freshness.
func AgreeAuditKey(api frontend.API, secret, recipient [32]frontend.Variable) (auditor, ephemeral [33]frontend.Variable, shared [32]frontend.Variable) {
	// 1. Reject recipient aliases before they can enter the application transcript.
	var bits []frontend.Variable
	var bound [256]frontend.Variable
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	for _, b := range recipient {
		bits = append(bits, api.ToBinary(b, 8)...)
	}
	for i := range bound {
		bound[i] = p.Bit(i)
	}
	api.AssertIsEqual(cmp.IsLessBinary(api, bits, bound[:]), 1)
	// 2. Prove nonzero DH and the ephemeral public key from the same clamped scalar.
	shared = x25519.ECDH(api, secret, recipient)
	pub := x25519.ScalarMulGenerator(api, secret)
	// 3. Preserve the tagged key format used by the transcript and host implementations.
	auditor[0], ephemeral[0] = 4, 4
	copy(auditor[1:], recipient[:])
	copy(ephemeral[1:], pub[:])
	return
}
