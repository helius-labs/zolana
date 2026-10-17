package base

import (
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// auditStreamKeySchedule extracts 44 canonical bytes from two domain-separated
// Poseidon outputs. The first contributes 31 bytes and the second 13 bytes.
// This is scoped to auditor envelopes. Other encrypted ring data keeps its KDF.
func auditStreamKeySchedule(api frontend.API, secret frontend.Variable) (key [32]frontend.Variable, nonce [12]frontend.Variable) {
	tag := func(counter byte) *big.Int {
		return new(big.Int).SetBytes(append([]byte(auditEncInfo), counter))
	}
	head := canonicalBytes(api, gadget.PoseidonHash(api, []frontend.Variable{tag(0), secret}))
	tail := canonicalBytes(api, gadget.PoseidonHash(api, []frontend.Variable{tag(1), secret}))
	copy(key[:31], head[1:])
	key[31] = tail[19]
	copy(nonce[:], tail[20:])
	return
}
