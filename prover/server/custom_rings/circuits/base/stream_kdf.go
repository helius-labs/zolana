package base

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// auditStreamKeySchedule draws the AES-256 key and CTR nonce from the low canonical bytes of Poseidon(auditEncInfo ‖ 0, secret) and Poseidon(auditEncInfo ‖ 1, secret).
func auditStreamKeySchedule(api frontend.API, secret frontend.Variable) (key [32]frontend.Variable, nonce [12]frontend.Variable) {
	rc := rangecheck.New(api)
	tag := func(counter byte) *big.Int {
		return new(big.Int).SetBytes(append([]byte(auditEncInfo), counter))
	}
	head := gadget.FieldLowBytesBE(api, rc, gadget.PoseidonHash(api, []frontend.Variable{tag(0), secret}), 31)
	tail := gadget.FieldLowBytesBE(api, rc, gadget.PoseidonHash(api, []frontend.Variable{tag(1), secret}), 13)
	copy(key[:31], head)
	key[31] = tail[0]
	copy(nonce[:], tail[1:])
	return
}
