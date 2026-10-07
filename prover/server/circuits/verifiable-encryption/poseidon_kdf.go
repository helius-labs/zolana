package verifiableencryption

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
)

const (
	DomSepSilo  uint32 = 0x544d5349
	DomSepKey   uint32 = 0x544d534b
	DomSepNonce uint32 = 0x544d534e
)

func KeySchedule(
	api frontend.API,
	sharedSecret frontend.Variable,
	info []byte,
) (key [32]frontend.Variable, nonce [12]frontend.Variable) {
	infoBytes := make([]frontend.Variable, len(info))
	for i, b := range info {
		infoBytes[i] = b
	}
	infoFields := gadget.PackBytesBE(api, infoBytes)

	siloInputs := []frontend.Variable{
		frontend.Variable(uint64(DomSepSilo)),
		sharedSecret,
	}
	siloInputs = append(siloInputs, infoFields...)
	siloed := gadget.PoseidonHash(api, siloInputs)

	keyLo := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepKey)),
		siloed,
	})
	keyHi := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepKey + 1)),
		siloed,
	})

	keyLoBytes := FieldToBytesBE(api, keyLo, 32)
	keyHiBytes := FieldToBytesBE(api, keyHi, 32)
	for i := 0; i < 16; i++ {
		key[i] = keyHiBytes[16+i]
		key[16+i] = keyLoBytes[16+i]
	}

	nonceRaw := gadget.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(uint64(DomSepNonce)),
		siloed,
	})
	nonceBytes := FieldToBytesBE(api, nonceRaw, 32)
	for i := 0; i < 12; i++ {
		nonce[i] = nonceBytes[20+i]
	}

	return key, nonce
}
