package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"

	"zolana/prover/circuits/gadget"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/circuits/verifiable-encryption/aes"
	"zolana/prover/circuits/verifiable-encryption/p256"
)

const CountersDisclosureDomain = "CRING/spend-counters/v1"

type successorCounters struct {
	salt   frontend.Variable
	assets [NVelocityAssets]frontend.Variable
	spent  [NVelocityAssets]frontend.Variable
}

func (s successorCounters) encrypt(api frontend.API, txViewingKey p256.PublicKey, salt [16]frontend.Variable) (frontend.Variable, error) {
	agreement := p256.SelfAgreeKey(api, txViewingKey)
	compressed := agreement.PublicKey
	ikm := append(append(append([]frontend.Variable{}, agreement.SharedX[:]...), compressed[:]...), compressed[:]...)
	zeros := make([]frontend.Variable, 32)
	for i := range zeros {
		zeros[i] = 0
	}
	prk, err := counterHMAC(api, zeros, ikm)
	if err != nil {
		return nil, err
	}
	info := counterConstants([]byte("TSPP/hpke/TSPP/tx"))
	for _, b := range salt {
		api.ToBinary(b, 8)
	}
	info = append(info, salt[:]...)
	info = append(info, 255, 255, 255, 255)
	first, err := counterHMAC(api, prk, append(append([]frontend.Variable{}, info...), 1))
	if err != nil {
		return nil, err
	}
	second, err := counterHMAC(api, prk, append(append(append([]frontend.Variable{}, first...), info...), 2))
	if err != nil {
		return nil, err
	}
	var key [32]frontend.Variable
	var nonce [12]frontend.Variable
	copy(key[:], first)
	copy(nonce[:], second)

	plaintext := ve.FieldToBytesBE(api, s.salt, 32)
	for i, asset := range s.assets {
		plaintext = append(plaintext, ve.FieldToBytesBE(api, asset, 32)...)
		bits := api.ToBinary(s.spent[i], 64)
		for j := 0; j < 8; j++ {
			plaintext = append(plaintext, api.FromBinary(bits[j*8:(j+1)*8]...))
		}
	}
	ciphertext := aes.CTREncrypt(api, key, nonce, plaintext)
	disclosure := counterConstants([]byte(CountersDisclosureDomain))
	disclosure = append(disclosure, salt[:]...)
	disclosure = append(disclosure, compressed[:]...)
	disclosure = append(disclosure, ciphertext...)
	return gadget.HashBytes(api, disclosure), nil
}

func counterConstants(bytes []byte) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = b
	}
	return out
}

func counterHMAC(api frontend.API, key, message []frontend.Variable) ([]frontend.Variable, error) {
	if len(key) != 32 {
		panic("invalid counter HMAC key length")
	}
	inner := make([]frontend.Variable, 64)
	outer := make([]frontend.Variable, 64)
	for i := range inner {
		if i < len(key) {
			inner[i] = xorByte(api, key[i], 0x36)
			outer[i] = xorByte(api, key[i], 0x5c)
		} else {
			inner[i], outer[i] = 0x36, 0x5c
		}
	}
	digest, err := counterSHA256(api, append(inner, message...))
	if err != nil {
		return nil, err
	}
	return counterSHA256(api, append(outer, digest...))
}

func xorByte(api frontend.API, a, b frontend.Variable) frontend.Variable {
	aBits := api.ToBinary(a, 8)
	bBits := api.ToBinary(b, 8)
	resultBits := make([]frontend.Variable, 8)
	for i := range resultBits {
		resultBits[i] = api.Sub(api.Add(aBits[i], bBits[i]), api.Mul(2, api.Mul(aBits[i], bBits[i])))
	}
	return api.FromBinary(resultBits...)
}

func counterSHA256(api frontend.API, input []frontend.Variable) ([]frontend.Variable, error) {
	h, err := sha2.New(api)
	if err != nil {
		return nil, err
	}
	bytes := make([]uints.U8, len(input))
	for i, b := range input {
		bytes[i] = uints.U8{Val: b}
	}
	h.Write(bytes)
	digest := h.Sum()
	out := make([]frontend.Variable, len(digest))
	for i, b := range digest {
		out[i] = b.Val
	}
	return out, nil
}
