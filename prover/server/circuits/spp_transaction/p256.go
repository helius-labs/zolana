package transaction

import (
	"math/big"

	gadgetlib "zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

const (
	p256LimbBits = 128
	// 2^240, the coefficient of the SEC1 prefix byte in the first pack_be chunk
	// of a 33-byte compressed point (sec1[0:31] as a big-endian integer).
	sec1PrefixShift = 240
)

// P256PublicKey and P256Signature are the gnark ECDSA witness types pinned to
// the P256 instantiation used by the ownership rail.
type (
	P256PublicKey = gnarkecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]
	P256Signature = gnarkecdsa.Signature[emulated.P256Fr]
)

// P256PkFieldGadget folds a P256 VIEWING key into pk_field =
// hash_bytes(sec1_compressed) = Poseidon(33, chunk0, chunk1), where the chunks
// are pack_be over the 33-byte SEC1 point: chunk0 = sec1[0:31] as a big-endian
// integer = (2 + y_parity)·2^240 + (x >> 16), chunk1 = sec1[31:33] = x mod 2^16.
type P256PkFieldGadget struct {
	Chunk0 frontend.Variable
	Chunk1 frontend.Variable
}

func (gadget P256PkFieldGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(33), gadget.Chunk0, gadget.Chunk1,
	})
}

func P256PkFieldFromPubkeyCircuit(
	api frontend.API,
	pub P256PublicKey,
) (frontend.Variable, error) {
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](
		api,
		sw_emulated.GetCurveParams[emulated.P256Fp](),
	)
	if err != nil {
		return nil, err
	}
	point := sw_emulated.AffinePoint[emulated.P256Fp](pub)
	curve.AssertIsOnCurve(&point)
	return P256PkFieldFromPointCircuit(api, point)
}

// P256PkFieldFromPointCircuit folds an already-parsed P256 point into the viewing
// pk_field. It does not assert the point is on the curve; callers that need that
// guarantee (e.g. P256PkFieldFromPubkeyCircuit, or after p256.PointOnCurve)
// ensure it separately.
func P256PkFieldFromPointCircuit(
	api frontend.API,
	point sw_emulated.AffinePoint[emulated.P256Fp],
) (frontend.Variable, error) {
	fp, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		return nil, err
	}
	yBits := fp.ToBitsCanonical(&point.Y)
	xBits := fp.ToBitsCanonical(&point.X)
	// SEC1 prefix = 2 + y_parity, occupying byte 0 of the 33-byte point, i.e. the
	// most significant byte of the 31-byte chunk0 (coefficient 2^240).
	prefix := api.Add(big.NewInt(2), yBits[0])
	prefixTerm := api.Mul(prefix, new(big.Int).Lsh(big.NewInt(1), sec1PrefixShift))
	chunk0 := api.Add(prefixTerm, gnarkbits.FromBinary(api, xBits[16:])) // (2+parity)·2^240 + (x>>16)
	chunk1 := gnarkbits.FromBinary(api, xBits[:16])                      // x mod 2^16
	return abstractor.Call(api, P256PkFieldGadget{
		Chunk0: chunk0,
		Chunk1: chunk1,
	}), nil
}

// OwnerPkFieldGadget folds a P256 OWNER public key into pk_field =
// hash_bytes(x) = Poseidon(32, chunk0, chunk1) over the 32-byte x-coordinate:
// chunk0 = x[0:31] as a big-endian integer = x >> 8, chunk1 = x[31] = x mod 2^8.
// The y-parity is intentionally excluded (it is carried in the encrypted data,
// not the owner identity), so a P256 owner pk_field has the same 32-byte-tag
// shape as an ed25519 owner. The VIEWING key hashes the full 33-byte SEC1 point.
type OwnerPkFieldGadget struct {
	Chunk0 frontend.Variable
	Chunk1 frontend.Variable
}

func (gadget OwnerPkFieldGadget) DefineGadget(api frontend.API) interface{} {
	return gadgetlib.PoseidonHash(api, []frontend.Variable{
		frontend.Variable(32), gadget.Chunk0, gadget.Chunk1,
	})
}

// OwnerPkFieldFromPubkeyCircuit derives the parity-free owner pk_field from a
// P256 public key (asserting it is on the curve).
func OwnerPkFieldFromPubkeyCircuit(
	api frontend.API,
	pub P256PublicKey,
) (frontend.Variable, error) {
	curve, err := sw_emulated.New[emulated.P256Fp, emulated.P256Fr](
		api,
		sw_emulated.GetCurveParams[emulated.P256Fp](),
	)
	if err != nil {
		return nil, err
	}
	point := sw_emulated.AffinePoint[emulated.P256Fp](pub)
	curve.AssertIsOnCurve(&point)
	fp, err := emulated.NewField[emulated.P256Fp](api)
	if err != nil {
		return nil, err
	}
	xBits := fp.ToBitsCanonical(&point.X)
	chunk0 := gnarkbits.FromBinary(api, xBits[8:]) // x >> 8
	chunk1 := gnarkbits.FromBinary(api, xBits[:8]) // x mod 2^8
	return abstractor.Call(api, OwnerPkFieldGadget{
		Chunk0: chunk0,
		Chunk1: chunk1,
	}), nil
}

// p256MessageHashToP256Fr reconstructs the full 256-bit SHA-256 ECDSA message
// digest from its two big-endian 128-bit limbs. Each limb is range-checked to
// 128 bits by ToBinary; concatenating low (bits 0..128) then high (bits
// 128..256) yields the canonical 256-bit scalar fed to the emulated P256 curve.
func p256MessageHashToP256Fr(api frontend.API, low, high frontend.Variable) (*emulated.Element[emulated.P256Fr], error) {
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, err
	}
	bits := append(api.ToBinary(low, p256LimbBits), api.ToBinary(high, p256LimbBits)...)
	return fr.FromBits(bits...), nil
}
