package base

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	ve "github.com/helius-labs/zolana/prover/server/circuits/encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Envelope encrypts Plaintext to the X25519 key AuditorPk under the ephemeral secret EphSk, fresh per envelope or the keystream repeats.
type Envelope struct {
	Plaintext []frontend.Variable
	EphSk     [32]frontend.Variable
	AuditorPk [32]frontend.Variable
	// Info keys the schedule of Seal, SealAuditStream reads no info.
	Info string
}

// Sealed carries both tagged keys packed with gadget.PackBytesBE and the ciphertext, every ciphertext byte bounded to 8 bits by the cipher's tables.
type Sealed struct {
	Auditor, Eph, Ciphertext []frontend.Variable
}

type keySchedule func(secret frontend.Variable) ([32]frontend.Variable, [12]frontend.Variable)

// Seal encrypts under the verifiable-encryption key schedule of Info.
func (e Envelope) Seal(api frontend.API) Sealed {
	return e.seal(api, func(secret frontend.Variable) ([32]frontend.Variable, [12]frontend.Variable) {
		return ve.KeySchedule(api, secret, gadget.ConstBytes(e.Info), len(e.Info))
	})
}

// SealAuditStream encrypts under the audit stream schedule every delivered body shares.
func (e Envelope) SealAuditStream(api frontend.API) Sealed {
	return e.seal(api, func(secret frontend.Variable) ([32]frontend.Variable, [12]frontend.Variable) {
		return auditStreamKeySchedule(api, secret)
	})
}

func (e Envelope) seal(api frontend.API, schedule keySchedule) Sealed {
	// 1. One encoding per auditor key, the program packs the configured key bytes as they are.
	agreement := agreeCanonical(api, e.EphSk, e.AuditorPk)
	// 2. The X25519 gadgets bound every key byte and return canonical bytes, the packings below need no byte check.
	eph := x25519.ScalarMulGenerator(api, e.EphSk)
	sealed := Sealed{Auditor: packBounded(api, tagged(e.AuditorPk)), Eph: packBounded(api, tagged(eph))}
	// 3. Binding both keys keeps the key schedule input from replaying under another key pair.
	secret := gadget.PoseidonHash(api, slices.Concat(
		[]frontend.Variable{uint64(DomSepCRShared)}, packBounded(api, agreement[:]), sealed.Eph, sealed.Auditor,
	))
	// 4. The cipher's byte tables bound every plaintext byte.
	key, nonce := schedule(secret)
	sealed.Ciphertext = aes.NewCipher(api, key).CTREncrypt(nonce, e.Plaintext)
	return sealed
}
