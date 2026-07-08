package squadskeyencryption

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/verifiable-encryption/aes"
	zoneutils "zolana/prover/circuits/zone-utils"
	"zolana/prover/circuits/zone-utils/p256"
)

// RecipientKey is a public-only recovery or auditor key the shared viewing
// secret is encrypted to. Pubkey is the 65-byte uncompressed P-256 point
// (0x04 || x || y); its compressed form is bound into the public input hash.
type RecipientKey struct {
	Pubkey [65]frontend.Variable
}

// Circuit is the Key Encryption Proof (squads_policy_program.md, "Key Encryption
// Proof"). It proves verifiable encryption of a shared viewing secret key to a
// set of recovery and auditor keys, that the published shared-viewing-key
// commitment commits to that same secret, and that the encrypted nullifier
// secret commits to the published nullifier pubkey. It touches no UTXOs and has
// no transaction hash.
//
// NumKeys = R + A is the recovery-plus-auditor recipient count; the circuit does
// not distinguish the two, ordering is an on-chain concern. One shared ephemeral
// key covers every ciphertext (recipient and nullifier), zone tx_viewing_pk style.
type Circuit struct {
	NumKeys int `gnark:"-"`

	// OldStateHash binds the proof to a prior account state on rotation; 0 at
	// creation. A public passthrough: the on-chain program checks it against the
	// stored keys-and-ciphertexts hash, the circuit only folds it into the chain.
	OldStateHash frontend.Variable

	// ViewingSecretKey is the shared viewing scalar: its public key is the
	// account's shared_viewing_key and it is the 32-byte plaintext encrypted to
	// every recipient.
	ViewingSecretKey emulated.Element[emulated.P256Fr]

	// EphemeralSecretKey is the single ephemeral scalar shared across all
	// ciphertexts, a full-range P-256 scalar witnessed as an emulated P256Fr
	// element like ViewingSecretKey.
	EphemeralSecretKey emulated.Element[emulated.P256Fr]

	NullifierSecret frontend.Variable

	// RecipientKeys has length NumKeys.
	RecipientKeys []RecipientKey

	PublicInputHash frontend.Variable `gnark:",public"`
}

// NewKeyEncryptionCircuit builds the circuit for numKeys recovery-plus-auditor
// recipient keys.
func NewKeyEncryptionCircuit(numKeys int) *Circuit {
	return &Circuit{
		NumKeys:       numKeys,
		RecipientKeys: make([]RecipientKey, numKeys),
	}
}

func (c *Circuit) Define(api frontend.API) error {
	if err := c.validateLayout(); err != nil {
		return err
	}

	g := aes.NewAESGadget(api)

	commitment, viewingSkBytes, err := viewingKeyCommitmentAndBytes(api, c.ViewingSecretKey)
	if err != nil {
		return err
	}

	// shared_viewing_key = sk·G, bound into the chain via its compressed form so
	// the published public key matches the committed secret.
	sharedPkUncompressed := p256.ScalarMulGenerator(api, viewingSkBytes)
	sharedPkComp := p256.CompressPubkey(api, sharedPkUncompressed)
	sharedPkLo, sharedPkHi := zoneutils.Pack33To2FECircuit(api, sharedPkComp)

	// Single shared ephemeral key covers every ciphertext.
	ephBits, err := p256ScalarBits(api, c.EphemeralSecretKey)
	if err != nil {
		return err
	}
	ephBytes := scalarBytesBE(api, ephBits)
	ephPkComp := p256.CompressPubkey(api, p256.ScalarMulGenerator(api, ephBytes))
	ephPkLo, ephPkHi := zoneutils.Pack33To2FECircuit(api, ephPkComp)

	// Public input chain (fixed order; the on-chain program recomputes it from
	// instruction data): old_state_hash, shared_viewing_key, commitment,
	// ephemeral pk, then per key (recipient key, ciphertext hash), then
	// nullifier_pubkey and the nullifier ciphertext hash.
	chain := []frontend.Variable{
		c.OldStateHash,
		sharedPkLo, sharedPkHi,
		commitment,
		ephPkLo, ephPkHi,
	}

	for i := range c.RecipientKeys {
		pk := c.RecipientKeys[i].Pubkey
		p256.PointOnCurve(api, pk)
		rpkComp := p256.CompressPubkey(api, pk)
		rpkLo, rpkHi := zoneutils.Pack33To2FECircuit(api, rpkComp)
		ctHash := ecdhEncrypt(api, g, ephBytes, ephPkComp, pk, rpkComp, viewingSkBytes[:])
		chain = append(chain, rpkLo, rpkHi, ctHash)
	}

	// Nullifier: the published nullifier_pubkey commits to the secret, which is
	// encrypted to the shared viewing key so any holder who recovers the shared
	// secret can decrypt it. Reuses the shared ephemeral against sk·G.
	nullifierPubkey := gadget.PoseidonHash(api, []frontend.Variable{c.NullifierSecret})
	nullPlaintext := zoneutils.FieldToBytesBE(api, c.NullifierSecret, 31)
	nullCtHash := ecdhEncrypt(api, g, ephBytes, ephPkComp, sharedPkUncompressed, sharedPkComp, nullPlaintext)
	chain = append(chain, nullifierPubkey, nullCtHash)

	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, chain))
	return nil
}

func (c *Circuit) validateLayout() error {
	if c.NumKeys < 1 {
		return fmt.Errorf("squads_key_encryption: NumKeys must be >= 1, got %d", c.NumKeys)
	}
	if got := len(c.RecipientKeys); got != c.NumKeys {
		return fmt.Errorf("squads_key_encryption: recipient key count mismatch: got %d want %d", got, c.NumKeys)
	}
	return nil
}
