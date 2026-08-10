package squadszone

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	gnarkbits "github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
	squadsutils "zolana/prover/circuits/squads/utils"
	"zolana/prover/circuits/verifiable-encryption/aes"
)

var (
	labelTxViewing = new(big.Int).SetBytes([]byte("TSPP/tx_viewing"))
	labelBlinding  = new(big.Int).SetBytes([]byte("blinding"))
)

// The change ciphertext is AES-CTR over amount u64 || asset 32B read from the
// UTXO, diverging from the spec's asset_id. There is no tag. Integrity comes
// from the Poseidon ciphertext hash folded into the public input hash.
const SenderCiphertextLen = 8 + 32

type Sender struct {
	Account ViewingKeyAccount
}

// deriveTxViewingSk mirrors the Zone Proof KDF chain in squads_policy_program.md.
func deriveTxViewingSk(api frontend.API, viewingSk emulated.Element[emulated.P256Fr], firstNullifier frontend.Variable) (frontend.Variable, error) {
	fr, err := emulated.NewField[emulated.P256Fr](api)
	if err != nil {
		return nil, err
	}
	skBits := fr.ToBitsCanonical(&viewingSk)
	skLow := gnarkbits.FromBinary(api, skBits[:p256ScalarLimbBits])
	skHigh := gnarkbits.FromBinary(api, skBits[p256ScalarLimbBits:])

	viewRoot := squadsutils.PoseidonKDF(api, skLow, skHigh)
	txViewingSecret := squadsutils.PoseidonKDF(api, viewRoot, labelTxViewing)
	return squadsutils.PoseidonKDF(api, txViewingSecret, firstNullifier), nil
}

// DeriveTxViewingSk derives the shared ephemeral tx_viewing_sk. The first
// nullifier from Inputs[0] under the sender's nullifier secret seeds the KDF
// chain over the sender's viewing secret. One ephemeral key covers every
// ciphertext in the transaction, so it is derived once and reused for the
// recipient.
func (s Sender) DeriveTxViewingSk(api frontend.API, tx squadsutils.Transaction) (frontend.Variable, error) {
	firstInput := tx.Inputs[0]
	firstNullifier := abstractor.Call(api, shared.NullifierGadget{
		UtxoHash:        firstInput.Hash(api),
		Blinding:        firstInput.Blinding,
		NullifierSecret: s.Account.Private.NullifierSecret,
	})
	return deriveTxViewingSk(api, s.Account.Private.SharedViewingSecretKey, firstNullifier)
}

// Constrain enforces the full sender side and returns the ciphertext hash to
// fold into the public input hash. It binds the account (owner, nullifier pk,
// shared-viewing-secret commitment) against every real input and the sender
// change output. It pins the change blinding to the derived KDF blinding
// masked to its low 248 bits. It verifiably encrypts (amount, asset) under a
// key and nonce derived from the shared tx_viewing_sk.
func (s Sender) Constrain(api frontend.API, g *aes.AESGadget, tx squadsutils.Transaction, inputsDummy []frontend.Variable, txViewingSk, publicAmount, recipientAmount frontend.Variable) (frontend.Variable, error) {
	if err := s.Account.Constrain(api, tx, inputsDummy, SenderOutputIndex); err != nil {
		return nil, err
	}

	output := tx.Outputs[SenderOutputIndex]

	// Value conservation over the single asset. Enforced on every path, so a
	// proposal-less withdrawal still binds public_amount to the spent inputs and
	// the change output.
	sumInputs := frontend.Variable(0)
	for i := range tx.Inputs {
		sumInputs = api.Add(sumInputs, tx.Inputs[i].Amount)
	}
	api.AssertIsEqual(sumInputs, api.Add(api.Add(output.Amount, publicAmount), recipientAmount))

	// SPP's OutputUtxo blinding is 31 bytes, so the change blinding is the KDF
	// output masked to its low 248 bits (top byte of the 32-byte BE encoding
	// zeroed). Both the zone and SPP folds then use the same field element for
	// any deposit blinding. Mirrored by the Rust derive_change_blinding.
	blinding := squadsutils.PoseidonKDF(api, txViewingSk, labelBlinding)
	blindingBits := gnarkbits.ToBinary(api, blinding, gnarkbits.WithNbDigits(256))
	api.AssertIsEqual(output.Blinding, gnarkbits.FromBinary(api, blindingBits[:248]))

	key, nonce := squadsutils.KeySchedule(api, txViewingSk, nil, 0)
	return s.ConstrainEncryption(api, g, key, nonce, output.Amount, output.Asset), nil
}

func (s Sender) ConstrainEncryption(api frontend.API, g *aes.AESGadget, key [32]frontend.Variable, nonce [12]frontend.Variable, amount, asset frontend.Variable) frontend.Variable {
	plaintext := senderPlaintextBytes(api, amount, asset)
	ciphertext := aes.CTREncrypt(api, g, key, nonce, plaintext[:])
	return gadget.PoseidonHash(api, squadsutils.PackBytesBE(api, ciphertext, 16))
}

func senderPlaintextBytes(api frontend.API, amount, asset frontend.Variable) [SenderCiphertextLen]frontend.Variable {
	var pt [SenderCiphertextLen]frontend.Variable
	copy(pt[0:8], squadsutils.FieldToBytesBE(api, amount, 8))
	copy(pt[8:40], squadsutils.FieldToBytesBE(api, asset, 32))
	return pt
}
