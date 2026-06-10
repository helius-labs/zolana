//go:build spp_e2e_fixtures

package spp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"

	"light/light-prover/prover/spp/parse"
	"light/light-prover/prover/spp/protocol"
	txprover "light/light-prover/prover/spp/prover/transaction"
)

func (b *scenarioBuilder) fixture(ps *txprover.ProofSystem, signerHex string, sc scenario) (E2EFixture, error) {
	req, err := b.request(sc)
	if err != nil {
		return E2EFixture{}, err
	}

	// P256 inputs sign the proof's p256 message digest, which is only known
	// after the transcript is built, so derive it first then re-prove with the
	// signature attached.
	if sc.p256 && len(sc.inputs) > 0 {
		payload, err := txprover.BuildProofSigningPayload(ps, txprover.ProofBundleRequest{
			SolanaSignerPubkey: signerHex,
			Transactions:       []txprover.ProofTransactionRequest{req},
		})
		if err != nil {
			return E2EFixture{}, err
		}
		msg, err := parse.Hex32(payload.Transactions[0].P256MessageHash)
		if err != nil {
			return E2EFixture{}, err
		}
		r, s, err := ecdsa.Sign(rand.Reader, b.p256Priv, msg[:])
		if err != nil {
			return E2EFixture{}, err
		}
		req.P256OwnerPubkey = bytesHex(b.p256Pubkey)
		req.P256SignatureR = proofField(r)
		req.P256SignatureS = proofField(s)
	}

	bundle, err := txprover.BuildProofBundle(ps, txprover.ProofBundleRequest{
		SolanaSignerPubkey: signerHex,
		Transactions:       []txprover.ProofTransactionRequest{req},
	})
	if err != nil {
		return E2EFixture{}, err
	}
	tx := bundle.Transactions[0]

	expRoot, _, err := protocol.BuildSparseStateTree(sc.expState)
	if err != nil {
		return E2EFixture{}, err
	}

	// BuildProofBundle pads transcript arrays to the shape; the fixture (and the
	// on-chain instruction) carry only real entries and the verifier pads them
	// back to the shape with zeros. Real slots come first, so slice to the real
	// counts. Root indices are already real-length.
	nReal, mReal := len(sc.inputs), len(sc.outputs)

	return E2EFixture{
		Name:                    tx.Name,
		Shape:                   sc.shape,
		RequiresP256:            sc.p256 && len(sc.inputs) > 0,
		ExpiryUnixTs:            tx.ExpiryUnixTs,
		SenderViewTag:           tx.SenderViewTag,
		Proof:                   tx.Proof,
		RelayerFee:              tx.RelayerFee,
		Nullifiers:              tx.Nullifiers[:nReal],
		OutputUtxoHashes:        tx.OutputUtxoHashes[:mReal],
		UtxoTreeRootIndex:       tx.UtxoTreeRootIndex,
		NullifierTreeRootIndex:  tx.NullifierTreeRootIndex,
		PrivateTxHash:           tx.PrivateTxHash,
		PublicAmountMode:        tx.PublicAmountMode,
		PublicSolAmount:         tx.PublicSolAmount,
		PublicSplAmount:         tx.PublicSplAmount,
		PublicSplAssetPubkey:    tx.PublicSplAssetPubkey,
		EncryptedUtxos:          tx.EncryptedUtxos,
		ExpectedStateNextIndex:  sc.expStateNext,
		ExpectedQueueNextIndex:  sc.expQueueNext,
		ExpectedStateRoot:       fieldHex(expRoot),
		PublicInputHash:         tx.PublicInputHash,
		ExternalDataHash:        tx.ExternalDataHash,
		UserSolAccount:          tx.UserSolAccount,
		UserSplTokenAccount:     tx.UserSplTokenAccount,
		SplTokenInterface:       tx.SplTokenInterface,
		SolanaOwnerInputIndices: tx.SolanaOwnerInputIndices,
		DebugInputUtxoHashes:    tx.DebugInputUtxoHashes[:nReal],
		DebugOutputUtxoHashes:   tx.DebugOutputUtxoHashes[:mReal],
		DebugUtxoTreeRoots:      tx.DebugUtxoTreeRoots[:nReal],
		DebugNullifierTreeRoots: tx.DebugNullifierTreeRoots[:nReal],
	}, nil
}

// request converts a scenario into the high-level prover request.
func (b *scenarioBuilder) request(sc scenario) (txprover.ProofTransactionRequest, error) {
	tag := sc.tag
	if tag == 0 && sc.name != "" {
		tag = fixtureTransact
	}

	userSol, userSpl, splIface := b.settlementAccounts(sc)
	req := txprover.ProofTransactionRequest{
		Name:                     sc.name,
		InstructionDiscriminator: tag,
		ExpiryUnixTs:             fixtureExpiryUnixTs,
		SenderViewTag:            proofField(big.NewInt(sc.senderTag)),
		PublicAmountMode:         sc.mode,
		EncryptedUtxos:           bytesHex(sc.encrypted),
		ProgramIDHashchain:       proofField(big.NewInt(0)),
		DataHash:                 proofField(big.NewInt(0)),
		ZoneDataHash:             proofField(big.NewInt(0)),
		UserSolAccount:           bytesHex(userSol[:]),
		UserSplTokenAccount:      bytesHex(userSpl[:]),
		SplTokenInterface:        bytesHex(splIface[:]),
	}
	if sc.publicSol != 0 {
		v := sc.publicSol
		req.PublicSolAmount = &v
	}
	if sc.publicSpl != 0 {
		v := sc.publicSpl
		req.PublicSplAmount = &v
		req.PublicSplAssetPubkey = bytesHex(b.options.PublicSplAssetPubkey[:])
	}

	for index, hash := range sc.state {
		req.StateEntries = append(req.StateEntries, txprover.ProofStateEntry{
			Index: index,
			Hash:  proofField(hash),
		})
	}

	nullifierSecret := big.NewInt(solanaNullifierSecret)
	if sc.p256 {
		nullifierSecret = big.NewInt(p256NullifierSecret)
	}
	for _, in := range sc.inputs {
		utxo := b.utxoRequest(in.utxo)
		if sc.p256 {
			utxo.OwnerP256Pubkey = bytesHex(b.p256Pubkey)
		} else {
			utxo.OwnerSolanaPubkey = bytesHex(b.options.SolanaSignerPubkey[:])
		}
		utxo.Owner = ""
		req.Inputs = append(req.Inputs, txprover.ProofInputRequest{
			Utxo:            utxo,
			LeafIndex:       in.leafIndex,
			NullifierSecret: proofField(nullifierSecret),
		})
		req.UtxoTreeRootIndex = append(req.UtxoTreeRootIndex, sc.rootIndex)
		req.NullifierTreeRootIndex = append(req.NullifierTreeRootIndex, 0)
	}
	for _, out := range sc.outputs {
		req.Outputs = append(req.Outputs, b.utxoRequest(out))
	}
	return req, nil
}

func (b *scenarioBuilder) settlementAccounts(sc scenario) ([32]byte, [32]byte, [32]byte) {
	var zero [32]byte
	switch {
	case sc.publicSol != 0:
		userSol := b.options.UserSolAccount
		if userSol == zero {
			userSol = b.options.SolanaSignerPubkey
		}
		return userSol, zero, zero
	case sc.publicSpl != 0:
		return zero, b.options.UserSplToken, b.options.SplTokenInterface
	default:
		return zero, zero, zero
	}
}

// utxoRequest builds a request UTXO with its owner pinned as a raw hash (used
// directly for outputs; overwritten with owner components for inputs).
func (b *scenarioBuilder) utxoRequest(u protocol.Utxo) txprover.ProofUtxoRequest {
	return txprover.ProofUtxoRequest{
		Domain:        proofField(u.Domain),
		Owner:         proofField(u.Owner),
		AssetID:       proofField(u.AssetID),
		AssetAmount:   proofField(u.AssetAmount),
		Blinding:      proofField(u.Blinding),
		DataHash:      proofField(u.DataHash),
		ZoneDataHash:  proofField(u.ZoneDataHash),
		ZoneProgramID: proofField(u.ZoneProgramID),
	}
}

func ownerHashFor(keyHashFn func([32]byte) (*big.Int, error), pubkey [32]byte, nullifierSecret int64) (*big.Int, error) {
	keyHash, err := keyHashFn(pubkey)
	if err != nil {
		return nil, err
	}
	pk, err := protocol.NullifierPk(big.NewInt(nullifierSecret))
	if err != nil {
		return nil, err
	}
	return protocol.OwnerHash(keyHash, pk)
}

func sampleUtxo(base int64, owner, assetID *big.Int, amount int64) protocol.Utxo {
	return protocol.Utxo{
		Domain:      big.NewInt(protocol.UtxoDomain),
		Owner:       new(big.Int).Set(owner),
		AssetID:     new(big.Int).Set(assetID),
		AssetAmount: big.NewInt(amount),
		Blinding:    big.NewInt(base + 5),
		// Default transact requires bare UTXOs (no program/policy/zone data).
		DataHash:      big.NewInt(0),
		ZoneDataHash:  big.NewInt(0),
		ZoneProgramID: big.NewInt(0),
	}
}

func mustHash(u protocol.Utxo) *big.Int {
	h, err := protocol.UtxoHash(u)
	if err != nil {
		panic(err)
	}
	return h
}

func proofField(value *big.Int) string {
	return "0x" + fieldHex(value)
}

func fieldHex(value *big.Int) string {
	return fmt.Sprintf("%064x", value)
}

func bytesHex(value []byte) string {
	return fmt.Sprintf("%x", value)
}
