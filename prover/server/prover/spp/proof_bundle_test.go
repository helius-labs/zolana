package spp

import (
	"crypto/elliptic"
	"math/big"
	"testing"
)

func TestBuildProofSigningPayloadAllowsUnsignedP256Input(t *testing.T) {
	priv, err := fixedP256PrivateKey(big.NewInt(11))
	if err != nil {
		t.Fatal(err)
	}
	p256Pubkey := elliptic.MarshalCompressed(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	nullifierSecret := big.NewInt(19)
	ownerKeyHash, err := P256OwnerKeyHash(p256Pubkey)
	if err != nil {
		t.Fatal(err)
	}
	nullifierPk, err := NullifierPk(nullifierSecret)
	if err != nil {
		t.Fatal(err)
	}
	owner, err := OwnerHash(ownerKeyHash, nullifierPk)
	if err != nil {
		t.Fatal(err)
	}
	utxo := Utxo{
		Domain:          big.NewInt(UtxoDomain),
		Owner:           owner,
		Asset:           big.NewInt(1),
		AssetAmount:     big.NewInt(5),
		Blinding:        big.NewInt(23),
		DataHash:        big.NewInt(0),
		PolicyData:      big.NewInt(0),
		PolicyProgramID: big.NewInt(0),
	}
	utxoHash, err := UtxoHash(utxo)
	if err != nil {
		t.Fatal(err)
	}

	request := ProofBundleRequest{
		SolanaSignerPubkey: proofBytesHex(make([]byte, 32)),
		Transactions: []ProofTransactionRequest{{
			Name:                     "unsigned-p256",
			InstructionDiscriminator: 1,
			ExpiryUnixTs:             123,
			SenderViewTag:            proofFieldHex(big.NewInt(9)),
			PublicAmountMode:         0,
			EncryptedUtxos:           "00",
			StateEntries: []ProofStateEntry{{
				Index: 0,
				Hash:  proofFieldHex(utxoHash),
			}},
			Inputs: []ProofInputRequest{{
				Utxo: ProofUtxoRequest{
					Domain:          proofFieldHex(utxo.Domain),
					OwnerP256Pubkey: proofBytesHex(p256Pubkey),
					Asset:           proofFieldHex(utxo.Asset),
					AssetAmount:     proofFieldHex(utxo.AssetAmount),
					Blinding:        proofFieldHex(utxo.Blinding),
					DataHash:        proofFieldHex(utxo.DataHash),
					PolicyData:      proofFieldHex(utxo.PolicyData),
					PolicyProgramID: proofFieldHex(utxo.PolicyProgramID),
				},
				LeafIndex:       0,
				NullifierSecret: proofFieldHex(nullifierSecret),
			}},
			ProgramIDHashChain: proofFieldHex(big.NewInt(0)),
		}},
	}

	payload, err := BuildProofSigningPayload(&ProofSystem{Shape: Shape{NInputs: 1, NOutputs: 2}}, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload.Transactions) != 1 {
		t.Fatalf("payload transaction count = %d, want 1", len(payload.Transactions))
	}
	if !payload.Transactions[0].RequiresP256Signature {
		t.Fatal("signing payload did not request a P256 signature")
	}
	if payload.Transactions[0].PrivateTxHash == proofFieldHex(big.NewInt(0)) {
		t.Fatal("private tx hash was zero")
	}

	if _, err := BuildProofBundle(&ProofSystem{Shape: Shape{NInputs: 1, NOutputs: 2}}, request); err == nil {
		t.Fatal("unsigned P256 proof bundle unexpectedly succeeded")
	}
}

func TestSignedAmountsByMode(t *testing.T) {
	// Transfer (mode 0) moves no public value: SPL must be zero, not a deposit
	// (the regression — previously +amount, which minted SPL). SOL is -fee only.
	if got := signedSplAmount(0, 100); got.Sign() != 0 {
		t.Fatalf("signedSplAmount(transfer, 100) = %s, want 0", got)
	}
	if got := signedSolAmount(0, 100, 0); got.Sign() != 0 {
		t.Fatalf("signedSolAmount(transfer, 100, fee=0) = %s, want 0", got)
	}
	// Shield (mode 1): +amount.
	if got := signedSplAmount(1, 100); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("signedSplAmount(shield, 100) = %s, want 100", got)
	}
	if got := signedSolAmount(1, 100, 0); got.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("signedSolAmount(shield, 100, 0) = %s, want 100", got)
	}
	// Unshield (mode 2): -amount for SPL, -(amount+fee) for SOL.
	if got := signedSplAmount(2, 100); got.Cmp(SignedToFe(big.NewInt(-100))) != 0 {
		t.Fatalf("signedSplAmount(unshield, 100) = %s, want -100", got)
	}
	if got := signedSolAmount(2, 100, 5); got.Cmp(SignedToFe(big.NewInt(-105))) != 0 {
		t.Fatalf("signedSolAmount(unshield, 100, fee=5) = %s, want -105", got)
	}
	// The relayer fee is always subtracted from SOL, including on a transfer.
	if got := signedSolAmount(0, 0, 7); got.Cmp(SignedToFe(big.NewInt(-7))) != 0 {
		t.Fatalf("signedSolAmount(transfer, 0, fee=7) = %s, want -7", got)
	}
}

func TestValidatePublicAmountMode(t *testing.T) {
	for _, m := range []uint8{0, 1, 2} {
		if err := validatePublicAmountMode(m); err != nil {
			t.Fatalf("mode %d rejected: %v", m, err)
		}
	}
	for _, m := range []uint8{3, 4, 255} {
		if err := validatePublicAmountMode(m); err == nil {
			t.Fatalf("mode %d accepted, want error", m)
		}
	}
}

func TestExternalDataHashBindsExpiry(t *testing.T) {
	base := proofExternalData{InstructionDiscriminator: 1, ExpiryUnixTs: 100}
	later := base
	later.ExpiryUnixTs = 200
	if proofExternalDataFieldHash(base).Cmp(proofExternalDataFieldHash(later)) == 0 {
		t.Fatal("external_data_hash does not depend on expiry_unix_ts")
	}
}

func TestBuildProofTreesRejectsBadStateEntries(t *testing.T) {
	duplicate := ProofTransactionRequest{StateEntries: []ProofStateEntry{
		{Index: 3, Hash: proofFieldHex(big.NewInt(1))},
		{Index: 3, Hash: proofFieldHex(big.NewInt(2))},
	}}
	if _, err := buildProofTrees(duplicate); err == nil {
		t.Fatal("duplicate state leaf index accepted, want error")
	}

	outOfRange := ProofTransactionRequest{StateEntries: []ProofStateEntry{
		{Index: uint64(1) << StateTreeHeight, Hash: proofFieldHex(big.NewInt(1))},
	}}
	if _, err := buildProofTrees(outOfRange); err == nil {
		t.Fatal("out-of-range state leaf index accepted, want error")
	}
}

func TestParseBigIntRule(t *testing.T) {
	cases := []struct {
		in   string
		want string // decimal
	}{
		{"100", "100"},  // small decimal
		{"0x64", "100"}, // 0x hex
		{"123456789012345678901", "123456789012345678901"},                          // 21-digit decimal (was mis-read as hex)
		{"0000000000000000000000000000000000000000000000000000000000000064", "100"}, // canonical 64-char hex
	}
	for _, c := range cases {
		got, err := parseBigInt(c.in)
		if err != nil {
			t.Fatalf("parseBigInt(%q): %v", c.in, err)
		}
		if got.String() != c.want {
			t.Fatalf("parseBigInt(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}
