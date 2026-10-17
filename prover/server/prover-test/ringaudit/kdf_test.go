package ringaudit

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func TestAuditStreamKDFVector(t *testing.T) {
	key, nonce := keySchedule(t, big.NewInt(0x12345), auditEncInfo)
	for _, vector := range []struct{ name, got, want string }{
		{"key", hex.EncodeToString(key[:]), "0b2e1ebe77448c2a18dc91fb208e751595208775296803011e0084baaf1bbb6d"},
		{"nonce", hex.EncodeToString(nonce[:]), "cc2327b19f62560112747d6f"},
		{"ciphertext", hex.EncodeToString(ctrEncrypt(t, key, nonce, make([]byte, 32))), "001d45a89ea12a64c7e6886ce543a66f77971b2c1052688ff668fe8c0c5d7c7b"},
	} {
		if vector.got != vector.want {
			t.Errorf("%s: got %s want %s", vector.name, vector.got, vector.want)
		}
	}
}

func TestAuditEnvelopeVector(t *testing.T) {
	k := DefaultKeys(t)
	dhLo, dhHi := pack32(k.dh)
	ephLo, ephHi := pack33(k.ephPk)
	auditorLo, auditorHi := pack33(Tagged(k.auditorPk[:]))
	secret := spptest.MustPoseidon(t, 8, []*big.Int{
		tag(base.DomSepCRShared), dhLo, dhHi, ephLo, ephHi, auditorLo, auditorHi,
	})
	key, nonce := keySchedule(t, secret, auditEncInfo)
	ciphertext := ctrEncrypt(t, key, nonce, k.txSk[:])
	if got := hex.EncodeToString(ciphertext); got != "da94f616e95702bdea89178dd9c4547393ebce9d47e67d0cac1533f13b678b90" {
		t.Fatalf("auditor ciphertext: %s", got)
	}
	hash, err := protocol.HashBytes(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(hash.FillBytes(make([]byte, 32))); got != "2ec8fca72d305d1cfc2ea01acb5058150dd251c32da26baa29affbca9f7779d9" {
		t.Fatalf("auditor ciphertext hash: %s", got)
	}
}
