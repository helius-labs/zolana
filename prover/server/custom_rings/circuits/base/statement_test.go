package base_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type statementVectors struct {
	Audit []auditStatementVector `json:"audit"`
}

type auditStatementVector struct {
	Kind             string                  `json:"kind"`
	FirstNullifier   string                  `json:"first_nullifier"`
	RingProgramID    string                  `json:"ring_id"`
	TxViewingU       string                  `json:"tx_viewing_u"`
	AuditorPubkey    string                  `json:"auditor_pubkey"`
	EphU             string                  `json:"eph_u"`
	Sealed           string                  `json:"sealed"`
	Salt             string                  `json:"salt"`
	Layout           int64                   `json:"layout"`
	Outputs          []statementOutputVector `json:"outputs"`
	Disclosure       []string                `json:"disclosure"`
	PrivateTxHash    string                  `json:"private_tx_hash"`
	Epoch            uint64                  `json:"epoch"`
	FirstContactRoot string                  `json:"first_contact_root"`
	SenderCommitment string                  `json:"sender_commitment"`
	Elements         []string                `json:"elements"`
	PublicInputHash  string                  `json:"public_input_hash"`
}

type statementOutputVector struct {
	Kind string `json:"kind"`
	Hash string `json:"hash"`
	U    string `json:"u"`
	Tag  string `json:"tag"`
	Body string `json:"body"`
}

// The host builders every honest witness solves against rebuild the program's audit statements of the Rust vector.
func TestAuditStatementsMatchRustVectors(t *testing.T) {
	var vectors statementVectors
	readRingVector(t, "ring-statements.json", &vectors)
	kinds := map[string]bool{}
	for _, v := range vectors.Audit {
		t.Run(v.Kind, func(t *testing.T) {
			head := ringaudit.AuditHead{
				FirstNullifier: vectorField(t, v.FirstNullifier),
				RingProgramID:  vectorField(t, v.RingProgramID),
				TxViewingU:     [32]byte(hexBytes(t, v.TxViewingU, 32)),
				AuditorPubkey:  [33]byte(hexBytes(t, v.AuditorPubkey, 33)),
				EphU:           [32]byte(hexBytes(t, v.EphU, 32)),
				Sealed:         hexBytes(t, v.Sealed, 32),
				Salt:           [16]byte(hexBytes(t, v.Salt, 16)),
				Layout:         v.Layout,
			}
			outputs := make([]ringaudit.StatementOutput, len(v.Outputs))
			for i, o := range v.Outputs {
				outputs[i] = ringaudit.StatementOutput{Hash: vectorField(t, o.Hash), Exit: o.Kind == "exit"}
				if o.U != "" {
					outputs[i].U = [32]byte(hexBytes(t, o.U, 32))
				}
				if o.Tag != "" {
					outputs[i].Tag = new(big.Int).SetBytes(hexBytes(t, o.Tag, base.TagLen))
				}
				if o.Body != "" {
					outputs[i].Body = hexBytes(t, o.Body, 40)
				}
			}
			disclosure := make([]*big.Int, len(v.Disclosure))
			for i, field := range v.Disclosure {
				disclosure[i] = vectorField(t, field)
			}
			var elements []*big.Int
			switch v.Kind {
			case "packed":
				elements = ringaudit.PackedStatement(t, head, outputs, disclosure)
			case "delivered":
				elements = ringaudit.DeliveredStatement(t, head, outputs, disclosure)
			case "anonymous":
				elements = ringaudit.AnonymousStatement(t, head, outputs, disclosure, ringaudit.AnonymousTail{
					PrivateTxHash:    vectorField(t, v.PrivateTxHash),
					Epoch:            v.Epoch,
					FirstContactRoot: vectorField(t, v.FirstContactRoot),
					SenderCommitment: vectorField(t, v.SenderCommitment),
				})
			default:
				t.Fatalf("unknown audit kind %q", v.Kind)
			}
			kinds[v.Kind] = true
			if len(elements) != len(v.Elements) {
				t.Fatalf("%d elements, the vector holds %d", len(elements), len(v.Elements))
			}
			for i, element := range elements {
				if element.Cmp(vectorField(t, v.Elements[i])) != 0 {
					t.Errorf("element %d is %x, the vector holds %s", i, element, v.Elements[i])
				}
			}
			if hash := spptest.MustHashChain4(t, elements); hash.Cmp(vectorField(t, v.PublicInputHash)) != 0 {
				t.Errorf("public input %x, the vector holds %s", hash, v.PublicInputHash)
			}
		})
	}
	if len(kinds) != 3 {
		t.Fatalf("the vector covers %v, want packed, delivered and anonymous", kinds)
	}
}

func hexBytes(t *testing.T, value string, n int) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil || len(raw) != n {
		t.Fatalf("invalid %d-byte vector value %q", n, value)
	}
	return raw
}
