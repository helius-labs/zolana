package base

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/rangecheck"
	ve "github.com/helius-labs/zolana/prover/server/circuits/encryption"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// These cumulative compilations include deferred lookup costs. Their differences
// are marginal costs in this order, not standalone gadget prices.
type auditCostCircuit struct {
	CustomRingConfidentialCircuit
	Stage int `gnark:"-"`
}

func (c *auditCostCircuit) Define(api frontend.API) error {
	if c.Stage == 0 {
		return nil
	}
	if c.Stage <= 3 {
		_ = TaggedPubkey(api, c.TxViewingSk)
		if c.Stage == 2 {
			_, _, _ = AgreeAuditKey(api, c.EphSk, c.AuditorPk)
		}
		if c.Stage == 3 {
			_ = (Envelope{Plaintext: c.TxViewingSk[:], EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: auditEncInfo}).Seal(api)
		}
		return nil
	}
	a := Audit{PrivateTxHash: c.PrivateTxHash, Anonymous: 0, TxViewingSk: c.TxViewingSk, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Salt: c.Salt}
	api.AssertIsEqual(c.NOut, 2)
	tx := AuditTx{Outputs: c.Outputs, NOut: SelectCount(api, 2, 1, AuditOutputSlots)}
	for i := range tx.Hashes {
		tx.Hashes[i] = 0
		if c.Stage >= 5 && i < 2 {
			tx.Hashes[i] = tx.Outputs[i].Hash(api)
		}
	}
	elements := a.Define(api, rangecheck.New(api), tx)
	if c.Stage >= 6 {
		api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, elements[:]))
	}
	return nil
}

func auditConstraintCount(t *testing.T, c frontend.Circuit) int {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	return cs.GetNbConstraints()
}

func TestAuditCostBreakdown(t *testing.T) {
	labels := []string{"empty", "viewing_public_key", "plus_auditor_key_agreement", "plus_envelope_kdf_and_aes", "plus_disclosure_and_framing", "plus_note_commitments_and_output_hash", "plus_public_statement"}
	previous := 0
	for stage, label := range labels {
		count := auditConstraintCount(t, &auditCostCircuit{Stage: stage})
		t.Logf("%s cumulative=%d marginal=%d", label, count, count-previous)
		previous = count
	}
	full := auditConstraintCount(t, &CustomRingConfidentialCircuit{})
	if previous != full {
		t.Fatalf("breakdown %d differs from production %d", previous, full)
	}
}

// Compare the older general KDF with the auditor-only stream schedule.
// The latter accepts every canonical field value, including q-1.
type auditKDFCostCircuit struct {
	Secret frontend.Variable
	Stream bool `gnark:"-"`
}

func (c *auditKDFCostCircuit) Define(api frontend.API) error {
	if !c.Stream {
		_, _ = ve.KeySchedule(api, c.Secret, ConstBytes(auditEncInfo), len(auditEncInfo))
		return nil
	}
	_, _ = auditStreamKeySchedule(api, c.Secret)
	return nil
}
func TestAuditKDFStructuralCost(t *testing.T) {
	legacy := auditConstraintCount(t, &auditKDFCostCircuit{})
	stream := auditConstraintCount(t, &auditKDFCostCircuit{Stream: true})
	t.Logf("legacy=%d audit_stream=%d saving=%d", legacy, stream, legacy-stream)
	if stream >= legacy {
		t.Fatal("auditor stream did not save constraints")
	}
}
