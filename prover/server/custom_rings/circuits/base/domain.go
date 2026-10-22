package base

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Ring domains, distinct ASCII tags mirrored by custom-rings/interface/src/domain.rs and sdk-libs/ts/src/keypair/ring-domain.ts.
const (
	// AuditStatementDomain = "CRAU"
	AuditStatementDomain = 0x43524155
	// PackedSlotSecretDomain = "CRAS"
	PackedSlotSecretDomain = 0x43524153
	// DeliveredSlotSecretDomain = "CRDS"
	DeliveredSlotSecretDomain = 0x43524453
	// ConfidentialRingSecretDomain = "CRRC"
	ConfidentialRingSecretDomain = 0x43525243
	// AnonymousRingSecretDomain = "CRRA"
	AnonymousRingSecretDomain = 0x43525241
	// InboxKeyDomain = "CRIK"
	InboxKeyDomain = 0x4352494b
	// InboxTagDomain = "CRIT"
	InboxTagDomain = 0x43524954
	// PairKeyDomain = "CRPK"
	PairKeyDomain = 0x4352504b
	// PairTagDomain = "CRPT"
	PairTagDomain = 0x43525054
	// SenderCommitmentDomain = "CRSC"
	SenderCommitmentDomain = 0x43525343
	// DisclosurePadDomain = "CROD"
	DisclosurePadDomain = 0x43524f44
	// PolicyStatementDomain = "CRPO"
	PolicyStatementDomain = 0x4352504f
	// PolicyTableDomain = "CRTB"
	PolicyTableDomain = 0x43525442
	// QueueWriteDomain = "CRQW"
	QueueWriteDomain = 0x43525157
	// ApplyRecordsDomain = "CRAP"
	ApplyRecordsDomain = 0x43524150
	// RegisterKeyDomain = "CRRG"
	RegisterKeyDomain = 0x43525247
	// DepositBlindingDomain = "CRDB"
	DepositBlindingDomain = 0x43524442
)

// Envelope and merge pad domains, mirrored by custom-rings/client/src/encryption.rs, its merge_disclosure module and sdk-libs/ts/src/keypair/audit.ts.
const (
	// DomSepCRShared = "CR_S"
	DomSepCRShared = 0x43525f53
	// MergeDisclosureDomain = "CR_MD", a merge pad under the same key never repeats an output pad.
	MergeDisclosureDomain = 0x4352_5f4d44
)

// DepositBlinding is Poseidon(CRDB, blindingSecret), a deposit blinding no anchor opens as a first contact.
func DepositBlinding(api frontend.API, blindingSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{DepositBlindingDomain, blindingSecret})
}
