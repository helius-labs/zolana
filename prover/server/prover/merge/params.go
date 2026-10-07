package merge

import (
	"math/big"

	"zolana/prover/prover/common"
)

type InputParams struct {
	Domain       *big.Int
	Amount       *big.Int
	Blinding     *big.Int
	RingDataHash *big.Int

	StatePathElements []*big.Int
	StatePathIndex    *big.Int

	NullifierLowValue        *big.Int
	NullifierNextValue       *big.Int
	NullifierLowPathElements []*big.Int
	NullifierLowPathIndex    *big.Int

	TreeSlot  *big.Int
	Nullifier *big.Int
}

type OutputParams struct {
	RingDataHash *big.Int
	Hash         *big.Int
}

type MergeParameters struct {
	CircuitType common.CircuitType

	Inputs []InputParams
	Output OutputParams

	TreeSlots []common.TreeSlotParams

	OutputTreeID *big.Int

	Mint [32]byte

	ViewingPk   [65]byte
	EphemeralSk [32]byte

	RingProgramID *big.Int

	OwnerPkHash         *big.Int
	UserNullifierPk     *big.Int
	UserNullifierSecret *big.Int

	OutputRingDataHash *big.Int

	ExternalDataHash *big.Int
	PrivateTxHash    *big.Int
	AllowDummyInputs *big.Int

	PublicInputHash *big.Int
}
