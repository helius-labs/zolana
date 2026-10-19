package protocol

import "fmt"

const (
	StateTreeHeight     = 32
	NullifierTreeHeight = 40
	CompressedProofSize = 192
	// MaxTransactionAddresses is the address limit of a v1 Solana transaction.
	MaxTransactionAddresses = 64
	// FixedTransactAddresses is the number of transact accounts that are neither
	// a nullifier PDA nor an owner signer: payer, tree, program, system program.
	FixedTransactAddresses = 4
)

// OwnerSignerSlots is the number of owner signers a transaction with nInputs
// inputs can carry: at most one per input, bounded by the addresses a v1
// transaction has left after the fixed transact accounts and one nullifier PDA
// per input. Mirrors shared.OwnerSignerSlots in the circuit.
func OwnerSignerSlots(nInputs int) int {
	return min(nInputs, MaxTransactionAddresses-FixedTransactAddresses-nInputs)
}

// Shape identifies one fixed-size SPP transaction circuit.
type Shape struct {
	NInputs  int
	NOutputs int
}

// SupportedShapes lists every fixed-size circuit that has a key, cheapest
// first. This is the validation set, mirroring SPP_SUPPORTED_SHAPES in
// program-libs/interface/src/shape.rs. It is the single source of truth for the
// shape set; do not duplicate it.
//
// The order is the smallest-fit search order: an input costs about 22.7k
// constraints and an output about 2k, so shapes are sorted by
// 22.7k*NInputs + 2k*NOutputs and the first shape that holds a transaction is
// the cheapest one that does. A shape that fits inside another is always
// cheaper, so it always comes first.
var SupportedShapes = []Shape{
	{NInputs: 1, NOutputs: 2},
	{NInputs: 1, NOutputs: 4},
	{NInputs: 1, NOutputs: 8},
	{NInputs: 2, NOutputs: 2},
	{NInputs: 2, NOutputs: 4},
	{NInputs: 1, NOutputs: 16},
	{NInputs: 2, NOutputs: 8},
	{NInputs: 3, NOutputs: 2},
	{NInputs: 3, NOutputs: 4},
	{NInputs: 2, NOutputs: 16},
	{NInputs: 3, NOutputs: 8},
	{NInputs: 4, NOutputs: 2},
	{NInputs: 4, NOutputs: 4},
	{NInputs: 4, NOutputs: 8},
	{NInputs: 5, NOutputs: 2},
	{NInputs: 5, NOutputs: 4},
	{NInputs: 4, NOutputs: 16},
	{NInputs: 5, NOutputs: 8},
	{NInputs: 6, NOutputs: 2},
	{NInputs: 6, NOutputs: 4},
	{NInputs: 5, NOutputs: 16},
	{NInputs: 6, NOutputs: 8},
	{NInputs: 8, NOutputs: 2},
	{NInputs: 8, NOutputs: 4},
	{NInputs: 8, NOutputs: 8},
	{NInputs: 8, NOutputs: 16},
	{NInputs: 12, NOutputs: 2},
	{NInputs: 12, NOutputs: 4},
	{NInputs: 12, NOutputs: 8},
	{NInputs: 16, NOutputs: 2},
	{NInputs: 16, NOutputs: 4},
	{NInputs: 16, NOutputs: 8},
	{NInputs: 24, NOutputs: 2},
	{NInputs: 24, NOutputs: 4},
	{NInputs: 32, NOutputs: 2},
	{NInputs: 40, NOutputs: 2},
	{NInputs: 48, NOutputs: 2},
	{NInputs: 49, NOutputs: 2},
}

// AutoShapes is the smallest-fit search order. Every supported shape is
// reachable by automatic selection, so it is the full SupportedShapes list.
var AutoShapes = SupportedShapes

// SmallestSupportedShape returns the smallest shape with a key that holds the
// given real input/output counts, searching the full validation set.
func SmallestSupportedShape(nInputs, nOutputs int) (Shape, error) {
	if nInputs < 0 || nOutputs < 0 {
		return Shape{}, fmt.Errorf("spp: negative arity %d inputs / %d outputs", nInputs, nOutputs)
	}
	for _, shape := range SupportedShapes {
		if nInputs <= shape.NInputs && nOutputs <= shape.NOutputs {
			return shape, nil
		}
	}
	return Shape{}, fmt.Errorf("spp: no supported shape holds %d inputs and %d outputs", nInputs, nOutputs)
}

// CanonicalShape returns the smallest automatic shape that holds the given
// real input/output counts. SPP derives the verifying key and public-input
// padding from the real counts with the same smallest-fit rule, so a proof
// built with any other shape can never verify on-chain.
func CanonicalShape(nInputs, nOutputs int) (Shape, error) {
	if nInputs < 0 || nOutputs < 0 {
		return Shape{}, fmt.Errorf("spp: negative arity %d inputs / %d outputs", nInputs, nOutputs)
	}
	for _, shape := range AutoShapes {
		if nInputs <= shape.NInputs && nOutputs <= shape.NOutputs {
			return shape, nil
		}
	}
	return Shape{}, fmt.Errorf("spp: no supported shape holds %d inputs and %d outputs", nInputs, nOutputs)
}

func NewShape(nInputs, nOutputs int) (Shape, error) {
	shape := Shape{NInputs: nInputs, NOutputs: nOutputs}
	if err := shape.Validate(); err != nil {
		return Shape{}, err
	}
	return shape, nil
}

func (s Shape) Validate() error {
	if s.NInputs < 1 {
		return fmt.Errorf("spp: NInputs must be >= 1, got %d", s.NInputs)
	}
	if s.NOutputs < 1 {
		return fmt.Errorf("spp: NOutputs must be >= 1, got %d", s.NOutputs)
	}
	if !s.IsSupported() {
		return fmt.Errorf("spp: unsupported circuit shape %s", s)
	}
	return nil
}

func (s Shape) IsSupported() bool {
	for _, supported := range SupportedShapes {
		if s == supported {
			return true
		}
	}
	return false
}

// SignerWidth is the public signer vector length on the signature-requiring
// rails: the payer plus OwnerSignerSlots. The ring authority rail uses 1.
func (s Shape) SignerWidth() int {
	return OwnerSignerSlots(s.NInputs) + 1
}

func (s Shape) String() string {
	return fmt.Sprintf("%d-%d", s.NInputs, s.NOutputs)
}
