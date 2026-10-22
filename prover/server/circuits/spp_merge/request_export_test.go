package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/records"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/requestfixture"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	customring "github.com/helius-labs/zolana/prover/server/prover/custom_ring"
	mergeprover "github.com/helius-labs/zolana/prover/server/prover/merge"
)

// TestExportMergeRequests writes one solving /prove body per served merge key:
//
//	REQUEST_FIXTURES=<dir> go test ./circuits/spp_merge -run TestExportMergeRequests
func TestExportMergeRequests(t *testing.T) {
	requests := requestfixture.NewWriter(t)
	for _, inputs := range mergeshared.SupportedInputCounts {
		for _, rail := range exportedMergeRails {
			requests.Write(t, rail.keyFile(inputs), newHonestMerge(t, rail, inputs, 0).request)
		}
	}
}

var exportedMergeRails = []mergeFixtureRail{defaultFixtureRail, ringFixtureRail}

func (r mergeFixtureRail) circuit() common.CircuitType {
	if r == ringFixtureRail {
		return common.MergeRingCircuitType
	}
	return common.MergeCircuitType
}

func (r mergeFixtureRail) keyFile(inputs int) string {
	return common.TransferKeyFile(r.circuit(), uint32(inputs), mergeprover.MergeNOutputs)
}

type honestMerge struct {
	witness frontend.Circuit
	request *mergeprover.MergeParameters
}

func newHonestMerge(t testing.TB, rail mergeFixtureRail, inputs, variant int) honestMerge {
	t.Helper()
	options := mergeFixtureOptions{inputCount: inputs, externalDataHash: big.NewInt(int64(900 + variant)), rail: rail}
	if rail == defaultFixtureRail {
		fixture := buildMergeFixture(t, options)
		return honestMerge{witness: fixture.defaultCircuit(), request: fixture.request(rail)}
	}
	options.ringProgramID = big.NewInt(71)
	options.inputRingData = []*big.Int{big.NewInt(31), big.NewInt(31)}
	options.outputRingData = big.NewInt(31)
	fixture := buildMergeFixture(t, options)
	return honestMerge{witness: fixture.ringCircuit(), request: fixture.request(rail)}
}

// request inverts MergeParameters.CreateWitness.
func (f *mergeWitnessFixture) request(rail mergeFixtureRail) *mergeprover.MergeParameters {
	value := spptest.AsBigInt
	p := &mergeprover.MergeParameters{
		CircuitType:          rail.circuit(),
		Output:               mergeprover.OutputParams{RingDataHash: value(f.output.RingDataHash), Hash: value(f.public.OutputHash)},
		OutputTreeID:         value(f.public.OutputTreeID),
		MintChunks:           f.mintChunks,
		RingProgramID:        f.ringProgramID,
		OwnerPkHash:          f.ownerPkHash,
		UserNullifierPk:      f.userNullifierPk,
		UserNullifierSecret:  f.userNullifierSecret,
		OutputRingDataHash:   f.outputRingDataHash,
		ExternalDataHash:     value(f.public.ExternalDataHash),
		PrivateTxHash:        value(f.public.PrivateTxHash),
		AllowDummyInputs:     value(f.public.AllowDummyInputs),
		OutputCiphertextSalt: value(f.public.OutputCiphertextSalt),
		PublicInputHash:      f.publicInputHash,
	}
	for _, slot := range f.public.TreeSlots {
		p.TreeSlots = append(p.TreeSlots, common.TreeSlotParams{
			ID:            value(slot.ID),
			UtxoRoot:      value(slot.UtxoRoot),
			NullifierRoot: value(slot.NullifierRoot),
		})
	}
	for i, in := range f.inputs {
		p.Inputs = append(p.Inputs, mergeprover.InputParams{
			Domain:                   value(in.Domain),
			Amount:                   value(in.Amount),
			Blinding:                 value(in.Blinding),
			RingDataHash:             value(in.RingDataHash),
			StatePathElements:        spptest.ToBigInts(in.StatePathElements),
			StatePathIndex:           value(in.StatePathIndex),
			NullifierLowValue:        value(in.NullifierLowValue),
			NullifierNextValue:       value(in.NullifierNextValue),
			NullifierLowPathElements: spptest.ToBigInts(in.NullifierLowPathElements),
			NullifierLowPathIndex:    value(in.NullifierLowPathIndex),
			TreeSlot:                 value(in.TreeSlot),
			Nullifier:                value(f.public.Nullifiers[i]),
		})
	}
	if rail == ringFixtureRail {
		p.MemberRegistryRoot = f.memberRegistryRoot
		p.RegisteredCiphertextHash = f.registeredCtHash
		p.MemberRecord = recordOpening(f.memberRecord)
		p.Anonymous = f.anonymous.Sign() != 0
	}
	return p
}

// recordOpening flattens the path in the order createRingWitness reads.
func recordOpening(o records.QuadRecordOpening) *customring.RecordOpening {
	value := spptest.AsBigInt
	opening := &customring.RecordOpening{
		Next:      customring.Field{Int: value(o.Next)},
		Lists:     value(o.Lists).Uint64(),
		EscrowKey: customring.Field{Int: value(o.EscrowKey)},
		Index:     value(o.Path.Index).Uint64(),
	}
	for _, level := range o.Path.Siblings {
		for _, sibling := range level {
			opening.Path = append(opening.Path, customring.Field{Int: value(sibling)})
		}
	}
	return opening
}
