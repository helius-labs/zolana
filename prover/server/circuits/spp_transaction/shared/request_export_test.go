package shared_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	defaultring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/default"
	"github.com/helius-labs/zolana/prover/server/prover-test/requestfixture"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
)

// TestExportTransferRequests writes one solving /prove body per served transfer key:
//
//	REQUEST_FIXTURES=<dir> go test ./circuits/spp_transaction/shared -run TestExportTransferRequests -timeout 0
func TestExportTransferRequests(t *testing.T) {
	requests := requestfixture.NewWriter(t)
	for _, circuit := range exportedTransfers {
		for _, shape := range protocol.SupportedShapes {
			if name := transferKeyFile(circuit, shape); name != "" {
				requests.Write(t, name, newHonestTransfer(t, circuit, shape, 0).request)
			}
		}
	}
}

var exportedTransfers = []common.CircuitType{
	common.TransferRingCircuitType,
	common.TransferConfidentialCircuitType,
	common.TransferAnonymousRingEddsaCircuitType,
	common.TransferRingAuthorityCircuitType,
}

func transferKeyFile(circuit common.CircuitType, shape protocol.Shape) string {
	return common.TransferKeyFile(circuit, uint32(shape.NInputs), uint32(shape.NOutputs))
}

type honestTransfer struct {
	witness frontend.Circuit
	request any
}

func newHonestTransfer(t testing.TB, circuit common.CircuitType, shape protocol.Shape, variant int) honestTransfer {
	t.Helper()
	seeded := func(a *testAssignment) *testAssignment {
		a.BlindingSeed = big.NewInt(int64(800 + variant))
		rebuildAfterOwnerChange(t, a)
		return a
	}
	switch circuit {
	case common.TransferConfidentialCircuitType:
		a := seeded(buildDefaultRingConfidentialEddsaAssignment(t, shape))
		refreshDefaultRingPublicInputHash(t, a)
		c := asDefaultRingConfidentialEddsa(a).(*defaultring.DefaultRingConfidentialEddsaCircuit)
		c.Shape = a.Shape
		return honestTransfer{witness: c, request: requestParameters(c)}
	case common.TransferRingCircuitType:
		a := seeded(buildCircuitAssignment(t, shape))
		c := asCustomRingConfidentialEddsa(a).(*customring.CustomRingConfidentialEddsaCircuit)
		c.Shape = a.Shape
		return honestTransfer{witness: c, request: ringRequestParameters(a, transfer.RingVariant)}
	case common.TransferAnonymousRingEddsaCircuitType:
		a := seeded(buildCircuitAssignment(t, shape))
		owner := hiddenOwnerKey(11)
		rewriteInputAsHiddenOwner(t, a, 0, owner)
		c := asCustomRingAnonymousEddsa(a, authorizeEddsa(t, a, owner, owner))
		c.Shape = a.Shape
		return honestTransfer{witness: c, request: eddsaRequestParameters(c)}
	case common.TransferRingAuthorityCircuitType:
		a := seeded(buildRingAuthorityAssignment(t, shape))
		refreshRingAuthorityPublicInputHash(t, a)
		c := asCustomRingAuthority(a).(*customring.CustomRingAuthorityCircuit)
		c.Shape = a.Shape
		return honestTransfer{witness: c, request: ringRequestParameters(a, transfer.RingAuthorityVariant)}
	}
	t.Fatalf("no honest transfer for %s", circuit)
	return honestTransfer{}
}

// ringRequestParameters inverts TransferParameters.CreateWitness for a ring variant.
func ringRequestParameters(a *testAssignment, rail transfer.Variant) *transfer.TransferParameters {
	p := requestParameters(asDefaultRingConfidentialEddsa(a).(*defaultring.DefaultRingConfidentialEddsaCircuit))
	p.Variant = rail
	p.RingProgramID = spptest.AsBigInt(a.RingProgramID)
	p.RingSecrets = spptest.ToBigInts(a.ringSecrets())
	if rail == transfer.RingAuthorityVariant {
		p.SignerPkHashes = spptest.ToBigInts(a.AuthoritySignerPkHashes())
		p.PublishedOutputOwnerPkHashes = nil
		p.Cache = transfer.CacheSelectionParams{}
	} else {
		p.PublishedOutputOwnerPkHashes = spptest.ToBigInts(a.PublishedOutputOwnerPkHashes())
	}
	return p
}
