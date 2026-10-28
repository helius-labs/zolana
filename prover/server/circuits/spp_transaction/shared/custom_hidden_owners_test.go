package shared_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"testing/cryptotest"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

var hiddenOwnersSystems = map[Shape]constraint.ConstraintSystem{}

// hiddenOwnersShape is the protocol shape for the counts with nOwners hidden
// owners.
func hiddenOwnersShape(shape protocol.Shape, nOwners int) Shape {
	s := txShape(shape)
	s.NHiddenOwners = nOwners
	return s
}

func compileHiddenOwners(t testing.TB, shape Shape) constraint.ConstraintSystem {
	t.Helper()
	if ccs, ok := hiddenOwnersSystems[shape]; ok {
		return ccs
	}
	circuit, err := customring.NewCustomRingAnonymousEddsaCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	hiddenOwnersSystems[shape] = ccs
	return ccs
}

// hiddenOwnersAuthorization is every hidden owner's signature over the one
// message, the input-to-owner indices, and the published default-owner chain.
type hiddenOwnersAuthorization struct {
	keys       [][32]byte
	signatures [][64]byte
	identities []*big.Int
	indices    []int
	low        *big.Int
	high       *big.Int
	published  *big.Int
}

// rewriteInputsAsHiddenOwners marks every input as hidden and derives its UTXO
// owner from the owner indices name.
func rewriteInputsAsHiddenOwners(t testing.TB, a *testAssignment, owners []ed25519.PrivateKey, indices []int) {
	t.Helper()
	for i, index := range indices {
		rewriteInputAsHiddenOwner(t, a, i, owners[index])
	}
}

// authorizeHiddenOwners signs the assignment's message with every owner and
// refreshes the public input hash with the published chain the circuit
// derives.
func authorizeHiddenOwners(t testing.TB, a *testAssignment, owners []ed25519.PrivateKey, indices []int) hiddenOwnersAuthorization {
	t.Helper()
	digest := eddsaDigest(a)
	auth := hiddenOwnersAuthorization{
		indices: indices,
		low:     new(big.Int).SetBytes(digest[16:]),
		high:    new(big.Int).SetBytes(digest[:16]),
	}
	for _, owner := range owners {
		key := publicKeyBytes(owner)
		var signature [64]byte
		copy(signature[:], ed25519.Sign(owner, digest[:]))
		auth.keys = append(auth.keys, key)
		auth.signatures = append(auth.signatures, signature)
		auth.identities = append(auth.identities, hiddenOwnerIdentity(t, key))
	}
	auth.published = publishedHiddenOwners(t, a, auth.identities, indices)
	refreshCustomRingAnonymousEddsaPublicInputHashWithOwner(t, a, digest, auth.published)
	return auth
}

// publishedHiddenOwners mirrors shared.AssertDefaultHiddenOwners: the chain of
// each owner's identity while one of its spent hidden UTXOs is in the default
// ring, zero otherwise.
func publishedHiddenOwners(t testing.TB, a *testAssignment, identities []*big.Int, indices []int) *big.Int {
	t.Helper()
	published := make([]*big.Int, len(identities))
	for j := range published {
		published[j] = big.NewInt(0)
	}
	for i, input := range a.Inputs {
		if spptest.AsBigInt(input.Utxo.Domain).Int64() == UtxoDomain &&
			spptest.AsBigInt(input.OwnerPkHash).Sign() == 0 &&
			spptest.AsBigInt(input.Utxo.RingProgramID).Sign() == 0 {
			published[indices[i]] = new(big.Int).Set(identities[indices[i]])
		}
	}
	chain, err := protocol.RightHashChain(published)
	return spptest.MustHash(t, chain, err)
}

func asHiddenOwnersCircuit(t testing.TB, a *testAssignment, auth hiddenOwnersAuthorization) *customring.CustomRingAnonymousEddsaCircuit {
	t.Helper()
	first := eddsaAuthorization{
		key:    auth.keys[0],
		low:    auth.low,
		high:   auth.high,
		pkHash: auth.identities[0],
	}
	first.signature = auth.signatures[0]
	c := asCustomRingAnonymousEddsa(a, first)
	c.Public.DefaultOwnerPkHash = auth.published
	c.Private.AdditionalOwnerPublicKeys = make([][32]frontend.Variable, len(auth.keys)-1)
	c.Private.AdditionalOwnerSignatures = make([][64]frontend.Variable, len(auth.keys)-1)
	for j := range c.Private.AdditionalOwnerPublicKeys {
		for k, b := range auth.keys[j+1] {
			c.Private.AdditionalOwnerPublicKeys[j][k] = b
		}
		for k, b := range auth.signatures[j+1] {
			c.Private.AdditionalOwnerSignatures[j][k] = b
		}
	}
	c.Private.InputHiddenOwners = make([]frontend.Variable, len(auth.indices))
	for i, index := range auth.indices {
		c.Private.InputHiddenOwners[i] = index
	}
	return c
}

// twoHiddenOwners is a 2x2 ring spend in which owner 0 spends input 0 and
// owner 1 spends input 1.
func twoHiddenOwners(t testing.TB) (constraint.ConstraintSystem, *testAssignment, []ed25519.PrivateKey) {
	t.Helper()
	host := protocol.Shape{NInputs: 2, NOutputs: 2}
	owners := []ed25519.PrivateKey{hiddenOwnerKey(0x91), hiddenOwnerKey(0x92)}
	a := eddsaRingAssignment(t, host, hiddenOwnerIdentity(t, publicKeyBytes(owners[0])))
	rewriteInputsAsHiddenOwners(t, a, owners, []int{0, 1})
	return compileHiddenOwners(t, hiddenOwnersShape(host, 2)), a, owners
}

func TestCustomRingAnonymousEddsaSolvesWithTwoHiddenOwners(t *testing.T) {
	ccs, a, owners := twoHiddenOwners(t)
	auth := authorizeHiddenOwners(t, a, owners, []int{0, 1})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), true)
}

func TestCustomRingAnonymousEddsaHiddenOwnersSizeTheirWires(t *testing.T) {
	shape := hiddenOwnersShape(protocol.Shape{NInputs: 3, NOutputs: 2}, 3)
	c, err := customring.NewCustomRingAnonymousEddsaCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Private.AdditionalOwnerPublicKeys) != 2 ||
		len(c.Private.AdditionalOwnerSignatures) != 2 ||
		len(c.Private.InputHiddenOwners) != 3 {
		t.Fatalf("got %d keys, %d signatures, %d indices",
			len(c.Private.AdditionalOwnerPublicKeys),
			len(c.Private.AdditionalOwnerSignatures),
			len(c.Private.InputHiddenOwners))
	}
	single, err := customring.NewCustomRingAnonymousEddsaCircuit(txShape(protocol.Shape{NInputs: 3, NOutputs: 2}))
	if err != nil {
		t.Fatal(err)
	}
	if len(single.Private.AdditionalOwnerPublicKeys)+len(single.Private.AdditionalOwnerSignatures)+len(single.Private.InputHiddenOwners) != 0 {
		t.Fatal("a single hidden owner must add no wires")
	}
}

// An input whose index names the other owner opens a UTXO that owner does not
// own.
func TestCustomRingAnonymousEddsaRejectsAWrongHiddenOwnerIndex(t *testing.T) {
	ccs, a, owners := twoHiddenOwners(t)
	auth := authorizeHiddenOwners(t, a, owners, []int{1, 0})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), false)
}

func TestCustomRingAnonymousEddsaRejectsAnOutOfRangeHiddenOwnerIndex(t *testing.T) {
	ccs, a, owners := twoHiddenOwners(t)
	auth := authorizeHiddenOwners(t, a, owners, []int{0, 1})
	c := asHiddenOwnersCircuit(t, a, auth)
	c.Private.InputHiddenOwners[1] = 2
	checkCachedWitness(t, ccs, c, false)
}

// A verified signature must stand for a spender: an owner that spends no input
// is refused even though its signature is valid.
func TestCustomRingAnonymousEddsaRequiresEveryHiddenOwnerToSpend(t *testing.T) {
	ccs, a, owners := twoHiddenOwners(t)
	rewriteInputsAsHiddenOwners(t, a, owners, []int{0, 0})
	auth := authorizeHiddenOwners(t, a, owners, []int{0, 0})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), false)
}

func TestCustomRingAnonymousEddsaRejectsARepeatedHiddenOwner(t *testing.T) {
	ccs, a, owners := twoHiddenOwners(t)
	repeated := []ed25519.PrivateKey{owners[0], owners[0]}
	rewriteInputsAsHiddenOwners(t, a, repeated, []int{0, 1})
	auth := authorizeHiddenOwners(t, a, repeated, []int{0, 1})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), false)
}

func TestCustomRingAnonymousEddsaRejectsAHiddenOwnerAsPublicSigner(t *testing.T) {
	for owner := range 2 {
		ccs, a, owners := twoHiddenOwners(t)
		a.SignerPkHashes[0] = hiddenOwnerIdentity(t, publicKeyBytes(owners[owner]))
		auth := authorizeHiddenOwners(t, a, owners, []int{0, 1})
		checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), false)
	}
}

func TestCustomRingAnonymousEddsaRejectsABadAdditionalSignature(t *testing.T) {
	ccs, a, owners := twoHiddenOwners(t)
	auth := authorizeHiddenOwners(t, a, owners, []int{0, 1})
	auth.signatures[1] = auth.signatures[0]
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), false)
}

// A non-hidden input stays authorized by the public signer vector next to the
// hidden owners, and every hidden owner still has to spend.
func TestCustomRingAnonymousEddsaMixesHiddenOwnersWithAPublicSigner(t *testing.T) {
	host := protocol.Shape{NInputs: 3, NOutputs: 2}
	owners := []ed25519.PrivateKey{hiddenOwnerKey(0x91), hiddenOwnerKey(0x92)}
	ccs := compileHiddenOwners(t, hiddenOwnersShape(host, 2))
	a := eddsaRingAssignment(t, host, hiddenOwnerIdentity(t, publicKeyBytes(owners[0])))
	rewriteInputsAsHiddenOwners(t, a, owners, []int{0, 1})
	signer := testSolanaPkField(t)
	nullifierPk := spptest.MustNullifierPk(t, spptest.AsBigInt(a.Inputs[2].NullifierSecret))
	a.Inputs[2].Utxo.Owner = spptest.MustOwnerHash(t, signer, nullifierPk)
	a.Inputs[2].OwnerPkHash = signer
	a.SignerPkHashes[0] = signer
	rebuildAfterOwnerChange(t, a)
	auth := authorizeHiddenOwners(t, a, owners, []int{0, 1, 0})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), true)

	a.SignerPkHashes[0] = 0
	auth = authorizeHiddenOwners(t, a, owners, []int{0, 1, 0})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), false)
}

const hiddenOwnersFixture = "../../../prover/transfer_eddsa/testdata/eddsa-ring-2x2-h2.json"

// TestCustomRingAnonymousEddsaHiddenOwnersRequestFixture pins the two-owner
// 2x2 request the prover's end to end test proves. Owner 0 spends a
// default-ring input, so the request also exercises the published owner chain.
// Rewrite it with
//
//	UPDATE_REQUEST_FIXTURE=1 go test ./circuits/spp_transaction/shared -run TestCustomRingAnonymousEddsaHiddenOwnersRequestFixture
func TestCustomRingAnonymousEddsaHiddenOwnersRequestFixture(t *testing.T) {
	cryptotest.SetGlobalRandom(t, 0)
	ccs, a, owners := twoHiddenOwners(t)
	moveInputToDefaultRing(t, a, 0, owners[0])
	auth := authorizeHiddenOwners(t, a, owners, []int{0, 1})
	params := eddsaRequestParameters(asHiddenOwnersCircuit(t, a, auth))
	params.NHiddenOwners = 2
	params.AdditionalOwnerPublicKeys = auth.keys[1:]
	params.AdditionalOwnerSignatures = auth.signatures[1:]
	params.InputHiddenOwners = []uint32{0, 1}
	data, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	var decoded transfer.AnonymousEddsaTransferParameters
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateShape(); err != nil {
		t.Fatal(err)
	}
	if got := decoded.ProofShape().KeyFile(); got != "transfer_eddsa_ring_2_2_h2.key" {
		t.Fatalf("key file %q", got)
	}
	witness, err := decoded.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	checkCachedWitness(t, ccs, witness, true)
	if os.Getenv("UPDATE_REQUEST_FIXTURE") != "" {
		if err := os.WriteFile(hiddenOwnersFixture, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(hiddenOwnersFixture)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, data) {
		t.Fatal("the committed two-owner request is stale; rewrite it with UPDATE_REQUEST_FIXTURE=1")
	}
}

// moveInputToDefaultRing takes input i out of the custom ring and re-derives
// its hidden owner.
func moveInputToDefaultRing(t testing.TB, a *testAssignment, i int, owner ed25519.PrivateKey) {
	t.Helper()
	a.Inputs[i].Utxo.RingProgramID = spptest.Fe(0)
	rewriteInputAsHiddenOwner(t, a, i, owner)
}

// One owner's default-ring spend publishes only that owner; the other owner's
// ring spend stays private, and the chain must say exactly that.
func TestCustomRingAnonymousEddsaPublishesOnlyTheDefaultRingHiddenOwner(t *testing.T) {
	ccs, a, owners := twoHiddenOwners(t)
	moveInputToDefaultRing(t, a, 0, owners[0])
	auth := authorizeHiddenOwners(t, a, owners, []int{0, 1})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), true)

	for name, published := range map[string][]*big.Int{
		"nobody":    {big.NewInt(0), big.NewInt(0)},
		"both":      {auth.identities[0], auth.identities[1]},
		"the other": {big.NewInt(0), auth.identities[1]},
		"unchained": nil,
	} {
		t.Run(name, func(t *testing.T) {
			claimed := auth
			if published == nil {
				claimed.published = auth.identities[0]
			} else {
				chain, err := protocol.RightHashChain(published)
				claimed.published = spptest.MustHash(t, chain, err)
			}
			refreshCustomRingAnonymousEddsaPublicInputHashWithOwner(t, a, eddsaDigest(a), claimed.published)
			checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, claimed), false)
		})
	}
}

// An owner that spends a ring hidden input is anonymous, so the same owner may
// not also spend a default-ring hidden input that would publish it.
func TestCustomRingAnonymousEddsaRejectsAnOwnerMixingDefaultAndRingSpends(t *testing.T) {
	host := protocol.Shape{NInputs: 3, NOutputs: 2}
	owners := []ed25519.PrivateKey{hiddenOwnerKey(0x91), hiddenOwnerKey(0x92)}
	ccs := compileHiddenOwners(t, hiddenOwnersShape(host, 2))
	a := eddsaRingAssignment(t, host, hiddenOwnerIdentity(t, publicKeyBytes(owners[0])))
	rewriteInputsAsHiddenOwners(t, a, owners, []int{0, 1, 0})
	moveInputToDefaultRing(t, a, 2, owners[0])
	auth := authorizeHiddenOwners(t, a, owners, []int{0, 1, 0})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), false)

	// The same three inputs solve once the default-ring input belongs to an
	// owner with no ring spend.
	a = eddsaRingAssignment(t, host, hiddenOwnerIdentity(t, publicKeyBytes(owners[0])))
	rewriteInputsAsHiddenOwners(t, a, owners, []int{0, 1, 1})
	moveInputToDefaultRing(t, a, 0, owners[0])
	auth = authorizeHiddenOwners(t, a, owners, []int{0, 1, 1})
	checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), true)
}

// A default-ring output publishes its owner tag. It may name the owner whose
// default-ring spend is already public, but not the other owner, whose ring
// spend must stay anonymous.
func TestCustomRingAnonymousEddsaKeepsARingSpenderOutOfPublishedOutputTags(t *testing.T) {
	for name, tc := range map[string]struct {
		outputOwner int
		valid       bool
	}{
		"published owner": {outputOwner: 0, valid: true},
		"ring spender":    {outputOwner: 1, valid: false},
	} {
		t.Run(name, func(t *testing.T) {
			ccs, a, owners := twoHiddenOwners(t)
			moveInputToDefaultRing(t, a, 0, owners[0])
			a.Outputs[0].Utxo.RingProgramID = spptest.Fe(0)
			rewriteOutputAsHiddenOwner(t, a, 0, owners[tc.outputOwner])
			auth := authorizeHiddenOwners(t, a, owners, []int{0, 1})
			checkCachedWitness(t, ccs, asHiddenOwnersCircuit(t, a, auth), tc.valid)
		})
	}
}
