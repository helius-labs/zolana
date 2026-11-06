package shared_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
)

// The anonymous EdDSA accepting vectors pin transactions the
// transfer-eddsa-ring circuit accepts, one functional path each. A circuit
// that composes with this rail (a custom ring's transfer proof) replays the
// scenarios to show it adds no restriction the SPP proof does not have.
//
// Rewrite the file with
//
//	UPDATE_ANONYMOUS_EDDSA_VECTORS=1 go test ./circuits/spp_transaction/shared -run TestAnonymousEddsaAcceptingVectors
const anonymousEddsaVectorsFile = "../../../../../test-vectors/anonymous_eddsa_accepting.json"

type anonymousVectorFile struct {
	Description string            `json:"description"`
	Vectors     []anonymousVector `json:"vectors"`
}

// anonymousVector is one accepting transaction. Scenario names every slot in
// the terms a composing circuit opens; Request is the exact prover request.
type anonymousVector struct {
	Name        string            `json:"name"`
	Cases       []int             `json:"cases"`
	Description string            `json:"description"`
	Scenario    anonymousScenario `json:"scenario"`
	Request     json.RawMessage   `json:"request"`
}

type anonymousScenario struct {
	NInputs          int    `json:"nInputs"`
	NOutputs         int    `json:"nOutputs"`
	RingProgramID    string `json:"ringProgramId"`
	HiddenOwnerKey   string `json:"hiddenOwnerKey"`
	HiddenIdentity   string `json:"hiddenIdentity"`
	DefaultOwner     string `json:"defaultOwnerPkHash"`
	AllowDummyInputs bool   `json:"allowDummyInputs"`
	// Signers is the public signer vector in order, a zero entry as an empty key.
	Signers      []scenarioParty  `json:"signers"`
	TreeSlots    []scenarioTree   `json:"treeSlots"`
	OutputTreeID uint16           `json:"outputTreeId"`
	CacheTreeID  uint16           `json:"cacheTreeId"`
	Inputs       []scenarioSlot   `json:"inputs"`
	Outputs      []scenarioSlot   `json:"outputs"`
	Public       []scenarioPublic `json:"public"`
}

type scenarioParty struct {
	Key      string `json:"key"`
	Identity string `json:"identity"`
}

type scenarioTree struct {
	ID           uint16 `json:"id"`
	HasStateRoot bool   `json:"hasStateRoot"`
}

// scenarioSlot is one input or output. Kind is utxo, address, dummy or
// compact. Owner is hidden, signer or recipient; a hidden input publishes
// owner tag 0. PublishedTag is the output's public owner tag.
type scenarioSlot struct {
	Kind          string `json:"kind"`
	Owner         string `json:"owner,omitempty"`
	OwnerKey      string `json:"ownerKey,omitempty"`
	OwnerIdentity string `json:"ownerIdentity"`
	NullifierPk   string `json:"nullifierPk"`
	Ring          bool   `json:"ring"`
	Mint          string `json:"mint,omitempty"`
	Asset         string `json:"asset"`
	Amount        string `json:"amount"`
	Blinding      string `json:"blinding"`
	DataHash      string `json:"dataHash"`
	RingDataHash  string `json:"ringDataHash"`
	TreeID        uint16 `json:"treeId"`
	TreeSlot      int    `json:"treeSlot"`
	Cached        bool   `json:"cached,omitempty"`
	Nullifier     string `json:"nullifier,omitempty"`
	Hash          string `json:"hash"`
	PublishedTag  string `json:"publishedTag,omitempty"`
}

type scenarioPublic struct {
	Mint   string `json:"mint"`
	Asset  string `json:"asset"`
	Amount string `json:"amount"`
}

// vectorParty is one Solana key with the nullifier secret its notes use.
type vectorParty struct {
	key    [32]byte
	secret int64
}

func (p vectorParty) identity(t testing.TB) *big.Int {
	t.Helper()
	identity, err := protocol.SolanaPkField(p.key)
	return mustValue(t, identity, err)
}

func (p vectorParty) nullifierPk(t testing.TB) *big.Int {
	t.Helper()
	pk, err := protocol.NullifierPk(big.NewInt(p.secret))
	return mustValue(t, pk, err)
}

func repeated(b byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = b
	}
	return out
}

var (
	vectorHiddenKey = hiddenOwnerKey(0x11)
	hiddenParty     = vectorParty{key: publicKeyBytes(vectorHiddenKey), secret: 7}
	signerA         = vectorParty{key: repeated(0x21), secret: 21}
	signerB         = vectorParty{key: repeated(0x22), secret: 22}
	signerC         = vectorParty{key: repeated(0x23), secret: 23}
	recipientA      = vectorParty{key: repeated(0x31), secret: 31}
	recipientB      = vectorParty{key: repeated(0x32), secret: 32}
	vectorRing      = big.NewInt(0x5a)
)

const (
	vectorMint     = 0x0a
	vectorMintB    = 0x0b
	vectorMintC    = 0x0c
	vectorSolMint  = 0x00
	maxAmount      = ^uint64(0)
	slotUtxo       = "utxo"
	slotAddress    = "address"
	slotDummy      = "dummy"
	slotCompact    = "compact"
	ownerHidden    = "hidden"
	ownerSigner    = "signer"
	ownerRecipient = "recipient"
)

// dummyTag names what a dummy output publishes as its owner tag.
type dummyTag struct {
	signer, output int
	defaultOwner   bool
}

var tagZero = dummyTag{signer: -1, output: -1}

func tagSigner(i int) dummyTag { return dummyTag{signer: i, output: -1} }
func tagOutput(j int) dummyTag { return dummyTag{signer: -1, output: j} }

var tagDefaultOwner = dummyTag{signer: -1, output: -1, defaultOwner: true}

type slotSpec struct {
	kind      string
	party     vectorParty
	owner     string
	ring      bool
	mint      byte
	amount    uint64
	data      int64
	ringData  int64
	treeSlot  int
	cached    bool
	readIndex int
	tag       dummyTag
}

func hiddenNote(ring bool, amount uint64) slotSpec {
	return slotSpec{kind: slotUtxo, party: hiddenParty, owner: ownerHidden, ring: ring, mint: vectorMint, amount: amount, tag: tagZero}
}

func signerNote(p vectorParty, ring bool, amount uint64) slotSpec {
	return slotSpec{kind: slotUtxo, party: p, owner: ownerSigner, ring: ring, mint: vectorMint, amount: amount, tag: tagZero}
}

func hiddenAddress() slotSpec {
	return slotSpec{kind: slotAddress, party: hiddenParty, owner: ownerHidden, tag: tagZero}
}

func signerAddress(p vectorParty) slotSpec {
	return slotSpec{kind: slotAddress, party: p, owner: ownerSigner, tag: tagZero}
}

func dummySlot() slotSpec   { return slotSpec{kind: slotDummy, tag: tagZero} }
func compactSlot() slotSpec { return slotSpec{kind: slotCompact, tag: tagZero} }

func dummyOutput(tag dummyTag) slotSpec { return slotSpec{kind: slotDummy, tag: tag} }

func payTo(p vectorParty, owner string, ring bool, amount uint64) slotSpec {
	return slotSpec{kind: slotUtxo, party: p, owner: owner, ring: ring, mint: vectorMint, amount: amount, tag: tagZero}
}

func (s slotSpec) withMint(mint byte) slotSpec { s.mint = mint; return s }
func (s slotSpec) withTree(slot int) slotSpec  { s.treeSlot = slot; return s }
func (s slotSpec) withData(data, ring int64) slotSpec {
	s.data, s.ringData = data, ring
	return s
}
func (s slotSpec) cachedAt(index int) slotSpec { s.cached, s.readIndex = true, index; return s }

type publicSpec struct {
	mint     byte
	amount   uint64
	withdraw bool
}

type vectorSpec struct {
	name        string
	cases       []int
	description string
	signers     []*vectorParty
	allowDummy  bool
	// treeIDs are the ids of the published tree slots, the rest stay zero.
	treeIDs      []uint16
	noStateRoot  []int
	outputTreeID uint16
	cacheTreeID  uint16
	inputs       []slotSpec
	outputs      []slotSpec
	public       []publicSpec
}

func signerList(parties ...*vectorParty) []*vectorParty { return parties }

func anonymousVectorSpecs() []vectorSpec {
	ring, dflt := true, false
	return []vectorSpec{
		{
			name: "hidden_ring_note", cases: []int{1, 8, 22, 32, 38, 101},
			description: "One hidden ring note pays a ring recipient and keeps ring change.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "hidden_two_notes", cases: []int{9},
			description: "Two hidden ring notes of the same owner.",
			inputs:      []slotSpec{hiddenNote(ring, 100), hiddenNote(ring, 50)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 120), payTo(hiddenParty, ownerHidden, ring, 30)},
		},
		{
			name: "hidden_then_signer", cases: []int{10, 11, 20},
			description: "A hidden ring note in slot 0 beside a public signer's ring note in slot 1.",
			signers:     signerList(&signerA),
			inputs:      []slotSpec{hiddenNote(ring, 100), signerNote(signerA, ring, 50)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 120), payTo(signerA, ownerSigner, ring, 30)},
		},
		{
			name: "signer_then_hidden", cases: []int{10},
			description: "A public signer's ring note in slot 0 beside a hidden ring note in slot 1.",
			signers:     signerList(&signerA),
			inputs:      []slotSpec{signerNote(signerA, ring, 50), hiddenNote(ring, 100)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 120), payTo(hiddenParty, ownerHidden, ring, 30)},
		},
		{
			name: "signer_at_last_index", cases: []int{11, 14},
			description: "The only public signer sits at the last signer index after zero entries.",
			signers:     signerList(nil, nil, &signerA),
			inputs:      []slotSpec{hiddenNote(ring, 100), signerNote(signerA, ring, 50)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 150), payTo(hiddenParty, ownerHidden, ring, 0)},
		},
		{
			name: "two_signers", cases: []int{12},
			description: "A hidden note beside two public signers' notes.",
			signers:     signerList(&signerA, &signerB),
			inputs:      []slotSpec{hiddenNote(ring, 100), signerNote(signerA, ring, 50), signerNote(signerB, ring, 25)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 150), payTo(signerB, ownerSigner, ring, 25)},
		},
		{
			name: "unused_signer", cases: []int{13},
			description: "The signer vector names a signer who owns no input.",
			signers:     signerList(&signerC),
			inputs:      []slotSpec{hiddenNote(ring, 100), hiddenNote(ring, 20)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 100), payTo(hiddenParty, ownerHidden, ring, 20)},
		},
		{
			name: "no_signers", cases: []int{15},
			description: "Every content input is hidden and the signer vector is all zero.",
			inputs:      []slotSpec{hiddenNote(ring, 70), hiddenNote(ring, 30)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 100), payTo(hiddenParty, ownerHidden, ring, 0)},
		},
		{
			name: "hidden_note_then_hidden_address", cases: []int{17, 25, 53, 57, 94},
			description: "A hidden ring note followed by a hidden address slot.",
			allowDummy:  true,
			inputs:      []slotSpec{hiddenNote(ring, 100), hiddenAddress()},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "hidden_address_then_hidden_note", cases: []int{55, 56},
			description: "A hidden address in slot 0 followed by a hidden ring note.",
			allowDummy:  true,
			inputs:      []slotSpec{hiddenAddress(), hiddenNote(ring, 100)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "hidden_address_only_with_deposit", cases: []int{23, 56, 93},
			description: "A hidden address is the only input; a public deposit funds a ring output.",
			allowDummy:  true,
			inputs:      []slotSpec{hiddenAddress()},
			outputs:     []slotSpec{payTo(hiddenParty, ownerHidden, ring, 40), dummyOutput(tagZero)},
			public:      []publicSpec{{mint: vectorMint, amount: 40}},
		},
		{
			name: "signer_address_beside_hidden_note", cases: []int{18},
			description: "A public signer's address beside a hidden ring note.",
			allowDummy:  true,
			signers:     signerList(&signerA),
			inputs:      []slotSpec{hiddenNote(ring, 100), signerAddress(signerA)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "non_compact_dummy_input", cases: []int{19, 52},
			description: "A hidden note and a dummy input that publishes its nullifier.",
			allowDummy:  true,
			inputs:      []slotSpec{hiddenNote(ring, 100), dummySlot()},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "compact_input_padding", cases: []int{51},
			description: "One hidden note followed by two compact input slots.",
			inputs:      []slotSpec{hiddenNote(ring, 100), compactSlot(), compactSlot()},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "dummy_flag_without_dummies", cases: []int{54},
			description: "The dummy-input flag is set while every input is a real note.",
			allowDummy:  true,
			inputs:      []slotSpec{hiddenNote(ring, 70), hiddenNote(ring, 30)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "default_hidden_deposit_into_ring", cases: []int{21, 28, 33},
			description: "Two default-ring hidden notes move into the ring; the owner is published.",
			inputs:      []slotSpec{hiddenNote(dflt, 70), hiddenNote(dflt, 30)},
			outputs:     []slotSpec{payTo(hiddenParty, ownerHidden, ring, 100), payTo(recipientA, ownerRecipient, ring, 0)},
		},
		{
			name: "default_hidden_stays_default", cases: []int{30},
			description: "Every note is default-ring under a non-zero ring program id.",
			inputs:      []slotSpec{hiddenNote(dflt, 70), hiddenNote(dflt, 30)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, dflt, 60), payTo(hiddenParty, ownerHidden, dflt, 40)},
		},
		{
			name: "ring_hidden_beside_signer_default", cases: []int{26},
			description: "A hidden ring note beside a public signer's default-ring note; no owner is published.",
			signers:     signerList(&signerA),
			inputs:      []slotSpec{hiddenNote(ring, 100), signerNote(signerA, dflt, 50)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 120), payTo(signerA, ownerSigner, ring, 30)},
		},
		{
			name: "default_hidden_beside_signer_ring", cases: []int{27},
			description: "A default-ring hidden note beside a public signer's ring note; the owner is published.",
			signers:     signerList(&signerA),
			inputs:      []slotSpec{hiddenNote(dflt, 100), signerNote(signerA, ring, 50)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 120), payTo(signerA, ownerSigner, ring, 30)},
		},
		{
			name: "ring_data_hash", cases: []int{31},
			description: "Ring notes carry a non-zero ring data hash on both sides.",
			inputs:      []slotSpec{hiddenNote(ring, 100).withData(0, 0x77)},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, ring, 60).withData(0, 0x78),
				payTo(hiddenParty, ownerHidden, ring, 40).withData(0, 0x79),
			},
		},
		{
			name: "exit_to_default_recipient", cases: []int{29, 34},
			description: "A hidden ring note pays a default-ring recipient and keeps ring change.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, dflt, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "deposit_and_exit_mixed", cases: []int{35},
			description: "Ring and default notes from one hidden owner pay ring and default outputs.",
			inputs:      []slotSpec{hiddenNote(ring, 100), hiddenNote(ring, 40), hiddenNote(ring, 10), hiddenNote(ring, 5)},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, ring, 80),
				payTo(recipientB, ownerRecipient, dflt, 50),
				payTo(hiddenParty, ownerHidden, ring, 20),
				payTo(recipientA, ownerRecipient, dflt, 5),
			},
		},
		{
			name: "signer_owned_data_output", cases: []int{39},
			description: "An output with a data hash is owned by a public signer.",
			signers:     signerList(&signerA),
			inputs:      []slotSpec{hiddenNote(ring, 100), signerNote(signerA, ring, 50)},
			outputs:     []slotSpec{payTo(signerA, ownerSigner, ring, 120).withData(0x55, 0x56), payTo(hiddenParty, ownerHidden, ring, 30)},
		},
		{
			name: "hidden_owned_ring_data_output", cases: []int{40},
			description: "A ring output with a data hash is owned by the hidden owner.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs:     []slotSpec{payTo(hiddenParty, ownerHidden, ring, 100).withData(0x55, 0x56), payTo(recipientA, ownerRecipient, ring, 0)},
		},
		{
			name: "hidden_owned_default_data_output", cases: []int{41},
			description: "A default-ring output with a data hash is owned by the published hidden owner.",
			inputs:      []slotSpec{hiddenNote(dflt, 100)},
			outputs:     []slotSpec{payTo(hiddenParty, ownerHidden, dflt, 100).withData(0x55, 0), payTo(recipientA, ownerRecipient, ring, 0)},
		},
		{
			name: "recipient_outputs_without_data", cases: []int{42, 77},
			description: "Every output pays a recipient who is not a signer.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, ring, 40),
				payTo(recipientB, ownerRecipient, ring, 30),
				payTo(recipientA, ownerRecipient, ring, 20),
				payTo(recipientB, ownerRecipient, ring, 10),
			},
		},
		{
			name: "dummy_output_tags", cases: []int{44, 45, 47, 49},
			description: "Dummy outputs publish tag 0, a signer, and a real default-ring output's owner.",
			signers:     signerList(&signerA),
			inputs:      []slotSpec{hiddenNote(ring, 100), signerNote(signerA, ring, 50)},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, dflt, 150),
				dummyOutput(tagZero),
				dummyOutput(tagSigner(0)),
				dummyOutput(tagOutput(0)),
			},
		},
		{
			name: "dummy_output_tag_default_owner", cases: []int{46},
			description: "A dummy output names the published default owner.",
			inputs:      []slotSpec{hiddenNote(dflt, 100)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 100), dummyOutput(tagDefaultOwner)},
		},
		{
			name: "compact_outputs", cases: []int{48, 79},
			description: "Two real outputs followed by two compact output slots.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, ring, 60),
				payTo(hiddenParty, ownerHidden, ring, 40),
				{kind: slotCompact, tag: tagZero},
				{kind: slotCompact, tag: tagZero},
			},
		},
		{
			name: "trailing_dummy_outputs", cases: []int{78, 82},
			description: "One real output followed by three non-compact dummies.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, ring, 100),
				dummyOutput(tagZero), dummyOutput(tagZero), dummyOutput(tagZero),
			},
		},
		{
			name: "zero_amount_output", cases: []int{81},
			description: "A real ring output carries amount 0.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 0), payTo(hiddenParty, ownerHidden, ring, 100)},
		},
		{
			name: "inputs_across_tree_slots", cases: []int{59, 63},
			description: "Five hidden notes each spent from its own tree slot.",
			treeIDs:     []uint16{7, 17, 19, 23, 29},
			inputs: []slotSpec{
				hiddenNote(ring, 10), hiddenNote(ring, 20).withTree(1), hiddenNote(ring, 30).withTree(2),
				hiddenNote(ring, 40).withTree(3), hiddenNote(ring, 50).withTree(4),
			},
			outputs: []slotSpec{payTo(recipientA, ownerRecipient, ring, 100), payTo(hiddenParty, ownerHidden, ring, 50)},
		},
		{
			name: "same_note_in_two_trees", cases: []int{60},
			description: "Notes with the same contents spent from two trees.",
			treeIDs:     []uint16{7, 17},
			inputs:      []slotSpec{hiddenNote(ring, 50), hiddenNote(ring, 50).withTree(1)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "tree_id_boundaries", cases: []int{61, 62},
			description:  "Inputs from trees 0 and 0xffff; outputs appended to tree 0xffff.",
			treeIDs:      []uint16{0, 0xffff},
			outputTreeID: 0xffff,
			inputs:       []slotSpec{hiddenNote(ring, 50), hiddenNote(ring, 50).withTree(1)},
			outputs:      []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "cached_input_beside_state_input", cases: []int{69, 71, 72, 73},
			description: "One input proves existence through the cache and one through the state tree.",
			treeIDs:     []uint16{7},
			cacheTreeID: 7,
			inputs:      []slotSpec{hiddenNote(ring, 70), hiddenNote(ring, 30).cachedAt(1)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "cached_input_without_state_root", cases: []int{70, 74, 75},
			description: "A default-ring hidden note read from the cache of a tree slot with no state root.",
			treeIDs:     []uint16{0xffff},
			noStateRoot: []int{0},
			cacheTreeID: 0xffff,
			inputs:      []slotSpec{hiddenNote(dflt, 100).cachedAt(0)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 40)},
		},
		{
			name: "public_deposit", cases: []int{84},
			description: "A public deposit tops up a hidden ring spend.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 120), payTo(hiddenParty, ownerHidden, ring, 30)},
			public:      []publicSpec{{mint: vectorMint, amount: 50}},
		},
		{
			name: "public_withdrawal", cases: []int{85},
			description: "A hidden ring spend withdraws part of its value publicly.",
			inputs:      []slotSpec{hiddenNote(ring, 70), hiddenNote(ring, 30)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 50), payTo(hiddenParty, ownerHidden, ring, 10)},
			public:      []publicSpec{{mint: vectorMint, amount: 40, withdraw: true}},
		},
		{
			name: "three_public_slots", cases: []int{86, 90},
			description: "Three distinct public assets, deposits and a withdrawal in one transaction.",
			inputs:      []slotSpec{hiddenNote(ring, 100), hiddenNote(ring, 80).withMint(vectorMintB)},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, ring, 90),
				payTo(recipientA, ownerRecipient, ring, 100).withMint(vectorMintB),
				payTo(recipientB, ownerRecipient, ring, 25).withMint(vectorMintC),
				payTo(hiddenParty, ownerHidden, ring, 0),
			},
			public: []publicSpec{
				{mint: vectorMint, amount: 10, withdraw: true},
				{mint: vectorMintB, amount: 20},
				{mint: vectorMintC, amount: 25},
			},
		},
		{
			name: "public_slot_two_active", cases: []int{87, 91},
			description: "Only the last public slot is active.",
			inputs:      []slotSpec{hiddenNote(ring, 100)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, 60), payTo(hiddenParty, ownerHidden, ring, 30)},
			public:      []publicSpec{{}, {}, {mint: vectorMint, amount: 10, withdraw: true}},
		},
		{
			name: "max_public_deposit", cases: []int{88},
			description: "A public deposit of 2^64-1 funds one ring output.",
			inputs:      []slotSpec{hiddenNote(ring, 0)},
			outputs:     []slotSpec{payTo(hiddenParty, ownerHidden, ring, maxAmount), payTo(recipientA, ownerRecipient, ring, 0)},
			public:      []publicSpec{{mint: vectorMint, amount: maxAmount}},
		},
		{
			name: "max_public_withdrawal", cases: []int{88},
			description: "A hidden note of 2^64-1 is withdrawn publicly in full.",
			inputs:      []slotSpec{hiddenNote(ring, maxAmount)},
			outputs:     []slotSpec{payTo(hiddenParty, ownerHidden, ring, 0), dummyOutput(tagZero)},
			public:      []publicSpec{{mint: vectorMint, amount: maxAmount, withdraw: true}},
		},
		{
			name: "input_sum_past_u64", cases: []int{89},
			description: "Two notes of 2^64-1 each split across two outputs.",
			inputs:      []slotSpec{hiddenNote(ring, maxAmount), hiddenNote(ring, maxAmount)},
			outputs:     []slotSpec{payTo(recipientA, ownerRecipient, ring, maxAmount), payTo(hiddenParty, ownerHidden, ring, maxAmount)},
		},
		{
			name: "multi_asset_private", cases: []int{90},
			description: "Three assets balance independently with no public movement.",
			inputs: []slotSpec{
				hiddenNote(ring, 100), hiddenNote(ring, 50).withMint(vectorMintB), hiddenNote(ring, 7).withMint(vectorSolMint),
			},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, ring, 100),
				payTo(recipientA, ownerRecipient, ring, 50).withMint(vectorMintB),
				payTo(hiddenParty, ownerHidden, ring, 7).withMint(vectorSolMint),
				dummyOutput(tagZero),
			},
		},
		{
			name: "eight_inputs_eight_outputs", cases: []int{99, 102},
			description: "Eight hidden notes pay eight ring outputs.",
			inputs: []slotSpec{
				hiddenNote(ring, 10), hiddenNote(ring, 11), hiddenNote(ring, 12), hiddenNote(ring, 13),
				hiddenNote(ring, 14), hiddenNote(ring, 15), hiddenNote(ring, 16), hiddenNote(ring, 17),
			},
			outputs: []slotSpec{
				payTo(recipientA, ownerRecipient, ring, 20), payTo(recipientB, ownerRecipient, ring, 20),
				payTo(recipientA, ownerRecipient, ring, 20), payTo(recipientB, ownerRecipient, ring, 20),
				payTo(recipientA, ownerRecipient, ring, 10), payTo(recipientB, ownerRecipient, ring, 10),
				payTo(recipientA, ownerRecipient, ring, 5), payTo(hiddenParty, ownerHidden, ring, 3),
			},
		},
		{
			name: "one_input_sixteen_outputs", cases: []int{99, 102},
			description: "One hidden note pays sixteen ring outputs of one asset.",
			inputs:      []slotSpec{hiddenNote(ring, 160)},
			outputs:     sixteenOutputs(),
		},
	}
}

func sixteenOutputs() []slotSpec {
	outputs := make([]slotSpec, 16)
	for i := range outputs {
		recipient := recipientA
		if i%2 == 1 {
			recipient = recipientB
		}
		outputs[i] = payTo(recipient, ownerRecipient, true, 10)
	}
	return outputs
}

func mustValue(t testing.TB, value *big.Int, err error) *big.Int {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func feHex(v *big.Int) string { return common.FeHex(v) }

func keyHex(key [32]byte) string { return "0x" + hex.EncodeToString(key[:]) }

func assetOf(t testing.TB, mint byte) *big.Int {
	t.Helper()
	asset, err := protocol.AssetField(repeated(mint))
	return mustValue(t, asset, err)
}

type builtSlot struct {
	utxo        protocol.Utxo
	secret      *big.Int
	ownerTag    *big.Int
	nullifierPk *big.Int
	identity    *big.Int
	hash        *big.Int
	nullifier   *big.Int
	published   *big.Int
}

func zeroUtxo(blinding *big.Int) protocol.Utxo {
	return protocol.Utxo{
		Domain: big.NewInt(protocol.DummyDomain), Owner: big.NewInt(0), Asset: big.NewInt(0), Amount: big.NewInt(0),
		Blinding: blinding, DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: big.NewInt(0),
	}
}

func (s slotSpec) ringID() *big.Int {
	if s.ring {
		return new(big.Int).Set(vectorRing)
	}
	return big.NewInt(0)
}

// contentUtxo is the utxo a note or output slot carries, blinding unset.
func (s slotSpec) contentUtxo(t testing.TB, nullifierPk *big.Int) protocol.Utxo {
	t.Helper()
	owner, err := protocol.OwnerHash(s.party.identity(t), nullifierPk)
	return protocol.Utxo{
		Domain: big.NewInt(protocol.UtxoDomain), Owner: mustValue(t, owner, err), Asset: assetOf(t, s.mint),
		Amount: new(big.Int).SetUint64(s.amount), DataHash: big.NewInt(s.data), RingDataHash: big.NewInt(s.ringData),
		RingProgramID: s.ringID(),
	}
}

// buildAnonymousVector derives every witness value of spec and returns the
// prover request with the scenario a composing circuit replays.
func buildAnonymousVector(t testing.TB, spec vectorSpec) anonymousVector {
	t.Helper()
	nIn, nOut := len(spec.inputs), len(spec.outputs)
	shape := Shape{NInputs: nIn, NOutputs: nOut}
	if spec.treeIDs == nil {
		spec.treeIDs = []uint16{7}
	}
	if spec.outputTreeID == 0 {
		spec.outputTreeID = 11
	}
	assertVectorBalances(t, spec)

	// Inputs.
	inputs := make([]builtSlot, nIn)
	stateEntries := map[uint64]*big.Int{}
	for i, s := range spec.inputs {
		treeID := big.NewInt(int64(spec.treeIDs[s.treeSlot]))
		in := builtSlot{secret: big.NewInt(0), ownerTag: big.NewInt(0), nullifierPk: big.NewInt(0), identity: big.NewInt(0)}
		switch s.kind {
		case slotUtxo:
			in.secret = big.NewInt(s.party.secret)
			in.nullifierPk = s.party.nullifierPk(t)
			in.utxo = s.contentUtxo(t, in.nullifierPk)
			in.utxo.Blinding = big.NewInt(1000 + int64(i))
		case slotAddress:
			pk, err := protocol.NullifierPk(big.NewInt(0))
			in.nullifierPk = mustValue(t, pk, err)
			owner, err := protocol.OwnerHash(s.party.identity(t), in.nullifierPk)
			in.utxo = zeroUtxo(big.NewInt(2000 + int64(i)))
			in.utxo.Domain, in.utxo.Owner = big.NewInt(protocol.AddressDomain), mustValue(t, owner, err)
		default:
			in.utxo = zeroUtxo(big.NewInt(3000 + int64(i)))
		}
		if s.kind == slotUtxo || s.kind == slotAddress {
			in.identity = s.party.identity(t)
			if s.owner != ownerHidden {
				in.ownerTag = in.identity
			}
		}
		hash, err := protocol.UtxoHash(in.utxo, treeID)
		in.hash = mustValue(t, hash, err)
		nullifier, err := protocol.Nullifier(in.hash, in.utxo.Blinding, in.secret)
		in.nullifier = mustValue(t, nullifier, err)
		in.published = in.nullifier
		if s.kind == slotCompact {
			in.published = big.NewInt(0)
		}
		if s.kind == slotUtxo {
			stateEntries[uint64(17+i)] = in.hash
		}
		inputs[i] = in
	}
	if inputs[0].published.Sign() == 0 {
		t.Fatalf("%s: slot 0 must publish a nullifier", spec.name)
	}
	stateRoot, stateProofs, err := protocol.BuildSparseStateTree(stateEntries)
	if err != nil {
		t.Fatal(err)
	}
	nullifierTree, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatal(err)
	}
	treeSlots := make([]common.TreeSlotParams, InputTrees)
	for k := range treeSlots {
		treeSlots[k] = common.TreeSlotParams{ID: big.NewInt(0), UtxoRoot: big.NewInt(0), NullifierRoot: big.NewInt(0)}
		if k < len(spec.treeIDs) {
			treeSlots[k] = common.TreeSlotParams{
				ID: big.NewInt(int64(spec.treeIDs[k])), UtxoRoot: stateRoot, NullifierRoot: nullifierTree.Root(),
			}
		}
	}
	for _, k := range spec.noStateRoot {
		treeSlots[k].UtxoRoot = big.NewInt(0)
	}

	// Cache selection.
	readHashes := zeroFields(nIn)
	cache := transfer.CacheSelectionParams{
		TreeID: big.NewInt(int64(spec.cacheTreeID)), IsCached: zeroFields(nIn), ReadIndex: zeroFields(nIn),
	}
	for i, s := range spec.inputs {
		if s.cached {
			readHashes[s.readIndex] = inputs[i].hash
			cache.IsCached[i] = big.NewInt(1)
			cache.ReadIndex[i] = big.NewInt(int64(s.readIndex))
		}
	}
	cache.ReadHashes = readHashes
	chain, err := protocol.RightHashChain4(readHashes)
	cache.ReadHashChain = mustValue(t, chain, err)

	// Outputs.
	blindingSeed := big.NewInt(4242)
	first := inputs[0].nullifier
	outputSeed, err := protocol.OutputBlindingSeed(first, blindingSeed)
	outputSeed = mustValue(t, outputSeed, err)
	outputs := make([]builtSlot, nOut)
	for i, s := range spec.outputs {
		blinding, err := protocol.OutputBlinding(first, outputSeed, i)
		blinding = mustValue(t, blinding, err)
		out := builtSlot{ownerTag: big.NewInt(0), nullifierPk: big.NewInt(0), identity: big.NewInt(0), published: big.NewInt(0)}
		if s.kind == slotUtxo {
			out.nullifierPk = s.party.nullifierPk(t)
			out.utxo = s.contentUtxo(t, out.nullifierPk)
			out.identity = s.party.identity(t)
			out.ownerTag = out.identity
			if !s.ring {
				out.published = out.identity
			}
		} else {
			out.utxo = zeroUtxo(nil)
		}
		out.utxo.Blinding = blinding
		hash, err := protocol.UtxoHash(out.utxo, big.NewInt(int64(spec.outputTreeID)))
		out.hash = mustValue(t, hash, err)
		outputs[i] = out
	}

	// Signer vector and the published default owner.
	signers := zeroFields(shape.SignerWidth())
	scenarioSigners := make([]scenarioParty, len(spec.signers))
	for k, p := range spec.signers {
		if p != nil {
			signers[k] = p.identity(t)
			scenarioSigners[k] = scenarioParty{Key: keyHex(p.key), Identity: feHex(signers[k])}
		} else {
			scenarioSigners[k] = scenarioParty{Identity: feHex(big.NewInt(0))}
		}
	}
	hiddenIdentity := hiddenParty.identity(t)
	defaultOwner := big.NewInt(0)
	for _, s := range spec.inputs {
		if s.kind == slotUtxo && s.owner == ownerHidden && !s.ring {
			defaultOwner = hiddenIdentity
		}
	}
	for i, s := range spec.outputs {
		if s.kind != slotDummy {
			continue
		}
		switch {
		case s.tag.signer >= 0:
			outputs[i].published = signers[s.tag.signer]
		case s.tag.output >= 0:
			outputs[i].published = outputs[s.tag.output].published
		case s.tag.defaultOwner:
			outputs[i].published = defaultOwner
		}
	}

	// Private transaction hash.
	inputHashes, addressNullifiers := zeroFields(nIn), zeroFields(nIn)
	for i, s := range spec.inputs {
		switch s.kind {
		case slotUtxo:
			inputHashes[i] = inputs[i].hash
		case slotAddress:
			addressNullifiers[i] = inputs[i].nullifier
		}
	}
	outputHashes, publishedOutputHashes := zeroFields(nOut), zeroFields(nOut)
	for i, s := range spec.outputs {
		if s.kind == slotUtxo {
			outputHashes[i] = outputs[i].hash
		}
		if s.kind != slotCompact {
			publishedOutputHashes[i] = outputs[i].hash
		}
	}
	privateBlinding, err := protocol.PrivateTxBlinding(first, blindingSeed)
	privateBlinding = mustValue(t, privateBlinding, err)
	privateTxHash, err := protocol.PrivateTxHash(inputHashes, outputHashes, addressNullifiers, privateBlinding)
	privateTxHash = mustValue(t, privateTxHash, err)

	// Hidden owner signature over sha256(private_tx_hash || external_data_hash).
	externalDataHash := big.NewInt(300)
	var message [64]byte
	privateTxHash.FillBytes(message[:32])
	externalDataHash.FillBytes(message[32:])
	digest := sha256.Sum256(message[:])
	messageHash, err := protocol.HashBytes(digest[:])
	messageHash = mustValue(t, messageHash, err)

	// Public slots and input flags.
	publicAssets, publicAmounts := zeroFields(NPublicSlots), zeroFields(NPublicSlots)
	scenarioPublics := make([]scenarioPublic, len(spec.public))
	for k, p := range spec.public {
		amount := new(big.Int).SetUint64(p.amount)
		if p.withdraw {
			amount.Neg(amount)
		}
		if p.amount != 0 {
			publicAssets[k] = assetOf(t, p.mint)
		}
		publicAmounts[k] = protocol.SignedToField(amount)
		scenarioPublics[k] = scenarioPublic{Mint: keyHex(repeated(p.mint)), Asset: feHex(publicAssets[k]), Amount: amount.String()}
	}
	treeIndexes := make([]*big.Int, nIn)
	for i, s := range spec.inputs {
		treeIndexes[i] = big.NewInt(int64(s.treeSlot))
	}
	inputFlags, err := common.PackInputFlags(spec.allowDummy, treeIndexes)
	inputFlags = mustValue(t, inputFlags, err)

	nullifiers, publishedOwners := make([]*big.Int, nIn), make([]*big.Int, nOut)
	for i := range inputs {
		nullifiers[i] = inputs[i].published
	}
	for i := range outputs {
		publishedOwners[i] = outputs[i].published
	}
	protocolSlots := make([]protocol.TreeSlot, InputTrees)
	for k, slot := range treeSlots {
		protocolSlots[k] = protocol.TreeSlot{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot}
	}
	publicInputs := protocol.PublicInputs{
		Nullifiers: nullifiers, OutputUtxoHashes: publishedOutputHashes, TreeSlots: protocolSlots,
		OutputTreeID: big.NewInt(int64(spec.outputTreeID)), PrivateTxHash: privateTxHash,
		PreimageAfterPrivateTxHash: []*big.Int{messageHash, defaultOwner},
		PreimageTail:               []*big.Int{cache.TreeID, cache.ReadHashChain},
		ExternalDataHash:           externalDataHash, RingProgramID: vectorRing, SignerPkHashes: signers,
		InputFlags: inputFlags, BindOutputOwnerTags: true, OutputOwnerPkHashes: publishedOwners,
	}
	for k := 0; k < NPublicSlots; k++ {
		publicInputs.PublicAssets[k], publicInputs.PublicAmounts[k] = publicAssets[k], publicAmounts[k]
	}
	publicInputHash, err := protocol.PublicInputHash(publicInputs)
	publicInputHash = mustValue(t, publicInputHash, err)

	params := &transfer.AnonymousEddsaTransferParameters{
		NInputs: uint32(nIn), NOutputs: uint32(nOut), TreeSlots: treeSlots,
		OutputTreeID: big.NewInt(int64(spec.outputTreeID)), ExternalDataHash: externalDataHash,
		PrivateTxHash: privateTxHash, BlindingSeed: blindingSeed,
		OwnerPublicKey:     hiddenParty.key,
		MessageHashLow:     new(big.Int).SetBytes(digest[16:]),
		MessageHashHigh:    new(big.Int).SetBytes(digest[:16]),
		DefaultOwnerPkHash: defaultOwner, PublicAssets: publicAssets, PublicAmounts: publicAmounts,
		RingProgramID: vectorRing, SignerPkHashes: signers, InputFlags: inputFlags,
		PublishedOutputOwnerPkHashes: publishedOwners, Cache: cache, PublicInputHash: publicInputHash,
	}
	copy(params.OwnerSignature[:], ed25519.Sign(vectorHiddenKey, digest[:]))

	nonInclusion := func(target *big.Int) protocol.NonInclusionWitness {
		w, err := nullifierTree.NonInclusionWitness(target)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	scenarioInputs := make([]scenarioSlot, nIn)
	for i, s := range spec.inputs {
		in := inputs[i]
		path, index := zeroFields(StateTreeHeight), big.NewInt(0)
		if proof, ok := stateProofs[uint64(17+i)]; ok {
			path, index = proof.PathElements, new(big.Int).SetUint64(proof.PathIndex)
		}
		nf := nonInclusion(in.nullifier)
		isDummy := int64(0)
		if s.kind == slotDummy || s.kind == slotCompact {
			isDummy = 1
		}
		params.Inputs = append(params.Inputs, transfer.InputParams{
			Utxo: utxoRequest(in.utxo), IsDummy: big.NewInt(isDummy),
			StatePathElements: path, StatePathIndex: index,
			NullifierLowValue: nf.LowValue, NullifierNextValue: nf.NextValue,
			NullifierLowPathElements: nf.PathElements, NullifierLowPathIndex: new(big.Int).SetUint64(nf.LowIndex),
			TreeSlot: big.NewInt(int64(s.treeSlot)), Nullifier: in.published,
			OwnerPkHash: in.ownerTag, NullifierSecret: in.secret,
		})
		scenarioInputs[i] = scenarioSlotOf(s, in, spec.treeIDs[s.treeSlot])
		scenarioInputs[i].Nullifier = feHex(in.published)
	}
	scenarioOutputs := make([]scenarioSlot, nOut)
	for i, s := range spec.outputs {
		out := outputs[i]
		isDummy := int64(1)
		if s.kind == slotUtxo {
			isDummy = 0
		}
		params.Outputs = append(params.Outputs, transfer.OutputParams{
			Utxo: utxoRequest(out.utxo), IsDummy: big.NewInt(isDummy), Hash: publishedOutputHashes[i],
			OwnerPkHash: out.ownerTag, NullifierPk: out.nullifierPk,
		})
		scenarioOutputs[i] = scenarioSlotOf(s, out, spec.outputTreeID)
		scenarioOutputs[i].Hash = feHex(publishedOutputHashes[i])
		scenarioOutputs[i].PublishedTag = feHex(out.published)
	}

	request, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	trees := make([]scenarioTree, len(spec.treeIDs))
	for k, id := range spec.treeIDs {
		trees[k] = scenarioTree{ID: id, HasStateRoot: treeSlots[k].UtxoRoot.Sign() != 0}
	}
	return anonymousVector{
		Name: spec.name, Cases: spec.cases, Description: spec.description, Request: request,
		Scenario: anonymousScenario{
			NInputs: nIn, NOutputs: nOut, RingProgramID: feHex(vectorRing),
			HiddenOwnerKey: keyHex(hiddenParty.key), HiddenIdentity: feHex(hiddenIdentity),
			DefaultOwner: feHex(defaultOwner), AllowDummyInputs: spec.allowDummy, Signers: scenarioSigners,
			TreeSlots: trees, OutputTreeID: spec.outputTreeID, CacheTreeID: spec.cacheTreeID,
			Inputs: scenarioInputs, Outputs: scenarioOutputs, Public: scenarioPublics,
		},
	}
}

func scenarioSlotOf(s slotSpec, built builtSlot, treeID uint16) scenarioSlot {
	slot := scenarioSlot{
		Kind: s.kind, OwnerIdentity: feHex(built.identity), NullifierPk: feHex(built.nullifierPk), Ring: s.ring,
		Asset: feHex(built.utxo.Asset), Amount: built.utxo.Amount.String(), Blinding: feHex(built.utxo.Blinding),
		DataHash: feHex(built.utxo.DataHash), RingDataHash: feHex(built.utxo.RingDataHash), TreeID: treeID,
		TreeSlot: s.treeSlot, Cached: s.cached, Hash: feHex(built.hash),
	}
	if s.kind == slotUtxo || s.kind == slotAddress {
		slot.Owner, slot.OwnerKey = s.owner, keyHex(s.party.key)
	}
	if s.kind == slotUtxo {
		slot.Mint = keyHex(repeated(s.mint))
	}
	return slot
}

func utxoRequest(u protocol.Utxo) transfer.UtxoParams {
	return transfer.UtxoParams{
		Domain: u.Domain, Owner: u.Owner, Asset: u.Asset, Amount: u.Amount, Blinding: u.Blinding,
		DataHash: u.DataHash, RingDataHash: u.RingDataHash, RingProgramID: u.RingProgramID,
	}
}

// assertVectorBalances fails early on a spec whose assets do not balance, so
// a typo reads as a spec error rather than a circuit refusal.
func assertVectorBalances(t testing.TB, spec vectorSpec) {
	t.Helper()
	sums := map[byte]*big.Int{}
	add := func(mint byte, amount *big.Int) {
		if sums[mint] == nil {
			sums[mint] = big.NewInt(0)
		}
		sums[mint].Add(sums[mint], amount)
	}
	for _, s := range spec.inputs {
		if s.kind == slotUtxo {
			add(s.mint, new(big.Int).SetUint64(s.amount))
		}
	}
	for _, p := range spec.public {
		amount := new(big.Int).SetUint64(p.amount)
		if p.withdraw {
			amount.Neg(amount)
		}
		add(p.mint, amount)
	}
	for _, s := range spec.outputs {
		if s.kind == slotUtxo {
			add(s.mint, new(big.Int).Neg(new(big.Int).SetUint64(s.amount)))
		}
	}
	for mint, sum := range sums {
		if sum.Sign() != 0 {
			t.Fatalf("%s: mint %#x is off by %s", spec.name, mint, sum)
		}
	}
}

func anonymousVectorsPath(t testing.TB) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	return filepath.Join(filepath.Dir(source), anonymousEddsaVectorsFile)
}

// Every committed vector decodes through the prover's request parser and
// solves the anonymous EdDSA circuit, and the file matches the generator.
func TestAnonymousEddsaAcceptingVectors(t *testing.T) {
	file := anonymousVectorFile{
		Description: "Transactions the transfer-eddsa-ring (CustomRingAnonymousEddsa) circuit accepts, one functional path each. " +
			"cases name the entries of the anonymous circuit's accepting test list. scenario describes every slot in the terms a composing circuit opens; " +
			"request is the exact prover request. Produced by TestAnonymousEddsaAcceptingVectors in " +
			"prover/server/circuits/spp_transaction/shared/anonymous_eddsa_vectors_test.go: " +
			"UPDATE_ANONYMOUS_EDDSA_VECTORS=1 go test ./circuits/spp_transaction/shared -run TestAnonymousEddsaAcceptingVectors",
	}
	for _, spec := range anonymousVectorSpecs() {
		file.Vectors = append(file.Vectors, buildAnonymousVector(t, spec))
	}
	for _, vector := range file.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			var params transfer.AnonymousEddsaTransferParameters
			if err := json.Unmarshal(vector.Request, &params); err != nil {
				t.Fatal(err)
			}
			if err := params.ValidateShape(); err != nil {
				t.Fatal(err)
			}
			witness, err := params.CreateWitness()
			if err != nil {
				t.Fatal(err)
			}
			skeleton, err := customring.NewCustomRingAnonymousEddsaCircuit(Shape{NInputs: int(params.NInputs), NOutputs: int(params.NOutputs)})
			if err != nil {
				t.Fatal(err)
			}
			if err := test.IsSolved(skeleton, witness, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			// A changed public input hash must not solve, so a pass above is not vacuous.
			params.PublicInputHash = new(big.Int).Add(params.PublicInputHash, big.NewInt(1))
			changed, err := params.CreateWitness()
			if err != nil {
				t.Fatal(err)
			}
			if test.IsSolved(skeleton, changed, ecc.BN254.ScalarField()) == nil {
				t.Fatal("a changed public input hash solved")
			}
		})
	}
	data := encodeAnonymousVectorFile(t, file)
	path := anonymousVectorsPath(t)
	if os.Getenv("UPDATE_ANONYMOUS_EDDSA_VECTORS") != "" {
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	committed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, data) {
		t.Fatalf("%s is stale; rewrite it with UPDATE_ANONYMOUS_EDDSA_VECTORS=1", anonymousEddsaVectorsFile)
	}
}

// encodeAnonymousVectorFile writes one compact vector per line, which keeps
// the long Merkle paths of every request off their own lines.
func encodeAnonymousVectorFile(t testing.TB, file anonymousVectorFile) []byte {
	t.Helper()
	description, err := json.Marshal(file.Description)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.WriteString("{\n  \"description\": ")
	out.Write(description)
	out.WriteString(",\n  \"vectors\": [\n")
	for i, vector := range file.Vectors {
		line, err := json.Marshal(vector)
		if err != nil {
			t.Fatal(err)
		}
		out.WriteString("    ")
		out.Write(line)
		if i+1 < len(file.Vectors) {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	out.WriteString("  ]\n}\n")
	return out.Bytes()
}
