package deposit_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/deposit"
	"github.com/helius-labs/zolana/prover/server/prover-test/refusal"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringdeposit"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringrecords"
)

func solve(c *deposit.CustomRingDepositCircuit) error {
	return test.IsSolved(&deposit.CustomRingDepositCircuit{}, c, ecc.BN254.ScalarField())
}

// The program builds one flag combination per ring mode, escrow only on a registry ring.
func TestDepositSolvesEveryRingMode(t *testing.T) {
	for _, tc := range []struct {
		count int
		mode  ringdeposit.RingMode
	}{{1, ringdeposit.ModeRegistry}, {deposit.MaxDeposits, ringdeposit.ModeRegistry}, {2, ringdeposit.ModeAnonymous}, {2, ringdeposit.ModeOff}} {
		if err := solve(ringdeposit.Build(t, tc.count, tc.mode).Circuit); err != nil {
			t.Fatalf("count %d mode %d: %v", tc.count, tc.mode, err)
		}
	}
}

// Each case changes one value of an honest deposit, rebinds the statement when the value
// is a statement element, and the named frames raise the refusal.
func TestDepositRefusals(t *testing.T) {
	define := []string{"deposit.(*CustomRingDepositCircuit).Define"}
	tests := []struct {
		name   string
		mode   ringdeposit.RingMode
		tamper func(*testing.T, *ringdeposit.Deposit)
		frames []string
	}{
		{"a commitment whose blinding is not in the CRDB domain", ringdeposit.ModeRegistry, func(t *testing.T, d *ringdeposit.Deposit) {
			// The commitments and the auditor's openings all use the raw secret as the blinding.
			*d = *ringdeposit.BuildBlinded(t, 2, ringdeposit.ModeRegistry, func(_ testing.TB, secret *big.Int) *big.Int { return secret })
		}, append([]string{"[assertIsEqual]"}, define...)},
		{"an escrowed owner opened through another member's record", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.Members[0] = d.Circuit.Members[1]
		}, []string{"gadget.AssertEqualWhen", "records.QuadRecordOpening.AssertPresent"}},
		{"a record escrowing another key", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.CtHashes[0] = big.NewInt(0xdd)
		}, append([]string{"gadget.AssertEqualWhen"}, define...)},
		{"a padding slot with a blinding secret", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.BlindingSecrets[deposit.MaxDeposits-1] = 1
		}, append([]string{"gadget.AssertZeroWhen"}, define...)},
		{"an anonymous owner hash of another key", ringdeposit.ModeAnonymous, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[0][1] = 0
		}, append([]string{"gadget.AssertEqualWhen"}, define...)},
		{"a key disclosed by a ring that is not anonymous", ringdeposit.ModeOff, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[0][0] = 1
		}, append([]string{"gadget.AssertZeroWhen"}, define...)},
		{"owner key bytes outside 0..255 with the same owner identity", ringdeposit.ModeAnonymous, func(_ *testing.T, d *ringdeposit.Deposit) {
			// Moving 256 between adjacent bytes keeps the identity, the envelope's byte table refuses the encoding.
			key := &d.Circuit.OwnerKeys[0]
			key[3], key[4] = key[3].(int)-1, key[4].(int)+256
		}, append([]string{"base.Envelope.Seal"}, define...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ringdeposit.Build(t, 2, tt.mode)
			tt.tamper(t, d)
			refusal.Require(t, solve(d.Circuit), tt.frames...)
		})
	}
}

func TestDepositKey(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &deposit.CustomRingDepositCircuit{}, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	if got, pinned := cs.GetNbConstraints(), 148856; got != pinned {
		t.Errorf("deposit constraints=%d, pinned %d", got, pinned)
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
		t.Errorf("deposit commitments %v", cs.GetCommitments())
	}
}

// depositStatementVector is the deposit case custom-rings/interface/tests/statements.rs writes, the registry root absent without escrow.
type depositStatementVector struct {
	ContextHash        ringrecords.Hex   `json:"context_hash"`
	Anonymous          bool              `json:"anonymous"`
	OwnerUtxoHashes    []ringrecords.Hex `json:"owner_utxo_hashes"`
	Ciphertexts        []string          `json:"ciphertexts"`
	AuditorPubkey      string            `json:"auditor_pubkey"`
	EphPk              string            `json:"eph_pk"`
	MemberRegistryRoot *ringrecords.Hex  `json:"member_registry_root"`
	PublicInputHash    ringrecords.Hex   `json:"public_input_hash"`
}

// depositStatementCircuit feeds the vector's commitments and envelope to the circuit's statement as base.Sealed packs them.
type depositStatementCircuit struct {
	PublicInputHash    frontend.Variable `gnark:",public"`
	ContextHash        frontend.Variable
	Count              frontend.Variable
	Anonymous          frontend.Variable
	KeyEscrow          frontend.Variable
	MemberRegistryRoot frontend.Variable
	Commitments        [deposit.MaxDeposits]frontend.Variable
	Ciphertext         [deposit.MaxDeposits * deposit.OpeningBytes]frontend.Variable
	AuditorPubkey      [33]frontend.Variable
	EphPk              [33]frontend.Variable
}

func (c *depositStatementCircuit) Define(api frontend.API) error {
	circuit := &deposit.CustomRingDepositCircuit{
		ContextHash: c.ContextHash, Count: c.Count, Anonymous: c.Anonymous, KeyEscrow: c.KeyEscrow, MemberRegistryRoot: c.MemberRegistryRoot,
	}
	sealed := base.Sealed{
		Auditor:    gadget.PackBytesBE(api, c.AuditorPubkey[:]),
		Eph:        gadget.PackBytesBE(api, c.EphPk[:]),
		Ciphertext: c.Ciphertext[:],
	}
	statement := deposit.Statement(api, circuit, base.SelectCount(api, c.Count, 1, deposit.MaxDeposits), c.Commitments[:], sealed)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, statement))
	return nil
}

// The Rust case is not a sealed envelope, so the circuit's statement method is solved against its public input.
func TestDepositStatementMatchesRustVector(t *testing.T) {
	raw, err := os.ReadFile("../../../../../test-vectors/ring-statements.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Deposit depositStatementVector `json:"deposit"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	v := vectors.Deposit
	if len(v.OwnerUtxoHashes) != len(v.Ciphertexts) || len(v.OwnerUtxoHashes) == 0 || len(v.OwnerUtxoHashes) > deposit.MaxDeposits {
		t.Fatalf("%d commitments for %d ciphertexts", len(v.OwnerUtxoHashes), len(v.Ciphertexts))
	}
	witness := &depositStatementCircuit{
		PublicInputHash: v.PublicInputHash.Int, ContextHash: v.ContextHash.Int, Count: len(v.OwnerUtxoHashes),
		Anonymous: 0, KeyEscrow: 0, MemberRegistryRoot: 0,
	}
	if v.Anonymous {
		witness.Anonymous = 1
	}
	if v.MemberRegistryRoot != nil {
		witness.KeyEscrow, witness.MemberRegistryRoot = 1, v.MemberRegistryRoot.Int
	}
	for i := range witness.Commitments {
		witness.Commitments[i] = 0
	}
	for i := range witness.Ciphertext {
		witness.Ciphertext[i] = 0
	}
	decode := func(value string, wires []frontend.Variable) {
		bytes, err := hex.DecodeString(value)
		if err != nil || len(bytes) != len(wires) {
			t.Fatalf("invalid %d-byte vector value %q", len(wires), value)
		}
		for i, b := range bytes {
			wires[i] = int(b)
		}
	}
	for i, commitment := range v.OwnerUtxoHashes {
		witness.Commitments[i] = commitment.Int
		decode(v.Ciphertexts[i], witness.Ciphertext[i*deposit.OpeningBytes:(i+1)*deposit.OpeningBytes])
	}
	decode(v.AuditorPubkey, witness.AuditorPubkey[:])
	decode(v.EphPk, witness.EphPk[:])
	if err := test.IsSolved(&depositStatementCircuit{}, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("the deposit statement differs from the Rust vector: %v", err)
	}
	witness.PublicInputHash = new(big.Int).Add(v.PublicInputHash.Int, big.NewInt(1))
	if test.IsSolved(&depositStatementCircuit{}, witness, ecc.BN254.ScalarField()) == nil {
		t.Fatal("the statement solved under another public input")
	}
}
