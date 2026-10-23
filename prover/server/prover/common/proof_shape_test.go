package common

import "testing"

func TestProtocolProofShapesKeepTheirKeyFileNames(t *testing.T) {
	for _, circuit := range []CircuitType{
		TransferConfidentialCircuitType,
		TransferRingCircuitType,
		TransferAnonymousRingEddsaCircuitType,
	} {
		shape := ProofShape{Circuit: circuit, Inputs: 2, Outputs: 2}
		want := map[CircuitType]string{
			TransferConfidentialCircuitType:       "transfer_confidential_2_2.key",
			TransferRingCircuitType:               "transfer_ring_2_2.key",
			TransferAnonymousRingEddsaCircuitType: "transfer_eddsa_ring_2_2.key",
		}[circuit]
		if got := shape.KeyFile(); got != want {
			t.Fatalf("%s: got %q want %q", circuit, got, want)
		}
		if got := TransferKeyFile(circuit, 2, 2); got != want {
			t.Fatalf("%s: TransferKeyFile got %q want %q", circuit, got, want)
		}
	}
}

func TestProofShapeDimensionsNameTheirOwnKeyFiles(t *testing.T) {
	cases := []struct {
		shape ProofShape
		want  string
	}{
		{ProofShape{Circuit: TransferRingCircuitType, Inputs: 2, Outputs: 2, SignerWidth: 1}, "transfer_ring_2_2_s1.key"},
		{ProofShape{Circuit: TransferConfidentialCircuitType, Inputs: 4, Outputs: 4, SignerWidth: 9}, "transfer_confidential_4_4_s9.key"},
		{ProofShape{Circuit: TransferAnonymousRingEddsaCircuitType, Inputs: 2, Outputs: 2, HiddenOwners: 2}, "transfer_eddsa_ring_2_2_h2.key"},
		{ProofShape{Circuit: TransferAnonymousRingEddsaCircuitType, Inputs: 4, Outputs: 2, SignerWidth: 3, HiddenOwners: 4}, "transfer_eddsa_ring_4_2_s3_h4.key"},
	}
	for _, tc := range cases {
		if got := tc.shape.KeyFile(); got != tc.want {
			t.Fatalf("%s: got %q want %q", tc.shape, got, tc.want)
		}
		width, owners, err := TransferKeyFileDimensions(tc.want)
		if err != nil {
			t.Fatal(err)
		}
		if width != tc.shape.SignerWidth || owners != tc.shape.HiddenOwners {
			t.Fatalf("%s: parsed width %d and owners %d", tc.want, width, owners)
		}
	}
}

func TestProtocolKeyFilesParseWithoutDimensions(t *testing.T) {
	for _, name := range KeyFiles() {
		width, owners, err := TransferKeyFileDimensions(name)
		if err != nil || width != 0 || owners != 0 {
			t.Fatalf("%s: got width %d owners %d err %v", name, width, owners, err)
		}
	}
}

func TestTransferKeyFileDimensionsRejectsMalformedSuffixes(t *testing.T) {
	for _, name := range []string{"transfer_ring_2_2_s0.key", "transfer_ring_2_2_sx.key", "transfer_eddsa_ring_2_2_h0.key"} {
		if _, _, err := TransferKeyFileDimensions(name); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// A preloaded system must be found by the lookup a request makes. The key
// directory is empty, so a cache miss would fail to load.
func TestPreloadedTransferSystemsAreFoundByShape(t *testing.T) {
	m := NewLazyKeyManager(t.TempDir(), &DownloadConfig{})
	for _, ps := range []*TransferProofSystem{
		{CircuitType: TransferConfidentialCircuitType, NInputs: 2, NOutputs: 2},
		{CircuitType: TransferAnonymousRingEddsaCircuitType, NInputs: 2, NOutputs: 2, HiddenOwners: 2},
		{CircuitType: MergeRingCircuitType, NInputs: 24, NOutputs: 1},
	} {
		if err := m.cacheSystem(ps.Shape().KeyFile(), ps); err != nil {
			t.Fatal(err)
		}
		got, err := m.GetTransferSystemFor(ps.Shape())
		if err != nil || got != ps {
			t.Fatalf("%s: preloaded system not found: %v", ps.Shape(), err)
		}
	}
	if _, err := m.GetTransferSystemFor(ProofShape{Circuit: TransferAnonymousRingEddsaCircuitType, Inputs: 2, Outputs: 2}); err == nil {
		t.Fatal("a two-owner system answered a protocol lookup")
	}
}

func TestProofShapeRejectsUnsupportedDimensions(t *testing.T) {
	for name, shape := range map[string]ProofShape{
		"hidden owners off the anonymous rail": {Circuit: TransferRingCircuitType, Inputs: 2, Outputs: 2, HiddenOwners: 2},
		"one explicit hidden owner":            {Circuit: TransferAnonymousRingEddsaCircuitType, Inputs: 2, Outputs: 2, HiddenOwners: 1},
		"more hidden owners than inputs":       {Circuit: TransferAnonymousRingEddsaCircuitType, Inputs: 2, Outputs: 2, HiddenOwners: 3},
		"signer width on ring authority":       {Circuit: TransferRingAuthorityCircuitType, Inputs: 2, Outputs: 2, SignerWidth: 2},
		"signer width on merge":                {Circuit: MergeCircuitType, Inputs: 8, Outputs: 1, SignerWidth: 2},
		"signer width past the address limit":  {Circuit: TransferRingCircuitType, Inputs: 2, Outputs: 2, SignerWidth: MaxTransferSignerWidth + 1},
		"unsupported counts":                   {Circuit: TransferRingCircuitType, Inputs: 7, Outputs: 2, SignerWidth: 2},
	} {
		if shape.Supported() || shape.KeyFile() != "" {
			t.Fatalf("%s: accepted %s", name, shape)
		}
	}
}
