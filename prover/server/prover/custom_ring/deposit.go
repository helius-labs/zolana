package custom_ring

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/custom_rings/circuits/deposit"
	"zolana/prover/prover/common"
)

// DepositParameters binds a deposit batch to its auditor disclosure proof.
type DepositParameters struct {
	PublicInputHash *big.Int
	ContextHash     *big.Int
	Count           uint32
	OwnerPkHashes   [deposit.MaxDeposits]*big.Int
	NullifierPks    [deposit.MaxDeposits]*big.Int
	Blindings       [deposit.MaxDeposits]*big.Int
	// Absent for the zero key, with escrow off or in padding.
	Keys      [deposit.MaxDeposits]*RegistryKey
	EphSk     [scalarLen]byte
	AuditorPk [uncompressedPubkeyLen]byte
	KeyEscrow KeyEscrow
}

// The HTTP request preserves exact array lengths and canonical field encodings.
type depositParametersJSON struct {
	CircuitType     string             `json:"circuitType"`
	PublicInputHash string             `json:"publicInputHash"`
	ContextHash     string             `json:"contextHash"`
	Count           uint32             `json:"count"`
	OwnerPkHashes   []string           `json:"ownerPkHashes"`
	NullifierPks    []string           `json:"nullifierPks"`
	Blindings       []string           `json:"blindings"`
	Keys            []*registryKeyJSON `json:"keys"`
	EphSk           string             `json:"ephSk"`
	AuditorPk       string             `json:"auditorPk"`
	KeyEscrow       bool               `json:"keyEscrow"`
	KeyRegistryRoot string             `json:"keyRegistryRoot"`
}

func (p *DepositParameters) MarshalJSON() ([]byte, error) {
	keys := make([]*registryKeyJSON, deposit.MaxDeposits)
	for i, key := range p.Keys {
		keys[i] = writeRegistryKey(key)
	}
	return json.Marshal(depositParametersJSON{
		CircuitType: string(common.CustomRingDepositCircuitType), PublicInputHash: common.ToHex(p.PublicInputHash),
		ContextHash: common.ToHex(p.ContextHash), Count: p.Count,
		OwnerPkHashes: writePath(p.OwnerPkHashes[:]), NullifierPks: writePath(p.NullifierPks[:]),
		Blindings: writePath(p.Blindings[:]), Keys: keys,
		EphSk: bytesHex(p.EphSk[:]), AuditorPk: bytesHex(p.AuditorPk[:]),
		KeyEscrow: p.KeyEscrow.Enabled, KeyRegistryRoot: common.ToHex(p.KeyEscrow.Root),
	})
}

func (p *DepositParameters) UnmarshalJSON(data []byte) error {
	var raw depositParametersJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if raw.CircuitType != string(common.CustomRingDepositCircuitType) {
		return fmt.Errorf("custom-ring-deposit: unexpected circuitType %q", raw.CircuitType)
	}
	if raw.Count < 1 || raw.Count > deposit.MaxDeposits || len(raw.Keys) != deposit.MaxDeposits {
		return fmt.Errorf("custom-ring-deposit: invalid count or opening array length")
	}
	p.Count = raw.Count
	var err error
	if p.PublicInputHash, err = fieldFromHex(raw.PublicInputHash, "publicInputHash"); err != nil {
		return err
	}
	if p.ContextHash, err = fieldFromHex(raw.ContextHash, "contextHash"); err != nil {
		return err
	}
	if p.KeyEscrow, err = readKeyEscrow(raw.KeyEscrow, raw.KeyRegistryRoot); err != nil {
		return err
	}
	for _, column := range []struct {
		dst  []*big.Int
		src  []string
		name string
	}{
		{p.OwnerPkHashes[:], raw.OwnerPkHashes, "ownerPkHashes"},
		{p.NullifierPks[:], raw.NullifierPks, "nullifierPks"},
		{p.Blindings[:], raw.Blindings, "blindings"},
	} {
		if err = readPath(column.dst, column.src, column.name); err != nil {
			return err
		}
	}
	for i := range p.Keys {
		if p.Keys[i], err = readRegistryKey(raw.Keys[i]); err != nil {
			return err
		}
		if i >= int(p.Count) {
			if p.OwnerPkHashes[i].Sign() != 0 || p.NullifierPks[i].Sign() != 0 || p.Blindings[i].Sign() != 0 || p.Keys[i] != nil {
				return fmt.Errorf("custom-ring-deposit: nonzero padding at slot %d", i)
			}
			continue
		}
		if err = p.KeyEscrow.requireEscrowed(p.Keys[i], fmt.Sprintf("deposit %d", i)); err != nil {
			return err
		}
	}
	if err := bytesFromHex(p.EphSk[:], raw.EphSk, "ephSk"); err != nil {
		return err
	}
	if err := validateP256Scalar(p.EphSk[:], "ephSk"); err != nil {
		return err
	}
	if err := bytesFromHex(p.AuditorPk[:], raw.AuditorPk, "auditorPk"); err != nil {
		return err
	}
	return validateP256Point(p.AuditorPk[:], "auditorPk")
}

func (p *DepositParameters) CreateWitness() (*deposit.CustomRingDepositCircuit, error) {
	if p.PublicInputHash == nil || p.ContextHash == nil || p.KeyEscrow.Root == nil || p.Count < 1 || p.Count > deposit.MaxDeposits {
		return nil, fmt.Errorf("custom-ring-deposit: missing hashes or invalid count")
	}
	circuit := &deposit.CustomRingDepositCircuit{
		PublicInputHash: p.PublicInputHash,
		ContextHash:     p.ContextHash,
		Count:           p.Count,
		KeyEscrow:       boolVar(p.KeyEscrow.Enabled),
		KeyRegistryRoot: p.KeyEscrow.Root,
	}
	for i := range circuit.OwnerPkHashes {
		if p.OwnerPkHashes[i] == nil || p.NullifierPks[i] == nil || p.Blindings[i] == nil {
			return nil, fmt.Errorf("custom-ring-deposit: missing opening at slot %d", i)
		}
		circuit.OwnerPkHashes[i], circuit.NullifierPks[i], circuit.Blindings[i] = p.OwnerPkHashes[i], p.NullifierPks[i], p.Blindings[i]
		assignRegistryKey(&circuit.Keys[i], p.Keys[i])
	}
	assignBytes(circuit.EphSk[:], p.EphSk[:])
	assignBytes(circuit.AuditorPk[:], p.AuditorPk[:])
	return circuit, nil
}
