package witness

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"

	"circuits/cancel"
	"circuits/create"
	"circuits/fill"
	"circuits/fill_verifiable_encryption"
	"circuits/stub"
)

func AssignStub(witnessValues map[string][]string) (frontend.Circuit, error) {
	c := &stub.Circuit{}

	fieldAssignments := []struct {
		key string
		dst *frontend.Variable
	}{
		{"PublicInputHash", &c.PublicInputHash},
		{"A", &c.A},
		{"B", &c.B},
	}

	known := make(map[string]bool, len(fieldAssignments))
	for _, field := range fieldAssignments {
		v, err := singleField(witnessValues, field.key)
		if err != nil {
			return nil, err
		}
		*field.dst = v
		known[field.key] = true
	}

	if err := checkUnexpected(witnessValues, known); err != nil {
		return nil, err
	}
	return c, nil
}

func AssignCreate(witnessValues map[string][]string) (frontend.Circuit, error) {
	c := &create.Circuit{}

	fieldAssignments := []struct {
		key string
		dst *frontend.Variable
	}{
		{"PublicInputHash", &c.PublicInputHash},
		{"PrivateTxHash", &c.PrivateTxHash},
		{"SourceAssetId", &c.SourceAssetId},
		{"SourceAsset", &c.SourceAsset},
		{"EscrowOwner", &c.EscrowOwner},
		{"SourceAmount", &c.SourceAmount},
		{"EscrowBlinding", &c.EscrowBlinding},
		{"DestinationAsset", &c.DestinationAsset},
		{"DestinationAmount", &c.DestinationAmount},
		{"MakerOwnerHash", &c.MakerOwnerHash},
		{"Expiry", &c.Expiry},
		{"TakerPkFe", &c.TakerPkFe},
		{"FillMode", &c.FillMode},
		{"ExternalDataHash", &c.ExternalDataHash},
		{"SourceInputHash", &c.SourceInputHash},
		{"ChangeAmount", &c.ChangeAmount},
		{"ChangeBlinding", &c.ChangeBlinding},
		{"MarkerOutputHash", &c.MarkerOutputHash},
	}

	known := make(map[string]bool, len(fieldAssignments)+1)
	for _, field := range fieldAssignments {
		v, err := singleField(witnessValues, field.key)
		if err != nil {
			return nil, err
		}
		*field.dst = v
		known[field.key] = true
	}

	if err := assignArray(witnessValues, "MakerViewingPk", c.MakerViewingPk[:]); err != nil {
		return nil, err
	}
	known["MakerViewingPk"] = true

	if err := checkUnexpected(witnessValues, known); err != nil {
		return nil, err
	}
	return c, nil
}

func AssignCancel(witnessValues map[string][]string) (frontend.Circuit, error) {
	c := &cancel.Circuit{}

	fieldAssignments := []struct {
		key string
		dst *frontend.Variable
	}{
		{"PublicInputHash", &c.PublicInputHash},
		{"PrivateTxHash", &c.PrivateTxHash},
		{"Expiry", &c.Expiry},
		{"SourceAsset", &c.SourceAsset},
		{"EscrowOwner", &c.EscrowOwner},
		{"SourceAmount", &c.SourceAmount},
		{"EscrowBlinding", &c.EscrowBlinding},
		{"DestinationAsset", &c.DestinationAsset},
		{"DestinationAmount", &c.DestinationAmount},
		{"MakerOwnerHash", &c.MakerOwnerHash},
		{"MakerOwnerPkField", &c.MakerOwnerPkField},
		{"MakerNullifierPk", &c.MakerNullifierPk},
		{"TakerPkFe", &c.TakerPkFe},
		{"FillMode", &c.FillMode},
		{"SourceOutputBlinding", &c.SourceOutputBlinding},
		{"ExternalDataHash", &c.ExternalDataHash},
	}

	known := make(map[string]bool, len(fieldAssignments)+1)
	for _, field := range fieldAssignments {
		v, err := singleField(witnessValues, field.key)
		if err != nil {
			return nil, err
		}
		*field.dst = v
		known[field.key] = true
	}

	if err := assignArray(witnessValues, "MakerViewingPk", c.MakerViewingPk[:]); err != nil {
		return nil, err
	}
	known["MakerViewingPk"] = true

	if err := checkUnexpected(witnessValues, known); err != nil {
		return nil, err
	}
	return c, nil
}

func AssignFill(witnessValues map[string][]string) (frontend.Circuit, error) {
	c := &fill.Circuit{}

	fieldAssignments := []struct {
		key string
		dst *frontend.Variable
	}{
		{"PublicInputHash", &c.PublicInputHash},
		{"PrivateTxHash", &c.PrivateTxHash},
		{"Expiry", &c.Expiry},
		{"SourceAsset", &c.SourceAsset},
		{"DestinationAsset", &c.DestinationAsset},
		{"EscrowOwner", &c.EscrowOwner},
		{"SourceAmount", &c.SourceAmount},
		{"EscrowBlinding", &c.EscrowBlinding},
		{"DestinationAmount", &c.DestinationAmount},
		{"MakerOwnerHash", &c.MakerOwnerHash},
		{"TakerPkFe", &c.TakerPkFe},
		{"TakerAddress", &c.TakerAddress},
		{"TakerInBlinding", &c.TakerInBlinding},
		{"SourceOutputBlinding", &c.SourceOutputBlinding},
		{"ExternalDataHash", &c.ExternalDataHash},
	}

	known := make(map[string]bool, len(fieldAssignments)+1)
	for _, field := range fieldAssignments {
		v, err := singleField(witnessValues, field.key)
		if err != nil {
			return nil, err
		}
		*field.dst = v
		known[field.key] = true
	}

	if err := assignArray(witnessValues, "MakerViewingPk", c.MakerViewingPk[:]); err != nil {
		return nil, err
	}
	known["MakerViewingPk"] = true

	if err := checkUnexpected(witnessValues, known); err != nil {
		return nil, err
	}
	return c, nil
}

func AssignFillVerifiableEncryption(witnessValues map[string][]string) (frontend.Circuit, error) {
	c := &fill_verifiable_encryption.Circuit{}

	fieldAssignments := []struct {
		key string
		dst *frontend.Variable
	}{
		{"PublicInputHash", &c.PublicInputHash},
		{"PrivateTxHash", &c.PrivateTxHash},
		{"Expiry", &c.Expiry},
		{"SourceAsset", &c.SourceAsset},
		{"DestinationAsset", &c.DestinationAsset},
		{"EscrowOwner", &c.EscrowOwner},
		{"SourceAmount", &c.SourceAmount},
		{"EscrowBlinding", &c.EscrowBlinding},
		{"DestinationAmount", &c.DestinationAmount},
		{"MakerOwnerHash", &c.MakerOwnerHash},
		{"TakerPkFe", &c.TakerPkFe},
		{"TakerNullifierPk", &c.TakerNullifierPk},
		{"TakerAddress", &c.TakerAddress},
		{"TakerInBlinding", &c.TakerInBlinding},
		{"DestinationOutputBlinding", &c.DestinationOutputBlinding},
		{"SourceOutputBlinding", &c.SourceOutputBlinding},
		{"ExternalDataHash", &c.ExternalDataHash},
	}

	known := make(map[string]bool, len(fieldAssignments)+1)
	for _, field := range fieldAssignments {
		v, err := singleField(witnessValues, field.key)
		if err != nil {
			return nil, err
		}
		*field.dst = v
		known[field.key] = true
	}

	if err := assignArray(witnessValues, "MakerViewingPk", c.MakerViewingPk[:]); err != nil {
		return nil, err
	}
	known["MakerViewingPk"] = true

	if err := checkUnexpected(witnessValues, known); err != nil {
		return nil, err
	}
	return c, nil
}

func assignArray(witnessValues map[string][]string, key string, dst []frontend.Variable) error {
	vals, ok := witnessValues[key]
	if !ok {
		return fmt.Errorf("witness: missing key %q", key)
	}
	if len(vals) != len(dst) {
		return fmt.Errorf("witness: key %q expected %d values, got %d", key, len(dst), len(vals))
	}
	for i, raw := range vals {
		n, ok := new(big.Int).SetString(raw, 10)
		if !ok {
			return fmt.Errorf("witness: key %q[%d] invalid decimal %q", key, i, raw)
		}
		dst[i] = frontend.Variable(n)
	}
	return nil
}

func checkUnexpected(witnessValues map[string][]string, known map[string]bool) error {
	for k := range witnessValues {
		if !known[k] {
			return fmt.Errorf("witness: unexpected key %q", k)
		}
	}
	return nil
}

func singleField(witnessValues map[string][]string, key string) (frontend.Variable, error) {
	n, err := singleBigInt(witnessValues, key)
	if err != nil {
		return nil, err
	}
	return frontend.Variable(n), nil
}

func singleBigInt(witnessValues map[string][]string, key string) (*big.Int, error) {
	vals, ok := witnessValues[key]
	if !ok {
		return nil, fmt.Errorf("witness: missing key %q", key)
	}
	if len(vals) != 1 {
		return nil, fmt.Errorf("witness: key %q expected 1 value, got %d", key, len(vals))
	}
	var raw string
	for _, v := range vals {
		raw = v
	}
	n, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return nil, fmt.Errorf("witness: key %q invalid decimal %q", key, raw)
	}
	return n, nil
}
