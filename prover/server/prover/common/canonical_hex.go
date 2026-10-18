package common

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// DecodeCanonicalHex accepts the wire spelling used for byte strings in ring proofs.
func DecodeCanonicalHex(encoded string) ([]byte, error) {
	if !strings.HasPrefix(encoded, "0x") || strings.ToLower(encoded) != encoded {
		return nil, fmt.Errorf("expected lowercase 0x-prefixed hex bytes")
	}
	decoded, err := hex.DecodeString(encoded[2:])
	if err != nil {
		return nil, fmt.Errorf("expected lowercase 0x-prefixed hex bytes: %w", err)
	}
	return decoded, nil
}

// DecodeCanonicalHexInto additionally requires the fixed byte width of out.
func DecodeCanonicalHexInto(out []byte, encoded string) error {
	if len(encoded) != 2+2*len(out) {
		return fmt.Errorf("expected %d lowercase 0x-prefixed hex bytes", len(out))
	}
	decoded, err := DecodeCanonicalHex(encoded)
	if err != nil {
		return err
	}
	copy(out, decoded)
	return nil
}
