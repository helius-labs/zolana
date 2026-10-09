package aes

import (
	"math/big"
	"testing"
)

// The Lean lookup hypotheses quote AesTables.lean, which is rendered from these
// accessors; newSpreadTables inserts the accessor rows directly. This test pins
// the accessors to the row construction the lookup tables used before they
// were built from the accessors.
func TestTableAccessorsMatchLookupRows(t *testing.T) {
	var substitution []*big.Int
	for region := 0; region < sboxRegion; region++ {
		for byteValue := 0; byteValue < tableRegionSize; byteValue++ {
			substitution = append(substitution, spreadValue(uint64(substitutionWords[region][byteValue]), bitsPerByte*wordBytes))
		}
	}
	for byteValue := 0; byteValue < tableRegionSize; byteValue++ {
		substitution = append(substitution, spreadValue(uint64(sbox0[byteValue]), bitsPerByte))
	}
	assertBigRows(t, "substitution", SubstitutionTable(), substitution)

	var spreadBytes []*big.Int
	for byteValue := 0; byteValue < tableRegionSize; byteValue++ {
		spreadBytes = append(spreadBytes, spreadValue(uint64(byteValue), bitsPerByte))
	}
	assertBigRows(t, "spread bytes", SpreadByteTable(), spreadBytes)

	parity := ChunkParityTable()
	if len(parity) != chunkRadix {
		t.Fatalf("chunk parity has %d rows, want %d", len(parity), chunkRadix)
	}
	for chunk, got := range parity {
		if want := chunkParity(chunk); got != want {
			t.Fatalf("chunk parity row %d is %d, want %d", chunk, got, want)
		}
	}

	sbox := SboxTable()
	if sbox != sbox0 {
		t.Fatal("SboxTable differs from the S-box")
	}
}

func TestSubstitutionRowsAreMixColumnsBytes(t *testing.T) {
	rows := SubstitutionTable()
	coefficients := [wordBytes]func(byte) byte{
		func(s byte) byte { return gfDouble(s) },
		func(s byte) byte { return s },
		func(s byte) byte { return s },
		func(s byte) byte { return gfDouble(s) ^ s },
	}
	for region := 0; region < sboxRegion; region++ {
		for a := 0; a < tableRegionSize; a++ {
			s := sbox0[a]
			want := new(big.Int)
			for j := 0; j < wordBytes; j++ {
				coefficient := coefficients[(j-region+wordBytes)%wordBytes]
				weight := new(big.Int).Exp(big.NewInt(spreadBase), big.NewInt(int64(bitsPerByte*j)), nil)
				term := new(big.Int).Mul(spreadValue(uint64(coefficient(s)), bitsPerByte), weight)
				want.Add(want, term)
			}
			if got := rows[region*tableRegionSize+a]; got.Cmp(want) != 0 {
				t.Fatalf("substitution row %d of region %d is %s, want %s", a, region, got, want)
			}
		}
	}
}

func gfDouble(s byte) byte {
	double := uint16(s) << 1
	if double > 0xff {
		double ^= gfModulus
	}
	return byte(double)
}

func assertBigRows(t *testing.T, name string, got, want []*big.Int) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s has %d rows, want %d", name, len(got), len(want))
	}
	for i := range want {
		if got[i].Cmp(want[i]) != 0 {
			t.Fatalf("%s row %d is %s, want %s", name, i, got[i], want[i])
		}
	}
}
