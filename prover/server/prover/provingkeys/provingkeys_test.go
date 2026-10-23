package provingkeys

import (
	"testing"
)

func TestParseMergesExtensionPins(t *testing.T) {
	base := []byte(`{"prefix":"proving-keys/v","keys":{"merge_24_1.key":{"sha256":"aa","size":1}}}`)
	for name, test := range map[string]struct {
		extension string
		ok        bool
	}{
		"release key": {`{"release":"https://keys.test/v1","keys":{"ext.key":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":2,"source":"release"}}}`, true},
		"no release":  {`{"keys":{"ext.key":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":2,"source":"release"}}}`, false},
		"no source":   {`{"release":"https://keys.test/v1","keys":{"ext.key":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":2}}}`, false},
		"path":        {`{"release":"https://keys.test/v1","keys":{"../ext.key":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":2,"source":"release"}}}`, false},
		"short sha":   {`{"release":"https://keys.test/v1","keys":{"ext.key":{"sha256":"bb","size":2,"source":"release"}}}`, false},
		"no size":     {`{"release":"https://keys.test/v1","keys":{"ext.key":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","source":"release"}}}`, false},
		"repin":       {`{"release":"https://keys.test/v1","keys":{"merge_24_1.key":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","size":2,"source":"release"}}}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := parse(base, [][]byte{[]byte(test.extension)})
			if (err == nil) != test.ok {
				t.Fatalf("parse error %v", err)
			}
			if !test.ok {
				return
			}
			extension, embedded := m.Keys["ext.key"], m.Keys["merge_24_1.key"]
			if m.Prefix != "proving-keys/v" || extension.Sha256 != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" || extension.URL != "https://keys.test/v1/ext.key" || embedded.Sha256 != "aa" || embedded.URL != "" {
				t.Fatalf("merged manifest %+v", m)
			}
		})
	}
}
