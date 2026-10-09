package tee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type testOAEPParams struct {
	Hash testAlgorithm `asn1:"explicit,tag:0"`
	MGF  testAlgorithm `asn1:"explicit,tag:1"`
}

type testRecipient struct {
	Version      int
	SubjectKeyID []byte `asn1:"tag:0"`
	Algorithm    testAlgorithm
	EncryptedKey []byte
}

type testEncryptedContent struct {
	ContentType asn1.ObjectIdentifier
	Algorithm   testAlgorithm
	Content     asn1.RawValue
}

type testEnvelopedData struct {
	Version    int
	Recipients []testRecipient `asn1:"set"`
	Content    testEncryptedContent
}

type testContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     testEnvelopedData `asn1:"explicit,tag:0"`
}

var (
	testOIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	testOIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	testOIDMGF1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

func testRaw(t *testing.T, value any) asn1.RawValue {
	t.Helper()
	der, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return asn1.RawValue{FullBytes: der}
}

func testOAEP(t *testing.T, hash, mgfHash asn1.ObjectIdentifier) testAlgorithm {
	t.Helper()
	return testAlgorithm{
		Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7},
		Parameters: testRaw(t, testOAEPParams{
			Hash: testAlgorithm{Algorithm: hash, Parameters: asn1.NullRawValue},
			MGF: testAlgorithm{
				Algorithm:  testOIDMGF1,
				Parameters: testRaw(t, testAlgorithm{Algorithm: mgfHash, Parameters: asn1.NullRawValue}),
			},
		}),
	}
}

func sealEnvelope(t *testing.T, recipient *rsa.PublicKey, plaintext []byte) testContentInfo {
	t.Helper()
	contentKey, iv := make([]byte, 32), make([]byte, aes.BlockSize)
	rand.Read(contentKey)
	rand.Read(iv)
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipient, contentKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	return testContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3},
		Content: testEnvelopedData{
			Version: 2,
			Recipients: []testRecipient{{
				Version:      2,
				SubjectKeyID: make([]byte, 32),
				Algorithm:    testOAEP(t, testOIDSHA256, testOIDSHA256),
				EncryptedKey: encryptedKey,
			}},
			Content: testEncryptedContent{
				ContentType: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1},
				Algorithm: testAlgorithm{
					Algorithm:  asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42},
					Parameters: testRaw(t, iv),
				},
				Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: encryptCBC(t, contentKey, iv, plaintext)},
			},
		},
	}
}

func encryptCBC(t *testing.T, key, iv, plaintext []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(bytes.Clone(plaintext), bytes.Repeat([]byte{byte(pad)}, pad)...)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	return padded
}

func (info testContentInfo) marshal(t *testing.T) []byte {
	t.Helper()
	der, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func testRecipientKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestOpenEnvelope(t *testing.T) {
	key := testRecipientKey(t)
	seed := bytes.Repeat([]byte{7}, seedSize)
	opened, err := openEnvelope(sealEnvelope(t, &key.PublicKey, seed).marshal(t), key)
	if err != nil || !bytes.Equal(opened, seed) {
		t.Fatalf("opened %x err %v", opened, err)
	}
}

// From openssl cms -encrypt -stream -aes-256-cbc -keyid with OAEP and MGF1 SHA-256.
func TestOpenEnvelopeFromOpenSSL(t *testing.T) {
	envelope, err := os.ReadFile(filepath.Join("testdata", "openssl_cms_envelope.ber"))
	if err != nil {
		t.Fatal(err)
	}
	der, err := os.ReadFile(filepath.Join("testdata", "openssl_cms_recipient.der"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openEnvelope(envelope, key.(*rsa.PrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(opened) != "a71f9862fe05326408acc4321736e784a3bc69c950982b29d9395f2608bb17a3" {
		t.Fatalf("opened %x", opened)
	}
}

func TestOpenEnvelopeJoinsContentSegments(t *testing.T) {
	key := testRecipientKey(t)
	seed := bytes.Repeat([]byte{9}, seedSize)
	info := sealEnvelope(t, &key.PublicKey, seed)
	ciphertext := info.Content.Content.Content.Bytes
	first, second := testRaw(t, ciphertext[:16]), testRaw(t, ciphertext[16:])
	info.Content.Content.Content = asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Bytes:      append(first.FullBytes, second.FullBytes...),
	}
	opened, err := openEnvelope(info.marshal(t), key)
	if err != nil || !bytes.Equal(opened, seed) {
		t.Fatalf("opened %x err %v", opened, err)
	}
}

func TestOpenEnvelopeRejects(t *testing.T) {
	key := testRecipientKey(t)
	seed := bytes.Repeat([]byte{7}, seedSize)
	for name, tc := range map[string]struct {
		plaintext []byte
		edit      func(*testContentInfo)
		raw       func([]byte) []byte
		want      string
	}{
		"tampered key": {
			edit: func(info *testContentInfo) { info.Content.Recipients[0].EncryptedKey[9] ^= 1 },
			want: "unwrap the content key",
		},
		"tampered padding": {
			edit: func(info *testContentInfo) { info.Content.Content.Content.Bytes[len(seed)-1] ^= 1 },
			want: "padding",
		},
		"short seed": {plaintext: seed[:31], want: "holds 31 bytes"},
		"long seed":  {plaintext: append(bytes.Clone(seed), 0), want: "holds 33 bytes"},
		"oversized":  {raw: func(der []byte) []byte { return append(der, make([]byte, maxKMSCiphertext)...) }, want: "exceeds"},
		"trailing":   {raw: func(der []byte) []byte { return append(der, 0) }, want: "trailing"},
		"truncated":  {raw: func(der []byte) []byte { return der[:len(der)-1] }, want: "truncated"},
		"not enveloped": {
			edit: func(info *testContentInfo) { info.ContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2} },
			want: "not EnvelopedData",
		},
		"version 0": {
			edit: func(info *testContentInfo) { info.Content.Version = 0 },
			want: "version is not 2",
		},
		"two recipients": {
			edit: func(info *testContentInfo) {
				info.Content.Recipients = append(info.Content.Recipients, info.Content.Recipients[0])
			},
			want: "exactly one recipient",
		},
		"PKCS#1 v1.5": {
			edit: func(info *testContentInfo) {
				info.Content.Recipients[0].Algorithm = testAlgorithm{
					Algorithm:  asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1},
					Parameters: asn1.NullRawValue,
				}
			},
			want: "algorithm is not",
		},
		"OAEP SHA-1": {
			edit: func(info *testContentInfo) {
				info.Content.Recipients[0].Algorithm = testOAEP(t, testOIDSHA1, testOIDSHA256)
			},
			want: "OAEP hash is not SHA-256",
		},
		"MGF1 SHA-1": {
			edit: func(info *testContentInfo) {
				info.Content.Recipients[0].Algorithm = testOAEP(t, testOIDSHA256, testOIDSHA1)
			},
			want: "not MGF1 SHA-256",
		},
		"AES-128-CBC": {
			edit: func(info *testContentInfo) {
				info.Content.Content.Algorithm.Algorithm = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
			},
			want: "algorithm is not",
		},
		"short IV": {
			edit: func(info *testContentInfo) { info.Content.Content.Algorithm.Parameters = testRaw(t, make([]byte, 8)) },
			want: "IV is malformed",
		},
	} {
		t.Run(name, func(t *testing.T) {
			plaintext := seed
			if tc.plaintext != nil {
				plaintext = tc.plaintext
			}
			info := sealEnvelope(t, &key.PublicKey, plaintext)
			if tc.edit != nil {
				tc.edit(&info)
			}
			envelope := info.marshal(t)
			if tc.raw != nil {
				envelope = tc.raw(envelope)
			}
			opened, err := openEnvelope(envelope, key)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("opened %x err %v, want %q", opened, err, tc.want)
			}
		})
	}
}

func TestParseBERRejectsMalformedInput(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []byte
		want string
	}{
		"deep nesting":         {bytes.Repeat([]byte{0x30, 0x80}, maxBERDepth+2), "too deep"},
		"indefinite primitive": {[]byte{0x04, 0x80, 0x00, 0x00}, "indefinite"},
		"unterminated":         {[]byte{0x30, 0x80, 0x05, 0x00}, "truncated"},
		"high tag number":      {[]byte{0x1f, 0x81, 0x00, 0x00}, "high tag"},
		"long length":          {[]byte{0x04, 0x83, 0x00, 0x00, 0x01, 0x00}, "length is malformed"},
		"overlong content":     {[]byte{0x04, 0x02, 0x00}, "truncated"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseBER(tc.in, 0); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}
