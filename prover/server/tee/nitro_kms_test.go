package tee

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hf/nsm/request"
	"github.com/hf/nsm/response"
)

const (
	testKMSKey       = "arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	testParentConfig = `{"ciphertext":"AQID","access_key_id":"AKIA","secret_access_key":"secret","session_token":"token"}`
)

func measuredKey() ([]byte, error) { return []byte(testKMSKey + "\n"), nil }

func parentSends(payload []byte) func(context.Context) (net.Conn, error) {
	return func(context.Context) (net.Conn, error) {
		enclave, parent := net.Pipe()
		go func() {
			parent.Write(payload)
			parent.Close()
		}()
		return enclave, nil
	}
}

func TestParentConfig(t *testing.T) {
	release := &kmsRelease{dial: parentSends([]byte(testParentConfig + "\n"))}
	config, err := release.parentConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := parentConfig{
		Ciphertext:      []byte{1, 2, 3},
		AccessKeyID:     "AKIA",
		SecretAccessKey: "secret",
		SessionToken:    "token",
	}
	if !reflect.DeepEqual(config, want) {
		t.Fatalf("config %+v", config)
	}
}

func TestParentConfigRejects(t *testing.T) {
	edit := func(from, to string) string { return strings.Replace(testParentConfig, from, to, 1) + "\n" }
	for name, tc := range map[string]struct {
		payload string
		want    string
	}{
		"oversized":       {testParentConfig + strings.Repeat(" ", maxParentConfig) + "\n", "exceeds"},
		"unterminated":    {testParentConfig, "not newline terminated"},
		"two objects":     {testParentConfig + testParentConfig + "\n", "more than one object"},
		"key_id":          {edit(`{`, `{"key_id":"`+testKMSKey+`",`), `unknown field "key_id"`},
		"region":          {edit(`{`, `{"region":"eu-central-1",`), `unknown field "region"`},
		"bad base64":      {edit("AQID", "!!"), "parent config"},
		"no ciphertext":   {edit("AQID", ""), "ciphertext has 0 bytes"},
		"long ciphertext": {edit("AQID", base64.StdEncoding.EncodeToString(make([]byte, maxKMSCiphertext+1))), "ciphertext has 6145 bytes"},
		"no token":        {edit(`"token"`, `""`), "lacks credentials"},
	} {
		t.Run(name, func(t *testing.T) {
			release := &kmsRelease{dial: parentSends([]byte(tc.payload))}
			if _, err := release.parentConfig(context.Background()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
		})
	}
}

func TestParentConfigTimesOut(t *testing.T) {
	silent := func(context.Context) (net.Conn, error) {
		enclave, parent := net.Pipe()
		t.Cleanup(func() { parent.Close() })
		return enclave, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := (&kmsRelease{dial: silent}).parentConfig(ctx); !errors.Is(err, context.DeadlineExceeded) && !isTimeout(err) {
		t.Fatalf("err %v", err)
	}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func TestKMSClientTargetsTheRoutedHost(t *testing.T) {
	client := newKMSClient("eu-central-1", aws.Credentials{}).(*kms.Client)
	if endpoint := aws.ToString(client.Options().BaseEndpoint); endpoint != "https://kms.eu-central-1.amazonaws.com" {
		t.Fatalf("endpoint %s", endpoint)
	}
}

func TestNitroKeySource(t *testing.T) {
	unread := func() ([]byte, error) { t.Fatal("boot read the KMS key"); return nil, nil }
	for _, source := range []string{"boot\n", "boot"} {
		if n, err := newNitro(&fakeNSM{}, source, unread); err != nil || n.release != nil {
			t.Fatalf("source %q nitro %+v err %v", source, n, err)
		}
	}
	n, err := newNitro(&fakeNSM{}, "kms\n", measuredKey)
	if err != nil || n.release.keyARN != testKMSKey || n.release.region != "eu-central-1" {
		t.Fatalf("nitro %+v err %v", n, err)
	}
	for _, source := range []string{"", "KMS", "kms boot", "fallback"} {
		if _, err := newNitro(&fakeNSM{}, source, measuredKey); err == nil {
			t.Fatalf("source %q accepted", source)
		}
	}
	missing := func() ([]byte, error) { return nil, os.ErrNotExist }
	if _, err := newNitro(&fakeNSM{}, "kms", missing); err == nil || !strings.Contains(err.Error(), "nitro KMS key") {
		t.Fatalf("err %v", err)
	}
}

func TestKMSReleaseRequiresAKeyARN(t *testing.T) {
	for _, keyARN := range []string{
		"",
		"1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:eu-central-1:111122223333:alias/prover",
		"arn:aws:kms:eu-central-1:111122223333:key/mrk-1234abcd12ab34cd56ef1234567890ab",
		"arn:aws:kms:eu-central-1:11112222333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws-cn:kms:cn-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"arn:aws:kms:eu-central-1.evil.com:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		testKMSKey + "\nx",
	} {
		if _, err := newKMSRelease(keyARN); err == nil {
			t.Fatalf("%q accepted", keyARN)
		}
	}
}

// attestingNSM echoes the requested public key as the document.
type attestingNSM struct {
	requests []*request.Attestation
}

func (a *attestingNSM) Send(r request.Request) (response.Response, error) {
	attestation := r.(*request.Attestation)
	a.requests = append(a.requests, attestation)
	return response.Response{Attestation: &response.Attestation{Document: attestation.PublicKey}}, nil
}

type fakeKMS struct {
	t    *testing.T
	seed []byte
	err  error
}

func (f *fakeKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if f.err != nil {
		return nil, f.err
	}
	if aws.ToString(in.KeyId) != testKMSKey || !bytes.Equal(in.CiphertextBlob, []byte{1, 2, 3}) ||
		in.Recipient == nil || in.Recipient.KeyEncryptionAlgorithm != types.KeyEncryptionMechanismRsaesOaepSha256 {
		f.t.Fatalf("Decrypt input %+v", in)
	}
	recipient, err := x509.ParsePKIXPublicKey(in.Recipient.AttestationDocument)
	if err != nil {
		f.t.Fatal(err)
	}
	if recipient.(*rsa.PublicKey).N.BitLen() != 2048 {
		f.t.Fatalf("recipient has %d bits", recipient.(*rsa.PublicKey).N.BitLen())
	}
	envelope := sealEnvelope(f.t, recipient.(*rsa.PublicKey), f.seed).marshal(f.t)
	return &kms.DecryptOutput{CiphertextForRecipient: envelope}, nil
}

func kmsNitro(t *testing.T, kmsErr error) (*nitro, *attestingNSM) {
	t.Helper()
	nsm := &attestingNSM{}
	n, err := newNitro(nsm, "kms\n", measuredKey)
	if err != nil {
		t.Fatal(err)
	}
	n.release.dial = parentSends([]byte(testParentConfig + "\n"))
	n.release.client = func(region string, credentials aws.Credentials) kmsDecrypter {
		if region != "eu-central-1" || credentials.AccessKeyID != "AKIA" || credentials.SessionToken != "token" {
			t.Fatalf("region %s credentials %+v", region, credentials)
		}
		return &fakeKMS{t: t, seed: bytes.Repeat([]byte{0x5e}, seedSize), err: kmsErr}
	}
	return n, nsm
}

func TestNitroKMSReleaseSharesOneKey(t *testing.T) {
	first, nsm := kmsNitro(t, nil)
	second, _ := kmsNitro(t, nil)
	a, err := New(context.Background(), Config{Attester: first})
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(context.Background(), Config{Attester: second})
	if err != nil {
		t.Fatal(err)
	}
	derived, err := deriveKey(bytes.Repeat([]byte{0x5e}, seedSize))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.PublicKey(), b.PublicKey()) || !bytes.Equal(a.PublicKey(), derived.PublicKey().Bytes()) {
		t.Fatalf("keys %x %x, derived %x", a.PublicKey(), b.PublicKey(), derived.PublicKey().Bytes())
	}
	if len(nsm.requests) != 1 || nsm.requests[0].Nonce != nil || nsm.requests[0].UserData != nil {
		t.Fatalf("NSM requests %+v", nsm.requests)
	}
}

func TestNitroKMSReleaseFailsClosed(t *testing.T) {
	n, _ := kmsNitro(t, errors.New("AccessDeniedException"))
	if _, err := New(context.Background(), Config{Attester: n}); err == nil || !strings.Contains(err.Error(), "KMS key release: KMS Decrypt: AccessDeniedException") {
		t.Fatalf("err %v", err)
	}

	n, _ = kmsNitro(t, nil)
	n.release.dial = func(context.Context) (net.Conn, error) { return nil, errors.New("connection reset") }
	if _, err := New(context.Background(), Config{Attester: n}); err == nil || !strings.Contains(err.Error(), "parent config: connection reset") {
		t.Fatalf("err %v", err)
	}

	refused, _ := kmsNitro(t, nil)
	refused.nsm = &fakeNSM{answer: response.Response{Error: response.ECInvalidArgument}}
	refused.release.client = func(string, aws.Credentials) kmsDecrypter { t.Fatal("KMS called without a document"); return nil }
	if _, err := New(context.Background(), Config{Attester: refused}); err == nil || !strings.Contains(err.Error(), "NSM attestation") {
		t.Fatalf("err %v", err)
	}
}

type recordingKMS struct {
	inputs []*kms.DecryptInput
}

func (r *recordingKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	r.inputs = append(r.inputs, in)
	return nil, errors.New("recorded")
}

func TestNitroKMSDecryptNamesTheMeasuredKey(t *testing.T) {
	n, _ := kmsNitro(t, nil)
	recorder := &recordingKMS{}
	n.release.client = func(string, aws.Credentials) kmsDecrypter { return recorder }
	if _, err := New(context.Background(), Config{Attester: n}); err == nil {
		t.Fatal("recorded Decrypt released a key")
	}
	if len(recorder.inputs) != 1 || aws.ToString(recorder.inputs[0].KeyId) != testKMSKey {
		t.Fatalf("Decrypt inputs %+v", recorder.inputs)
	}
}

func TestNitroKMSRefusesAParentKeyID(t *testing.T) {
	n, _ := kmsNitro(t, nil)
	other := `{"key_id":"arn:aws:kms:eu-central-1:444455556666:key/1234abcd-12ab-34cd-56ef-1234567890ab",` + testParentConfig[1:]
	n.release.dial = parentSends([]byte(other + "\n"))
	n.release.client = func(string, aws.Credentials) kmsDecrypter { t.Fatal("KMS called with a parent key_id"); return nil }
	if _, err := New(context.Background(), Config{Attester: n}); err == nil || !strings.Contains(err.Error(), `unknown field "key_id"`) {
		t.Fatalf("err %v", err)
	}
}
