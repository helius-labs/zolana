package tee

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/hf/nsm/request"
	"github.com/mdlayher/vsock"
)

const (
	parentCID           = 3
	parentConfigPort    = 8200
	maxParentConfig     = 64 << 10
	parentConfigTimeout = 10 * time.Second
	kmsTimeout          = 30 * time.Second
	// KMS caps CiphertextBlob and CiphertextForRecipient here.
	maxKMSCiphertext = 6144
)

var kmsKeyARNPattern = regexp.MustCompile(`^arn:aws:kms:([a-z]{2}(?:-[a-z]+)+-[0-9]+):[0-9]{12}:key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Unmeasured, trusted only through KMS.
type parentConfig struct {
	Ciphertext      []byte `json:"ciphertext"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

type kmsDecrypter interface {
	Decrypt(context.Context, *kms.DecryptInput, ...func(*kms.Options)) (*kms.DecryptOutput, error)
}

type kmsRelease struct {
	keyARN string
	region string
	dial   func(context.Context) (net.Conn, error)
	client func(region string, credentials aws.Credentials) kmsDecrypter
}

func newKMSRelease(keyARN string) (*kmsRelease, error) {
	match := kmsKeyARNPattern.FindStringSubmatch(keyARN)
	if match == nil {
		return nil, fmt.Errorf("nitro KMS key %q is not a key ARN", keyARN)
	}
	return &kmsRelease{keyARN: keyARN, region: match[1], dial: dialParent, client: newKMSClient}, nil
}

func (r *kmsRelease) seed(ctx context.Context, attest func(*request.Attestation) ([]byte, error)) ([]byte, error) {
	config, err := r.parentConfig(ctx)
	if err != nil {
		return nil, err
	}
	recipient, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	publicKey, err := x509.MarshalPKIXPublicKey(&recipient.PublicKey)
	if err != nil {
		return nil, err
	}
	document, err := attest(&request.Attestation{PublicKey: publicKey})
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, kmsTimeout)
	defer cancel()
	credentials := aws.Credentials{
		AccessKeyID:     config.AccessKeyID,
		SecretAccessKey: config.SecretAccessKey,
		SessionToken:    config.SessionToken,
		Source:          "nitro parent",
	}
	answer, err := r.client(r.region, credentials).Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: config.Ciphertext,
		// KMS refuses a ciphertext made under any other key.
		KeyId: aws.String(r.keyARN),
		Recipient: &types.RecipientInfo{
			KeyEncryptionAlgorithm: types.KeyEncryptionMechanismRsaesOaepSha256,
			AttestationDocument:    document,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("KMS Decrypt: %w", err)
	}
	return openEnvelope(answer.CiphertextForRecipient, recipient)
}

// The parent closes after one newline terminated object.
func (r *kmsRelease) parentConfig(ctx context.Context) (parentConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, parentConfigTimeout)
	defer cancel()
	conn, err := r.dial(ctx)
	if err != nil {
		return parentConfig{}, fmt.Errorf("parent config: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return parentConfig{}, fmt.Errorf("parent config: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(conn, maxParentConfig+1))
	if err != nil {
		return parentConfig{}, fmt.Errorf("parent config: %w", err)
	}
	if len(raw) > maxParentConfig {
		return parentConfig{}, fmt.Errorf("parent config exceeds %d bytes", maxParentConfig)
	}
	line, terminated := bytes.CutSuffix(raw, []byte("\n"))
	if !terminated {
		return parentConfig{}, errors.New("parent config is not newline terminated")
	}
	return parseParentConfig(line)
}

func parseParentConfig(line []byte) (parentConfig, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var config parentConfig
	if err := decoder.Decode(&config); err != nil {
		return parentConfig{}, fmt.Errorf("parent config: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return parentConfig{}, errors.New("parent config holds more than one object")
	}
	switch {
	case len(config.Ciphertext) == 0 || len(config.Ciphertext) > maxKMSCiphertext:
		return parentConfig{}, fmt.Errorf("parent config ciphertext has %d bytes", len(config.Ciphertext))
	case config.AccessKeyID == "" || config.SecretAccessKey == "" || config.SessionToken == "":
		return parentConfig{}, errors.New("parent config lacks credentials")
	}
	return config, nil
}

func dialParent(context.Context) (net.Conn, error) {
	return vsock.Dial(parentCID, parentConfigPort, nil)
}

func newKMSClient(region string, credentials aws.Credentials) kmsDecrypter {
	return kms.New(kms.Options{
		Region: region,
		// The image routes only this host.
		BaseEndpoint: aws.String("https://kms." + region + ".amazonaws.com"),
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return credentials, nil
		}),
	})
}
