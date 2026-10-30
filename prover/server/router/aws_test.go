package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func TestAWSSourceRequiresVersionedBoundedS3AndRegionalSecret(t *testing.T) {
	var versioned, oversized, secretError atomic.Bool
	versioned.Store(true)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Error("AWS request was not authenticated")
		}
		if r.Method == http.MethodGet {
			if r.Header.Get("X-Amz-Expected-Bucket-Owner") != "558215002830" {
				t.Error("registry owner not bound")
			}
			if r.URL.Path != "/private-test/registry.json" {
				t.Errorf("unexpected object path %s", r.URL.Path)
			}
			if versioned.Load() {
				w.Header().Set("X-Amz-Version-Id", "test-version-1")
			}
			if oversized.Load() {
				_, _ = w.Write([]byte(strings.Repeat("x", maxRegistryBytes+1)))
				return
			}
			_, _ = w.Write([]byte(`{"schema_version":1}`))
			return
		}
		if !strings.Contains(r.Header.Get("Authorization"), "/ap-southeast-1/secretsmanager/") {
			t.Error("credential request used the registry region")
		}
		var input struct {
			SecretID string `json:"SecretId"`
		}
		if json.NewDecoder(r.Body).Decode(&input) != nil || input.SecretID != "arn:aws:secretsmanager:ap-southeast-1:558215002830:secret:test-key" {
			t.Error("credential ARN was changed")
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		if secretError.Load() {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","message":"private details"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"SecretString": regional})
	}))
	defer server.Close()
	cfg := aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test-only-id", SecretAccessKey: "test-only-secret"}, nil
		}),
	}
	source, err := NewAWSSource(cfg, "private-test", "registry.json", "558215002830")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := source.Registry(t.Context()); err != nil {
		t.Fatal(err)
	}
	versioned.Store(false)
	if _, err := source.Registry(t.Context()); err != ErrRegistry {
		t.Fatal("unversioned registry accepted")
	}
	versioned.Store(true)
	oversized.Store(true)
	if _, err := source.Registry(t.Context()); err != ErrRegistry {
		t.Fatal("oversized registry accepted")
	}
	arn := "arn:aws:secretsmanager:ap-southeast-1:558215002830:secret:test-key"
	if key, err := source.Secret(t.Context(), arn); err != nil || key != regional {
		t.Fatal("regional origin credential was not resolved")
	}
	secretError.Store(true)
	if _, err := source.Secret(t.Context(), arn); err != ErrRegistry {
		t.Fatal("AWS error was not sanitized")
	}
}

func TestAWSLoadCancellationIsBounded(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	source, err := NewAWSSource(aws.Config{
		Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test-only-id", SecretAccessKey: "test-only-secret"}, nil
		}),
	}, "private-test", "registry.json", "558215002830")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := source.Registry(ctx); done <- err }()
	<-started
	cancel()
	select {
	case err := <-done:
		if err != ErrRegistry {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled registry load did not finish")
	}
}
