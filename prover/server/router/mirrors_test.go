package router

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type mirrorFixture struct {
	mu        sync.Mutex
	documents map[string][]byte
	denied    map[string]bool
	hanging   map[string]bool
	source    *AWSSource
}

func mirroredSource(t *testing.T, revision uint64) *mirrorFixture {
	t.Helper()
	document := registryJSON(t, revision)
	f := &mirrorFixture{documents: map[string][]byte{"primary": document, "mirror-eu": document, "mirror-ap": document}, denied: map[string]bool{}, hanging: map[string]bool{}}
	regions := map[string]string{"primary": "us-east-1", "mirror-eu": "eu-north-1", "mirror-ap": "ap-southeast-1"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/x-amz-json-1.1")
			_ = json.NewEncoder(w).Encode(map[string]string{"SecretString": regional})
			return
		}
		bucket := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[0]
		if r.URL.Path != "/"+bucket+"/registry.json" || r.Header.Get("X-Amz-Expected-Bucket-Owner") != "558215002830" || !strings.Contains(r.Header.Get("Authorization"), "/"+regions[bucket]+"/s3/") {
			t.Error("mirror request changed its object, region or expected owner")
		}
		f.mu.Lock()
		data, denied, hanging := f.documents[bucket], f.denied[bucket], f.hanging[bucket]
		f.mu.Unlock()
		if hanging {
			<-r.Context().Done()
			return
		}
		if denied {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("X-Amz-Version-Id", bucket+"-object-version")
		_, _ = w.Write(data)
	}))
	t.Cleanup(server.Close)
	config := aws.Config{Region: "us-east-1", BaseEndpoint: aws.String(server.URL), HTTPClient: server.Client(), RetryMaxAttempts: 1,
		Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: "test-only-id", SecretAccessKey: "test-only-secret"}, nil
		}),
	}
	var err error
	f.source, err = NewAWSSource(config, "primary", "registry.json", "558215002830", RegistryMirror{Region: "eu-north-1", Bucket: "mirror-eu"}, RegistryMirror{Region: "ap-southeast-1", Bucket: "mirror-ap"})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMirrorsSelectHighestValidRevisionAndRejectConflictingBytes(t *testing.T) {
	f := mirroredSource(t, 1)
	first, err := f.source.Registry(t.Context())
	if err != nil || first.Region != "us-east-1" || first.Version != "primary-object-version" {
		t.Fatal("equal mirrors did not retain the preferred source identity")
	}
	f.mu.Lock()
	f.documents["mirror-eu"] = registryJSON(t, 2)
	f.mu.Unlock()
	next, err := f.source.Registry(t.Context())
	if err != nil || next.Region != "eu-north-1" {
		t.Fatal("newer mirror did not win over the primary")
	}
	var changed Registry
	if json.Unmarshal(next.Data, &changed) != nil {
		t.Fatal("invalid selected registry")
	}
	changed.Generations[0].Draining = true
	conflict, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.documents["mirror-ap"] = conflict
	f.mu.Unlock()
	if _, err := f.source.Registry(t.Context()); err != ErrRegistry {
		t.Fatal("conflicting highest-revision mirrors were accepted")
	}
	f.mu.Lock()
	f.documents["primary"] = registryJSON(t, 3)
	f.mu.Unlock()
	if value, err := f.source.Registry(t.Context()); err != nil || value.Region != "us-east-1" {
		t.Fatal("a conflict below the selected revision blocked recovery")
	}
}

func TestMirrorReadsSurvivePrimaryDenialAndCorruption(t *testing.T) {
	f := mirroredSource(t, 1)
	f.denied["primary"] = true
	if value, err := f.source.Registry(t.Context()); err != nil || value.Region != "eu-north-1" {
		t.Fatal("unavailable primary blocked a valid regional mirror")
	}
	f.mu.Lock()
	f.denied["primary"] = false
	f.documents["primary"] = []byte(`{"revision":99}`)
	f.mu.Unlock()
	if value, err := f.source.Registry(t.Context()); err != nil || value.Region != "eu-north-1" {
		t.Fatal("malformed primary blocked a valid regional mirror")
	}
}

func TestAnOlderMirrorNeverRenewsTheActiveRegistry(t *testing.T) {
	f := mirroredSource(t, 2)
	r, err := New(f.source, ingress, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.transport.CloseIdleConnections)
	if err := r.Refresh(t.Context()); err != nil {
		t.Fatal(err)
	}
	previous := r.current
	previous.loaded = time.Now().UTC().Add(-registryMaxAge - time.Second)
	f.mu.Lock()
	f.denied["primary"] = true
	f.documents["mirror-eu"], f.documents["mirror-ap"] = registryJSON(t, 1), registryJSON(t, 1)
	f.mu.Unlock()
	if err := r.Refresh(t.Context()); err != ErrRegistry || r.current != previous || r.available(r.current, time.Now()) {
		t.Fatal("falling back to an older mirror reset trust or freshness")
	}
}

func TestAnUnresponsiveRegistryRegionHasABoundedRead(t *testing.T) {
	f := mirroredSource(t, 1)
	f.hanging["primary"] = true
	ctx, cancel := context.WithTimeout(t.Context(), 6*time.Second)
	defer cancel()
	value, err := f.source.Registry(ctx)
	if err != nil || value.Region != "eu-north-1" || ctx.Err() != nil {
		t.Fatal("a hanging region exhausted the whole registry deadline")
	}
}
