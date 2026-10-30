// Package router forwards opaque TEE requests by recipient, behind an authenticated gateway.
package router

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxRegistryBytes = 1 << 20

var identifier = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,127}$`)
var recipient = regexp.MustCompile(`^[0-9a-f]{64}$`)
var secretARN = regexp.MustCompile(`^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):([0-9]{12}):secret:[A-Za-z0-9/_+=.@-]+$`)
var accountID = regexp.MustCompile(`^[0-9]{12}$`)

var ErrRegistry = errors.New("routing registry rejected")

// Source is an operator-authenticated registry and origin-credential source.
// It confers no client trust in a prover, image, or recipient key.
type Source interface {
	Registry(context.Context) (RegistryDocument, error)
	Secret(context.Context, string) (string, error)
}

// RegistryDocument retains the selected operator source for private diagnostics.
type RegistryDocument struct {
	Data    []byte
	Region  string
	Version string
}

type Registry struct {
	SchemaVersion int          `json:"schema_version"`
	Revision      uint64       `json:"revision"`
	ExpiresAt     int64        `json:"expires_at"`
	Generations   []Generation `json:"generations"`
}

type Generation struct {
	ID          string    `json:"id"`
	Region      string    `json:"region"`
	RecipientID string    `json:"recipient_id"`
	Draining    bool      `json:"draining"`
	Disabled    bool      `json:"disabled"`
	Backends    []Backend `json:"backends"`
}

type Backend struct {
	ID        string `json:"id"`
	Origin    string `json:"origin"`
	APIKeyARN string `json:"api_key_arn"`
}

func decodeRegistry(data []byte, now time.Time) (Registry, error) {
	var value Registry
	if len(data) > maxRegistryBytes || uniqueJSON(data) != nil {
		return value, ErrRegistry
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || value.SchemaVersion != 1 ||
		value.Revision == 0 || value.Revision > 1<<53-1 ||
		value.ExpiresAt <= now.Unix() || value.ExpiresAt > 1<<53-1 ||
		len(value.Generations) == 0 || len(value.Generations) > 32 {
		return Registry{}, ErrRegistry
	}
	ids, keys, backends, origins := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, generation := range value.Generations {
		if !identifier.MatchString(generation.ID) || !identifier.MatchString(generation.Region) ||
			!recipient.MatchString(generation.RecipientID) || ids[generation.ID] || keys[generation.RecipientID] ||
			len(generation.Backends) == 0 || len(generation.Backends) > 8 {
			return Registry{}, ErrRegistry
		}
		ids[generation.ID], keys[generation.RecipientID] = true, true
		for _, backend := range generation.Backends {
			match := secretARN.FindStringSubmatch(backend.APIKeyARN)
			if !identifier.MatchString(backend.ID) || backends[backend.ID] || len(match) == 0 || match[2] != generation.Region {
				return Registry{}, ErrRegistry
			}
			origin, err := originURL(backend.Origin)
			if err != nil || origins[origin.String()] {
				return Registry{}, ErrRegistry
			}
			origins[origin.String()] = true
			backends[backend.ID] = true
		}
	}
	if len(backends) > 64 {
		return Registry{}, ErrRegistry
	}
	return value, nil
}

func originURL(value string) (*url.URL, error) {
	origin, err := url.Parse(value)
	if err != nil || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.ForceQuery ||
		origin.Fragment != "" || origin.RawPath != "" || (origin.Path != "" && origin.Path != "/") {
		return nil, ErrRegistry
	}
	ip := net.ParseIP(origin.Hostname())
	loopback := ip != nil && ip.IsLoopback()
	if origin.Scheme != "https" && !(origin.Scheme == "http" && loopback) {
		return nil, ErrRegistry
	}
	origin.Path = ""
	return origin, nil
}

func validAPIKey(key string) bool {
	if len(key) < 16 || len(key) > 4096 {
		return false
	}
	for _, b := range []byte(key) {
		if b < 0x21 || b > 0x7e {
			return false
		}
	}
	return true
}

func registryDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Detect duplicate members before decoding a configuration into typed fields.
func uniqueJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var read func(int) error
	read = func(depth int) error {
		if depth > 16 {
			return ErrRegistry
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, compound := token.(json.Delim)
		if !compound {
			return nil
		}
		if delimiter != '{' && delimiter != '[' {
			return ErrRegistry
		}
		keys := map[string]bool{}
		for decoder.More() {
			if delimiter == '{' {
				member, err := decoder.Token()
				key, ok := member.(string)
				if err != nil || !ok || keys[key] {
					return ErrRegistry
				}
				keys[key] = true
			}
			if err := read(depth + 1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	}
	if err := read(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("%w: trailing data", ErrRegistry)
	}
	return nil
}

func withoutAPIKey(raw string) string {
	var kept []string
	for _, pair := range strings.Split(raw, "&") {
		key, _, _ := strings.Cut(pair, "=")
		decoded, err := url.QueryUnescape(key)
		if pair != "" && !(err == nil && decoded == "api-key") {
			kept = append(kept, pair)
		}
	}
	return strings.Join(kept, "&")
}
