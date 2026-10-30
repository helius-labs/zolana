package router

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/helius-labs/zolana/prover/server/tee"
)

const (
	maxBody        = 64*1024*1024 + 1024
	registryMaxAge = time.Minute
	healthMaxAge   = 20 * time.Second
	probeTimeout   = 5 * time.Second
	loadTimeout    = 20 * time.Second
	requestTimeout = 10 * time.Minute
	attestation    = "/tee/v1/attestation"
)

var keyPath = regexp.MustCompile(`^/prove/[A-Za-z0-9_-]{1,128}(/indexed|/status)?$`)
var requestHeaders = []string{"Content-Type", tee.HeaderVersion, tee.HeaderEnc, tee.HeaderKeyID, tee.HeaderCiphertext, "X-Sync", "X-Async", "X-Prover-Timing", "X-Request-Id"}
var responseHeaders = []string{"Content-Type", tee.HeaderVersion, "Retry-After", "Server-Timing", "X-Prover-Timing", "X-Request-Id"}

type backend struct {
	id, region, recipientID, key string
	origin                       *url.URL
	healthy                      bool
	checked                      time.Time
	forwarded                    atomic.Uint64
}

type generation struct {
	draining bool
	disabled bool
	backends []*backend
}

type snapshot struct {
	revision uint64
	digest   string
	expires  time.Time
	loaded   time.Time
	keys     map[string]generation
	order    []string
}

// Router has no enclave key or client-policy authority. Source and ingressKey
// belong to the operator; the SDK still verifies every selected recipient.
type Router struct {
	source          Source
	region          string
	auth            [32]byte
	transport       *http.Transport
	client          *http.Client
	mu              sync.RWMutex
	current         *snapshot
	next            atomic.Uint64
	admitted        atomic.Uint64
	refreshFailures atomic.Uint64
	probeFailures   atomic.Uint64
	forwardFailures atomic.Uint64
	unavailable     atomic.Uint64
	slots           chan struct{}
}

func New(source Source, ingressKey, preferredRegion string) (*Router, error) {
	if source == nil || !validAPIKey(ingressKey) || !identifier.MatchString(preferredRegion) {
		return nil, ErrRegistry
	}
	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: requestTimeout,
		IdleConnTimeout: 60 * time.Second, MaxIdleConns: 128, MaxIdleConnsPerHost: 16,
		MaxConnsPerHost: 64, DisableCompression: true, ForceAttemptHTTP2: true,
		// Do not inherit an ambient HTTP proxy or disable certificate verification.
	}
	return &Router{
		source: source, region: preferredRegion, auth: sha256.Sum256([]byte(ingressKey)), transport: transport, slots: make(chan struct{}, 128),
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// Run periodically refreshes the shared registry and local endpoint observations.
// A rejected update never partially replaces the active map. Only a complete
// successful reload renews its freshness; prolonged failure closes admission.
func (r *Router) Run(ctx context.Context) {
	defer r.transport.CloseIdleConnections()
	var loading sync.WaitGroup
	loading.Go(func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			if r.Refresh(ctx) != nil {
				r.refreshFailures.Add(1)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	defer loading.Wait()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		r.Probe(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (r *Router) Refresh(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, loadTimeout)
	defer cancel()
	data, err := r.source.Registry(ctx)
	if err != nil {
		return ErrRegistry
	}
	now := time.Now()
	config, err := decodeRegistry(data, now)
	if err != nil {
		return ErrRegistry
	}
	digest := registryDigest(data)
	r.mu.RLock()
	previous := r.current
	r.mu.RUnlock()
	if previous != nil && (config.Revision < previous.revision || (config.Revision == previous.revision && digest != previous.digest)) {
		return ErrRegistry
	}
	candidate := &snapshot{revision: config.Revision, digest: digest, expires: time.Unix(config.ExpiresAt, 0), loaded: now, keys: make(map[string]generation)}
	secrets := map[string]string{}
	for _, entry := range config.Generations {
		group := generation{draining: entry.Draining, disabled: entry.Disabled}
		for _, destination := range entry.Backends {
			key, ok := secrets[destination.APIKeyARN]
			if !ok {
				key, err = r.source.Secret(ctx, destination.APIKeyARN)
				if err != nil || !validAPIKey(key) {
					return ErrRegistry
				}
				secrets[destination.APIKeyARN] = key
			}
			origin, _ := originURL(destination.Origin) // decodeRegistry already proved this invariant.
			group.backends = append(group.backends, &backend{id: destination.ID, region: entry.Region, recipientID: entry.RecipientID, origin: origin, key: key})
		}
		candidate.keys[entry.RecipientID] = group
		candidate.order = append(candidate.order, entry.RecipientID)
	}
	if ctx.Err() != nil || !time.Now().Before(candidate.expires) {
		return ErrRegistry
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Preserve observations only for an unchanged endpoint, key and recipient.
	if r.current != nil {
		if candidate.revision < r.current.revision || (candidate.revision == r.current.revision && candidate.digest != r.current.digest) {
			return ErrRegistry
		}
		for id, group := range candidate.keys {
			for index, next := range group.backends {
				for _, old := range r.current.keys[id].backends {
					if next.id == old.id && next.origin.String() == old.origin.String() && next.key == old.key {
						group.backends[index] = old
					}
				}
			}
		}
	}
	// Freshness includes host suspension; UTC strips Go's monotonic reading,
	// which can pause during sleep. Backward wall-clock movement fails closed.
	candidate.loaded = time.Now().UTC()
	r.current = candidate
	return nil
}

// Probe checks readiness and observed recipient identity, not vendor trust.
// A malicious health answer cannot authorize a key in the client's policy.
func (r *Router) Probe(parent context.Context) {
	r.mu.RLock()
	current := r.current
	r.mu.RUnlock()
	if current == nil {
		return
	}
	var workers sync.WaitGroup
	for _, group := range current.keys {
		if group.disabled {
			continue
		}
		for _, target := range group.backends {
			workers.Go(func() {
				// The validated registry caps fan-out at 64 endpoints. Slow or dead
				// endpoints must not prevent healthy regions from being checked.
				ctx, cancel := context.WithTimeout(parent, probeTimeout)
				defer cancel()
				ready := r.probe(ctx, target)
				if !ready {
					r.probeFailures.Add(1)
				}
				r.mu.Lock()
				target.healthy, target.checked = ready, time.Now().UTC()
				r.mu.Unlock()
			})
		}
	}
	workers.Wait()
}

func (r *Router) probe(ctx context.Context, target *backend) bool {
	ready := *target.origin
	ready.Path = "/ready"
	if _, err := r.get(ctx, target, &ready, 4096); err != nil {
		return false
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false
	}
	quote := *target.origin
	quote.Path, quote.RawQuery = tee.GatewayPrefix+attestation, "nonce="+hex.EncodeToString(nonce[:])
	data, err := r.get(ctx, target, &quote, 1<<20)
	if err != nil || uniqueJSON(data) != nil {
		return false
	}
	var answer struct {
		Key string `json:"hpke_public_key"`
	}
	if json.Unmarshal(data, &answer) != nil || !recipient.MatchString(answer.Key) {
		return false
	}
	key, err := hex.DecodeString(answer.Key)
	if err != nil {
		return false
	}
	id, err := tee.RecipientID(key)
	return err == nil && id == target.recipientID
}

func (r *Router) get(ctx context.Context, target *backend, address *url.URL, limit int64) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address.String(), nil)
	if err != nil {
		return nil, ErrRegistry
	}
	request.Header.Set("X-API-Key", target.key)
	request.Header.Set("Cache-Control", "no-store")
	response, err := r.client.Do(request)
	if err != nil {
		return nil, ErrRegistry
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrRegistry
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, ErrRegistry
	}
	return data, nil
}

func (r *Router) available(current *snapshot, now time.Time) bool {
	return current != nil && now.Before(current.expires) && !now.Before(current.loaded) && now.Sub(current.loaded) < registryMaxAge
}

func healthy(target *backend, now time.Time) bool {
	return target.healthy && !now.Before(target.checked) && now.Sub(target.checked) < healthMaxAge
}

func (r *Router) choose(key string) *backend {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := time.Now()
	if !r.available(r.current, now) {
		return nil
	}
	var candidates, nearby []*backend
	for _, id := range r.current.order {
		group := r.current.keys[id]
		if group.disabled || (key != "" && key != id) || (key == "" && group.draining) {
			continue
		}
		for _, target := range group.backends {
			if healthy(target, now) {
				candidates = append(candidates, target)
				if target.region == r.region {
					nearby = append(nearby, target)
				}
			}
		}
	}
	if len(nearby) > 0 {
		candidates = nearby
	}
	if len(candidates) == 0 {
		return nil
	}
	return candidates[r.next.Add(1)%uint64(len(candidates))]
}

// Ready is for a private load-balancer health port, not the public prover route.
func (r *Router) Ready(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != "/ready" {
		fail(w, http.StatusNotFound, "route_unknown")
		return
	}
	if r.choose("") == nil {
		fail(w, http.StatusServiceUnavailable, "tee_router_not_ready")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ready"}`)
}

// Status exposes only operator identifiers and counters on the private admin port.
func (r *Router) Status(w http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || request.URL.Path != "/status" {
		fail(w, http.StatusNotFound, "route_unknown")
		return
	}
	type endpoint struct {
		ID        string `json:"id"`
		Region    string `json:"region"`
		Healthy   bool   `json:"healthy"`
		Draining  bool   `json:"draining"`
		Disabled  bool   `json:"disabled"`
		Forwarded uint64 `json:"forwarded"`
	}
	value := struct {
		Revision        uint64     `json:"revision"`
		Fresh           bool       `json:"registry_fresh"`
		Backends        []endpoint `json:"backends"`
		Admitted        uint64     `json:"admitted"`
		RefreshFailures uint64     `json:"refresh_failures"`
		ProbeFailures   uint64     `json:"probe_failures"`
		ForwardFailures uint64     `json:"forward_failures"`
		Unavailable     uint64     `json:"unavailable"`
	}{Admitted: r.admitted.Load(), RefreshFailures: r.refreshFailures.Load(), ProbeFailures: r.probeFailures.Load(), ForwardFailures: r.forwardFailures.Load()}
	value.Backends = []endpoint{}
	value.Unavailable = r.unavailable.Load()
	r.mu.RLock()
	if r.current != nil {
		value.Revision, value.Fresh = r.current.revision, r.available(r.current, time.Now())
		for _, id := range r.current.order {
			group := r.current.keys[id]
			for _, target := range group.backends {
				value.Backends = append(value.Backends, endpoint{ID: target.id, Region: target.region, Healthy: !group.disabled && healthy(target, time.Now()), Draining: group.draining, Disabled: group.disabled, Forwarded: target.forwarded.Load()})
			}
		}
	}
	r.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

func (r *Router) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	supplied := sha256.Sum256([]byte(request.Header.Get("X-API-Key")))
	if len(request.Header.Values("X-API-Key")) != 1 || subtle.ConstantTimeCompare(supplied[:], r.auth[:]) != 1 {
		fail(w, http.StatusUnauthorized, "tee_router_unauthorized")
		return
	}
	if request.URL.RawPath != "" || !strings.HasPrefix(request.URL.Path, tee.GatewayPrefix+"/") || request.URL.ForceQuery {
		fail(w, http.StatusNotFound, "route_unknown")
		return
	}
	path := strings.TrimPrefix(request.URL.Path, tee.GatewayPrefix)
	isAttestation := path == attestation && request.Method == http.MethodGet
	metadata := path == "/health" || path == "/proving-keys"
	proof := keyPath.MatchString(path)
	allowed := isAttestation || (metadata && request.Method == http.MethodGet) || (proof && ((strings.HasSuffix(path, "/status") && request.Method == http.MethodGet) || (!strings.HasSuffix(path, "/status") && request.Method == http.MethodPost)))
	if !allowed {
		fail(w, http.StatusNotFound, "route_unknown")
		return
	}
	for _, header := range requestHeaders {
		if len(request.Header.Values(header)) > 1 {
			fail(w, http.StatusBadRequest, "tee_duplicate_header")
			return
		}
	}
	if request.Header.Get("Content-Encoding") != "" && request.Header.Get("Content-Encoding") != "identity" {
		fail(w, http.StatusBadRequest, "tee_content_encoding")
		return
	}
	if request.ContentLength > maxBody {
		fail(w, http.StatusRequestEntityTooLarge, "tee_body_limit")
		return
	}
	if request.Method == http.MethodGet && request.Body != nil && request.Body != http.NoBody {
		fail(w, http.StatusBadRequest, "tee_get_body")
		return
	}
	key := ""
	if isAttestation {
		if request.Header.Get(tee.HeaderVersion) != "" {
			fail(w, http.StatusBadRequest, "tee_attestation_plaintext_required")
			return
		}
	} else {
		key = request.Header.Get(tee.HeaderKeyID)
		if request.Header.Get(tee.HeaderVersion) != tee.Version || !recipient.MatchString(key) {
			fail(w, http.StatusBadRequest, "tee_recipient_required")
			return
		}
	}
	target := r.choose(key)
	if target == nil {
		r.unavailable.Add(1)
		fail(w, http.StatusServiceUnavailable, "tee_generation_unavailable")
		return
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		w.Header().Set("Retry-After", "1")
		fail(w, http.StatusServiceUnavailable, "tee_router_overloaded")
		return
	}
	r.admitted.Add(1)
	target.forwarded.Add(1)
	ctx, cancel := context.WithTimeout(request.Context(), requestTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	request.Body = http.MaxBytesReader(w, request.Body, maxBody)
	proxy := &httputil.ReverseProxy{
		Transport: r.transport,
		ErrorLog:  log.New(io.Discard, "", 0),
		Rewrite: func(proxy *httputil.ProxyRequest) {
			proxy.Out.URL.Scheme, proxy.Out.URL.Host = target.origin.Scheme, target.origin.Host
			proxy.Out.URL.Path, proxy.Out.URL.RawPath = proxy.In.URL.Path, ""
			proxy.Out.URL.RawQuery = withoutAPIKey(proxy.In.URL.RawQuery)
			proxy.Out.Host, proxy.Out.GetBody = target.origin.Host, nil
			proxy.Out.Header = make(http.Header)
			for _, header := range requestHeaders {
				if value := proxy.In.Header.Get(header); value != "" {
					proxy.Out.Header.Set(header, value)
				}
			}
			proxy.Out.Header.Set("X-API-Key", target.key)
		},
		ModifyResponse: func(response *http.Response) error {
			if !isAttestation && response.StatusCode >= 200 && response.StatusCode < 300 && response.Header.Get(tee.HeaderVersion) != tee.Version {
				return errors.New("unauthenticated prover success")
			}
			headers := make(http.Header)
			for _, header := range responseHeaders {
				if value := response.Header.Get(header); value != "" {
					headers.Set(header, value)
				}
			}
			headers.Set("Cache-Control", "no-store")
			response.Header = headers
			response.Body = http.MaxBytesReader(w, response.Body, maxBody)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			r.forwardFailures.Add(1)
			r.mu.Lock()
			target.healthy = false
			r.mu.Unlock()
			// The origin may have consumed the request. Never emit the pre-forward
			// generation-unavailable code or replay a proof submission here.
			fail(w, http.StatusBadGateway, "tee_upstream_unavailable")
		},
	}
	proxy.ServeHTTP(w, request)
}

func fail(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(struct {
		Code string `json:"code"`
	}{code})
}
