package server

import (
	"crypto/subtle"
	"net"
	"net/http"
	"os"
	"strings"
	"zolana/prover/logging"
)

type authMiddleware struct {
	next   http.Handler
	apiKey string
}

func NewAPIKeyMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return &authMiddleware{
			next:   next,
			apiKey: apiKey,
		}
	}
}

func (m *authMiddleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !m.isAuthenticated(r) {
		logging.Logger().Warn().
			Str("remote_addr", r.RemoteAddr).
			Str("path", r.URL.Path).
			Str("method", r.Method).
			Msg("Unauthorized API request - missing or invalid API key")

		unauthorizedError := &Error{
			StatusCode: http.StatusUnauthorized,
			Code:       "unauthorized",
			Message:    "Invalid or missing API key. Please provide a valid API key in the Authorization header as 'Bearer <api-key>' or in the X-API-Key header.",
		}
		unauthorizedError.send(w)
		return
	}

	m.next.ServeHTTP(w, r)
}

func (m *authMiddleware) isAuthenticated(r *http.Request) bool {
	if m.apiKey == "" {
		return true
	}

	providedKey := m.extractAPIKey(r)
	if providedKey == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(m.apiKey), []byte(providedKey)) == 1
}

func (m *authMiddleware) extractAPIKey(r *http.Request) string {
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		return apiKey
	}

	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		if strings.HasPrefix(authHeader, "Bearer ") {
			return strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	return ""
}

func getAPIKeyFromEnv() string {
	if apiKey := os.Getenv("ZOLANA_PROVER_API_KEY"); apiKey != "" {
		return apiKey
	}
	return os.Getenv("PROVER_API_KEY")
}

func requiresAuthentication(path string) bool {
	publicPaths := []string{
		"/health",
	}

	for _, publicPath := range publicPaths {
		if path == publicPath {
			return false
		}
	}

	return true
}

func isLoopbackBindAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func conditionalAuthMiddleware(apiKey string, requireConfiguredKey bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if requiresAuthentication(r.URL.Path) {
				// The prover is a native-client service, not a browser API. Reject
				// browser-originated requests even on loopback so an arbitrary page
				// cannot drive expensive local proofs through permissive CORS/PNA.
				if r.Header.Get("Origin") != "" {
					(&Error{
						StatusCode: http.StatusForbidden,
						Code:       "browser_origin_forbidden",
						Message:    "browser-originated proof requests are not accepted",
					}).send(w)
					return
				}
				if apiKey == "" && requireConfiguredKey {
					(&Error{
						StatusCode: http.StatusServiceUnavailable,
						Code:       "api_key_required",
						Message:    "ZOLANA_PROVER_API_KEY or PROVER_API_KEY must be configured when the prover listens beyond localhost",
					}).send(w)
					return
				}
				authHandler := NewAPIKeyMiddleware(apiKey)(next)
				authHandler.ServeHTTP(w, r)
			} else {
				next.ServeHTTP(w, r)
			}
		})
	}
}
