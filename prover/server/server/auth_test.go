package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayAuthentication(t *testing.T) {
	for _, test := range []struct {
		name   string
		target string
		header string
		value  string
		status int
	}{
		{"missing", "/auth", "", "", http.StatusUnauthorized},
		{"wrong", "/auth", "X-API-Key", "wrong", http.StatusUnauthorized},
		{"api key", "/auth", "X-API-Key", "secret", http.StatusNoContent},
		{"bearer", "/auth", "Authorization", "Bearer secret", http.StatusNoContent},
		{"query", "/auth?api-key=secret", "", "", http.StatusNoContent},
		{"wrong query", "/auth?api-key=wrong", "", "", http.StatusUnauthorized},
		{"other query", "/auth?api-keys=secret", "", "", http.StatusUnauthorized},
		{"header over query", "/auth?api-key=secret", "X-API-Key", "wrong", http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.target, nil)
			if test.header != "" {
				request.Header.Set(test.header, test.value)
			}
			response := httptest.NewRecorder()
			handler := conditionalAuthMiddleware("secret")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}))
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status %d, want %d", response.Code, test.status)
			}
		})
	}
}
