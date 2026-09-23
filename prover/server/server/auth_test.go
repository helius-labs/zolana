package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGatewayAuthentication(t *testing.T) {
	for _, test := range []struct {
		name   string
		header string
		value  string
		status int
	}{
		{"missing", "", "", http.StatusUnauthorized},
		{"wrong", "X-API-Key", "wrong", http.StatusUnauthorized},
		{"api key", "X-API-Key", "secret", http.StatusNoContent},
		{"bearer", "Authorization", "Bearer secret", http.StatusNoContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/auth", nil)
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
