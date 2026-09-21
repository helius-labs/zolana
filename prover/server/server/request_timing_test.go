package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"zolana/prover/prover/timing"
)

func TestRequestTimingOptIn(t *testing.T) {
	for _, enabled := range []string{"", "true"} {
		for _, requested := range []string{"", "true"} {
			t.Run(enabled+"/"+requested, func(t *testing.T) {
				t.Setenv("PROVER_REQUEST_TIMING", enabled)
				handler := observeProofHTTP("complete", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					finish := timing.FromContext(r.Context()).Start("witness")
					finish()
					w.WriteHeader(http.StatusBadRequest)
					_, _ = w.Write([]byte(`{"error":"invalid"}`))
				}))
				request := httptest.NewRequest(http.MethodPost, "/prove", nil)
				request.Header.Set("X-Prover-Timing", requested)
				request.Header.Set("X-Request-ID", "not-a-uuid")
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, request)
				if response.Code != http.StatusBadRequest || response.Body.String() != `{"error":"invalid"}` {
					t.Fatal("timing changed the response")
				}
				if enabled != "true" || requested != "true" {
					if response.Header().Get("Server-Timing") != "" || response.Header().Get("X-Prover-Timing") != "" {
						t.Fatal("unrequested timing was exposed")
					}
					return
				}
				var spans []timing.Span
				if err := json.Unmarshal([]byte(response.Header().Get("X-Prover-Timing")), &spans); err != nil || len(spans) != 2 {
					t.Fatalf("invalid timing response: %v", err)
				}
				if !isValidJobID(response.Header().Get("X-Request-ID")) {
					t.Fatal("invalid correlation identifier")
				}
			})
		}
	}
}
