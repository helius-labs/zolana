package indexed

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestIndexerResponseBoundary(t *testing.T) {
	for _, fault := range []string{"id", "status", "content", "size", "null", "error", "version"} {
		t.Run(fault, func(t *testing.T) {
			resolver, err := NewResolver(Config{URL: "https://indexer.test", APIKey: "test-key", Concurrency: 1})
			if err != nil {
				t.Fatal(err)
			}
			resolver.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				if request.URL.Query().Get("api-key") != "test-key" || request.URL.Path != "/getMerkleProofs" || request.Header.Get("Content-Type") != "application/json" {
					t.Error("request headers missing")
				}
				response := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}}
				body := `{"jsonrpc":"2.0","id":"getMerkleProofs","result":{}}`
				switch fault {
				case "id":
					body = strings.Replace(body, "getMerkleProofs", "other", 1)
				case "status":
					response.StatusCode = 500
				case "content":
					response.Header.Set("Content-Type", "text/html")
				case "size":
					body = strings.Repeat(" ", (2<<20)+1)
				case "null":
					body = strings.Replace(body, `"result":{}`, `"result":null`, 1)
				case "error":
					body = strings.Replace(body, `"result":{}`, `"error":{"code":-1}`, 1)
				case "version":
					body = strings.Replace(body, "2.0", "1.0", 1)
				}
				response.Body = io.NopCloser(strings.NewReader(body))
				return response, nil
			})
			if _, err := resolver.call(context.Background(), proofQuery{Method: "getMerkleProofs"}); err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}
