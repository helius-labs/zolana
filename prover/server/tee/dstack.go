package tee

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// guest speaks the dstack v0 guest agent API, the one dstack-nvidia-0.5.x serves.
type guest struct {
	client *http.Client
}

type guestQuote struct {
	Quote    []byte
	EventLog json.RawMessage
	VMConfig string
}

func newGuest(socket string) *guest {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}
	return &guest{client: &http.Client{Transport: transport, Timeout: 30 * time.Second}}
}

// key returns the KMS derived secret for path, the same for every instance of the app.
func (g *guest) key(ctx context.Context, path string) ([]byte, error) {
	var response struct {
		Key string `json:"key"`
	}
	if err := g.call(ctx, "GetKey", map[string]string{"path": path, "purpose": "hpke"}, &response); err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(response.Key)
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("dstack GetKey returned a malformed key")
	}
	return key, nil
}

func (g *guest) quote(ctx context.Context, reportData [64]byte) (guestQuote, error) {
	var response struct {
		Quote    string `json:"quote"`
		EventLog string `json:"event_log"`
		VMConfig string `json:"vm_config"`
	}
	if err := g.call(ctx, "GetQuote", map[string]string{"report_data": hex.EncodeToString(reportData[:])}, &response); err != nil {
		return guestQuote{}, err
	}
	quote, err := hex.DecodeString(response.Quote)
	if err != nil || len(quote) == 0 {
		return guestQuote{}, fmt.Errorf("dstack GetQuote returned a malformed quote")
	}
	eventLog := json.RawMessage(response.EventLog)
	var events []json.RawMessage
	if err := json.Unmarshal(eventLog, &events); err != nil {
		return guestQuote{}, fmt.Errorf("dstack GetQuote returned a malformed event log: %w", err)
	}
	return guestQuote{Quote: quote, EventLog: eventLog, VMConfig: response.VMConfig}, nil
}

func (g *guest) call(ctx context.Context, method string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://dstack/"+method, bytes.NewReader(body))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/json")
	httpResponse, err := g.client.Do(httpRequest)
	if err != nil {
		return fmt.Errorf("dstack %s: %w", method, err)
	}
	defer httpResponse.Body.Close()
	body, err = io.ReadAll(io.LimitReader(httpResponse.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("dstack %s: %w", method, err)
	}
	if httpResponse.StatusCode != http.StatusOK {
		return fmt.Errorf("dstack %s: HTTP %d", method, httpResponse.StatusCode)
	}
	if err := json.Unmarshal(body, response); err != nil {
		return fmt.Errorf("dstack %s: %w", method, err)
	}
	return nil
}
