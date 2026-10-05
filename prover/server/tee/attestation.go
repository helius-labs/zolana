package tee

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"zolana/prover/logging"
)

const AttestationPath = "/tee/v1/attestation"

type Attestation struct {
	Quote         string          `json:"quote"`
	EventLog      json.RawMessage `json:"event_log"`
	VMConfig      string          `json:"vm_config"`
	Collateral    Collateral      `json:"collateral"`
	HPKEPublicKey string          `json:"hpke_public_key"`
	// GPU is the raw NRAS response, already verified inside the TEE and bound
	// into report_data by its sha256.
	GPU *string `json:"gpu"`
}

// AttestationHandler serves GET AttestationPath?nonce=<32 byte hex>.
func (s *Server) AttestationHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		nonce, err := hex.DecodeString(r.URL.Query().Get("nonce"))
		if err != nil || len(nonce) != NonceSize {
			writeJSON(w, http.StatusBadRequest, map[string]string{"code": "invalid_nonce", "message": "nonce must be 32 bytes hex"})
			return
		}
		select {
		case s.permits <- struct{}{}:
			defer func() { <-s.permits }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"code": "attestation_busy", "message": "attestation capacity exhausted"})
			return
		}
		attestation, err := s.attest(r, nonce)
		if err != nil {
			logging.Logger().Error().Err(err).Msg("attestation failed")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"code": "attestation_unavailable", "message": "attestation is unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, attestation)
	})
}

func (s *Server) attest(r *http.Request, nonce []byte) (*Attestation, error) {
	ctx := r.Context()
	var gpuToken []byte
	var gpu *string
	if s.gpu != nil {
		token, err := s.gpu.attest(ctx, GPUNonce(nonce, s.publicKey))
		if err != nil {
			return nil, err
		}
		gpuToken = token
		text := string(token)
		gpu = &text
	}
	quote, err := s.guest.quote(ctx, ReportData(nonce, s.publicKey, gpuToken))
	if err != nil {
		return nil, err
	}
	collateral, err := s.collateral.forQuote(ctx, quote.Quote)
	if err != nil {
		return nil, err
	}
	return &Attestation{
		Quote:         hex.EncodeToString(quote.Quote),
		EventLog:      quote.EventLog,
		VMConfig:      quote.VMConfig,
		Collateral:    collateral,
		HPKEPublicKey: hex.EncodeToString(s.publicKey),
		GPU:           gpu,
	}, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	body, err := json.Marshal(value)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		logging.Logger().Error().Err(err).Msg("error writing response")
	}
}
