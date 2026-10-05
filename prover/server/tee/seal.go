package tee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"zolana/prover/logging"
)

// Wrap passes a request without HeaderVersion through unsealed, so TEE use
// stays a client choice.
func (s *Server) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := r.Header.Get(HeaderVersion)
		if version == "" {
			next.ServeHTTP(w, r)
			return
		}
		if version != Version {
			rejectSealed(w, "tee_version_unsupported")
			return
		}
		plaintext, responseKey, err := s.open(w, r)
		if err != nil {
			rejectSealed(w, "tee_seal_invalid")
			return
		}
		inner := r.Clone(r.Context())
		inner.Body = io.NopCloser(bytes.NewReader(plaintext))
		inner.ContentLength = int64(len(plaintext))
		inner.Header.Del(HeaderVersion)
		inner.Header.Del(HeaderEnc)
		inner.Header.Set("Content-Type", "application/json")

		recorder := newRecorder()
		next.ServeHTTP(recorder, inner)

		sealed, err := sealResponse(responseKey, recorder.status, recorder.body.Bytes())
		if err != nil {
			logging.Logger().Error().Err(err).Msg("sealing prover response failed")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for name, values := range recorder.header {
			if name == "Content-Type" || name == "Content-Length" {
				continue
			}
			w.Header()[name] = values
		}
		w.Header().Set(HeaderVersion, Version)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(sealed)))
		w.WriteHeader(recorder.status)
		if _, err := w.Write(sealed); err != nil {
			logging.Logger().Error().Err(err).Msg("error writing sealed response")
		}
	})
}

func (s *Server) open(w http.ResponseWriter, r *http.Request) ([]byte, []byte, error) {
	enc, err := hex.DecodeString(r.Header.Get(HeaderEnc))
	if err != nil {
		return nil, nil, err
	}
	_, kdf, aead := suite()
	recipient, err := hpke.NewRecipient(enc, s.key, kdf, aead, []byte(hpkeInfo))
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSealedBody))
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := recipient.Open(requestAAD(r.Method, r.RequestURI), ciphertext)
	if err != nil {
		return nil, nil, err
	}
	responseKey, err := recipient.Export(responseExport, responseKeySize)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, responseKey, nil
}

// sealResponse keys AES-GCM with a single use export of the request context,
// so the zero nonce never repeats under one key.
func sealResponse(key []byte, status int, body []byte) ([]byte, error) {
	gcm, err := responseAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 2, 2+len(body))
	binary.BigEndian.PutUint16(plaintext, uint16(status))
	plaintext = append(plaintext, body...)
	return gcm.Seal(nil, make([]byte, gcm.NonceSize()), plaintext, nil), nil
}

func responseAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func rejectSealed(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	body, _ := json.Marshal(map[string]string{"code": code, "message": "sealed request rejected"})
	_, _ = w.Write(body)
}

type recorder struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func newRecorder() *recorder {
	return &recorder{header: http.Header{}, status: http.StatusOK}
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(status int) {
	if !r.wroteHeader {
		r.status = status
		r.wroteHeader = true
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	r.wroteHeader = true
	return r.body.Write(p)
}
