package tee

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"zolana/prover/logging"
)

const (
	codeVersionUnsupported = "tee_version_unsupported"
	codeRequestMalformed   = "tee_request_malformed"
	// Reserved for an HPKE failure, a client re-attests on it when the platform rotates its key per boot.
	codeDecryptionFailed = "tee_decryption_failed"

	// Nenc of DHKEM(X25519), RFC 9180.
	encSize = 32
)

// Wrap passes a request without HeaderVersion through unencrypted, so TEE use
// stays a client choice.
func (s *Server) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := r.Header.Get(HeaderVersion)
		if version == "" {
			next.ServeHTTP(w, r)
			return
		}
		if version != Version {
			rejectEncrypted(w, codeVersionUnsupported)
			return
		}
		// net/http drops a HEAD answer body, so its encrypted answer never arrives.
		if r.Method == http.MethodHead {
			rejectEncrypted(w, codeRequestMalformed)
			return
		}
		enc, ciphertext, err := readEncrypted(w, r)
		if err != nil {
			rejectEncrypted(w, codeRequestMalformed)
			return
		}
		plaintext, responseKey, err := s.open(r, enc, ciphertext)
		if err != nil {
			rejectEncrypted(w, codeDecryptionFailed)
			return
		}
		inner := r.Clone(r.Context())
		inner.Body = io.NopCloser(bytes.NewReader(plaintext))
		inner.ContentLength = int64(len(plaintext))
		inner.Header.Del(HeaderVersion)
		inner.Header.Del(HeaderEnc)
		inner.Header.Del(HeaderCiphertext)
		inner.Header.Set("Content-Type", "application/json")

		recorder := newRecorder()
		next.ServeHTTP(recorder, inner)

		encrypted, err := encryptResponse(responseKey, recorder.status, recorder.body.Bytes())
		if err != nil {
			logging.Logger().Error().Err(err).Msg("encrypting prover response failed")
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
		w.Header().Set("Content-Length", strconv.Itoa(len(encrypted)))
		w.WriteHeader(recorder.status)
		if _, err := w.Write(encrypted); err != nil {
			logging.Logger().Error().Err(err).Msg("error writing encrypted response")
		}
	})
}

func readEncrypted(w http.ResponseWriter, r *http.Request) (enc, ciphertext []byte, err error) {
	if enc, err = hexHeader(r, HeaderEnc); err != nil {
		return nil, nil, err
	}
	if len(enc) != encSize {
		return nil, nil, fmt.Errorf("%s is not %d bytes", HeaderEnc, encSize)
	}
	if bodiless(r.Method) {
		ciphertext, err = hexHeader(r, HeaderCiphertext)
	} else {
		ciphertext, err = io.ReadAll(http.MaxBytesReader(w, r.Body, maxEncryptedBody))
	}
	return enc, ciphertext, err
}

func hexHeader(r *http.Request, name string) ([]byte, error) {
	value := r.Header.Get(name)
	if value == "" {
		return nil, fmt.Errorf("%s is missing", name)
	}
	return hex.DecodeString(value)
}

func (s *Server) open(r *http.Request, enc, ciphertext []byte) ([]byte, []byte, error) {
	_, kdf, aead := suite()
	recipient, err := hpke.NewRecipient(enc, s.key, kdf, aead, []byte(hpkeInfo))
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

// Replayed requests share a response key and require independent nonces.
func encryptResponse(key []byte, status int, body []byte) ([]byte, error) {
	gcm, err := responseAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, 2, 2+len(body))
	binary.BigEndian.PutUint16(plaintext, uint16(status))
	plaintext = append(plaintext, body...)
	return gcm.Seal(nil, nil, plaintext, nil), nil
}

func responseAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

func bodiless(method string) bool {
	return method == http.MethodGet
}

func rejectEncrypted(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	body, _ := json.Marshal(map[string]string{"code": code, "message": "encrypted request rejected"})
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
