package server

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/helius-labs/zolana/prover/server/logging"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/request"
)

// A proof request is read whole before it is parsed, so its body is the first
// memory any caller can make the prover hold. Every bound here applies before
// a byte of it is buffered.
const (
	// The largest transfer, merge or extension body, with margin. The widest
	// transfer shape encodes to a few hundred KiB.
	maxProofBodyBytes = request.MaxBodyBytes
	// An indexed body names its inputs and leaves the paths to the indexer.
	maxIndexedBodyBytes = 1 << 20
	// Bytes one hex field element takes in a body: "0x", 64 digits, quotes
	// and a separator.
	fieldElementBodyBytes = 70
	// Time a client has to deliver its whole body once its headers are in.
	bodyReadTimeout = 60 * time.Second
	// Time a client has to deliver its request headers.
	requestHeaderTimeout = 10 * time.Second
	// Bodies read at once unless PROVER_BODY_READ_CONCURRENCY says otherwise.
	// Each holds at most its limit, so this times the largest limit bounds the
	// memory request bodies can take.
	defaultBodyReadPermits = 16
)

// maxBodyBytes is the largest body the key a path names can need. A batch
// carries two Merkle paths per element, so its bound follows from its shape;
// a path that names no key may carry any circuit, so it takes the largest.
func maxBodyBytes(keyFile string) int64 {
	limit := int64(maxProofBodyBytes)
	for _, shape := range common.BatchAddressAppendShapes() {
		batch := batchBodyBytes(shape[0], shape[1])
		if keyFile == common.BatchKeyFile(common.BatchAddressAppendCircuitType, shape[0], shape[1]) {
			return batch
		}
		if keyFile == "" && batch > limit {
			limit = batch
		}
	}
	return limit
}

// batchBodyBytes bounds an address-append body: per element a low and a new
// Merkle path of treeHeight siblings plus four values, and half again as
// margin for a client that formats numbers less tightly.
func batchBodyBytes(treeHeight, batchSize uint32) int64 {
	elements := int64(batchSize) * (2*int64(treeHeight) + 4)
	return elements*fieldElementBodyBytes*3/2 + maxIndexedBodyBytes
}

// bodyAdmission bounds how many request bodies are read at once. A nil
// admission bounds none.
type bodyAdmission struct {
	permits chan struct{}
}

func newBodyAdmission(permits int) *bodyAdmission {
	if permits < 1 {
		permits = 1
	}
	logging.Logger().Info().
		Int("permits", permits).
		Msg("Request body admission control")
	return &bodyAdmission{permits: make(chan struct{}, permits)}
}

// bodyReadPermits is the concurrent body bound. PROVER_BODY_READ_CONCURRENCY
// overrides it, sized against the memory an instance has to spare.
func bodyReadPermits() int {
	if val := os.Getenv("PROVER_BODY_READ_CONCURRENCY"); val != "" {
		if permits, err := strconv.Atoi(val); err == nil && permits > 0 {
			return permits
		}
		logging.Logger().Warn().
			Str("value", val).
			Msg("Ignoring unparseable PROVER_BODY_READ_CONCURRENCY")
	}
	return defaultBodyReadPermits
}

// read buffers r's body, refusing one above limit before reading past it, and
// one that would exceed the concurrent read bound before reading any of it.
// The body must arrive within bodyReadTimeout; the deadline is lifted once it
// has, so it never bears on the proof that follows.
func (a *bodyAdmission) read(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, *Error) {
	if a != nil {
		select {
		case a.permits <- struct{}{}:
			defer func() { <-a.permits }()
		default:
			BodyReadsShedTotal.Inc()
			return nil, overloadedError()
		}
	}
	if r.ContentLength > limit {
		return nil, bodyTooLarge(limit)
	}
	controller := http.NewResponseController(w)
	// A writer that cannot set deadlines (a test recorder) reads without one.
	_ = controller.SetReadDeadline(time.Now().Add(bodyReadTimeout))
	defer func() { _ = controller.SetReadDeadline(time.Time{}) }()

	var buf bytes.Buffer
	// A declared length is allocated once, rather than grown to by doubling,
	// which holds up to twice the body while the last copy is made.
	if r.ContentLength > 0 {
		buf.Grow(int(r.ContentLength))
	}
	if _, err := buf.ReadFrom(http.MaxBytesReader(w, r.Body, limit)); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, bodyTooLarge(limit)
		}
		logging.Logger().Error().Err(err).Msg("Error reading request body")
		return nil, malformedBodyError(err)
	}
	return buf.Bytes(), nil
}

func bodyTooLarge(limit int64) *Error {
	return &Error{
		StatusCode: http.StatusRequestEntityTooLarge,
		Code:       "body_too_large",
		Message:    "request body exceeds " + strconv.FormatInt(limit, 10) + " bytes",
	}
}
