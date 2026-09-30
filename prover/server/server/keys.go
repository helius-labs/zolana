package server

import (
	"fmt"
	"net/http"
	"path"
	"slices"
	"strings"
	"zolana/prover/prover/common"
)

// A proof is sent to the path of the proving key that proves it:
// /prove/<key> and /prove/<key>/indexed, <key> being the key file name without
// ".key" (transfer_p256_ring_2_3, merge_36_1, batch_address-append_40_250).
//
// The key is in the path because the Helius gateway routes and prices REST
// calls on (method, path) alone and never reads the body. A proving key fixes
// the cost of a proof and the hardware it suits, so the gateway can send each
// key to a pool at a price. Which keys share a pool or a price is gateway
// configuration; this server only proves the keys it serves and checks that a
// body is the proof its path paid for.
const keyFileSuffix = ".key"

// knownKeyFiles is every key file this binary proves.
var knownKeyFiles = common.KeyFiles()

// ServedKeys is the set of proving key files a deployment proves.
type ServedKeys struct {
	files []string
}

// ParseServedKeys resolves --serve patterns (path.Match syntax, over key names
// without ".key"). None serves every key. A pattern matching no key is an
// error, so a typo cannot silently shrink a pool to nothing.
func ParseServedKeys(patterns []string) (*ServedKeys, error) {
	all := knownKeyFiles
	if len(patterns) == 0 {
		return &ServedKeys{files: all}, nil
	}
	served := map[string]bool{}
	for _, pattern := range patterns {
		matched := false
		for _, file := range all {
			ok, err := path.Match(pattern, keyName(file))
			if err != nil {
				return nil, fmt.Errorf("invalid --serve pattern %q: %w", pattern, err)
			}
			if ok {
				served[file] = true
				matched = true
			}
		}
		if !matched {
			return nil, fmt.Errorf("--serve pattern %q matches no proving key", pattern)
		}
	}
	var files []string
	for _, file := range all {
		if served[file] {
			files = append(files, file)
		}
	}
	return &ServedKeys{files: files}, nil
}

// Serves reports whether file is served. A nil set serves every key.
func (keys *ServedKeys) Serves(file string) bool {
	return keys == nil || slices.Contains(keys.files, file)
}

// Names lists the served keys as their paths name them.
func (keys *ServedKeys) Names() []string {
	files := knownKeyFiles
	if keys != nil {
		files = keys.files
	}
	names := make([]string, len(files))
	for i, file := range files {
		names[i] = keyName(file)
	}
	return names
}

func keyName(file string) string {
	return strings.TrimSuffix(file, keyFileSuffix)
}

// keyAdmission is checked against the key file a request resolves to, after
// its body is decoded and before any key is loaded. It runs where the key is
// resolved rather than at the door because only the decoded body fixes the
// shape, and an indexed body only once the indexer has filled it in.
type keyAdmission struct {
	served *ServedKeys
	// The key file the request's path named. Empty for /prove and
	// /prove/indexed, which take any served key.
	expected string
}

func (admission keyAdmission) admit(file string) *Error {
	if admission.expected != "" && file != admission.expected {
		resolved := keyName(file)
		if file == "" {
			resolved = "no proving key"
		}
		// A body proved on another key's path would be priced and pooled as
		// that key.
		return &Error{
			StatusCode: http.StatusBadRequest,
			Code:       "proving_key_mismatch",
			Message:    fmt.Sprintf("request resolves to %s; its path names %s", resolved, keyName(admission.expected)),
		}
	}
	if file != "" && !admission.served.Serves(file) {
		return keyNotServed(file)
	}
	return nil
}

func keyNotServed(file string) *Error {
	return &Error{
		StatusCode: http.StatusNotFound,
		Code:       "proving_key_not_served",
		Message:    fmt.Sprintf("%s is not proved by this deployment", keyName(file)),
	}
}

// keyPathHandler serves /prove/<key> and /prove/<key>/indexed: it resolves the
// key the path names and hands the request to prove, which holds the body to
// it.
type keyPathHandler struct {
	prove proveHandler
}

func (handler keyPathHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("key") + keyFileSuffix
	if !slices.Contains(knownKeyFiles, file) {
		(&Error{
			StatusCode: http.StatusNotFound,
			Code:       "unknown_proving_key",
			Message:    fmt.Sprintf("no proving key named %s", r.PathValue("key")),
		}).send(w)
		return
	}
	if !handler.prove.served.Serves(file) {
		keyNotServed(file).send(w)
		return
	}
	prove := handler.prove
	prove.provingKey = file
	prove.ServeHTTP(w, r)
}
