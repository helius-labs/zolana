//go:build !aeglos

package tee

import "errors"

func newGPUAttester() (gpuAttester, error) {
	return nil, errors.New("GPU attestation requires the aeglos build")
}
