package tee

import "errors"

var ErrQueueUnsupported = errors.New("TEE requires synchronous proof execution")
