package main

/*
#include <stdint.h>
#include <stdlib.h>
*/
import "C"

import (
	"unsafe"

	"github.com/hashicorp/vault/shamir"
)

//export shamir_split
func shamir_split(secret *C.uint8_t, secretLen C.size_t, parts C.int, threshold C.int, out *C.uint8_t) C.int {
	sec := C.GoBytes(unsafe.Pointer(secret), C.int(secretLen))
	shares, err := shamir.Split(sec, int(parts), int(threshold))
	if err != nil {
		return -1
	}
	shareLen := int(secretLen) + 1
	outSlice := unsafe.Slice((*byte)(unsafe.Pointer(out)), int(parts)*shareLen)
	for i, sh := range shares {
		if len(sh) != shareLen {
			return -2
		}
		copy(outSlice[i*shareLen:(i+1)*shareLen], sh)
	}
	return 0
}

//export shamir_combine
func shamir_combine(shares *C.uint8_t, k C.int, shareLen C.size_t, out *C.uint8_t) C.int {
	flat := C.GoBytes(unsafe.Pointer(shares), C.int(int(k)*int(shareLen)))
	sl := int(shareLen)
	parts := make([][]byte, int(k))
	for i := 0; i < int(k); i++ {
		parts[i] = flat[i*sl : (i+1)*sl]
	}
	secret, err := shamir.Combine(parts)
	if err != nil {
		return -1
	}
	outSlice := unsafe.Slice((*byte)(unsafe.Pointer(out)), len(secret))
	copy(outSlice, secret)
	return C.int(len(secret))
}

func main() {}
