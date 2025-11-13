// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package kem

import (
	"crypto/sha3"
	"io"

	"github.com/jrick/ss/internal/kmac"
)

func kmac256KDF(key []byte, customization []byte, length int) []byte {
	out := make([]byte, length)
	h := kmac.NewKMAC256(key, length, customization)
	h.Sum(out[:0])
	return out
}

func cshake256CSPRNG(key []byte, customization []byte) io.Reader {
	h := sha3.NewCSHAKE256(nil, customization)
	_, err := h.Write(key)
	if err != nil {
		panic(err)
	}
	return h
}
