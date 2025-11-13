// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Implemention taken, with modifications to use crypto/sha3's CSHAKE, from
// abandoned CL https://go-review.googlesource.com/c/crypto/+/108715.

package kmac

// This file provides function for creating KMAC instances.
// KMAC is a Message Authentication Code that based on SHA-3 and
// specified in NIST Special Publication 800-185, "SHA-3 Derived Functions:
// cSHAKE, KMAC, TupleHash and ParallelHash" [1]
//
// [1] https://doi.org/10.6028/NIST.SP.800-185

import (
	"crypto/sha3"
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	// According to [1]:
	// "When used as a MAC, applications of this Recommendation shall
	// not select an output length L that is less than 32 bits, and
	// shall only select an output length less than 64 bits after a
	// careful risk analysis is performed."
	// 64 bits was selected for safety.
	kmacMinimumTagSize = 8
)

// KMAC specific context
type kmac struct {
	*sha3.SHAKE     // cSHAKE context and Read/Write operations
	tagSize     int // tag size

	// initBlock is the KMAC specific initialization set of bytes. It is initialized
	// by newKMAC function and stores the key, encoded by the method specified in 3.3 of [1].
	// It is stored here in order for Reset() to be able to put context into
	// initial state.
	initBlock []byte
}

// NewKMAC128 returns a new KMAC hash providing 128 bits of security using
// the given key, which must have 16 bytes or more, generating the given tagSize
// bytes output and using the given customizationString.
// Note that unlike other hash implementations in the standard library,
// the returned Hash does not implement encoding.BinaryMarshaler
// or encoding.BinaryUnmarshaler.
func NewKMAC128(key []byte, tagSize int, customizationString []byte) hash.Hash {
	if len(key) < 16 {
		panic("Key must not be smaller than security strength")
	}
	c := sha3.NewCSHAKE128([]byte("KMAC"), customizationString)
	return newKMAC(key, tagSize, c)
}

// NewKMAC256 returns a new KMAC hash providing 256 bits of security using
// the given key, which must have 32 bytes or more, generating the given tagSize
// bytes output and using the given customizationString.
// Note that unlike other hash implementations in the standard library,
// the returned Hash does not implement encoding.BinaryMarshaler
// or encoding.BinaryUnmarshaler.
func NewKMAC256(key []byte, tagSize int, customizationString []byte) hash.Hash {
	if len(key) < 32 {
		panic("Key must not be smaller than security strength")
	}
	c := sha3.NewCSHAKE256([]byte("KMAC"), customizationString)
	return newKMAC(key, tagSize, c)
}

func newKMAC(key []byte, tagSize int, c *sha3.SHAKE) hash.Hash {
	if tagSize < kmacMinimumTagSize {
		panic("tagSize is too small")
	}

	k := &kmac{SHAKE: c, tagSize: tagSize}

	// leftEncode returns max 9 bytes
	k.initBlock = make([]byte, 0, 9+len(key))
	k.initBlock = append(k.initBlock, leftEncode(uint64(len(key)*8))...)
	k.initBlock = append(k.initBlock, key...)
	k.Write(bytepad(k.initBlock, k.BlockSize()))
	return k
}

// Reset resets the hash to initial state.
func (k *kmac) Reset() {
	k.SHAKE.Reset()
	k.Write(bytepad(k.initBlock, k.BlockSize()))
}

// BlockSize returns the hash block size.
func (k *kmac) BlockSize() int {
	return k.SHAKE.BlockSize()
}

// Size returns the tag size.
func (k *kmac) Size() int {
	return k.tagSize
}

// Sum appends the current KMAC to b and returns the resulting slice.
// It does not change the underlying hash state.
func (k *kmac) Sum(b []byte) []byte {
	dup := *k.SHAKE
	dup.Write(rightEncode(uint64(k.tagSize * 8)))
	hash := make([]byte, k.tagSize)
	dup.Read(hash)
	return append(b, hash...)
}

func bytepad(data []byte, rate int) []byte {
	out := make([]byte, 0, 9+len(data)+rate-1)
	out = append(out, leftEncode(uint64(rate))...)
	out = append(out, data...)
	if padlen := rate - len(out)%rate; padlen < rate {
		out = append(out, make([]byte, padlen)...)
	}
	return out
}

func leftEncode(x uint64) []byte {
	// Let n be the smallest positive integer for which 2^(8n) > x.
	n := (bits.Len64(x) + 7) / 8
	if n == 0 {
		n = 1
	}
	// Return n || x with n as a byte and x an n bytes in big-endian order.
	b := make([]byte, 9)
	binary.BigEndian.PutUint64(b[1:], x)
	b = b[9-n-1:]
	b[0] = byte(n)
	return b
}

func rightEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[:8], value)
	// Trim all but last leading zero bytes
	i := byte(0)
	for i < 7 && b[i] == 0 {
		i++
	}
	// Append number of encoded bytes
	b[8] = 8 - i
	return b[i:]
}
