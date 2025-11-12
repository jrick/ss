// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package kem

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSntrup4591761RoundTrip(t *testing.T) {
	kem := NewSNTRUP4591761()

	seed := make([]byte, 64)
	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	pubkey, privkey, err := kem.GenerateKey(seed)
	if err != nil {
		t.Fatalf("GenerateKeys: %v", err)
	}

	ciphertext, sharedKey1, err := kem.Encapsulate(pubkey)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	sharedKey2, err := kem.Decapsulate(nil /* unused */, privkey, ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(sharedKey1, sharedKey2) {
		t.Fatalf("Failed to derive same shared key")
	}
}
