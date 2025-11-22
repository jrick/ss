// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package kem

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestSntrup4591761RoundTrip(t *testing.T) {
	kem := SNTRUP4591761()

	seed := make([]byte, 64)
	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	pubkey, err := kem.GenerateKey(seed)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ciphertext, sharedKey1, err := kem.Encapsulate(pubkey)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	sharedKey2, err := kem.Decapsulate(seed, ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(sharedKey1, sharedKey2) {
		t.Fatalf("Failed to derive same shared key")
	}
}

func TestSntrup4591761LegacyDecapsulate(t *testing.T) {
	kem := SNTRUP4591761()

	seed := make([]byte, 64)
	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	pubkey, privkey, err := generateSntrup4591761(seed)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ciphertext, sharedKey1, err := kem.Encapsulate(pubkey[:])
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	sharedKey2, err := kem.Decapsulate(privkey[:], ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(sharedKey1, sharedKey2) {
		t.Fatalf("Failed to derive same shared key")
	}
}

func TestX25519Sntrup4591761RoundTrip(t *testing.T) {
	kem := X25519SNTRUP4591761()

	seed := make([]byte, 64)
	_, err := rand.Read(seed)
	if err != nil {
		panic(err)
	}

	pubkey, err := kem.GenerateKey(seed)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ciphertext, sharedKey1, err := kem.Encapsulate(pubkey)
	if err != nil {
		t.Fatalf("Encapsulate: %v", err)
	}

	sharedKey2, err := kem.Decapsulate(seed, ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate: %v", err)
	}

	if !bytes.Equal(sharedKey1, sharedKey2) {
		t.Fatalf("Failed to derive same shared key")
	}
}
