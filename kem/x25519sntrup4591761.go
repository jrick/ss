// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package kem

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/companyzero/sntrup4591761"
)

type kemX25519SNTRUP4591761 struct{}

var _kemX25519SNTRUP4591761 = new(kemX25519SNTRUP4591761)

// X25519SNTRUP4591761 returns the KEM implementation for sntrup4591761.
func X25519SNTRUP4591761() KEM {
	return _kemX25519SNTRUP4591761
}

func (kemX25519SNTRUP4591761) String() string {
	return "x25519-sntrup4591761"
}

func (kemX25519SNTRUP4591761) GenerateKey(seed []byte) (pubkey []byte, err error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("x25519-sntrup4591761: invalid seed length %d", len(seed))
	}

	pub, _, err := generateX25519Sntrup4591761(seed)
	if err != nil {
		return nil, err
	}
	return (*pub)[:], err
}

func (kemX25519SNTRUP4591761) Encapsulate(pubkey []byte) (ciphertext, sharedKey []byte, err error) {
	if len(pubkey) != X25519SNTRUP4591761PublicKeySize {
		return nil, nil, fmt.Errorf("x25519-sntrup4591761: invalid pubkey length %d", len(pubkey))
	}

	ct, key, err := encapX25519Sntrup4591761((*x25519SNTRUP4591761PublicKey)(pubkey))
	if err != nil {
		return nil, nil, err
	}
	return ct[:], key[:], nil
}

func (kemX25519SNTRUP4591761) Decapsulate(seed, ciphertext []byte) (sharedKey []byte, err error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("x25519-sntrup4591761: invalid seed length %d", len(seed))
	}
	if len(ciphertext) != X25519SNTRUP4591761CiphertextSize {
		return nil, fmt.Errorf("x25519-sntrup4591761: invalid ciphertext length %d", len(ciphertext))
	}

	pub, priv, err := generateX25519Sntrup4591761(seed)
	if err != nil {
		return nil, err
	}

	return decapX25519Sntrup4591761(pub, priv, (*x25519SNTRUP4591761Ciphertext)(ciphertext))
}

const (
	kdfSaltSize          = 32
	x25519PublicKeySize  = 32
	x25519PrivateKeySize = 32
)

const (
	X25519SNTRUP4591761PublicKeySize  = x25519PublicKeySize + sntrup4591761.PublicKeySize
	X25519SNTRUP4591761PrivateKeySize = x25519PrivateKeySize + sntrup4591761.PrivateKeySize
	X25519SNTRUP4591761CiphertextSize = kdfSaltSize + x25519PublicKeySize + sntrup4591761.CiphertextSize
)

type (
	x25519SNTRUP4591761PublicKey  = [X25519SNTRUP4591761PublicKeySize]byte
	x25519SNTRUP4591761PrivateKey = [X25519SNTRUP4591761PrivateKeySize]byte
	x25519SNTRUP4591761Ciphertext = [X25519SNTRUP4591761CiphertextSize]byte
)

func generateX25519Sntrup4591761(seed []byte) (*x25519SNTRUP4591761PublicKey, *x25519SNTRUP4591761PrivateKey, error) {
	x25519SubKey := kmac256KDF(seed, []byte("ss x25519-sntrup4591761 subkey x25519"), x25519PrivateKeySize)
	sntrup4591761CSPRNG := cshake256CSPRNG(seed, []byte("ss x25519-sntrup45917671 csprng sntrup4591761"))

	x25519 := ecdh.X25519()
	x25519Priv, err := x25519.NewPrivateKey(x25519SubKey)
	if err != nil {
		return nil, nil, err
	}
	x25519Pub := x25519Priv.Public().(*ecdh.PublicKey)

	sntrup4591761Pub, sntrup4591761Priv, err := sntrup4591761.GenerateKey(sntrup4591761CSPRNG)
	if err != nil {
		return nil, nil, err
	}

	combinedPub := (*x25519SNTRUP4591761PublicKey)(append(x25519Pub.Bytes(), (*sntrup4591761Pub)[:]...))
	combinedPriv := (*x25519SNTRUP4591761PrivateKey)(append(x25519Priv.Bytes(), (*sntrup4591761Priv)[:]...))
	return combinedPub, combinedPriv, nil
}

func encapX25519Sntrup4591761(pub *x25519SNTRUP4591761PublicKey) (*x25519SNTRUP4591761Ciphertext, []byte, error) {
	rPubBytes := pub[:x25519PublicKeySize]
	sntrup4591761Pub := (*sntrup4591761.PublicKey)(pub[x25519PublicKeySize:])

	// Derive ephemeral key for non-interactive X25519 KEM.
	// The shared secret is derived through X25519 of the recipient's public key and the ephemeral private key.
	// The ephemeral public key becomes the X25519 ciphertext.
	x25519 := ecdh.X25519()
	ePriv, err := x25519.GenerateKey(rand.Reader) // Non-determinism OK.
	if err != nil {
		return nil, nil, err
	}
	ePub := ePriv.Public().(*ecdh.PublicKey)
	rPub, err := x25519.NewPublicKey(rPubBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid recipient X25519 public key: %w", err)
	}
	x25519SharedKey, err := ePriv.ECDH(rPub)
	if err != nil {
		return nil, nil, err
	}

	// Perform sntrup4591761 encapsulation.
	sntrup4591761Ciphertext, sntrup4591761SharedKey, err := sntrup4591761.Encapsulate(rand.Reader, sntrup4591761Pub)
	if err != nil {
		return nil, nil, err
	}

	// Derive a salt to include in KDF customization below.
	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		panic(err)
	}

	// Concatenate salt, X25519, and sntrup4591761 ciphertexts.
	combinedCiphertext := (*x25519SNTRUP4591761Ciphertext)(append(append(salt, ePub.Bytes()...), sntrup4591761Ciphertext[:]...))

	// Combine X25519 and sntrup4591761 shared keys with KMAC-256.
	ikm := append(x25519SharedKey, sntrup4591761SharedKey[:]...)
	var info bytes.Buffer
	info.Grow(32*3 + sntrup4591761.PublicKeySize + len("ss x25519-sntrup4591761"))
	info.Write(ePub.Bytes())
	info.Write(rPubBytes)
	info.Write(sntrup4591761Pub[:])
	info.Write(salt)
	info.WriteString("ss x25519-sntrup4591761")
	combinedKey := kmac256KDF(ikm, info.Bytes(), 32)

	return combinedCiphertext, combinedKey, nil
}

func decapX25519Sntrup4591761(pub *x25519SNTRUP4591761PublicKey, priv *x25519SNTRUP4591761PrivateKey, ct *x25519SNTRUP4591761Ciphertext) ([]byte, error) {
	rPubBytes := pub[:x25519PublicKeySize]
	sntrup4591761Pub := (*sntrup4591761.PublicKey)(pub[x25519PublicKeySize:])

	rPrivBytes := priv[:x25519PrivateKeySize]
	sntrup4591761Priv := (*sntrup4591761.PrivateKey)(priv[x25519PrivateKeySize:])

	salt := ct[:kdfSaltSize]
	ePubBytes := ct[kdfSaltSize : kdfSaltSize+x25519PublicKeySize]
	sntrup4591761CT := (*sntrup4591761.Ciphertext)(ct[kdfSaltSize+x25519PublicKeySize:])

	// Derive X25519 shared key from ephemeral public key in ciphertext
	// and our recipient private key.
	x25519 := ecdh.X25519()
	ePub, err := x25519.NewPublicKey(ePubBytes)
	if err != nil {
		return nil, err
	}
	rPriv, err := x25519.NewPrivateKey(rPrivBytes)
	if err != nil {
		return nil, err
	}
	x25519SharedKey, err := rPriv.ECDH(ePub)
	if err != nil {
		return nil, err
	}

	// Perform sntrup4591761 decapsulation.
	sntrup4591761SharedKey, ok := sntrup4591761.Decapsulate(sntrup4591761CT, sntrup4591761Priv)
	if ok != 1 {
		return nil, errors.New("sntrup4591761: decapsulate failure")
	}

	// Combine X25519 and sntrup4591761 shared keys with KMAC-256.
	ikm := append(x25519SharedKey, sntrup4591761SharedKey[:]...)
	var info bytes.Buffer
	info.Grow(32*3 + sntrup4591761.PublicKeySize + len("ss x25519-sntrup4591761"))
	info.Write(ePubBytes)
	info.Write(rPubBytes)
	info.Write(sntrup4591761Pub[:])
	info.Write(salt)
	info.WriteString("ss x25519-sntrup4591761")
	key := kmac256KDF(ikm, info.Bytes(), 32)
	return key, nil
}
