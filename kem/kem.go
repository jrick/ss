// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package kem

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"errors"
	"fmt"

	"github.com/companyzero/sntrup4591761"
)

// SeedSize is the required byte length of seeds for GenerateKey.
const SeedSize = 64

// KeySize is the size of the shared key.
const KeySize = 32

// KEM describes the algorithms for a Key Encapsulation Mechanicm (KEM) to key
// the encryption stream.
type KEM interface {
	String() string

	// GenerateKey deterministically derives the KEM keypair from the seed.
	// Seeds must 64 bytes of entropy.
	GenerateKey(seed []byte) (pubkey, privkey []byte, err error)

	// Encapsulate creates a shared key and a ciphertext to be shared with
	// the recipient.
	Encapsulate(pubkey []byte) (ciphertext, sharedKey []byte, err error)

	// Decapsulate recovers the shared key created by the message sender
	// from the ciphertext.
	//
	// The shared key will always be 32-bytes long and suitable to use to
	// key an AEAD.
	Decapsulate(pubkey, privkey, ciphertext []byte) (sharedKey []byte, err error)
}

type kemSNTRUP4591761 struct{}

// NewSNTRUP4591761 returns a KEM implementation for sntrup4591761.
func NewSNTRUP4591761() KEM {
	return new(kemSNTRUP4591761)
}

func (kemSNTRUP4591761) String() string {
	return "sntrup4591761"
}

func (kemSNTRUP4591761) GenerateKey(seed []byte) (pubkey, privkey []byte, err error) {
	if len(seed) != SeedSize {
		return nil, nil, fmt.Errorf("sntrup4591761: invalid seed length")
	}

	pub, priv, err := generateSntrup4591761(seed)
	if err != nil {
		return nil, nil, err
	}
	return (*pub)[:], (*priv)[:], err
}

func (kemSNTRUP4591761) Encapsulate(pubkey []byte) (ciphertext, sharedKey []byte, err error) {
	if len(pubkey) != sntrup4591761.PublicKeySize {
		return nil, nil, fmt.Errorf("sntrup4591761: invalid pubkey length")
	}

	ct, key, err := encapSntrup4591761((*sntrup4591761.PublicKey)(pubkey))
	if err != nil {
		return nil, nil, err
	}
	return ct[:], key[:], nil
}

func (kemSNTRUP4591761) Decapsulate(_, privkey, ciphertext []byte) (sharedKey []byte, err error) {
	// Note: pubkey is unused.  There is no HKDF call during decapsulate
	// to use the pubkey as additional info.
	if len(privkey) != sntrup4591761.PrivateKeySize {
		return nil, fmt.Errorf("sntrup4591761: invalid privkey length %d", len(privkey))
	}
	if len(ciphertext) != sntrup4591761.CiphertextSize {
		return nil, fmt.Errorf("sntrup4591761: invalid ciphertext length %d", len(ciphertext))
	}

	return decapSntrup4591761(nil, (*sntrup4591761.PrivateKey)(privkey), (*sntrup4591761.Ciphertext)(ciphertext))
}

func generateSntrup4591761(seed []byte) (*sntrup4591761.PublicKey, *sntrup4591761.PrivateKey, error) {
	sntrup4591761SubKey, err := hkdf.Key(sha256.New, seed, nil, "ss sntrup4591761 subkey", 32)
	if err != nil {
		return nil, nil, err
	}

	sntrup4591761PRG := sha3.NewSHAKE256()
	_, err = sntrup4591761PRG.Write(sntrup4591761SubKey)
	if err != nil {
		return nil, nil, err
	}

	return sntrup4591761.GenerateKey(sntrup4591761PRG)
}

func encapSntrup4591761(pk *sntrup4591761.PublicKey) (*sntrup4591761.Ciphertext, []byte, error) {
	ct, sharedKey, err := sntrup4591761.Encapsulate(rand.Reader, pk)
	return ct, (*sharedKey)[:], err
}

func decapSntrup4591761(_ *sntrup4591761.PublicKey, priv *sntrup4591761.PrivateKey, ct *sntrup4591761.Ciphertext) ([]byte, error) {
	sharedKey, ok := sntrup4591761.Decapsulate(ct, priv)
	if ok != 1 {
		return nil, errors.New("sntrup4591761: decapsulate failure")
	}
	return (*sharedKey)[:], nil
}
