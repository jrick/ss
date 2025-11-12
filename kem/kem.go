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

	// GenerateKey deterministically derives the KEM public key from the seed.
	// Seeds must provide 64 bytes of entropy.
	// The serialized private key is never exposed by this interface.
	GenerateKey(seed []byte) (pubkey []byte, err error)

	// Encapsulate creates a shared key and a ciphertext to be shared with
	// the recipient.
	Encapsulate(pubkey []byte) (ciphertext, sharedKey []byte, err error)

	// Decapsulate recovers the shared key created by the message sender
	// from the ciphertext.
	//
	// If seed not SeedSize, but is instead the size of the KEM's
	// serialized private key, for legacy compatibility, the seed
	// parameter will be interpreted as the private key rather than
	// generating the private key from the seed.  Only the sntrup4591761
	// KEM supports this legacy behavior due to existing keyfiles that
	// contain private keys.
	//
	// The shared key will always be 32-bytes long and suitable to use to
	// key an AEAD.
	Decapsulate(seed, ciphertext []byte) (sharedKey []byte, err error)
}

// Open returns the KEM instance for a cryptosystem name.
func Open(name string) (KEM, error) {
	switch name {
	case _kemSNTRUP4591761.String():
		return _kemSNTRUP4591761, nil
	default:
		return nil, fmt.Errorf("unknown KEM %q", name)
	}
}

type kemSNTRUP4591761 struct{}

var _kemSNTRUP4591761 = new(kemSNTRUP4591761)

// SNTRUP4591761 returns a KEM implementation for sntrup4591761.
func SNTRUP4591761() KEM {
	return _kemSNTRUP4591761
}

func (kemSNTRUP4591761) String() string {
	return "sntrup4591761"
}

func (kemSNTRUP4591761) GenerateKey(seed []byte) (pubkey []byte, err error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("sntrup4591761: invalid seed length")
	}

	pub, _, err := generateSntrup4591761(seed)
	if err != nil {
		return nil, err
	}
	return (*pub)[:], err
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

func (kemSNTRUP4591761) Decapsulate(seed, ciphertext []byte) (sharedKey []byte, err error) {
	var privkey *sntrup4591761.PrivateKey
	switch len(seed) {
	case SeedSize:
		_, privkey, err = generateSntrup4591761(seed)
		if err != nil {
			return nil, err
		}
	case sntrup4591761.PrivateKeySize:
		privkey = (*sntrup4591761.PrivateKey)(seed)
	default:
		return nil, fmt.Errorf("sntrup4591761: invalid privkey length %d", len(privkey))
	}
	if len(ciphertext) != sntrup4591761.CiphertextSize {
		return nil, fmt.Errorf("sntrup4591761: invalid ciphertext length %d", len(ciphertext))
	}

	return decapSntrup4591761(nil, privkey, (*sntrup4591761.Ciphertext)(ciphertext))
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
