// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package kem

import "fmt"

// SeedSize is the required byte length of seeds for GenerateKey.
const SeedSize = 64

// KeySize is the size of the shared key.
const KeySize = 32

// KEM describes the algorithms for a Key Encapsulation Mechanism (KEM) to key
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
