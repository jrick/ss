// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package kem

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/companyzero/sntrup4591761"
)

type kemSNTRUP4591761 struct{}

var _kemSNTRUP4591761 = new(kemSNTRUP4591761)

// SNTRUP4591761 returns the KEM implementation for sntrup4591761.
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
	csprng := cshake256CSPRNG(seed, []byte("ss sntrup4591761 csprng"))
	return sntrup4591761.GenerateKey(csprng)
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
