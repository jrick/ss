// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"

	ntrup "github.com/companyzero/sntrup4591761"
	"golang.org/x/crypto/chacha20poly1305"
)

// counter implements a 12-byte little endian counter suitable for use as an
// incrementing ChaCha20-Poly1305 nonce.
type counter struct {
	limbs [3]uint32
	bytes []byte
}

func newCounter() *counter {
	return &counter{bytes: make([]byte, 12)}
}

func (c *counter) inc() {
	var carry uint32
	c.limbs[0], carry = bits.Add32(c.limbs[0], 1, carry)
	c.limbs[1], carry = bits.Add32(c.limbs[1], 0, carry)
	c.limbs[2], carry = bits.Add32(c.limbs[2], 0, carry)
	if carry == 1 {
		panic("nonce reuse")
	}
	binary.LittleEndian.PutUint32(c.bytes[0:4], c.limbs[0])
	binary.LittleEndian.PutUint32(c.bytes[4:8], c.limbs[1])
	binary.LittleEndian.PutUint32(c.bytes[8:12], c.limbs[2])
}


// PublicKey is a type alias for a properly-sized byte array to represent a
// Streamlined NTRU Prime 4591^761 public key.
type PublicKey = [ntrup.PublicKeySize]byte

// SecretKey is a type alias for a properly-sized byte array to represent a
// Streamlined NTRU Prime 4591^761 secret key.
type SecretKey = [ntrup.PrivateKeySize]byte

const streamVersion = 1

const chunksize = 1 << 16 // does not include AEAD overhead

// Encrypt performs stream encryption, reading plaintext from r and writing an
// encrypted stream to w which can only be decrypted by pk's secret key.
// Cryptographically-secure randomness is provided by rand.
func Encrypt(rand io.Reader, w io.Writer, r io.Reader, pk *PublicKey) error {
	// Derive and encapsulate an ephemeral shared symmetric key to encrypt a
	// message that can only be decapsulated using pk's secret key.
	sharedKeyCiphertext, sharedKeyPlaintext, err := ntrup.Encapsulate(rand, pk)
	if err != nil {
		return err
	}
	aead, err := chacha20poly1305.New(sharedKeyPlaintext[:])
	if err != nil {
		return err
	}

	// # Protocol
	//
	// Header
	// - Protocol version (1, encoded 4 bytes little endian)
	// - NTRUP ciphertext of ChaCha20-Poly1305 key
	//
	// Blocks
	// - ChaCha20-Poly1305 chunked payloads
	//
	// A little endian counter is used as the AD for each block,
	// with stream header prepended to the counter for the first block.

	ad := make([]byte, 0, 4+len(sharedKeyCiphertext)+chacha20poly1305.NonceSize)
	header := ad[:4+len(sharedKeyCiphertext)]

	binary.LittleEndian.PutUint32(header, streamVersion)
	copy(header[4:], sharedKeyCiphertext[:])

	// Write header
	_, err = w.Write(header)
	if err != nil {
		return err
	}

	// Read/write blocks
	buf := make([]byte, chunksize)
	ad = ad[:4+len(sharedKeyCiphertext)]
	nonce := newCounter()
	for {
		l, err := io.ReadFull(r, buf)
		if l > 0 {
			ad = append(ad, nonce.bytes...)

			block := buf[:l]
			block = aead.Seal(block[:0], nonce.bytes, block, ad)
			_, err := w.Write(block)
			if err != nil {
				return err
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}

		ad = ad[:0]
		nonce.inc()
	}
}

// Decrypt performs stream decryption, reading ciphertext from r, decrypting
// with sk, and writing a stream of plaintext to w.
func Decrypt(w io.Writer, r io.Reader, sk *SecretKey) error {
	ad := make([]byte, 0, 4+ntrup.CiphertextSize+chacha20poly1305.NonceSize)
	header := ad[:4+ntrup.CiphertextSize]
	_, err := io.ReadAtLeast(r, header, len(header))
	if err != nil {
		return err
	}

	// Read header values
	proto := header[:4]
	if binary.LittleEndian.Uint32(proto) != streamVersion {
		return fmt.Errorf("unknown protocol version %x", proto)
	}
	sharedKeyCiphertext := new([ntrup.CiphertextSize]byte)
	copy(sharedKeyCiphertext[:], header[4:])

	sharedKeyPlaintext, ok := ntrup.Decapsulate(sharedKeyCiphertext, sk)
	if ok != 1 {
		return errors.New("cannot decrypt message key")
	}
	aead, err := chacha20poly1305.New(sharedKeyPlaintext[:])
	if err != nil {
		return err
	}

	buf := make([]byte, chunksize+aead.Overhead())
	ad = ad[:4+ntrup.CiphertextSize]
	nonce := newCounter()
	for {
		// Append nonce to current AD (the header for the first block, nothing for rest)
		ad = append(ad, nonce.bytes...)

		l, err := io.ReadFull(r, buf)
		if l > 0 {
			block := buf[:l]
			block, err = aead.Open(block[:0], nonce.bytes, block, ad)
			if err != nil {
				return err
			}
			_, err := w.Write(block)
			if err != nil {
				return err
			}
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
		if err != nil {
			return err
		}

		ad = ad[:0]
		nonce.inc()
	}
}
