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

const streamVersion = 2

const chunksize = 1 << 16 // does not include AEAD overhead

const overhead = 16 // poly1305 tag overhead

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

	nonce := newCounter()
	buf := make([]byte, 0, chunksize+overhead)
	aead, err := chacha20poly1305.New(sharedKeyPlaintext[:])
	if err != nil {
		return err
	}

	// # Protocol
	//
	// Key Exchange
	// - SNTRUP 4591^761 encapsulated ChaCha20-Poly1305 key
	//
	// Version negotiation
	// - ChaCha20-Poly1305 sealed protocol version (4 bytes little endian),
	//   using zero nonce and encapsulated key ciphertext as Associated Data.
	//   Version is currently 2, and no other versions are implemented.
	//
	// Blocks
	// - ChaCha20-Poly1305 chunked payloads (incrementing previous nonce)
	//
	// A little endian counter is used as the AD for each block,
	// with stream header prepended to the counter for the first block.

	// Write encapsulated key
	_, err = w.Write(sharedKeyCiphertext[:])
	if err != nil {
		return err
	}

	// Write sealed version
	buf = buf[:4]
	binary.LittleEndian.PutUint32(buf, streamVersion)
	buf = aead.Seal(buf[:0], nonce.bytes, buf, sharedKeyCiphertext[:])
	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	// Read/write chunks
	for {
		nonce.inc()

		chunk := buf[:chunksize]
		l, err := io.ReadFull(r, chunk)
		if l > 0 {
			chunk = aead.Seal(chunk[:0], nonce.bytes, chunk[:l], nil)
			_, err := w.Write(chunk)
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
	}
}

// Decrypt performs stream decryption, reading ciphertext from r, decrypting
// with sk, and writing a stream of plaintext to w.
func Decrypt(w io.Writer, r io.Reader, sk *SecretKey) error {
	sharedKeyCiphertext := new([ntrup.CiphertextSize]byte)
	_, err := io.ReadFull(r, sharedKeyCiphertext[:])
	if err != nil {
		return err
	}
	sharedKeyPlaintext, ok := ntrup.Decapsulate(sharedKeyCiphertext, sk)
	if ok != 1 {
		return errors.New("cannot decrypt message key")
	}

	nonce := newCounter()
	buf := make([]byte, 0, chunksize+overhead)
	aead, err := chacha20poly1305.New(sharedKeyPlaintext[:])
	if err != nil {
		return err
	}

	// Read sealed version
	buf = buf[:4+overhead]
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	buf, err = aead.Open(buf[:0], nonce.bytes, buf, sharedKeyCiphertext[:])
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(buf) != streamVersion {
		return fmt.Errorf("unknown protocol version %x", buf)
	}

	for {
		nonce.inc()

		chunk := buf[:chunksize+overhead]
		l, err := io.ReadFull(r, chunk)
		if l > 0 {
			chunk, err = aead.Open(chunk[:0], nonce.bytes, chunk[:l], nil)
			if err != nil {
				return err
			}
			_, err := w.Write(chunk)
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
	}
}
