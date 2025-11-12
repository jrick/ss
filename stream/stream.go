// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"runtime"

	"github.com/companyzero/sntrup4591761"
	"github.com/jrick/ss/kem"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"
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

const streamVersion = 3

const chunksize = 1 << 16 // does not include AEAD overhead

const overhead = 16 // poly1305 tag overhead

// KeyScheme describes the keying scheme used for message encryption.  It is
// recorded in the stream header, and decrypters must first parse the scheme
// from the header before deriving or recovering the encryption key.
type KeyScheme byte

// Key schemes
const (
	Sntrup4591761Scheme KeyScheme = iota + 1
	Argon2idScheme
)

func kemToScheme(k kem.KEM) (KeyScheme, error) {
	switch k {
	case kem.SNTRUP4591761():
		return Sntrup4591761Scheme, nil
	default:
		return 0, fmt.Errorf("unknown scheme for KEM %v", k)
	}
}

// Encapsulate creates the header beginning a PKI encryption stream.  It derives
// an ephemeral ChaCha20-Poly1305 symmetric key and encapsulates (encrypts) the
// key for the public key pk, recording the key ciphertext in the header.
// Cryptographically-secure randomness is read from rand.
func Encapsulate(kem kem.KEM, pubkey []byte) (header []byte, aeadKey []byte, err error) {
	// Derive and encapsulate an ephemeral shared symmetric key to encrypt a
	// message that can only be decapsulated using pk's secret key.
	sharedKeyCiphertext, sharedKeyPlaintext, err := kem.Encapsulate(pubkey)
	if err != nil {
		return
	}

	scheme, err := kemToScheme(kem)
	if err != nil {
		return
	}

	header = make([]byte, 1+len(sharedKeyCiphertext))
	header[0] = byte(scheme)
	copy(header[1:], sharedKeyCiphertext[:])

	return header, sharedKeyPlaintext, nil
}

// PassphraseHeader creates the header beginning a passphrase-protected encryption stream.
// The time and memory parameters describe Argon2id difficulty parameters, where
// memory is measured in KiB.
// Cryptographically-secure randomness is read from rand.
func PassphraseHeader(rand io.Reader, passphrase []byte, time, memory uint32) (header []byte, aeadKey []byte, err error) {
	threads := uint8(runtime.NumCPU())

	header = make([]byte, 1+16+9+overhead)
	header[0] = byte(Argon2idScheme)
	salt := header[1:17]
	htime := header[17 : 17+4]
	hmemory := header[17+4 : 17+8]
	hthreads := header[17+8 : 17+9]
	data := header[:17+9]
	htag := header[17+9:]
	// Read random salt and store to header
	_, err = io.ReadFull(rand, salt)
	if err != nil {
		return
	}
	// Write time, memory, and threads
	binary.LittleEndian.PutUint32(htime, time)
	binary.LittleEndian.PutUint32(hmemory, memory)
	hthreads[0] = threads

	// Derive a 64-byte Argon2id key from the passphrase.
	// The first 32 bytes becomes an authentication key, allowing detection of an
	// invalid passphrase during derivation from the header values, rather than
	// hitting authentication errors during stream decryption.
	// The final 32 bytes is the stream symmetric key.
	idkey := argon2.IDKey(passphrase, salt, time, memory, threads, 64)

	// Authenticate key derivation
	var tag [overhead]byte
	var polyKey [32]byte
	copy(polyKey[:], idkey[:32])
	poly1305.Sum(&tag, data, &polyKey)
	copy(htag, tag[:])

	return header, idkey[32:], nil
}

// Encrypt performs symmetric stream encryption, reading plaintext from r and
// writing an encrypted stream to w which can only be decrypted with knowledge
// of key.  The steam header is Associated Data.
func Encrypt(w io.Writer, r io.Reader, header []byte, aeadKey []byte) error {
	buf := make([]byte, 0, chunksize+overhead)
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return err
	}

	// # Protocol
	//
	// Keying Header
	// - Uniquely describes keying scheme and carries related data.
	//   Examples include sntrup4591761 encapsulation or KDF parameters.
	//
	// Version
	// - ChaCha20-Poly1305 sealed protocol version, using a zero nonce, with
	//   header as the Associated Data.
	//   Version is currently 3, and no other versions are implemented.
	//   Future versions may allow description of the chunk size or
	//
	// Blocks
	// - ChaCha20-Poly1305 chunked payloads (incrementing previous nonce)

	// Write header
	_, err = w.Write(header)
	if err != nil {
		return err
	}

	// Write sealed version
	buf = buf[:4]
	binary.LittleEndian.PutUint32(buf, streamVersion)
	nonce := newCounter()
	buf = aead.Seal(buf[:0], nonce.bytes, buf, header)
	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	// Read/write chunks
	for {
		chunk := buf[:chunksize]
		l, err := io.ReadFull(r, chunk)
		if l > 0 {
			nonce.inc()
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

// Header represents a parsed stream header.  It records the keying scheme for
// the stream symmetric key, as well as parameters needed to derive the key
// given the specific scheme.  The Bytes field records the raw bytes of the full
// header, which must be passed to Decrypt for authentication.
type Header struct {
	Bytes  []byte
	Scheme KeyScheme

	// For KEM schemes
	KEM        kem.KEM
	Ciphertext []byte

	// For Argon2idScheme
	Salt    []byte
	Time    uint32
	Memory  uint32
	Threads uint8
	Tag     [16]byte
}

// ReadHeader parses the stream header from the reader.
func ReadHeader(r io.Reader) (*Header, error) {
	var scheme [1]byte
	_, err := io.ReadFull(r, scheme[:])
	if err != nil {
		return nil, err
	}
	h := new(Header)
	h.Scheme = KeyScheme(scheme[0])

	switch h.Scheme {
	case Sntrup4591761Scheme:
		h.Bytes = make([]byte, 1+sntrup4591761.CiphertextSize)
		h.Bytes[0] = scheme[0]
		_, err = io.ReadFull(r, h.Bytes[1:])
		if err != nil {
			return nil, err
		}
		h.Ciphertext = h.Bytes[1:]
		h.KEM = kem.SNTRUP4591761()
	case Argon2idScheme:
		h.Bytes = make([]byte, 1+16+9+overhead)
		h.Bytes[0] = scheme[0]
		_, err = io.ReadFull(r, h.Bytes[1:])
		if err != nil {
			return nil, err
		}
		h.Salt = h.Bytes[1 : 1+16]
		h.Time = binary.LittleEndian.Uint32(h.Bytes[17:])
		h.Memory = binary.LittleEndian.Uint32(h.Bytes[17+4 : 17+8])
		h.Threads = h.Bytes[17+8]
		copy(h.Tag[:], h.Bytes[17+9:])
	default:
		return nil, fmt.Errorf("stream: unknown key scheme %#0x", h.Scheme)
	}
	return h, nil
}

// Decapsulate decrypts a PKI encrypted symmetric key from the header.
// The scheme must be for PKI encryption.
func Decapsulate(h *Header, seedOrPrivateKey []byte) (aeadKey []byte, err error) {
	if h.KEM == nil {
		return nil, errors.New("stream: nothing to decapsulate in header")
	}

	sharedKeyPlaintext, err := h.KEM.Decapsulate(seedOrPrivateKey, h.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("stream: cannot decapsulate message key: %w", err)
	}
	return sharedKeyPlaintext, nil
}

// PassphraseKey derives a symmetric key from a passphrase.
// The header scheme must be for symmetric passphrase encryption.
func PassphraseKey(h *Header, passphrase []byte) (aeadKey []byte, err error) {
	if h.Scheme != Argon2idScheme {
		return nil, errors.New("stream: not a symmetric passphrase encryption scheme")
	}
	idkey := argon2.IDKey(passphrase, h.Salt, h.Time, h.Memory, h.Threads, 64)

	// Authenticate key derivation
	var polyKey [32]byte
	copy(polyKey[:], idkey[:32])
	data := h.Bytes[:17+9]
	if !poly1305.Verify(&h.Tag, data, &polyKey) {
		return nil, errors.New("stream: incorrect passphrase")
	}

	return idkey[32:], nil
}

// Decrypt performs symmetric stream decryption, reading ciphertext from r,
// decrypting with key, and writing a stream of plaintext to w.  The steam
// header is Associated Data.
func Decrypt(w io.Writer, r io.Reader, header []byte, aeadKey []byte) error {
	nonce := newCounter()
	buf := make([]byte, 0, chunksize+overhead)
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return err
	}

	// Read sealed version
	buf = buf[:4+overhead]
	_, err = io.ReadFull(r, buf)
	if err != nil {
		return err
	}
	buf, err = aead.Open(buf[:0], nonce.bytes, buf, header)
	if err != nil {
		return err
	}
	if binary.LittleEndian.Uint32(buf) != streamVersion {
		return fmt.Errorf("unknown protocol version %x", buf)
	}

	for {
		chunk := buf[:chunksize+overhead]
		l, err := io.ReadFull(r, chunk)
		if l > 0 {
			var err error
			nonce.inc()
			chunk, err = aead.Open(chunk[:0], nonce.bytes, chunk[:l], nil)
			if err != nil {
				return err
			}
			_, err = w.Write(chunk)
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
