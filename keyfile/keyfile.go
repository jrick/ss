// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package keyfile

import (
	"bufio"
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strconv"
	"strings"

	"github.com/companyzero/sntrup4591761"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const saltsize = 16

// Argon2idParams describes the difficulty parameters used when deriving a
// symmetric encryption key from a passphrase using the Argon2id KDF.
type Argon2idParams struct {
	Time   uint32
	Memory uint32
}

// NewArgon2idParams creates the Argon2id parameters from time and memory
// (measured in KiB) values.
func NewArgon2idParams(time, memoryKiB uint32) *Argon2idParams {
	return &Argon2idParams{
		Time:   time,
		Memory: memoryKiB,
	}
}

// Keyfields describes keyfile fields that must be preserved when a key is
// reencrypted.
type Keyfields struct {
	Comment     string
	Fingerprint string
}

// GenerateKeys generates a random Streamlined NTRU Prime 4591^761
// public/secret key pair, writing the public key to pkw and secret key to skw.
// The secret key is encrypted with ChaCha20-Poly1305 using a symmetric key
// derived using Argon2id from passphrase and specified KDF parameters.
// Cryptographically-secure randomness is provided by rand.
func GenerateKeys(rand io.Reader, pkw, skw io.Writer, passphrase []byte, kdfp *Argon2idParams, comment string) (fingerprint string, err error) {
	// Derive secret keyfile encryption key from password using Argon2id
	salt := make([]byte, saltsize)
	_, err = rand.Read(salt)
	if err != nil {
		return "", err
	}
	ncpu := uint8(min(runtime.NumCPU(), 256))
	time := kdfp.Time
	memory := kdfp.Memory
	skKey := argon2.IDKey(passphrase, salt, time, memory, ncpu, chacha20poly1305.KeySize)

	// Generate NTRU Prime key
	pk, sk, err := sntrup4591761.GenerateKey(rand)
	if err != nil {
		return "", err
	}

	// Create fingerprint string from public key
	h := sha512.New()
	h.Write(pk[:])
	fingerprint = "sha512:" + base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Write public key
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "ss encryption public key\n")
	fmt.Fprintf(buf, "comment: %s\n", comment)
	fmt.Fprintf(buf, "cryptosystem: sntrup4591761\n")
	fmt.Fprintf(buf, "fingerprint: %s\n", fingerprint)
	fmt.Fprintf(buf, "encoding: base64\n")
	fmt.Fprintf(buf, "\n")
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	enc.Write(pk[:])
	enc.Close()
	fmt.Fprintf(buf, "\n")
	_, err = io.Copy(pkw, buf)
	if err != nil {
		return "", err
	}

	// Write secret key
	buf.Reset()
	kf := Keyfields{
		Comment:     comment,
		Fingerprint: fingerprint,
	}
	err = writeSecretKey(buf, sk, kf, skKey, salt, time, memory, ncpu)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(skw, buf)
	if err != nil {
		return "", err
	}

	return fingerprint, nil
}

func writeSecretKey(buf *bytes.Buffer, sk *SecretKey, kf Keyfields, skKey []byte, salt []byte, time, memory uint32, threads uint8) error {
	fmt.Fprintf(buf, "ss encryption secret key\n")
	fmt.Fprintf(buf, "comment: %s\n", kf.Comment)
	fmt.Fprintf(buf, "cryptosystem: sntrup4591761\n")
	fmt.Fprintf(buf, "fingerprint: %s\n", kf.Fingerprint)
	fmt.Fprintf(buf, "encryption: argon2id-chacha20-poly1305\n")
	fmt.Fprintf(buf, "argon2id-salt: %s\n", base64.StdEncoding.EncodeToString(salt))
	fmt.Fprintf(buf, "argon2id-time: %d\n", time)
	fmt.Fprintf(buf, "argon2id-memory: %d\n", memory)
	fmt.Fprintf(buf, "argon2id-threads: %d\n", threads)
	fmt.Fprintf(buf, "encoding: base64\n")
	// Everything above is Associated Data
	data := buf.Bytes()
	fmt.Fprintf(buf, "\n")
	aead, err := chacha20poly1305.New(skKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	skCiphertext := aead.Seal(nil, nonce, sk[:], data)
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	enc.Write(skCiphertext)
	enc.Close()
	fmt.Fprintf(buf, "\n")
	return nil
}

// EncryptSecretKey writes the secret key encrypted in keyfile format to skw.
func EncryptSecretKey(rand io.Reader, skw io.Writer, sk *SecretKey, passphrase []byte, kdfp *Argon2idParams, kf Keyfields) error {
	salt := make([]byte, saltsize)
	_, err := rand.Read(salt)
	if err != nil {
		return err
	}
	ncpu := uint8(min(runtime.NumCPU(), 256))
	time := kdfp.Time
	memory := kdfp.Memory
	skKey := argon2.IDKey(passphrase, salt, time, memory, ncpu, chacha20poly1305.KeySize)

	buf := new(bytes.Buffer)
	err = writeSecretKey(buf, sk, kf, skKey, salt, time, memory, ncpu)
	if err != nil {
		return err
	}
	_, err = io.Copy(skw, buf)
	return err
}

func readKeyFile(r io.Reader, firstLine string) (fields map[string]string, ad []byte, encodedKey string, err error) {
	fields = make(map[string]string)

	s := bufio.NewScanner(r)
	i := 0
	keyline := false
	adbuf := new(bytes.Buffer)
	for s.Scan() {
		line := s.Text()
		if len(line) > 0 && line[0] == '#' {
			continue
		}
		if keyline {
			encodedKey = line
			break
		}
		if i == 0 {
			if line != firstLine {
				err = fmt.Errorf("first line does not match %q", firstLine)
				return
			}
			fmt.Fprintf(adbuf, "%s\n", line)
			i++
			continue
		}
		if line == "" {
			// uncommented empty line indicates next line is the encoded key
			keyline = true
			continue
		}
		const sep = ": "
		split := strings.Index(line, sep)
		if split == -1 {
			err = errors.New("missing field separator")
			return
		}
		k, v := line[:split], line[split+len(sep):]
		if _, ok := fields[k]; ok {
			err = fmt.Errorf("duplicate field %q", k)
			return
		}
		fields[k] = v
		fmt.Fprintf(adbuf, "%s\n", line)
	}

	return fields, adbuf.Bytes(), encodedKey, nil
}

func requireFields(fields, required map[string]string) error {
	for k, v := range required {
		if fields[k] != v {
			return fmt.Errorf("keyfile field %q must be %q, but is %q", k, v, fields[k])
		}
	}
	return nil
}

// PublicKey is a type alias for a properly-sized byte array to represent a
// Streamlined NTRU Prime 4591^761 public key.
type PublicKey = [sntrup4591761.PublicKeySize]byte

// SecretKey is a type alias for a properly-sized byte array to represent a
// Streamlined NTRU Prime 4591^761 secret key.
type SecretKey = [sntrup4591761.PrivateKeySize]byte

// ReadPublicKey reads a Streamlined NTRU Prime 4591^761 public key in the
// keyfile format from r.
func ReadPublicKey(r io.Reader) (*PublicKey, error) {
	fields, _, encodedKey, err := readKeyFile(r, "ss encryption public key")
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, err
	}
	err = requireFields(fields, map[string]string{
		"cryptosystem": "sntrup4591761",
		"encoding":     "base64",
	})
	if err != nil {
		return nil, err
	}
	if len(key) != sntrup4591761.PublicKeySize {
		return nil, fmt.Errorf("public key has invalid length %d", len(key))
	}
	pk := new(PublicKey)
	copy(pk[:], key)
	return pk, nil
}

// OpenSecretKey reads and decrypts an encryted Streamlined NTRU Prime 4591^761
// secret key in the keyfile format from r.
func OpenSecretKey(r io.Reader, passphrase []byte) (_ *SecretKey, _ Keyfields, err error) {
	e := func(err error) (*SecretKey, Keyfields, error) {
		return nil, Keyfields{}, err
	}

	fields, keyAD, encodedSealedKey, err := readKeyFile(r, "ss encryption secret key")
	if err != nil {
		return
	}
	sealedKey, err := base64.StdEncoding.DecodeString(encodedSealedKey)
	if err != nil {
		return
	}
	err = requireFields(fields, map[string]string{
		"cryptosystem": "sntrup4591761",
		"encryption":   "argon2id-chacha20-poly1305",
		"encoding":     "base64",
	})
	if err != nil {
		return
	}
	salt, err := base64.StdEncoding.DecodeString(fields["argon2id-salt"])
	if err != nil {
		return
	}
	time, err := strconv.ParseUint(fields["argon2id-time"], 10, 32)
	if err != nil {
		return e(fmt.Errorf("argon2id-time: %w", err))
	}
	memory, err := strconv.ParseUint(fields["argon2id-memory"], 10, 32)
	if err != nil {
		return e(fmt.Errorf("argon2id-memory: %w", err))
	}
	ncpu, err := strconv.ParseUint(fields["argon2id-threads"], 10, 8)
	if err != nil {
		return e(fmt.Errorf("argon2id-threads: %w", err))
	}
	derivedKey := argon2.IDKey(passphrase, salt, uint32(time), uint32(memory), uint8(ncpu), chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(derivedKey)
	if err != nil {
		return
	}
	skNonce := make([]byte, aead.NonceSize())
	key, err := aead.Open(sealedKey[:0], skNonce, sealedKey, keyAD)
	if err != nil {
		return
	}
	sk := new(SecretKey)
	if len(key) != len(sk) {
		return e(fmt.Errorf("secret key has invalid length %d", len(key)))
	}
	copy(sk[:], key)
	var kf Keyfields
	kf.Comment = fields["comment"]
	kf.Fingerprint = fields["fingerprint"]
	return sk, kf, nil
}
