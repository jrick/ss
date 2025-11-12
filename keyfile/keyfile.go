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

	"github.com/jrick/ss/kem"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const saltsize = 16

// Argon2idParams describes the difficulty parameters used when deriving a
// symmetric encryption key from a passphrase using the Argon2id KDF.
type Argon2idParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// NewArgon2idParams creates the Argon2id parameters from time and memory
// (measured in KiB) values.
func NewArgon2idParams(time, memoryKiB uint32) *Argon2idParams {
	return &Argon2idParams{
		Time:    time,
		Memory:  memoryKiB,
		Threads: uint8(min(runtime.NumCPU(), 256)),
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
func GenerateKeys(rand io.Reader, pkw, skw io.Writer, kem kem.KEM, passphrase []byte, kdfp *Argon2idParams, comment string) (fingerprint string, err error) {
	// Derive secret keyfile encryption key from password using Argon2id
	salt := make([]byte, saltsize)
	_, err = rand.Read(salt)
	if err != nil {
		return "", err
	}
	time := kdfp.Time
	memory := kdfp.Memory
	threads := kdfp.Threads
	aeadKey := argon2.IDKey(passphrase, salt, time, memory, threads, chacha20poly1305.KeySize)

	// Generate keys
	seed := make([]byte, 64)
	_, err = rand.Read(seed)
	if err != nil {
		return "", err
	}
	pk, err := kem.GenerateKey(seed)
	if err != nil {
		return "", err
	}

	// Create fingerprint string from public key
	h := sha512.New()
	h.Write(pk)
	fingerprint = "sha512:" + base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Write public key
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "ss encryption public key\n")
	fmt.Fprintf(buf, "comment: %s\n", comment)
	fmt.Fprintf(buf, "cryptosystem: %v\n", kem)
	fmt.Fprintf(buf, "fingerprint: %s\n", fingerprint)
	fmt.Fprintf(buf, "encoding: base64\n")
	fmt.Fprintf(buf, "\n")
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	enc.Write(pk)
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
	err = writeSecretKey(kem.String(), buf, seed, kf, aeadKey, salt, time, memory, threads)
	if err != nil {
		return "", err
	}
	_, err = io.Copy(skw, buf)
	if err != nil {
		return "", err
	}

	return fingerprint, nil
}

func writeSecretKey(kemName string, buf *bytes.Buffer, seed []byte, kf Keyfields, aeadKey []byte,
	salt []byte, time, memory uint32, threads uint8) error {
	fmt.Fprintf(buf, "ss encryption secret key\n")
	fmt.Fprintf(buf, "comment: %s\n", kf.Comment)
	fmt.Fprintf(buf, "cryptosystem: %v\n", kemName)
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
	aead, err := chacha20poly1305.New(aeadKey)
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	seedCiphertext := aead.Seal(nil, nonce, seed, data)
	enc := base64.NewEncoder(base64.StdEncoding, buf)
	enc.Write(seedCiphertext)
	enc.Close()
	fmt.Fprintf(buf, "\n")
	return nil
}

// EncryptSecretKey writes the secret key encrypted in keyfile format to skw.
func EncryptSecretKey(rand io.Reader, skw io.Writer, kem kem.KEM, sk []byte, passphrase []byte, kdfp *Argon2idParams, kf Keyfields) error {
	salt := make([]byte, saltsize)
	_, err := rand.Read(salt)
	if err != nil {
		return err
	}
	time := kdfp.Time
	memory := kdfp.Memory
	threads := uint8(min(runtime.NumCPU(), 256))
	skKey := argon2.IDKey(passphrase, salt, time, memory, threads, chacha20poly1305.KeySize)

	buf := new(bytes.Buffer)
	err = writeSecretKey(kem.String(), buf, sk, kf, skKey, salt, time, memory, threads)
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

// ReadPublicKey reads a KEM public key in the keyfile format from r.
func ReadPublicKey(r io.Reader) (kem.KEM, []byte, error) {
	fields, _, encodedKey, err := readKeyFile(r, "ss encryption public key")
	if err != nil {
		return nil, nil, err
	}
	key, err := base64.StdEncoding.DecodeString(encodedKey)
	if err != nil {
		return nil, nil, err
	}
	err = requireFields(fields, map[string]string{
		"encoding": "base64",
	})
	if err != nil {
		return nil, nil, err
	}
	kem, err := kem.Open(fields["cryptosystem"])
	if err != nil {
		return nil, nil, err
	}
	return kem, key, nil
}

// OpenSecretKey reads and decrypts an encrypted KEM seed or secret key in the
// keyfile format from r.
func OpenSecretKey(r io.Reader, passphrase []byte) (kem.KEM, []byte, Keyfields, error) {
	e := func(err error) (kem.KEM, []byte, Keyfields, error) {
		return nil, nil, Keyfields{}, err
	}

	fields, keyAD, encodedSealedKey, err := readKeyFile(r, "ss encryption secret key")
	if err != nil {
		return e(err)
	}
	sealedKey, err := base64.StdEncoding.DecodeString(encodedSealedKey)
	if err != nil {
		return e(err)
	}
	err = requireFields(fields, map[string]string{
		"encryption": "argon2id-chacha20-poly1305",
		"encoding":   "base64",
	})
	if err != nil {
		return e(err)
	}
	kem, err := kem.Open(fields["cryptosystem"])
	if err != nil {
		return e(err)
	}
	salt, err := base64.StdEncoding.DecodeString(fields["argon2id-salt"])
	if err != nil {
		return e(err)
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
		return e(err)
	}
	skNonce := make([]byte, aead.NonceSize())
	sk, err := aead.Open(sealedKey[:0], skNonce, sealedKey, keyAD)
	if err != nil {
		return e(err)
	}
	var kf Keyfields
	kf.Comment = fields["comment"]
	kf.Fingerprint = fields["fingerprint"]
	return kem, sk, kf, nil
}
