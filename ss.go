// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/jrick/ss/kem"
	"github.com/jrick/ss/keyfile"
	"github.com/jrick/ss/stream"
	"golang.org/x/term"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage of %s:
  %[1]s keygen [-i id] [-C cryptosystem] [-t time] [-m memory (MiB)] [-c comment]
  %[1]s chpass [-i id] [-t time] [-m memory (MiB)]
  %[1]s encrypt [-i id|pubkey] [-in input] [-out output]
  %[1]s encrypt -passphrase [-in input] [-out output] [-t time] [-m memory (MiB)]
  %[1]s decrypt [-i id] [-in input] [-out output]
`, filepath.Base(os.Args[0]))
	os.Exit(2)
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format, args...)
	os.Exit(1)
}

func init() {
	flag.Usage = usage
}

var appdir string

func main() {
	err := pledge("stdio rpath wpath cpath getpw tty unveil")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	appdir = func() string {
		u, err := user.Current()
		if err != nil {
			logf("appdir: %v\n", err)
			return "."
		}
		if u.HomeDir == "" {
			logf("appdir: user homedir is unknown\n")
			return "."
		}
		dir := filepath.Join(u.HomeDir, ".ss")
		err = unveil(dir, "rwc")
		if err != nil {
			fatalf("unveil %v: %v\n", dir, err)
		}
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err = os.Mkdir(dir, 0700)
			if err != nil {
				fatalf("%v\n", err)
			}
		}
		return dir
	}()
	if appdir == "." {
		err = unveil(appdir, "rwc")
		if err != nil {
			fatalf("unveil %v: %v\n", appdir, err)
		}
	}

	err = pledge("stdio rpath wpath cpath tty unveil")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	flag.Parse()          // for -h usage
	if len(os.Args) < 2 { // one command is required
		usage()
	}
	switch os.Args[1] {
	case "keygen":
		fs := new(keygenFlags).parse(os.Args[2:])
		err = keygen(fs)
	case "chpass":
		fs := new(chpassFlags).parse(os.Args[2:])
		err = chpass(fs)
	case "encrypt":
		fs := new(encryptFlags).parse(os.Args[2:])
		encrypt(fs)
	case "decrypt":
		fs := new(decryptFlags).parse(os.Args[2:])
		decrypt(fs)
	default:
		fmt.Fprintf(os.Stderr, "no command %q\n", os.Args[1])
		usage()
	}
	if err != nil {
		fatalf("%v\n", err)
	}
}

type keygenFlags struct {
	identity     string
	cryptosystem string
	time         uint
	memory       uint
	force        bool
	comment      string
}

const (
	defaultID           = "id"
	defaultCryptosystem = "x25519-sntrup4591761"
	defaultTime         = 3
	defaultMemory       = 1024 + 256
)

func (f *keygenFlags) parse(args []string) *keygenFlags {
	fs := flag.NewFlagSet("ss keygen", flag.ExitOnError)
	fs.StringVar(&f.identity, "i", defaultID, "identity name")
	fs.StringVar(&f.cryptosystem, "C", defaultCryptosystem, "cryptosystem")
	fs.UintVar(&f.time, "t", defaultTime, "Argon2id time")
	fs.UintVar(&f.memory, "m", defaultMemory, "Argon2id memory (MiB)")
	fs.BoolVar(&f.force, "f", false, "force Argon2id key derivation despite low parameters")
	fs.StringVar(&f.comment, "c", "", "comment")
	fs.Parse(args)
	return f
}

func openTTY() (*os.File, error) {
	return os.OpenFile("/dev/tty", os.O_RDWR, 0)
}

func promptPassphrase(tty *os.File, prompt string) ([]byte, error) {
	_, err := fmt.Fprintf(tty, "%s: ", prompt)
	if err != nil {
		return nil, err
	}
	passphrase, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return passphrase, err
}

func keygen(fs *keygenFlags) (err error) {
	err = unveil("/dev/tty", "rw")
	if err != nil {
		fatalf("unveil /dev/tty: %v\n", err)
	}
	unveilBlock()

	tty, err := openTTY()
	if err != nil {
		fatalf("%v\n", err)
	}
	defer tty.Close()

	id := fs.identity
	kem, err := kem.Open(fs.cryptosystem)
	if err != nil {
		return fmt.Errorf("unknown cryptosystem %q", fs.cryptosystem)
	}
	pkFilename := filepath.Join(appdir, id+".public")
	skFilename := filepath.Join(appdir, id+".secret")
	if fi, err := os.Stat(pkFilename); !os.IsNotExist(err) && fi.Size() != 0 {
		return fmt.Errorf("%q keys already exist in %s", id, appdir)
	}
	if fi, err := os.Stat(skFilename); !os.IsNotExist(err) && fi.Size() != 0 {
		return fmt.Errorf("%q keys already exist in %s", id, appdir)
	}

	pkFile, err := os.OpenFile(pkFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer pkFile.Close()
	skFile, err := os.OpenFile(skFilename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer skFile.Close()

	// Drop "rpath wpath cpath"
	err = pledge("stdio tty")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	time := uint32(fs.time)
	memory := uint32(fs.memory)
	if memory < defaultMemory {
		logf("warning: recommended Argon2id memory parameter is %d MiB\n",
			defaultMemory)
		if !fs.force {
			return errors.New("choose stronger parameters, use defaults, or force with -f")
		}
	}

	prompt := fmt.Sprintf("Key passphrase for %s", skFilename)
	passphrase, err := promptPassphrase(tty, prompt)
	if err != nil {
		return err
	}
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
	}
	prompt += " (again)"
	passphraseAgain, err := promptPassphrase(tty, prompt)
	if err != nil {
		return err
	}

	// Drop "tty"
	err = pledge("stdio")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	if !bytes.Equal(passphrase, passphraseAgain) {
		return errors.New("passphrases do not match")
	}

	kdfp := keyfile.NewArgon2idParams(time, memory*1024)
	fp, err := keyfile.GenerateKeys(rand.Reader, pkFile, skFile, kem, passphrase, kdfp, fs.comment)
	if err != nil {
		return err
	}
	logf("created %v\n", pkFilename)
	logf("created %v\n", skFilename)
	logf("fingerprint: %s\n", fp)
	return nil
}

type chpassFlags struct {
	identity string
	time     uint
	memory   uint
	force    bool
}

func (f *chpassFlags) parse(args []string) *chpassFlags {
	fs := flag.NewFlagSet("ss chpass", flag.ExitOnError)
	fs.StringVar(&f.identity, "i", defaultID, "identity name")
	fs.UintVar(&f.time, "t", defaultTime, "Argon2id time")
	fs.UintVar(&f.memory, "m", defaultMemory, "Argon2id memory (MiB)")
	fs.BoolVar(&f.force, "f", false, "force Argon2id key derivation despite low parameters")
	fs.Parse(args)
	return f
}

func chpass(fs *chpassFlags) error {
	err := unveil("/dev/tty", "rw")
	if err != nil {
		fatalf("unveil /dev/tty: %v\n", err)
	}
	unveilBlock()

	tty, err := openTTY()
	if err != nil {
		fatalf("%v\n", err)
	}
	defer tty.Close()

	id := fs.identity
	skFilename := filepath.Join(appdir, id+".secret")
	if _, err := os.Stat(skFilename); os.IsNotExist(err) {
		return fmt.Errorf("%q not found", skFilename)
	}
	skFile, err := os.Open(skFilename)
	if err != nil {
		fatalf("%v\n", err)
	}
	tmpDir, tmpBasename := filepath.Split(skFilename)
	tmpFi, err := os.CreateTemp(tmpDir, tmpBasename)
	if err != nil {
		return err
	}
	tmpFiName := tmpFi.Name()

	err = pledge("stdio rpath cpath tty")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	time := uint32(fs.time)
	memory := uint32(fs.memory)
	if memory < defaultMemory {
		logf("warning: recommended Argon2id memory parameter is %d MiB\n",
			defaultMemory)
		if !fs.force {
			return errors.New("choose stronger parameters, use defaults, or force with -f")
		}
	}

	prompt := fmt.Sprintf("Current passphrase for %s", skFilename)
	passphrase, err := promptPassphrase(tty, prompt)
	if err != nil {
		return err
	}
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
	}

	kem, sk, kf, err := keyfile.OpenSecretKey(skFile, passphrase)
	if err != nil {
		logf("%s: %v\n", skFilename, err)
		fatalf("The secret keyfile cannot be opened.  " +
			"This may be due to keyfile tampering or an incorrect passphrase.\n")
	}
	skFile.Close()

	prompt = "New passphrase"
	passphrase, err = promptPassphrase(tty, prompt)
	if err != nil {
		return err
	}
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
	}
	prompt += " (again)"
	passphraseAgain, err := promptPassphrase(tty, prompt)
	if err != nil {
		return err
	}
	if !bytes.Equal(passphrase, passphraseAgain) {
		return errors.New("passphrases do not match")
	}

	// Drop "tty"
	// rpath necessary for os.Lstat performed by os.Rename
	err = pledge("stdio rpath cpath")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	kdfp := keyfile.NewArgon2idParams(time, memory*1024)
	err = keyfile.EncryptSecretKey(rand.Reader, tmpFi, kem, sk, passphrase, kdfp, kf)
	if err != nil {
		return err
	}
	tmpFi.Close()
	err = os.Rename(tmpFiName, skFilename)
	if err != nil {
		return err
	}
	logf("rewrote %v\n", skFilename)
	return nil
}

type encryptFlags struct {
	passphrase bool
	time       uint
	memory     uint
	force      bool
	id         string
	in         string
	out        string
	usage      func()
}

func (f *encryptFlags) parse(args []string) *encryptFlags {
	fs := flag.NewFlagSet("ss encrypt", flag.ExitOnError)
	fs.StringVar(&f.id, "i", defaultID, "identity")
	fs.BoolVar(&f.passphrase, "passphrase", false, "secure via passphrase (no PKI)")
	fs.UintVar(&f.time, "t", defaultTime, "Argon2id time (used with -passphrase)")
	fs.UintVar(&f.memory, "m", defaultMemory, "Argon2id memory (MiB; used with -passphrase)")
	fs.BoolVar(&f.force, "f", false, "force Argon2id key derivation despite low parameters")
	fs.StringVar(&f.in, "in", "", "input file")
	fs.StringVar(&f.out, "out", "", "output file")
	fs.Parse(args)
	f.usage = fs.Usage
	return f
}

func stdio(outFlag, inFlag string) (io.Writer, io.Reader) {
	out := os.Stdout
	in := os.Stdin
	var err error
	if outFlag != "" && outFlag != "-" {
		err = unveil(outFlag, "rwc")
		if err != nil {
			fatalf("unveil %v rwc: %v\n", outFlag, err)
		}
		out, err = os.Create(outFlag)
		if err != nil {
			fatalf("%v\n", err)
		}
		err = unveil(outFlag, "w")
		if err != nil {
			fatalf("unveil %v w: %v\n", outFlag, err)
		}
	}
	if inFlag != "" && inFlag != "-" {
		err = unveil(inFlag, "r")
		if err != nil {
			fatalf("unveil %v: %v\n", inFlag, err)
		}
		in, err = os.Open(inFlag)
		if err != nil {
			fatalf("%v\n", err)
		}
	}
	return out, in
}

func encrypt(fs *encryptFlags) {
	if appdir != "." {
		err := unveil(appdir, "r")
		if err != nil {
			fatalf("unveil %v: %v\n", appdir, err)
		}
	}

	out, in := stdio(fs.out, fs.in)
	switch out := out.(type) {
	case interface{ Fd() uintptr }: // implemented by *os.File
		if term.IsTerminal(int(out.Fd())) {
			logf("output file is a terminal\n")
			logf("use shell redirection or set -out flag to a filename\n")
			fs.usage()
			os.Exit(2)
		}
	}

	if fs.passphrase {
		encryptPassphrase(fs, out, in)
		return
	}

	err := pledge("stdio rpath unveil")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	// Read identity's public key
	pkFilename := fs.id
	if !strings.HasSuffix(pkFilename, ".public") {
		pkFilename = filepath.Join(appdir, fs.id+".public")
		err = unveil(appdir, "")
		if err != nil {
			fatalf("unveil %v: %v\n", appdir, err)
		}
	}
	err = unveil(pkFilename, "r")
	if err != nil {
		fatalf("unveil %v: %v\n", pkFilename, err)
	}
	err = pledge("stdio rpath")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}
	if _, err := os.Stat(pkFilename); os.IsNotExist(err) {
		logf("%s does not exist\n", pkFilename)
		fatalf("use '-i' flag to choose another identity or generate default " +
			"keys with 'ss keygen'\n")
	}
	pkFile, err := os.Open(pkFilename)
	if err != nil {
		fatalf("%v\n", err)
	}
	err = pledge("stdio")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}
	kem, pk, err := keyfile.ReadPublicKey(pkFile)
	if err != nil {
		fatalf("%s: %v\n", pkFilename, err)
	}

	header, key, err := stream.Encapsulate(kem, pk)
	if err != nil {
		fatalf("%v\n", err)
	}

	err = stream.Encrypt(out, in, header, key)
	if err != nil {
		fatalf("%v\n", err)
	}
}

func encryptPassphrase(fs *encryptFlags, out io.Writer, in io.Reader) {
	err := unveil("/dev/tty", "rw")
	if err != nil {
		fatalf("unveil /dev/tty: %v\n", err)
	}
	err = pledge("stdio rpath wpath tty")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	tty, err := openTTY()
	if err != nil {
		fatalf("%v\n", err)
	}

	err = pledge("stdio tty")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	time := uint32(fs.time)
	memory := uint32(fs.memory)
	if memory < defaultMemory {
		logf("warning: recommended Argon2id memory parameter is %d MiB\n",
			defaultMemory)
		if !fs.force {
			fatalf("choose stronger parameters, use defaults, or force with -f\n")
		}
	}
	memory *= 1024

	passphrase, err := promptPassphrase(tty, "Encryption passphrase")
	if err != nil {
		fatalf("%v\n", err)
	}
	passphraseAgain, err := promptPassphrase(tty, "Encryption passphrase (again)")
	if err != nil {
		fatalf("%v\n", err)
	}
	err = pledge("stdio")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}
	if !bytes.Equal(passphrase, passphraseAgain) {
		logf("passphrases do not match\n")
	}

	header, key, err := stream.PassphraseHeader(rand.Reader, passphrase, time, memory)
	if err != nil {
		fatalf("%v\n", err)
	}

	err = stream.Encrypt(out, in, header, key)
	if err != nil {
		fatalf("%v\n", err)
	}
}

type decryptFlags struct {
	id  string
	in  string
	out string
}

func (f *decryptFlags) parse(args []string) *decryptFlags {
	fs := flag.NewFlagSet("ss decrypt", flag.ExitOnError)
	fs.StringVar(&f.id, "i", defaultID, "identity")
	fs.StringVar(&f.in, "in", "", "input file")
	fs.StringVar(&f.out, "out", "", "output file")
	fs.Parse(args)
	return f
}

func decrypt(fs *decryptFlags) {
	if appdir != "." {
		err := unveil(appdir, "r")
		if err != nil {
			fatalf("unveil: %v\n", err)
		}
	}
	err := unveil("/dev/tty", "rw")
	if err != nil {
		fatalf("unveil /dev/tty: %v\n", err)
	}

	out, in := stdio(fs.out, fs.in)
	unveilBlock()

	tty, err := openTTY()
	if err != nil {
		fatalf("%v\n", err)
	}

	skFilename := filepath.Join(appdir, fs.id+".secret")
	skFile, skOpenErr := os.Open(skFilename)

	// Drop "rpath wpath cpath"
	err = pledge("stdio tty")
	if err != nil {
		fatalf("pledge: %v\n", err)
	}

	var aeadKey []byte
	header, err := stream.ReadHeader(in)
	if err != nil {
		fatalf("%v\n", err)
	}
	switch header.Scheme {
	case stream.Sntrup4591761Scheme, stream.X25519Sntrup4591761Scheme:
		if skOpenErr != nil {
			fatalf("%v\n", skOpenErr)
		}

		// Read and decrypt secret key
		passphrase, err := promptPassphrase(tty, fmt.Sprintf("Key passphrase for %s", skFilename))
		if err != nil {
			fatalf("%v\n", err)
		}

		// Drop "tty"
		err = pledge("stdio")
		if err != nil {
			fatalf("pledge: %v\n", err)
		}

		kem, sk, _, err := keyfile.OpenSecretKey(skFile, passphrase)
		if err != nil {
			logf("%s: %v\n", skFilename, err)
			fatalf("The secret keyfile cannot be opened.  " +
				"This may be due to keyfile tampering or an incorrect passphrase.\n")
		}
		if kem != header.KEM {
			fatalf("KEM mismatch between encrypted stream (%v) and keyfile (%v).  "+
				"Use -i to select other identity keyfiles.\n", header.KEM, kem)
		}
		aeadKey, err = stream.Decapsulate(header, sk)
		if err != nil {
			fatalf("%v\n", err)
		}
	case stream.Argon2idScheme:
		passphrase, err := promptPassphrase(tty, "Decryption passphrase")
		if err != nil {
			fatalf("%v\n", err)
		}

		// Drop "tty"
		err = pledge("stdio")
		if err != nil {
			fatalf("pledge: %v\n", err)
		}

		aeadKey, err = stream.PassphraseKey(header, passphrase)
		if err != nil {
			fatalf("%v\n", err)
		}
	default:
		fatalf("Unknown encryption scheme '%d'\n", header.Scheme)
	}

	err = stream.Decrypt(out, in, header.Bytes, aeadKey)
	if err != nil {
		fatalf("%v\n", err)
	}
}
