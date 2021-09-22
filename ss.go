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
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/jrick/ss/keyfile"
	"github.com/jrick/ss/stream"
	"golang.org/x/crypto/ssh/terminal"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage of %s:
  %[1]s keygen [-i id] [-t time] [-m memory (MiB)] [-c comment]
  %[1]s chpass [-i id] [-t time] [-m memory (MiB)]
  %[1]s encrypt [-i id|pubkey] [-in input] [-out output]
  %[1]s encrypt -passphrase [-in input] [-out output] [-t time] [-m memory (MiB)]
  %[1]s decrypt [-i id] [-in input] [-out output]
`, filepath.Base(os.Args[0]))
	os.Exit(2)
}

func init() {
	flag.Usage = usage
}

func main() {
	err := pledge("stdio rpath wpath cpath getpw tty")
	if err != nil {
		log.Fatalf("pledge: %v", err)
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
		log.Fatal(err)
	}
}

type keygenFlags struct {
	identity string
	time     uint
	memory   uint
	force    bool
	comment  string
}

const (
	defaultID     = "id"
	defaultTime   = 1
	defaultMemory = 64
)

func (f *keygenFlags) parse(args []string) *keygenFlags {
	fs := flag.NewFlagSet("ss keygen", flag.ExitOnError)
	fs.StringVar(&f.identity, "i", defaultID, "identity name")
	fs.UintVar(&f.time, "t", defaultTime, "Argon2id time")
	fs.UintVar(&f.memory, "m", defaultMemory, "Argon2id memory (MiB)")
	fs.BoolVar(&f.force, "f", false, "force Argon2id key derivation despite low parameters")
	fs.StringVar(&f.comment, "c", "", "comment")
	fs.Parse(args)
	return f
}

func promptPassphrase(prompt string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	defer tty.Close()
	_, err = fmt.Fprintf(tty, "%s: ", prompt)
	if err != nil {
		panic(err)
	}
	passphrase, err := terminal.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return passphrase, err
}

func appdir() string {
	u, err := user.Current()
	if err != nil {
		log.Printf("appdir: %v", err)
		return ""
	}
	if u.HomeDir == "" {
		log.Printf("appdir: user homedir is unknown")
		return ""
	}
	dir := filepath.Join(u.HomeDir, ".ss")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			log.Fatal(err)
		}
	}
	return dir
}

func keygen(fs *keygenFlags) (err error) {
	id := fs.identity
	appdir := appdir()
	pkFilename := filepath.Join(appdir, id+".public")
	skFilename := filepath.Join(appdir, id+".secret")
	if _, err := os.Stat(pkFilename); !os.IsNotExist(err) {
		return fmt.Errorf("%q keys already exist in %s", id, appdir)
	}
	if _, err := os.Stat(skFilename); !os.IsNotExist(err) {
		return fmt.Errorf("%q keys already exist in %s", id, appdir)
	}
	defer func() {
		if err != nil {
			os.Remove(pkFilename)
			os.Remove(skFilename)
		}
	}()

	time := uint32(fs.time)
	memory := uint32(fs.memory)
	if memory < defaultMemory {
		log.Printf("warning: recommended Argon2id memory parameter is %d MiB",
			defaultMemory)
		if !fs.force {
			return errors.New("choose stronger parameters, use defaults, or force with -f")
		}
	}

	prompt := fmt.Sprintf("Key passphrase for %s", skFilename)
	passphrase, err := promptPassphrase(prompt)
	if err != nil {
		return err
	}
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
	}
	prompt += " (again)"
	passphraseAgain, err := promptPassphrase(prompt)
	if err != nil {
		return err
	}
	if !bytes.Equal(passphrase, passphraseAgain) {
		return errors.New("passphrases do not match")
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

	kdfp := &keyfile.Argon2idParams{Time: time, Memory: memory * 1024}
	fp, err := keyfile.GenerateKeys(rand.Reader, pkFile, skFile, passphrase, kdfp, fs.comment)
	if err != nil {
		return err
	}
	log.Printf("create %v", pkFilename)
	log.Printf("create %v", skFilename)
	log.Printf("fingerprint: %s", fp)
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
	id := fs.identity
	appdir := appdir()
	skFilename := filepath.Join(appdir, id+".secret")
	if _, err := os.Stat(skFilename); os.IsNotExist(err) {
		return fmt.Errorf("%q not found", skFilename)
	}
	skFile, err := os.Open(skFilename)
	if err != nil {
		log.Fatal(err)
	}

	time := uint32(fs.time)
	memory := uint32(fs.memory)
	if memory < defaultMemory {
		log.Printf("warning: recommended Argon2id memory parameter is %d MiB",
			defaultMemory)
		if !fs.force {
			return errors.New("choose stronger parameters, use defaults, or force with -f")
		}
	}

	prompt := fmt.Sprintf("Current passphrase for %s", skFilename)
	passphrase, err := promptPassphrase(prompt)
	if err != nil {
		return err
	}
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
	}

	sk, kf, err := keyfile.OpenSecretKey(skFile, passphrase)
	if err != nil {
		log.Printf("%s: %v", skFilename, err)
		log.Fatal("The secret keyfile cannot be opened.  " +
			"This may be due to keyfile tampering or an incorrect passphrase.")
	}
	skFile.Close()

	prompt = "New passphrase"
	passphrase, err = promptPassphrase(prompt)
	if err != nil {
		return err
	}
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
	}
	prompt += " (again)"
	passphraseAgain, err := promptPassphrase(prompt)
	if err != nil {
		return err
	}
	if !bytes.Equal(passphrase, passphraseAgain) {
		return errors.New("passphrases do not match")
	}

	tmpDir, tmpBasename := filepath.Split(skFilename)
	tmpFi, err := os.CreateTemp(tmpDir, tmpBasename)
	if err != nil {
		return err
	}
	kdfp := &keyfile.Argon2idParams{Time: time, Memory: memory * 1024}
	err = keyfile.EncryptSecretKey(rand.Reader, tmpFi, sk, passphrase, kdfp, kf)
	if err != nil {
		return err
	}
	tmpFi.Close()
	err = os.Rename(tmpFi.Name(), skFilename)
	if err != nil {
		return err
	}
	log.Printf("rewrite %v", skFilename)
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
		out, err = os.Create(outFlag)
		if err != nil {
			log.Fatal(err)
		}
	}
	if inFlag != "" && inFlag != "-" {
		in, err = os.Open(inFlag)
		if err != nil {
			log.Fatal(err)
		}
	}
	return out, in
}

func encrypt(fs *encryptFlags) {
	out, in := stdio(fs.out, fs.in)
	switch out := out.(type) {
	case interface{ Fd() uintptr }: // implemented by *os.File
		if terminal.IsTerminal(int(out.Fd())) {
			log.Printf("output file is a terminal")
			log.Printf("use shell redirection or set -out flag to a filename")
			fs.usage()
			os.Exit(2)
		}
	}

	var header []byte
	var key *stream.SymmetricKey
	var err error
	if fs.passphrase {
		time := uint32(fs.time)
		memory := uint32(fs.memory)
		if memory < defaultMemory {
			log.Printf("warning: recommended Argon2id memory parameter is %d MiB",
				defaultMemory)
			if !fs.force {
				log.Fatal("choose stronger parameters, use defaults, or force with -f")
			}
		}
		memory *= 1024

		passphrase, err := promptPassphrase("Encryption passphrase")
		if err != nil {
			log.Fatal(err)
		}
		passphraseAgain, err := promptPassphrase("Encryption passphrase (again)")
		if err != nil {
			log.Fatal(err)
		}
		if !bytes.Equal(passphrase, passphraseAgain) {
			log.Fatal("passphrases do not match")
		}
		header, key, err = stream.PassphraseHeader(rand.Reader, passphrase, time, memory)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		// Read identity's public key
		pkFilename := fs.id
		if !strings.HasSuffix(pkFilename, ".public") {
			appdir := appdir()
			pkFilename = filepath.Join(appdir, fs.id+".public")
		}
		if _, err := os.Stat(pkFilename); os.IsNotExist(err) {
			log.Printf("%s does not exist", pkFilename)
			log.Fatal("use '-i' flag to choose another identity or generate default keys with 'ss keygen'")
		}
		pkFile, err := os.Open(pkFilename)
		if err != nil {
			log.Fatal(err)
		}
		pk, err := keyfile.ReadPublicKey(pkFile)
		if err != nil {
			log.Fatalf("%s: %v", pkFilename, err)
		}

		header, key, err = stream.Encapsulate(rand.Reader, pk)
		if err != nil {
			log.Fatal(err)
		}
	}

	err = stream.Encrypt(out, in, header, key)
	if err != nil {
		log.Fatal(err)
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
	out, in := stdio(fs.out, fs.in)
	header, err := stream.ReadHeader(in)
	if err != nil {
		log.Fatal(err)
	}

	var key *stream.SymmetricKey
	switch header.Scheme {
	default:
		panic(header.Scheme)
	case stream.StreamlinedNTRUPrime4591761Scheme:
		// Read and decrypt secret key
		appdir := appdir()
		skFilename := filepath.Join(appdir, fs.id+".secret")
		skFile, err := os.Open(skFilename)
		if err != nil {
			log.Fatal(err)
		}
		passphrase, err := promptPassphrase(fmt.Sprintf("Key passphrase for %s", skFilename))
		if err != nil {
			log.Fatal(err)
		}
		sk, _, err := keyfile.OpenSecretKey(skFile, passphrase)
		if err != nil {
			log.Printf("%s: %v", skFilename, err)
			log.Fatal("The secret keyfile cannot be opened.  " +
				"This may be due to keyfile tampering or an incorrect passphrase.")
		}
		key, err = stream.Decapsulate(header, sk)
		if err != nil {
			log.Fatal(err)
		}
	case stream.Argon2idScheme:
		passphrase, err := promptPassphrase("Decryption passphrase")
		if err != nil {
			log.Fatal(err)
		}
		key, err = stream.PassphraseKey(header, passphrase)
		if err != nil {
			log.Fatal(err)
		}
	}
	err = stream.Decrypt(out, in, header.Bytes, key)
	if err != nil {
		log.Fatal(err)
	}
}
