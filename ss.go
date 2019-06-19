// This code is available on the terms of the project LICENSE.md file,
// also available online at https://blueoakcouncil.org/license/1.0.0.

package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/jrick/ss/keyfile"
	"github.com/jrick/ss/stream"
	"golang.org/x/crypto/ssh/terminal"
)

func usage() {
	fmt.Fprintf(os.Stderr, `Usage of %s:
  %[1]s keygen [-i id] [-t time] [-m memory (KiB)] [-c comment]
  %[1]s encrypt [-i id] [-in input] [-out output]
  %[1]s decrypt [-i id] [-in input] [-out output]
`, filepath.Base(os.Args[0]))
	os.Exit(2)
}

func init() {
	flag.Usage = usage
}

func main() {
	flag.Parse()          // for -h usage
	if len(os.Args) < 2 { // one command is required
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		fs := new(keygenFlags).parse(os.Args[2:])
		err = keygen(fs)
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
	defaultTime   = 1
	defaultMemory = 64 * 1024
)

func (f *keygenFlags) parse(args []string) *keygenFlags {
	fs := flag.NewFlagSet("ss keygen", flag.ExitOnError)
	fs.StringVar(&f.identity, "i", defaultID, "identity name")
	fs.UintVar(&f.time, "t", defaultTime, "Argon2id time")
	fs.UintVar(&f.memory, "m", defaultMemory, "Argon2id memory (KiB)")
	fs.BoolVar(&f.force, "f", false, "force Argon2id key derivation despite low parameters")
	fs.StringVar(&f.comment, "c", "", "comment")
	fs.Parse(args)
	return f
}

func promptPassphrase() ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		panic(err)
	}
	defer tty.Close()
	_, err = fmt.Fprint(tty, "Secret key passphrase: ")
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
		r := recover()
		if r != nil || err != nil {
			os.Remove(pkFilename)
			os.Remove(skFilename)
		}
		if r != nil {
			panic(r)
		}
	}()

	passphrase, err := promptPassphrase()
	if err != nil {
		return err
	}
	if len(passphrase) == 0 {
		return errors.New("empty passphrase")
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

	time := uint32(fs.time)
	memory := uint32(fs.memory)
	if memory < defaultMemory {
		log.Printf("warning: recommended Argon2id memory parameter is %d KiB (%d MiB)",
			defaultMemory, defaultMemory/1024)
		if !fs.force {
			return errors.New("choose stronger parameters, use defaults, or force with -f")
		}
	}

	kdfp := &keyfile.Argon2idParams{Time: time, Memory: memory}
	fp, err := keyfile.GenerateKeys(rand.Reader, pkFile, skFile, passphrase, kdfp, fs.comment)
	if err != nil {
		return err
	}
	log.Printf("create %v", pkFilename)
	log.Printf("create %v", skFilename)
	log.Printf("fingerprint: %s", fp)
	return nil
}

type encryptFlags struct {
	id  string
	in  string
	out string
}

func (f *encryptFlags) parse(args []string) *encryptFlags {
	fs := flag.NewFlagSet("ss enc", flag.ExitOnError)
	fs.StringVar(&f.id, "i", defaultID, "identity")
	fs.StringVar(&f.in, "in", "", "input file")
	fs.StringVar(&f.out, "out", "", "output file")
	fs.Parse(args)
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
	if inFlag != "" && outFlag != "-" {
		in, err = os.Open(inFlag)
		if err != nil {
			log.Fatal(err)
		}
	}
	return out, in
}

func encrypt(fs *encryptFlags) {
	// Read identity's public key
	appdir := appdir()
	pkFilename := filepath.Join(appdir, fs.id+".public")
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

	out, in := stdio(fs.out, fs.in)
	err = stream.Encrypt(rand.Reader, out, in, pk)
	if err != nil {
		log.Fatal(err)
	}
}

type decryptFlags struct {
	id  string
	in  string
	out string
}

const defaultID = "id"

func (f *decryptFlags) parse(args []string) *decryptFlags {
	fs := flag.NewFlagSet("ss dec", flag.ExitOnError)
	fs.StringVar(&f.id, "i", defaultID, "identity")
	fs.StringVar(&f.in, "in", "", "input file")
	fs.StringVar(&f.out, "out", "", "output file")
	fs.Parse(args)
	return f
}

func decrypt(fs *decryptFlags) {
	// Read and decrypt secret key
	appdir := appdir()
	skFilename := filepath.Join(appdir, fs.id+".secret")
	skFile, err := os.Open(skFilename)
	if err != nil {
		log.Fatal(err)
	}
	passphrase, err := promptPassphrase()
	if err != nil {
		log.Fatal(err)
	}
	sk, err := keyfile.OpenSecretKey(skFile, passphrase)
	if err != nil {
		log.Printf("%s: %v", skFilename, err)
		log.Fatal("The secret keyfile cannot be opened.  " +
			"This may be due to keyfile tampering or an incorrect passphrase.")
	}

	out, in := stdio(fs.out, fs.in)
	err = stream.Decrypt(out, in, sk)
	if err != nil {
		log.Fatal(err)
	}
}
