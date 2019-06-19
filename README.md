# Ss

Ss is a tool and library to perform PKI-based file and stream encryption.  It
is built using:

* Streamlined NTRU Prime 4591^761 Cryptosystem (for PKI and shared key exchange)

* ChaCha20-Poly1305 (for Authenticated Encryption with Associated Data of encrypted
  messages and secret key files)

* Argon2id (for passphrase-based key derivation for encrypting secret key files)

To use the command-line tool, first generate your default keys with `ss keygen`.
Be sure to backup the created keys.  Secret keys are always encrypted with your
passphrase, and provided a sufficiently-strong passphrase was used, are safe to
backup with untrusted parties.

Files and streams can be encrypted for yourself with `ss encrypt`.  By default,
stdin is read and encrypted to stdout.  Use the `-in` and `-out` flags, or use
shell redirection, to deal with file input/output.

Encryption for another party may be performed by specifying the `-i` parameter
when running `ss encrypt`.  Their public keyfile must be saved at
`~/.ss/$them.public` for `ss` to recognize and read the key.

Decryption is performed using `ss decrypt`.  Like `encrypt`, this operation
consumes stdin and writes to stdout by default, and the same flags are used to
change this behavior.

## Install

```
$ GO111MODULE=on go get github.com/jrick/ss
```

## FAQ

### What does Ss stand for?

Super Sekrit.

Or something else.  I don't care.  Use your imagination.

### Why make this?

I never want to use GPG again.

## Disclaimer

Lattice-based cryptography is young and not well understood.  Use at your own risk.

## License

This project is free software released under the permissive
[Blue Oak Model License 1.0.0](https://blueoakcouncil.org/license/1.0.0).  All
contributions must share this license.
