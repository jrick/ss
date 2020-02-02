# Ss

Ss is a tool and library to perform passphrase-based or PKI-based file and
stream encryption.  It is built using:

* Streamlined NTRU Prime 4591^761 Cryptosystem (for PKI and shared key exchange)

* ChaCha20-Poly1305 (for Authenticated Encryption with Associated Data of encrypted
  messages and secret key files)

* Argon2id (for passphrase-based key derivation)

## PKI encryption

To use the PKI features, first generate your default keys with `ss keygen`.
Be sure to backup the created keys.  Secret keys are always encrypted with your
passphrase, and provided a sufficiently-strong passphrase was used, are safe to
backup with untrusted parties.

Files and streams can be encrypted for yourself with `ss encrypt`.  By default,
stdin is read and encrypted to stdout.  Use the `-in` and `-out` flags, or use
shell redirection, to deal with file input/output.

Encryption for another party is configured by specifying their identity name or
their pubkey file with the `-i` parameter.  Using identity names requires their
key to be recorded at `~/.ss/$them.public`.

Decryption is performed using `ss decrypt`.  Like `encrypt`, this operation
consumes stdin and writes to stdout by default, and the same flags are used to
change this behavior.

## Passphrase encryption

Passphrase encryption operates similarly to PKI encryption, but does not require
any keyfiles.  Instead, messages are encrypted with a key derived through a
passphrase.

Passphrase encryption is performed with `ss encrypt -passphrase`.  Decrypting
this output does not require any additional options.

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

Ss has not reached stability of any kind.  Decryption may require a build built at
the exact version used to encrypt a message.

Lattice-based cryptography is young and not widely understood.  Use at your own risk.

## License

This project is free software released under the permissive
[Blue Oak Model License 1.0.0](https://blueoakcouncil.org/license/1.0.0).  All
contributions must share this license.
