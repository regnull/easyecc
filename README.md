# Easy Elliptic Curve Cryptography in Go

This package ties several other commonly used cryptography packages together. The goal is to make common cryptographic operations simple. It is based on [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) cryptography, most famously used by Bitcoin.

## Creating Private Keys

There are several ways to create private keys:

```
import (
  "math/big"
  "github.com/regnull/easyecc"
)

key1, err := easyecc.NewRandomPrivateKey()
if err != nil {
  // Do something.
}


// Or, create a private key from a secret:
secret := big.NewInt(123)
key2, err := easyecc.NewPrivateKey(secret)

// Or, create a private key from a password and salt:
password := []byte("supersecretpassword")
salt := []byte("12345")
key3, err := easyecc.NewPrivateKeyFromPassword(password, salt)

// Or, create a private key from encrypted bytes:
// Read data from previously saved somehow.
passphrase := "super secret passphrase"
key4, err := easycc.NewPrivateKeyFromEncryptedWithPassphrase(data, passphrase)

// Finally, you can load a private key that was previously saved to a file:
key5, err := easyecc.LoadPrivateKey("some/file.key")
```

## Signing Data and Verifying the Signature
