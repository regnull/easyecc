# Easy Elliptic Curve Cryptography in Go

This package ties several other commonly used cryptography packages together. The goal is to make common cryptographic operations simple. It is based on [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) cryptography, most famously used by Bitcoin.

## Creating Private Keys

Create a new random private key:

```
  import github.com/regnull/easyecc
  
  key, err := easyecc.NewRandomPrivateKey()
  if err != nil {
    // Do something.
  }
```
