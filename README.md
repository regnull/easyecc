# Easy Elliptic Curve Cryptography in Go

![GitHub Workflow Status](https://github.com/regnull/easyecc/actions/workflows/go.yml/badge.svg)
[![GoDoc reference example](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/regnull/easyecc)
[![GoReportCard example](https://goreportcard.com/badge/github.com/regnull/easyecc)](https://goreportcard.com/report/github.com/regnull/easyecc)
[![Coverage Status](https://coveralls.io/repos/github/regnull/easyecc/badge.svg?branch=master)](https://coveralls.io/github/regnull/easyecc?branch=master)

This package ties several other commonly used cryptography packages together. The goal is to make common cryptographic operations simple. 
The following elliptic curves are supported:

* [secp256k1](https://en.bitcoin.it/wiki/Secp256k1)

* [P-256](https://neuromancer.sk/std/nist/P-256)

* [P-384](https://neuromancer.sk/std/nist/P-384)

* [P-521](https://neuromancer.sk/std/nist/P-521)


This package was originally the part of https://github.com/regnull/ubikom, but then became its own little package, because why not.

## Examples

(see examples_test.go and encryption_test.go files).

Elliptic curves are defined as constants:

```Go
const (
	SECP256K1 EllipticCurve = 1
	P256      EllipticCurve = 2
	P384      EllipticCurve = 3
	P521      EllipticCurve = 4
)
```

Use them when creating keys.

## Sign hash and verify signature (Using [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm))

```Go
privateKey := NewPrivateKeyFromSecret(P256, big.NewInt(12345))
data := "super secret message"
hash := Hash256([]byte(data))
signature, err := privateKey.Sign(hash)
if err != nil {
    log.Fatal(err)
}
publicKey := privateKey.PublicKey()
success := signature.Verify(publicKey, hash)
fmt.Printf("Signature verified: %v\n", success)
// Output: Signature verified: true
```

## Encrypt with shared secret (Using [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman)):

```Go
aliceKey, err := NewPrivateKey(P256)
if err != nil {
    log.Fatal(err)
}
bobKey, err := NewPrivateKey(P256)
if err != nil {
    log.Fatal(err)
}
data := "super secret message"
encrypted, err := aliceKey.Encrypt([]byte(data), bobKey.PublicKey())
if err != nil {
    log.Fatal(err)
}
decrypted, err := bobKey.Decrypt(encrypted, aliceKey.PublicKey())
if err != nil {
    log.Fatal(err)
}
fmt.Printf("%s\n", string(decrypted))
// Output: super secret message
```

## Encrypt private key with passphrase

```Go
privateKey := CreatePrivateKey(P256, big.NewInt(12345))
encryptedKey, err := privateKey.EncryptKeyWithPassphrase("my passphrase")
if err != nil {
	log.Fatal(err)
}
decryptedKey, err := CreatePrivateKeyFromEncrypted(P256, encryptedKey, "my passphrase")
fmt.Printf("%d\n", decryptedKey.Secret())
// Output: 12345
```

## Serialize Public Key

```Go
privateKey := CreatePrivateKey(P256, big.NewInt(12345))
publicKey := privateKey.PublicKey()
serializedCompressed := publicKey.SerializeCompressed()
fmt.Printf("%x\n", serializedCompressed)
publicKeyCopy, err := DeserializeCompressed(P256, serializedCompressed)
if err != nil {
	log.Fatal(err)
}
sameKey := publicKey.Equal(publicKeyCopy)
fmt.Printf("the correct key was created: %v\n", sameKey)
// Output: 0226efcebd0ee9e34a669187e18b3a9122b2f733945b649cc9f9f921e9f9dad812
// the correct key was created: true
```

## Getting Bitcoin and Ethereum addresses:
```Go
// BitcoinAddress and EthereumAddress only work for secp256k1 curve.
privateKey := CreatePrivateKey(SECP256K1, big.NewInt(12345))
publicKey := privateKey.PublicKey()
bitcoinAddress, err := publicKey.BitcoinAddress()
if err != nil {
	log.Fatal(err)
}
fmt.Printf("Bitcoin address: %s\n", bitcoinAddress)
ethereumAddress, err := publicKey.EthereumAddress()
if err != nil {
	log.Fatal(err)
}
fmt.Printf("Ethereum address: %s\n", ethereumAddress)
// Output: Bitcoin address: 12vieiAHxBe4qCUrwvfb2kRkDuc8kQ2VZ2
// Ethereum address: 0xEB4665750b1382DF4AeBF49E04B429AAAc4d9929
```

## JWK Support

EasyECC offers some limited JWK support (see https://www.rfc-editor.org/rfc/rfc7517).
Private keys can be exported and imported as JWK JSON:
```Go
privateKey := CreatePrivateKey(P256, big.NewInt(12345))
jwkBytes, err := privateKey.MarshalToJWK()
if err != nil {
	log.Fatal(err)
}
fmt.Printf("%s\n", jwkBytes)

privateKeyCopy, err := CreatePrivateKeyFromJWK(jwkBytes)
if err != nil {
	log.Fatal(err)
}
if privateKey.Equal(privateKeyCopy) {
	fmt.Printf("keys match!")
}
// Output: {
//   "kty": "EC",
//   "crv": "P-256",
//   "x": "Ju/OvQ7p40pmkYfhizqRIrL3M5RbZJzJ+fkh6fna2BI",
//   "y": "kCOL3pzHuzMNFQxncE3SWucFUgV0S28xv0BwdFhy0OY",
//   "d": "MDk"
// }
// keys match!
```
