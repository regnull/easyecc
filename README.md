# Easy Elliptic Curve Cryptography in Go

![GitHub Workflow Status](https://img.shields.io/github/workflow/status/regnull/easyecc/Go)

This package ties several other commonly used cryptography packages together. The goal is to make common cryptographic operations simple. It is based on [secp256k1](https://en.bitcoin.it/wiki/Secp256k1) cryptography, most famously used by Bitcoin.

This package was originally the part of https://github.com/regnull/ubikom, but then became its own little package, because why not.

## Examples

Sign hash and verify signature:

```
	privateKey := NewPrivateKey(big.NewInt(12345))
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

Encrypt data so only the owner of the private key can decrypt it:

```
	aliceKey, err := NewRandomPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	bobKey, err := NewRandomPrivateKey()
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

Encrypt private key with passphrase:
```
	privateKey := NewPrivateKey(big.NewInt(12345))
	encryptedKey, err := privateKey.EncryptKeyWithPassphrase("my passphrase")
	if err != nil {
		log.Fatal(err)
	}
	decryptedKey, err := NewPrivateKeyFromEncryptedWithPassphrase(encryptedKey, "my passphrase")
	fmt.Printf("%d\n", decryptedKey.Secret())
	// Output: 12345
```

Convert public key to the serialized compressed representation:
```
	privateKey := NewPrivateKey(big.NewInt(12345))
	publicKey := privateKey.PublicKey()
	serializedCompressed := publicKey.SerializeCompressed()
	fmt.Printf("%x\n", serializedCompressed)
	publicKeyCopy, err := NewPublicFromSerializedCompressed(serializedCompressed)
	if err != nil {
		log.Fatal(err)
	}
	sameKey := publicKey.Equal(publicKeyCopy)
	fmt.Printf("the correct key was created: %v\n", sameKey)
	// Output: 03f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f
	// the correct key was created: true
```
