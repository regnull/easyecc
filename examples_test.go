package easyecc

import (
	"fmt"
	"log"
	"math/big"
)

func ExamplePrivateKey_Sign() {
	privateKey := CreatePrivateKey(P256, big.NewInt(12345))
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
}

func ExamplePrivateKey_Encrypt() {
	aliceKey, err := GeneratePrivateKey(P256)
	if err != nil {
		log.Fatal(err)
	}
	bobKey, err := GeneratePrivateKey(P256)
	if err != nil {
		log.Fatal(err)
	}
	data := "super secret message"
	encrypted, err := aliceKey.EncryptECDH([]byte(data), bobKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := bobKey.DecryptECDH(encrypted, aliceKey.PublicKey())
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", string(decrypted))
	// Output: super secret message
}

func ExamplePrivateKey_EncryptKeyWithPassphrase() {
	privateKey := CreatePrivateKey(P256, big.NewInt(12345))
	encryptedKey, err := privateKey.EncryptKeyWithPassphrase("my passphrase")
	if err != nil {
		log.Fatal(err)
	}
	decryptedKey, err := CreatePrivateKeyFromEncrypted(P256, encryptedKey, "my passphrase")
	fmt.Printf("%d\n", decryptedKey.Secret())
	// Output: 12345
}

func ExamplePublicKey_SerializeCompressed() {
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
}

func ExamplePublicKey_BitcoinAndEthereumAddress() {
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
}
