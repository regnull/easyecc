package easyecc

import (
	"fmt"
	"log"
	"math/big"
)

func ExamplePrivateKey_Sign() {
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
}

func ExamplePrivateKey_Encrypt() {
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
}

func ExamplePrivateKey_MarshalToJSON() {
	privateKey := NewPrivateKeyFromSecret(P256, big.NewInt(12345))
	jwkBytes, err := privateKey.MarshalToJSON()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", jwkBytes)

	privateKeyCopy, err := NewPrivateKeyFromJSON(jwkBytes)
	if err != nil {
		log.Fatal(err)
	}
	if privateKey.Equal(privateKeyCopy) {
		fmt.Printf("keys match!")
	}
	// Output: {"kty":"EC","crv":"P-256","x":"Ju/OvQ7p40pmkYfhizqRIrL3M5RbZJzJ+fkh6fna2BI","y":"kCOL3pzHuzMNFQxncE3SWucFUgV0S28xv0BwdFhy0OY","d":"MDk"}
	// keys match!
}

func ExamplePublicKey_SerializeCompressed() {
	privateKey := NewPrivateKeyFromSecret(P256, big.NewInt(12345))
	publicKey := privateKey.PublicKey()
	serializedCompressed := publicKey.CompressedBytes()
	fmt.Printf("%x\n", serializedCompressed)
	publicKeyCopy, err := NewPublicKeyFromCompressedBytes(P256, serializedCompressed)
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
	privateKey := NewPrivateKeyFromSecret(SECP256K1, big.NewInt(12345))
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
